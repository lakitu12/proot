/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */
#include <sys/stat.h> /* lstat(2), */
#include <unistd.h>   /* getcwd(2), lstat(2), */
#include <string.h>   /* string(3), memset(3), */
#include <assert.h>   /* assert(3), */
#include <limits.h>   /* PATH_MAX, */
#include <errno.h>    /* E* */
#include <sys/queue.h> /* CIRCLEQ_*, */
#include <talloc.h>   /* talloc_*, */
#include "path/binding.h"
#include "path/path.h"
#include "path/canon.h"
#include "cli/note.h"
#include "compat.h"

// 固定宏定义，消除重复计算，编译器可常量折叠
#define HEAD(tracee, side)						\
	(side == GUEST							\
		? (tracee)->fs->bindings.guest				\
		: (side == HOST						\
			? (tracee)->fs->bindings.host			\
			: (tracee)->fs->bindings.pending))
#define NEXT(binding, side)						\
	(side == GUEST							\
		? CIRCLEQ_NEXT(binding, link.guest)			\
		: (side == HOST						\
			? CIRCLEQ_NEXT(binding, link.host)		\
			: CIRCLEQ_NEXT(binding, link.pending)))
#define CIRCLEQ_FOREACH_(tracee, binding, side)				\
	for (binding = CIRCLEQ_FIRST(HEAD(tracee, side));		\
	     binding != (void *) HEAD(tracee, side);			\
	     binding = NEXT(binding, side))
#define CIRCLEQ_INSERT_AFTER_(tracee, previous, binding, side) do {	\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.guest);   break; \
	case HOST:  CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.host);    break; \
	default:    CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)
#define CIRCLEQ_INSERT_BEFORE_(tracee, next, binding, side) do {	\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.guest);   break; \
	case HOST:  CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.host);    break; \
	default:    CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)
#define CIRCLEQ_INSERT_HEAD_(tracee, binding, side) do {		\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.guest);   break; \
	case HOST:  CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.host);    break; \
	default:    CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)
#define IS_LINKED(binding, link)					\
	((binding)->link.cqe_next != NULL && (binding)->link.cqe_prev != NULL)
#define CIRCLEQ_REMOVE_(tracee, binding, name) do {			\
	CIRCLEQ_REMOVE((tracee)->fs->bindings.name, binding, link.name);\
	(binding)->link.name.cqe_next = NULL;				\
	(binding)->link.name.cqe_prev = NULL;				\
	talloc_unlink((tracee)->fs->bindings.name, binding);		\
} while (0)

/**
 * Print all bindings (verbose purpose).
 */
static void print_bindings(const Tracee *tracee)
{
	const Binding *binding;
	if (__builtin_expect(tracee->fs->bindings.guest == NULL, 0))
		return;
	CIRCLEQ_FOREACH_(tracee, binding, GUEST) {
		if (compare_paths(binding->host.path, binding->guest.path) == PATHS_ARE_EQUAL)
			note(tracee, INFO, USER, "binding = %s", binding->host.path);
		else
			note(tracee, INFO, USER, "binding = %s:%s",
				binding->host.path, binding->guest.path);
	}
}

/**
 * 工具函数：安全获取当前工作目录（兼容const Tracee*）
 */
static inline int getcwd2_const(const Tracee *tracee, char guest_path[PATH_MAX])
{
	if (tracee == NULL) {
#ifdef __ANDROID__
		char *cwd = getcwd(guest_path, PATH_MAX);
		if (__builtin_expect(cwd != NULL, 1)) {
			return 0;
		}
		const char *pwd = getenv("PWD");
		if (pwd != NULL && strlen(pwd) < PATH_MAX) {
			strcpy(guest_path, pwd);
			return 0;
		}
		strcpy(guest_path, "/");
		return 0;
#else
		if (getcwd(guest_path, PATH_MAX) == NULL)
			return -errno;
#endif
	}
	else {
		const size_t cwd_len = strlen(tracee->fs->cwd);
		if (__builtin_expect(cwd_len >= PATH_MAX, 0))
			return -ENAMETOOLONG;
		memcpy(guest_path, tracee->fs->cwd, cwd_len + 1);
	}
	return 0;
}

/**
 * Get the binding for the given @path (relatively to the given
 * binding @side).
 */
__attribute__((pure))
Binding *get_binding(const Tracee *tracee, Side side, const char path[PATH_MAX])
{
	Binding *binding;
	size_t path_length;

	// 核心修复1：增加路径合法性校验，处理空路径/相对路径
	if (__builtin_expect(path == NULL || path[0] == '\0', 0)) {
		return NULL;
	}

	// 处理相对路径：自动转为绝对路径（基于当前工作目录）
	char abs_path[PATH_MAX];
	const char *use_path = path;
	if (path[0] != '/') {
		char cwd[PATH_MAX];
		// 核心修复2：用兼容const的getcwd2_const，解决指针类型不匹配警告
		int status = getcwd2_const(tracee, cwd);
		if (__builtin_expect(status < 0, 0)) {
			return NULL;
		}
		// 拼接为绝对路径
		status = join_paths(2, abs_path, cwd, path);
		if (__builtin_expect(status < 0, 0)) {
			return NULL;
		}
		use_path = abs_path;
	}

	// 此时use_path必为绝对路径，安全触发断言
	assert(use_path != NULL && use_path[0] == '/');
	path_length = strlen(use_path);

	CIRCLEQ_FOREACH_(tracee, binding, side) {
		const Path *ref;
		switch (side) {
		case GUEST: ref = &binding->guest; break;
		case HOST:  ref = &binding->host;  break;
		default:    assert(0); return NULL;
		}

		const Comparison comparison = compare_paths2(ref->path, ref->length, use_path, path_length);
		if (comparison != PATHS_ARE_EQUAL && comparison != PATH1_IS_PREFIX)
			continue;

		if (__builtin_expect(side == HOST && compare_paths(get_root(tracee), "/") != PATHS_ARE_EQUAL && belongs_to_guestfs(tracee, use_path), 0))
			continue;

		return binding;
	}
	return NULL;
}

/**
 * Get the binding path for the given @path (relatively to the given
 * binding @side).
 */
__attribute__((pure))
const char *get_path_binding(const Tracee *tracee, Side side, const char path[PATH_MAX])
{
	const Binding *binding = get_binding(tracee, side, path);
	if (__builtin_expect(binding == NULL, 0))
		return NULL;

	switch (side) {
	case GUEST: return binding->guest.path;
	case HOST:  return binding->host.path;
	default:    assert(0); return NULL;
	}
}

/**
 * Return the path to the guest rootfs for the given @tracee, from the
 * host point-of-view obviously.
 */
__attribute__((pure))
const char *get_root(const Tracee* tracee)
{
	const Binding *binding;
	if (__builtin_expect(tracee == NULL || tracee->fs == NULL, 0))
		return NULL;

	if (tracee->fs->bindings.guest == NULL) {
		if (__builtin_expect(tracee->fs->bindings.pending == NULL || CIRCLEQ_EMPTY(tracee->fs->bindings.pending), 0))
			return NULL;
		binding = CIRCLEQ_LAST(tracee->fs->bindings.pending);
		if (__builtin_expect(compare_paths(binding->guest.path, "/") != PATHS_ARE_EQUAL, 0))
			return NULL;
		return binding->host.path;
	}

	assert(!CIRCLEQ_EMPTY(tracee->fs->bindings.guest));
	binding = CIRCLEQ_LAST(tracee->fs->bindings.guest);
	assert(strcmp(binding->guest.path, "/") == 0);
	return binding->host.path;
}

/**
 * Substitute the guest path (if any) with the host path in @path.
 */
int substitute_binding(const Tracee *tracee, Side side, char path[PATH_MAX])
{
	const Binding *binding = get_binding(tracee, side, path);
	if (__builtin_expect(binding == NULL, 0))
		return -ENOENT;

	if (__builtin_expect(!binding->need_substitution, 1))
		return 0;

	const Path *ref, *reverse_ref;
	switch (side) {
	case GUEST: ref = &binding->guest; reverse_ref = &binding->host; break;
	case HOST:  ref = &binding->host;  reverse_ref = &binding->guest; break;
	default:    assert(0); return -EACCES;
	}

	substitute_path_prefix(path, ref->length, reverse_ref->path, reverse_ref->length);
	return 1;
}

/**
 * Remove @binding from all the @tracee's lists of bindings it belongs to.
 */
void remove_binding_from_all_lists(const Tracee *tracee, Binding *binding)
{
       if (IS_LINKED(binding, link.pending))
	       CIRCLEQ_REMOVE_(tracee, binding, pending);
       if (IS_LINKED(binding, link.guest))
	       CIRCLEQ_REMOVE_(tracee, binding, guest);
       if (IS_LINKED(binding, link.host))
	       CIRCLEQ_REMOVE_(tracee, binding, host);
}

/**
 * Insert @binding into the list of @bindings, in a sorted manner.
 */
static void insort_binding(const Tracee *tracee, Side side, Binding *binding)
{
	Binding *iterator, *previous = NULL;
	Binding *next = CIRCLEQ_FIRST(HEAD(tracee, side));

	CIRCLEQ_FOREACH_(tracee, iterator, side) {
		const Path *binding_path, *iterator_path;
		switch (side) {
		case PENDING:
		case GUEST: binding_path = &binding->guest; iterator_path = &iterator->guest; break;
		case HOST:  binding_path = &binding->host;  iterator_path = &iterator->host;  break;
		default:    assert(0); return;
		}

		const Comparison comparison = compare_paths2(binding_path->path, binding_path->length,
					    iterator_path->path, iterator_path->length);
		switch (comparison) {
		case PATHS_ARE_EQUAL:
			if (side == HOST) {
				previous = iterator;
				break;
			}
			if (__builtin_expect(tracee->verbose > 0 && getenv("PROOT_IGNORE_MISSING_BINDINGS") == NULL, 0)) {
				note(tracee, WARNING, USER,
					"both '%s' and '%s' are bound to '%s', "
					"only the last binding is active.",
					iterator->host.path, binding->host.path,
					binding->guest.path);
			}
			CIRCLEQ_INSERT_AFTER_(tracee, iterator, binding, side);
			remove_binding_from_all_lists(tracee, iterator);
			return;
		case PATH1_IS_PREFIX:  previous = iterator; break;
		case PATH2_IS_PREFIX:  if (next == (void *) HEAD(tracee, side)) next = iterator; break;
		case PATHS_ARE_NOT_COMPARABLE: break;
		default: assert(0); return;
		}
	}

	if (previous != NULL)
		CIRCLEQ_INSERT_AFTER_(tracee, previous, binding, side);
	else if (next != (void *) HEAD(tracee, side))
		CIRCLEQ_INSERT_BEFORE_(tracee, next, binding, side);
	else
		CIRCLEQ_INSERT_HEAD_(tracee, binding, side);
}

/**
 * c.f. function above.
 */
static void insort_binding2(const Tracee *tracee, Binding *binding)
{
	binding->need_substitution = (compare_paths(binding->host.path, binding->guest.path) != PATHS_ARE_EQUAL);
	insort_binding(tracee, GUEST, binding);
	insort_binding(tracee, HOST, binding);
}

/**
 * Create and insert a new binding into the list of @tracee's bindings.
 */
Binding *insort_binding3(const Tracee *tracee, const TALLOC_CTX *context,
			const char host_path[PATH_MAX], const char guest_path[PATH_MAX])
{
	Binding *binding = talloc_zero(context, Binding);
	if (__builtin_expect(binding == NULL, 0))
		return NULL;

	memcpy(binding->host.path, host_path, PATH_MAX);
	memcpy(binding->guest.path, guest_path, PATH_MAX);
	binding->host.length = strlen(binding->host.path);
	binding->guest.length = strlen(binding->guest.path);

	insort_binding2(tracee, binding);
	return binding;
}

/**
 * Free all bindings from @bindings. (Talloc destructor)
 */
static int remove_bindings(Bindings *bindings)
{
	Binding *binding, *next;
	Tracee *tracee = TRACEE(bindings);
	if (__builtin_expect(tracee == NULL, 0))
		return 0;

#define CIRCLEQ_REMOVE_ALL(name) do {				\
	binding = CIRCLEQ_FIRST(bindings);			\
	while (binding != (void *) bindings) {			\
		next = CIRCLEQ_NEXT(binding, link.name);		\
		CIRCLEQ_REMOVE_(tracee, binding, name);		\
		binding = next;					\
	}							\
} while (0)

	if (bindings == tracee->fs->bindings.pending)
		CIRCLEQ_REMOVE_ALL(pending);
	else if (bindings == tracee->fs->bindings.guest)
		CIRCLEQ_REMOVE_ALL(guest);
	else if (bindings == tracee->fs->bindings.host)
		CIRCLEQ_REMOVE_ALL(host);

	memset(bindings, 0, sizeof(Bindings));
	return 0;
}

/**
 * Allocate a new binding "@host:@guest" and attach it to pending list.
 */
Binding *new_binding(Tracee *tracee, const char *host, const char *guest, bool must_exist)
{
	Binding *binding;
	char base[PATH_MAX];
	int status;

	if (tracee->fs->bindings.pending == NULL) {
		tracee->fs->bindings.pending = talloc_zero(tracee->fs, Bindings);
		if (__builtin_expect(tracee->fs->bindings.pending == NULL, 0))
			return NULL;
		CIRCLEQ_INIT(tracee->fs->bindings.pending);
		talloc_set_destructor(tracee->fs->bindings.pending, remove_bindings);
	}

	binding = talloc_zero(tracee->ctx, Binding);
	if (__builtin_expect(binding == NULL, 0))
		return NULL;

	status = realpath2(tracee->reconf.tracee, binding->host.path, host, true);
	if (__builtin_expect(status < 0, 0)) {
		if (must_exist && getenv("PROOT_IGNORE_MISSING_BINDINGS") == NULL)
			note(tracee, WARNING, INTERNAL, "can't sanitize binding \"%s\": %s",
				host, strerror(-status));
		goto error;
	}
	binding->host.length = strlen(binding->host.path);

	guest = guest ?: host;
	if (guest[0] != '/') {
		status = getcwd2(tracee->reconf.tracee, base);
		if (__builtin_expect(status < 0, 0)) {
			note(tracee, WARNING, INTERNAL, "can't get cwd for binding: %s", strerror(-status));
			goto error;
		}
	}
	else
		strcpy(base, "/");

	status = join_paths(2, binding->guest.path, base, guest);
	if (__builtin_expect(status < 0, 0)) {
		note(tracee, WARNING, SYSTEM, "can't sanitize binding \"%s\"", guest);
		goto error;
	}
	binding->guest.length = strlen(binding->guest.path);

	insort_binding(tracee, PENDING, binding);
	return binding;

error:
	TALLOC_FREE(binding);
	return NULL;
}

/**
 * Canonicalize the guest part of the given @binding.
 */
static void initialize_binding(Tracee *tracee, Binding *binding)
{
	char path[PATH_MAX];
	struct stat statl;
	int status;

	if (compare_paths(binding->guest.path, "/") == PATHS_ARE_EQUAL) {
		binding->guest.length = 1;
		insort_binding2(tracee, binding);
		return;
	}

	strcpy(path, binding->guest.path);
	const size_t length = strlen(path);
	assert(length > 0);

	const bool dereference = (path[length - 1] != '!');
	if (!dereference)
		path[length - 1] = '\0';

	strcpy(binding->guest.path, "/");

	status = lstat(binding->host.path, &statl);
	tracee->glue_type = (status < 0 || S_ISBLK(statl.st_mode) || S_ISCHR(statl.st_mode)
			? S_IFREG : statl.st_mode & S_IFMT);

	status = canonicalize(tracee, path, dereference, binding->guest.path, 0);
	if (__builtin_expect(status < 0, 0)) {
		note(tracee, WARNING, INTERNAL,
			"sanitizing the guest path (binding) \"%s\": %s",
			path, strerror(-status));
		tracee->glue_type = 0;
		return;
	}

	chop_finality(binding->guest.path);
	binding->guest.length = strlen(binding->guest.path);

	tracee->glue_type = 0;
	insort_binding2(tracee, binding);
}

/**
 * Add bindings induced by @new_binding when @tracee is being sub-reconfigured.
 */
static void add_induced_bindings(Tracee *tracee, const Binding *new_binding)
{
	if (__builtin_expect(tracee->reconf.tracee == NULL, 1))
		return;

	Binding *old_binding;
	char path[PATH_MAX], path2[PATH_MAX];
	int status;

	strcpy(path, new_binding->host.path);
	status = detranslate_path(tracee->reconf.tracee, path, NULL);
	if (__builtin_expect(status < 0, 0))
		return;

	CIRCLEQ_FOREACH_(tracee->reconf.tracee, old_binding, GUEST) {
		const Comparison comparison = compare_paths(path, old_binding->guest.path);
		if (__builtin_expect(comparison != PATH1_IS_PREFIX, 1))
			continue;

		const size_t prefix_length = (strlen(path) == 1) ? 0 : strlen(path);
		status = join_paths(2, path2, new_binding->guest.path, old_binding->guest.path + prefix_length);
		if (__builtin_expect(status < 0, 0))
			continue;

		Binding *induced_binding = talloc_zero(tracee->ctx, Binding);
		if (__builtin_expect(induced_binding == NULL, 0))
			continue;

		memcpy(induced_binding->host.path, old_binding->host.path, PATH_MAX);
		memcpy(induced_binding->guest.path, path2, PATH_MAX);
		induced_binding->host.length = strlen(induced_binding->host.path);
		induced_binding->guest.length = strlen(induced_binding->guest.path);

		VERBOSE(tracee, 2, "induced binding: %s:%s (old) & %s:%s (new) -> %s:%s (induced)",
			old_binding->host.path, old_binding->guest.path, path, new_binding->guest.path,
			induced_binding->host.path, induced_binding->guest.path);

		insort_binding2(tracee, induced_binding);
	}
}

/**
 * Allocate guest/host binding lists and initialize all pending bindings.
 */
int initialize_bindings(Tracee *tracee)
{
	Binding *binding, *previous;

	assert(get_root(tracee) != NULL);
	assert(tracee->fs->bindings.pending != NULL);
	assert(tracee->fs->bindings.guest == NULL);
	assert(tracee->fs->bindings.host == NULL);

	tracee->fs->bindings.guest = talloc_zero(tracee->fs, Bindings);
	tracee->fs->bindings.host  = talloc_zero(tracee->fs, Bindings);
	if (__builtin_expect(tracee->fs->bindings.guest == NULL || tracee->fs->bindings.host == NULL, 0)) {
		note(tracee, ERROR, INTERNAL, "can't allocate enough memory");
		TALLOC_FREE(tracee->fs->bindings.guest);
		TALLOC_FREE(tracee->fs->bindings.host);
		return -1;
	}

	CIRCLEQ_INIT(tracee->fs->bindings.guest);
	CIRCLEQ_INIT(tracee->fs->bindings.host);
	talloc_set_destructor(tracee->fs->bindings.guest, remove_bindings);
	talloc_set_destructor(tracee->fs->bindings.host, remove_bindings);

	binding = CIRCLEQ_LAST(tracee->fs->bindings.pending);
	assert(compare_paths(binding->guest.path, "/") == PATHS_ARE_EQUAL);

	while (binding != (void *) tracee->fs->bindings.pending) {
		previous = CIRCLEQ_PREV(binding, link.pending);
		initialize_binding(tracee, binding);
		add_induced_bindings(tracee, binding);
		binding = previous;
	}

	TALLOC_FREE(tracee->fs->bindings.pending);

	if (tracee->verbose > 0)
		print_bindings(tracee);

	return 0;
}
