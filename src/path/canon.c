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
#include <sys/types.h> /* pid_t */
#include <limits.h>    /* PATH_MAX, */
#include <sys/param.h> /* MAXSYMLINKS, */
#include <errno.h>     /* E*, */
#include <sys/stat.h>  /* lstat(2), S_ISREG(), */
#include <unistd.h>    /* access(2), lstat(2), */
#include <string.h>    /* string(3), */
#include <assert.h>    /* assert(3), */
#include <stdio.h>     /* sscanf(3), snprintf(3), */
#include <stdlib.h>    /* realpath(3), */

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

// 安卓版本兼容配置
#define LINKERCONFIG_PATH "/linkerconfig"
#define LINKERCONFIG_LEN 13
// 安卓8无O_PATH，用AT_FDCWD兼容；安卓10+支持O_PATH，不影响
#ifndef O_PATH
#define O_PATH 010000000
#endif

/**
 * 安卓8+ 兼容：安全获取文件状态（处理低版本lstat权限限制）
 */
static inline int safe_lstat(const char *path, struct stat *stat_buf)
{
    int status = lstat(path, stat_buf);
    if (status == 0)
        return 0;

    // 安卓8/9：部分路径lstat返回ENOENT但实际存在，尝试用access二次校验
    if (errno == ENOENT) {
        // 检查路径是否存在（仅判断可达性，不要求读权限）
        if (access(path, F_OK) == 0) {
            // 无法获取状态时，默认标记为目录（兼容低版本常见场景）
            memset(stat_buf, 0, sizeof(struct stat));
            stat_buf->st_mode = S_IFDIR;
            return 0;
        }
    }
    return status;
}

/**
 * Put an end-of-string ('\0') right before the last component of @path.
 */
static inline void pop_component(char *path)
{
	size_t path_len;
	int offset;

	assert(path != NULL);
	path_len = strnlen(path, PATH_MAX);
	if (path_len == 0)
		return;

	offset = path_len - 1;
	assert(offset >= 0);

	// 根路径（"/"）不处理
	if (offset == 0) {
		assert(path[0] == '/' && path[1] == '\0');
		return;
	}

	// 跳过末尾路径分隔符
	while (offset > 1 && path[offset] == '/')
		offset--;

	// 查找上一个路径分隔符
	while (offset > 1 && path[offset] != '/')
		offset--;

	// 截断路径
	path[offset] = '\0';
	assert(path[0] == '/');
}

/**
 * Copy in @component the first path component pointed to by @cursor.
 */
static inline Finality next_component(char component[NAME_MAX], const char **cursor)
{
	const char *start;
	ptrdiff_t length;
	bool want_dir;

	assert(component != NULL && cursor != NULL);

	// 跳过前置路径分隔符
	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;

	start = *cursor;
	// 提取当前组件（到下一个分隔符或结束）
	while (**cursor != '\0' && **cursor != '/')
		(*cursor)++;
	length = *cursor - start;

	if (length >= NAME_MAX)
		return -ENAMETOOLONG;

	// 安全拷贝组件（兼容安卓8 strncpy行为）
	if (length > 0) {
		strncpy(component, start, length);
		component[length] = '\0';
	} else {
		component[0] = '\0';
	}

	want_dir = (**cursor == '/');
	// 跳过后续分隔符
	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;

	return (**cursor == '\0') ? (want_dir ? FINAL_SLASH : FINAL_NORMAL) : NOT_FINAL;
}

/**
 * Resolve bindings (if any) in @guest_path and copy the translated path into @host_path.
 */
static inline int substitute_binding_stat(Tracee *tracee, Finality finality, unsigned int recursion_level,
					const char guest_path[PATH_MAX], char host_path[PATH_MAX])
{
	struct stat statl;
	int status;

	strcpy(host_path, guest_path);
	status = substitute_binding(tracee, GUEST, host_path);
	if (status < 0)
		return status;

	// 绑定初始化阶段不通知扩展
	if (tracee->glue_type == 0) {
		status = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
					IS_FINAL(finality) && recursion_level == 0);
		if (status < 0)
			return status;
	}

	memset(&statl, 0, sizeof(struct stat));
	if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
		status = -ENOENT;
	} else {
		// 安卓8+ 兼容：用safe_lstat替代直接lstat
		status = safe_lstat(host_path, &statl);

		// 安卓12+ /linkerconfig兼容 + 安卓8/9权限兼容
		if (status < 0) {
			// 处理EACCES（高版本）和ENOENT（低版本）两种错误
			if ((errno == EACCES || errno == ENOENT) && 
				strncmp(host_path, LINKERCONFIG_PATH, LINKERCONFIG_LEN) == 0 && 
				host_path[LINKERCONFIG_LEN] == '\0') {
				status = 0;
				statl.st_mode = S_IFDIR;
			}
		}
	}

	// 绑定初始化阶段：创建host与guest的glue
	if (status < 0 && tracee->glue_type != 0) {
		statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
		status = (statl.st_mode == 0) ? -1 : 0;
	}

	// 非最终组件必须是目录或符号链接
	if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
		return (status < 0) ? -ENOENT : -ENOTDIR;

	return S_ISLNK(statl.st_mode) ? 1 : 0;
}

/**
 * Copy in @guest_path the canonicalization of @user_path regarding to @tracee->root.
 */
int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
		 char guest_path[PATH_MAX], unsigned int recursion_level)
{
	char scratch_path[PATH_MAX];
	Finality finality;
	const char *cursor;
	int status;

	// 循环链接防护
	if (recursion_level > MAXSYMLINKS)
		return -ELOOP;

	// 输入校验（兼容安卓8空指针处理）
	if (user_path == NULL || guest_path == NULL || user_path == guest_path)
		return -EINVAL;
	if (strnlen(user_path, PATH_MAX) >= PATH_MAX || strnlen(guest_path, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;

	// 初始化基准路径（绝对/相对）
	if (user_path[0] == '/') {
		strcpy(guest_path, "/");
	} else {
		if (guest_path[0] != '/')
			return -EINVAL;
	}

	// 递归规范化路径组件
	cursor = user_path;
	finality = NOT_FINAL;
	while (!IS_FINAL(finality)) {
		char component[NAME_MAX];
		char host_path[PATH_MAX];

		finality = next_component(component, &cursor);
		status = (int)finality;
		if (status < 0)
			return status;

		// 处理当前目录（.）
		if (strcmp(component, ".") == 0) {
			if (IS_FINAL(finality))
				finality = FINAL_DOT;
			continue;
		}

		// 处理上级目录（..）
		if (strcmp(component, "..") == 0) {
			pop_component(guest_path);
			if (IS_FINAL(finality))
				finality = FINAL_SLASH;
			continue;
		}

		// 拼接当前组件
		status = join_paths(2, scratch_path, guest_path, component);
		if (status < 0)
			return status;

		// 替换绑定并检查文件状态
		status = substitute_binding_stat(tracee, finality, recursion_level, scratch_path, host_path);
		if (status < 0)
			return status;

		// 非符号链接/无需解引用最终组件：直接更新guest_path
		if (status <= 0 || (finality == FINAL_NORMAL && !deref_final)) {
			if (strnlen(guest_path, PATH_MAX) + strnlen(component, NAME_MAX) + 2 >= PATH_MAX)
				return -ENAMETOOLONG;
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, component);
			if (status < 0)
				return status;
			continue;
		}

		// 处理符号链接：解引用并递归规范化
		Comparison comparison = compare_paths("/proc", guest_path);
		if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
			status = readlink_proc(tracee, scratch_path, guest_path, component, comparison);
			switch (status) {
			case CANONICALIZE:
				goto canon;
			case DONT_CANONICALIZE:
				if (finality == FINAL_NORMAL) {
					strcpy(guest_path, scratch_path);
					return 0;
				}
				break;
			default:
				if (status < 0)
					return status;
			}
		}

		// 读取符号链接目标（兼容安卓8 readlink行为）
		status = readlink(host_path, scratch_path, sizeof(scratch_path) - 1);
		if (status < 0)
			return status;
		if (status == sizeof(scratch_path))
			return -ENAMETOOLONG;
		scratch_path[status] = '\0';

		// 去除root前缀
		status = detranslate_path(tracee, scratch_path, host_path);
		if (status < 0)
			return status;

canon:
		// 递归规范化符号链接目标
		status = canonicalize(tracee, scratch_path, true, guest_path, recursion_level + 1);
		if (status < 0)
			return status;

		// 验证非最终组件为目录
		status = substitute_binding_stat(tracee, finality, recursion_level, guest_path, host_path);
		if (status < 0)
			return status;

		// 断言：符号链接仅允许命名文件描述符场景
		assert(status != 1 || sscanf(guest_path, "/proc/%*d/fd/%d", &status) == 1);
	}

	// 第一层递归：补充路径末尾的/或.（保持原始语义）
	if (recursion_level == 0) {
		switch (finality) {
		case FINAL_SLASH:
			if (strnlen(guest_path, PATH_MAX) + 2 >= PATH_MAX)
				return -ENAMETOOLONG;
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, "");
			if (status < 0)
				return status;
			break;
		case FINAL_DOT:
			if (strnlen(guest_path, PATH_MAX) + 3 >= PATH_MAX)
				return -ENAMETOOLONG;
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, ".");
			if (status < 0)
				return status;
			break;
		case FINAL_NORMAL:
			break;
		default:
			assert(0);
		}
	}

	return 0;
}

/**
 * A safer and simpler path canonicalization function that uses realpath when possible.
 */
int canonicalize_safe(Tracee *tracee, const char *user_path, bool deref_final,
             char guest_path[PATH_MAX], unsigned int recursion_level)
{
    char temp_path[PATH_MAX];
    char host_path[PATH_MAX];
    char resolved_path[PATH_MAX];
    int status;

    // 循环链接防护
    if (recursion_level > MAXSYMLINKS)
        return -ELOOP;

    // 输入校验
    if (user_path == NULL || guest_path == NULL || user_path == guest_path)
        return -EINVAL;
    if (strnlen(user_path, PATH_MAX) >= PATH_MAX)
        return -ENAMETOOLONG;

    // 构建完整路径（绝对/相对）
    if (user_path[0] == '/') {
        strncpy(temp_path, user_path, PATH_MAX - 1);
        temp_path[PATH_MAX - 1] = '\0';
    } else {
        if (guest_path[0] != '/')
            return -EINVAL;
        status = join_paths(2, temp_path, guest_path, user_path);
        if (status < 0)
            return status;
    }

    // 替换绑定路径
    strncpy(host_path, temp_path, PATH_MAX - 1);
    host_path[PATH_MAX - 1] = '\0';
    status = substitute_binding(tracee, GUEST, host_path);
    if (status < 0)
        return status;

    // 安卓8+ 兼容：realpath可能返回NULL（低版本无某些路径），fallback手动处理
    char *realpath_result = realpath(host_path, resolved_path);
    if (realpath_result != NULL) {
        const size_t len = strnlen(resolved_path, PATH_MAX);
        if (len >= PATH_MAX)
            return -ENAMETOOLONG;
        strncpy(guest_path, resolved_path, PATH_MAX - 1);
        guest_path[PATH_MAX - 1] = '\0';
        return 0;
    }

    // fallback：手动清理路径（处理.和..）
    char clean_path[PATH_MAX] = {0};
    char temp_copy[PATH_MAX];
    strncpy(temp_copy, host_path, PATH_MAX - 1);
    temp_copy[PATH_MAX - 1] = '\0';

    const bool is_absolute = (host_path[0] == '/');
    if (is_absolute)
        clean_path[0] = '/';

    // 分割路径组件处理
    char *token, *saveptr;
    token = strtok_r(temp_copy, "/", &saveptr);
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
            // 跳过当前目录
        } else if (strcmp(token, "..") == 0) {
            // 处理上级目录
            if (clean_path[0] != '\0') {
                size_t len = strlen(clean_path);
                if (len > 1) {
                    // 移除末尾组件
                    for (size_t i = len - 1; i > 0; i--) {
                        if (clean_path[i] == '/') {
                            clean_path[i + 1] = '\0';
                            break;
                        }
                    }
                    if (clean_path[0] == '/' && clean_path[1] == '\0') {
                        // 保持根路径
                    }
                }
            } else if (!is_absolute) {
                // 相对路径：添加..
                if (strlen(clean_path) + 3 >= PATH_MAX)
                    return -ENAMETOOLONG;
                strcat(clean_path, "../");
            }
        } else {
            // 拼接普通组件
            const size_t current_len = strlen(clean_path);
            if (current_len + strlen(token) + 2 >= PATH_MAX)
                return -ENAMETOOLONG;
            if (current_len > 0 && clean_path[current_len - 1] != '/')
                strcat(clean_path, "/");
            strcat(clean_path, token);
        }
        token = strtok_r(NULL, "/", &saveptr);
    }

    // 确保结果合法
    const size_t clean_len = strlen(clean_path);
    if (clean_len >= PATH_MAX)
        return -ENAMETOOLONG;
    if (clean_len == 0)
        strcpy(clean_path, "/");

    strncpy(guest_path, clean_path, PATH_MAX - 1);
    guest_path[PATH_MAX - 1] = '\0';
    (void)deref_final; // 兼容参数

    return 0;
}
