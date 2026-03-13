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

#include <sys/mman.h>	/* PROT_*, MAP_*, */
#include <assert.h>	/* assert(3),  */
#include <string.h>     /* strerror(3), */
#include <unistd.h>     /* sysconf(3), */
#include <sys/param.h>  /* MIN(), MAX(), */

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "execve/execve.h"
#include "cli/note.h"

#include "compat.h"

#define DEBUG_BRK(...) /* fprintf(stderr, __VA_ARGS__) */

/* ARM64专属：堆偏移量（适配页大小，默认4KB，兼容安卓设备） */
static word_t heap_offset = 0;

/**
 * Put @tracee's heap to a reliable location（ARM64优化版）
 */
void translate_brk_enter(Tracee *tracee)
{
	word_t new_brk_address;
	size_t old_heap_size;
	size_t new_heap_size;

	if (tracee->heap->disabled)
		return;

	/* 初始化堆偏移量（优先获取系统页大小，适配ARM64设备） */
	if (heap_offset == 0) {
		heap_offset = sysconf(_SC_PAGE_SIZE);
		/* 容错：系统调用失败时默认4KB（ARM64常见页大小） */
		if ((int) heap_offset <= 0)
			heap_offset = 0x1000;
	}

	new_brk_address = peek_reg(tracee, CURRENT, SYSARG_1);
	DEBUG_BRK("brk(0x%lx)\n", new_brk_address);

	/* 为模拟堆分配新内存映射 */
	if (tracee->heap->base == 0) {
		Sysnum sysnum;
		Mapping *mappings;
		Mapping *bss;

		/* 首次调用brk不应指定地址（ARM64兼容逻辑） */
		if (new_brk_address != 0) {
			if (tracee->verbose > 0)
				note(tracee, WARNING, INTERNAL,
					"process %d is doing suspicious brk()",	tracee->pid);
			return;
		}

		/* 堆地址靠近BSS段（ARM64内存布局优化，减少地址间隙） */
		mappings = tracee->load_info->mappings;
		bss = &mappings[talloc_array_length(mappings) - 1];
		new_brk_address = bss->addr + bss->length;

		/* ARM64优先使用mmap2（兼容安卓系统调用语义） */
		sysnum = detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER
			? PR_mmap2
			: PR_mmap;

		set_sysnum(tracee, sysnum);
		poke_reg(tracee, SYSARG_1 /* address */, new_brk_address);
		poke_reg(tracee, SYSARG_2 /* length  */, heap_offset);
		poke_reg(tracee, SYSARG_3 /* prot    */, PROT_READ | PROT_WRITE);
		poke_reg(tracee, SYSARG_4 /* flags   */, MAP_PRIVATE | MAP_ANONYMOUS);
		poke_reg(tracee, SYSARG_5 /* fd      */, -1);
		poke_reg(tracee, SYSARG_6 /* offset  */, 0);

		return;
	}

	/* 堆大小不能为负，直接返回当前堆顶 */
	if (new_brk_address < tracee->heap->base) {
		set_sysnum(tracee, PR_void);
		return;
	}

	new_heap_size = new_brk_address - tracee->heap->base;
	old_heap_size = tracee->heap->size;

	/* ARM64使用mremap调整堆大小（保持系统调用兼容性） */
	set_sysnum(tracee, PR_mremap);
	poke_reg(tracee, SYSARG_1 /* old_address */, tracee->heap->base - heap_offset);
	poke_reg(tracee, SYSARG_2 /* old_size    */, old_heap_size + heap_offset);
	poke_reg(tracee, SYSARG_3 /* new_size    */, new_heap_size + heap_offset);
	poke_reg(tracee, SYSARG_4 /* flags       */, 0);
	poke_reg(tracee, SYSARG_5 /* new_address */, 0);

	return;
}

/**
 * c.f. function above（brk系统调用退出处理）
 */
void translate_brk_exit(Tracee *tracee)
{
	word_t result;
	word_t sysnum;
	int tracee_errno;

	if (tracee->heap->disabled)
		return;

	assert(heap_offset > 0);

	sysnum = get_sysnum(tracee, MODIFIED);
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	tracee_errno = (int) result;

	switch (sysnum) {
	case PR_void:
		/* 返回当前堆顶地址（ARM64语义兼容） */
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mmap:
	case PR_mmap2:
		/* 错误处理：brk返回0而非-errno（ARM64系统调用语义） */
		if (tracee_errno < 0 && tracee_errno > -4096) {
			poke_reg(tracee, SYSARG_RESULT, 0);
			break;
		}

		/* 初始化堆基址和大小（跳过偏移页，模拟空堆） */
		tracee->heap->base = result + heap_offset;
		tracee->heap->size = 0;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mremap:
		/* 错误处理：返回原堆顶地址（ARM64兼容） */
		if (   (tracee_errno < 0 && tracee_errno > -4096)
		    || (tracee->heap->base != result + heap_offset)) {
			poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
			break;
		}

		/* 更新堆大小（减去偏移页） */
		tracee->heap->size = peek_reg(tracee, MODIFIED, SYSARG_3) - heap_offset;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_brk:
		/* 可疑调用标记堆为禁用（ARM64安全防护） */
		if (result == peek_reg(tracee, ORIGINAL, SYSARG_1))
			tracee->heap->disabled = true;
		break;

	default:
		assert(0);
	}

	DEBUG_BRK("brk() = 0x%lx\n", peek_reg(tracee, CURRENT, SYSARG_RESULT));
}
