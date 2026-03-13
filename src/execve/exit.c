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
#include <linux/auxvec.h>  /* AT_*,  */
#include <talloc.h>     /* talloc*, */
#include <sys/mman.h>   /* MAP_*, */
#include <assert.h>     /* assert(3), */
#include <string.h>     /* strlen(3), strerror(3), memset(3), */
#include <signal.h>     /* kill(2), SIG*, */
#include <unistd.h>     /* write(2), */
#include <errno.h>      /* E*, */
#include "execve/execve.h"
#include "execve/elf.h"
#include "loader/script.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "execve/auxv.h"
#include "path/binding.h"
#include "path/temp.h"
#include "cli/note.h"
#include "attribute.h"

/**
 * Fill @path with the content of @vectors, formatted according to
 * @ptracee's current ABI.
 */
__attribute__((cold))
static int fill_file_with_auxv(const Tracee *ptracee, const char *path,
			const ElfAuxVector *vectors)
{
	const ssize_t current_sizeof_word = sizeof_word(ptracee);
	ssize_t status;
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	// 批量写入，减少write系统调用次数
	size_t i = 0;
	byte_t buffer[PATH_MAX * 2]; // 预分配足够空间
	size_t buf_offset = 0;
	do {
		if (buf_offset + 2 * current_sizeof_word > sizeof(buffer)) {
			// 缓冲区满，写入并清空
			status = write(fd, buffer, buf_offset);
			if (status < (ssize_t)buf_offset) {
				close(fd);
				return -1;
			}
			buf_offset = 0;
		}
		// 拷贝type和value到缓冲区
		memcpy(buffer + buf_offset, &vectors[i].type, current_sizeof_word);
		buf_offset += current_sizeof_word;
		memcpy(buffer + buf_offset, &vectors[i].value, current_sizeof_word);
		buf_offset += current_sizeof_word;
	} while (vectors[i++].type != AT_NULL);

	// 写入剩余数据
	if (buf_offset > 0) {
		status = write(fd, buffer, buf_offset);
		if (status < (ssize_t)buf_offset) {
			close(fd);
			return -1;
		}
	}

	close(fd);
	return 0;
}

/**
 * Bind content of @vectors over /proc/{@ptracee->pid}/auxv.
 */
__attribute__((cold))
static int bind_proc_pid_auxv(const Tracee *ptracee)
{
	word_t vectors_address = get_elf_aux_vectors_address(ptracee);
	if (vectors_address == 0)
		return -1;

	ElfAuxVector *vectors = fetch_elf_aux_vectors(ptracee, vectors_address);
	if (vectors == NULL)
		return -1;

	// 精简路径创建，合并talloc操作
	char *guest_path = talloc_asprintf(ptracee->ctx, "/proc/%d/auxv", ptracee->pid);
	if (guest_path == NULL)
		return -1;

	// 精简绑定查找与删除逻辑
	Binding *binding = get_binding(ptracee, GUEST, guest_path);
	if (binding != NULL && compare_paths(binding->guest.path, guest_path) == PATHS_ARE_EQUAL) {
		remove_binding_from_all_lists(ptracee, binding);
		TALLOC_FREE(binding);
	}

	// 修复：添加const匹配create_temp_file返回值类型
	const char *host_path = create_temp_file(ptracee->ctx, "auxv");
	if (host_path == NULL)
		return -1;

	if (fill_file_with_auxv(ptracee, host_path, vectors) < 0)
		return -1;

	// 合并绑定创建与资源关联
	binding = insort_binding3(ptracee, ptracee->life_context, host_path, guest_path);
	if (binding == NULL)
		return -1;

	talloc_reparent(ptracee->ctx, binding, host_path);
	return 0;
}

/**
 * Convert @mappings into load @script statements at the given @cursor
 * position.
 */
__attribute__((always_inline))
static void *transcript_mappings(void *cursor, const Mapping *mappings)
{
	size_t nb_mappings = talloc_array_length(mappings);
	for (size_t i = 0; i < nb_mappings; i++) {
		LoadStatement *statement = cursor;
		statement->action = (mappings[i].flags & MAP_ANONYMOUS) ? LOAD_ACTION_MMAP_ANON : LOAD_ACTION_MMAP_FILE;
		// 逐字段赋值，兼容原版结构体定义（修复编译错误）
		statement->mmap.addr = mappings[i].addr;
		statement->mmap.length = mappings[i].length;
		statement->mmap.prot = mappings[i].prot;
		statement->mmap.offset = mappings[i].offset;
		statement->mmap.clear_length = mappings[i].clear_length;
		cursor += LOAD_STATEMENT_SIZE(*statement, mmap);
	}
	return cursor;
}

/**
 * Convert @tracee->load_info into a load script, then transfer this
 * latter into @tracee's memory.
 */
__attribute__((hot, flatten))
static int transfer_load_script(Tracee *tracee)
{
	// 缓存页大小（全局仅初始化一次）
	static word_t page_size = 0;
	static word_t page_mask = 0;
	if (page_size == 0) {
		page_size = sysconf(_SC_PAGE_SIZE);
		page_size = (page_size <= 0) ? 0x1000 : page_size;
		page_mask = ~(page_size - 1);
	}

	const word_t stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
	LoadInfo *load_info = tracee->load_info;
	bool has_interp = (load_info->interp != NULL);

	// 提前返回无效场景
	if (load_info->user_path == NULL || stack_pointer == 0)
		return -EINVAL;

	// 缓存字符串长度，避免重复strlen调用
	size_t string1_size = strlen(load_info->user_path) + 1;
	size_t string2_size = has_interp ? strlen(load_info->interp->user_path) + 1 : 0;
	size_t string3_size = (load_info->raw_path == load_info->user_path) ? 0 : strlen(load_info->raw_path) + 1;

	// 修复：移除defined宏，直接用sizeof_word对齐（兼容所有架构）
	size_t align_size = sizeof_word(tracee);
	size_t padding_size = (stack_pointer - string1_size - string2_size - string3_size) % align_size;
	size_t strings_size = string1_size + string2_size + string3_size + padding_size;

	// 缓存字符串地址，避免重复计算
	word_t string1_address = stack_pointer - strings_size;
	word_t string2_address = string1_address + string1_size;
	word_t string3_address = string3_size == 0 ? string1_address : string2_address + string2_size;

	// 预计算脚本大小，避免重复调用talloc_array_length
	size_t main_mappings_cnt = talloc_array_length(load_info->mappings);
	size_t interp_mappings_cnt = has_interp ? talloc_array_length(load_info->interp->mappings) : 0;
	bool needs_executable_stack = (load_info->needs_executable_stack || (has_interp && load_info->interp->needs_executable_stack));

	// 精简脚本大小计算
	size_t script_size = LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, open)
		+ (LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, mmap) * main_mappings_cnt)
		+ (has_interp ? (LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, open) + (LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, mmap) * interp_mappings_cnt)) : 0)
		+ (needs_executable_stack ? LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, make_stack_exec) : 0)
		+ LOAD_STATEMENT_SIZE(*(LoadStatement*)NULL, start);

	size_t buffer_size = script_size + strings_size;
	void *buffer = talloc_zero_size(tracee->ctx, buffer_size);
	if (buffer == NULL)
		return -ENOMEM;

	void *cursor = buffer;
	LoadStatement *statement;

	// 生成open语句（主程序）
	statement = cursor;
	statement->action = LOAD_ACTION_OPEN;
	statement->open.string_address = string1_address;
	cursor += LOAD_STATEMENT_SIZE(*statement, open);

	// 生成主程序mmap语句
	cursor = transcript_mappings(cursor, load_info->mappings);

	// 生成解释器相关语句（如有）
	word_t entry_point = ELF_FIELD(load_info->elf_header, entry);
	if (has_interp) {
		statement = cursor;
		statement->action = LOAD_ACTION_OPEN_NEXT;
		statement->open.string_address = string2_address;
		cursor += LOAD_STATEMENT_SIZE(*statement, open);

		cursor = transcript_mappings(cursor, load_info->interp->mappings);
		entry_point = ELF_FIELD(load_info->interp->elf_header, entry);
	}

	// 生成可执行栈语句（如有）
	if (needs_executable_stack) {
		statement = cursor;
		statement->action = LOAD_ACTION_MAKE_STACK_EXEC;
		statement->make_stack_exec.start = stack_pointer & page_mask;
		cursor += LOAD_STATEMENT_SIZE(*statement, make_stack_exec);
	}

	// 生成start语句（逐字段赋值，修复结构体编译错误）
	statement = cursor;
	statement->action = (tracee->as_ptracee.ptracer != NULL) ? LOAD_ACTION_START_TRACED : LOAD_ACTION_START;
	statement->start.stack_pointer = stack_pointer;
	statement->start.entry_point = entry_point;
	statement->start.at_phent = ELF_FIELD(load_info->elf_header, phentsize);
	statement->start.at_phnum = ELF_FIELD(load_info->elf_header, phnum);
	statement->start.at_entry = ELF_FIELD(load_info->elf_header, entry);
	statement->start.at_phdr = ELF_FIELD(load_info->elf_header, phoff) + load_info->mappings[0].addr;
	statement->start.at_execfn = string3_address;
	cursor += LOAD_STATEMENT_SIZE(*statement, start);

	// 32位兼容转换（精简循环）
	if (is_32on64_mode(tracee)) {
		size_t total_words = script_size / sizeof(uint64_t);
		for (size_t i = 0; i < total_words; i++) {
			((uint32_t *)buffer)[i] = (uint32_t)((uint64_t *)buffer)[i];
		}
	}

	// 批量拷贝字符串，减少memcpy调用
	byte_t *str_cursor = (byte_t *)cursor;
	memcpy(str_cursor, load_info->user_path, string1_size);
	str_cursor += string1_size;
	if (string2_size != 0) {
		memcpy(str_cursor, load_info->interp->user_path, string2_size);
		str_cursor += string2_size;
	}
	if (string3_size != 0) {
		memcpy(str_cursor, load_info->raw_path, string3_size);
		str_cursor += string3_size;
	}

	// 验证缓冲区大小（保留核心断言）
	assert((uintptr_t)str_cursor + padding_size - (uintptr_t)buffer == buffer_size);

	// 批量更新寄存器，减少poke_reg调用
	word_t new_sp = stack_pointer - buffer_size;
	poke_reg(tracee, STACK_POINTER, new_sp);
	poke_reg(tracee, USERARG_1, new_sp);

	// 一次性写入所有数据，减少内核交互
	int status = write_data(tracee, new_sp, buffer, buffer_size);
	if (status < 0)
		return status;

	// 标记寄存器已修改，避免重复操作
	save_current_regs(tracee, ORIGINAL);
	tracee->_regs_were_changed = true;

	return 0;
}

/**
 * Start the loading of @tracee.
 */
__attribute__((hot, flatten))
void translate_execve_exit(Tracee *tracee)
{
	// 快速路径：跳过loader，直接返回
	if (tracee->skip_proot_loader) {
		tracee->restore_original_regs = false;
		return;
	}

	// 处理ptraced加载完成通知
	if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee)) {
		// 批量更新寄存器，减少poke_reg调用
		poke_reg(tracee, SYSARG_RESULT, 0);
		set_sysnum(tracee, PR_execve);

		word_t orig_sp = peek_reg(tracee, ORIGINAL, SYSARG_2);
		word_t orig_ip = peek_reg(tracee, ORIGINAL, SYSARG_3);
		poke_reg(tracee, STACK_POINTER, orig_sp);
		poke_reg(tracee, INSTR_POINTER, orig_ip);
		poke_reg(tracee, RTLD_FINI, 0);
		poke_reg(tracee, STATE_FLAGS, 0);

#if defined(ARCH_ARM_EABI) && defined(__thumb__)
		tracee->_regs[CURRENT].ARM_cpsr &= ~PSR_T_BIT;
#endif

		save_current_regs(tracee, ORIGINAL);
		tracee->_regs_were_changed = true;

		// 绑定auxv（冷路径，无需优化）
		(void) bind_proc_pid_auxv(tracee);

		// 发送SIGTRAP（仅必要时）
		if ((tracee->as_ptracee.options & PTRACE_O_TRACEEXEC) == 0)
			kill(tracee->pid, SIGTRAP);
		return;
	}

#ifdef ARCH_ARM64
	tracee->is_aarch32 = IS_CLASS32(tracee->load_info->elf_header);
#endif

	// 检查execve执行结果，失败直接返回
	word_t syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int)syscall_result < 0)
		return;

	// 更新exe路径（精简talloc操作）
	if (tracee->new_exe != NULL) {
		talloc_unlink(tracee, tracee->exe);
		tracee->exe = talloc_reference(tracee, tracee->new_exe);
		talloc_set_name_const(tracee->exe, "$exe");
	}

	// 重置堆内存（精简判断逻辑）
	if (talloc_reference_count(tracee->heap) >= 1) {
		talloc_unlink(tracee, tracee->heap);
		tracee->heap = talloc_zero(tracee, Heap);
		if (tracee->heap == NULL)
			note(tracee, ERROR, INTERNAL, "can't alloc heap after execve");
	} else {
		memset(tracee->heap, 0, sizeof(Heap));
	}

	// 传输加载脚本（核心热点函数）
	mem_prepare_after_execve(tracee);
	int status = transfer_load_script(tracee);
	if (status < 0)
		note(tracee, ERROR, INTERNAL, "can't transfer load script: %s", strerror(-status));
}
