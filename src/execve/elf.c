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

#include <fcntl.h>  /* open(2), */
#include <unistd.h> /* read(2), close(2), */
#include <errno.h>  /* EACCES, ENOTSUP, */
#include <stdint.h> /* UINT64_MAX, */
#include <limits.h> /* PATH_MAX, */
#include <string.h> /* str*(3), memcpy(3), */
#include <assert.h> /* assert(3), */
#include <talloc.h> /* talloc_*, */
#include <stdbool.h> /* bool, true, false,  */

#include "execve/elf.h"
#include "tracee/tracee.h"
#include "cli/note.h"
#include "arch.h"
#include "compat.h"
#include "attribute.h"

/**
 * Open the ELF file @t_path and extract its header into @elf_header.
 */
__attribute__((hot, flatten))
int open_elf(const char *t_path, ElfHeader *elf_header)
{
    // 提前返回无效路径（避免后续系统调用）
    if (t_path == NULL || strlen(t_path) >= PATH_MAX)
        return -ENAMETOOLONG;

    int fd = open(t_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    // 一次性读取ELF头，减少read调用
    ssize_t status = read(fd, elf_header, sizeof(ElfHeader));
    if (status < 0) {
        close(fd);
        return -errno;
    }

    // 精简ELF有效性校验，合并条件判断
    if ((size_t)status < sizeof(ElfHeader)
        || ELF_IDENT(*elf_header, 0) != 0x7f
        || ELF_IDENT(*elf_header, 1) != 'E'
        || ELF_IDENT(*elf_header, 2) != 'L'
        || ELF_IDENT(*elf_header, 3) != 'F'
        || (!IS_CLASS32(*elf_header) && !IS_CLASS64(*elf_header))) {
        close(fd);
        return -ENOEXEC;
    }

    return fd;
}

/**
 * Invoke @callback(..., @data) for each program headers from the specified ELF file.
 */
__attribute__((hot, flatten))
int iterate_program_headers(const Tracee *tracee, int fd, const ElfHeader *elf_header,
			program_headers_iterator_t callback, void *data)
{
    ProgramHeader program_header;
    uint64_t elf_phoff = ELF_FIELD(*elf_header, phoff);
    uint16_t elf_phentsize = ELF_FIELD(*elf_header, phentsize);
    uint16_t elf_phnum = ELF_FIELD(*elf_header, phnum);

    // 提前返回无效参数，避免冗余操作
    if (elf_phnum >= 0xffff) {
        note(tracee, WARNING, INTERNAL, "%d: big PH tables are not yet supported.", fd);
        return -ENOTSUP;
    }
    if (!KNOWN_PHENTSIZE(*elf_header, elf_phentsize)) {
        note(tracee, WARNING, INTERNAL, "%d: unsupported size of program header.", fd);
        return -ENOTSUP;
    }

    // 定位程序头偏移，失败直接返回
    if (lseek(fd, elf_phoff, SEEK_SET) < 0)
        return -errno;

    // 遍历程序头，精简状态判断
    for (int i = 0; i < elf_phnum; i++) {
        ssize_t status = read(fd, &program_header, elf_phentsize);
        if (status != elf_phentsize)
            return (status < 0 ? -errno : -ENOTSUP);

        int cb_status = callback(elf_header, &program_header, data);
        if (cb_status != 0)
            return cb_status;
    }

    return 0;
}

/**
 * Check if @host_path is an ELF file for the host architecture.
 */
__attribute__((hot, flatten))
bool is_host_elf(const Tracee *tracee, const char *host_path)
{
    static int force_foreign = -1;
    // 缓存环境变量结果，避免重复getenv调用
    if (force_foreign < 0)
        force_foreign = (getenv("PROOT_FORCE_FOREIGN_BINARY") != NULL);

    // 快速路径：强制 foreign 或无 qemu，直接返回false
    if (force_foreign > 0 || !tracee->qemu)
        return false;

    // 缓存ELF解析结果（同路径重复调用直接复用）
    static char last_path[PATH_MAX] = "";
    static bool last_result = false;
    if (strcmp(host_path, last_path) == 0)
        return last_result;

    ElfHeader elf_header;
    int fd = open_elf(host_path, &elf_header);
    if (fd < 0) {
        strncpy(last_path, host_path, PATH_MAX-1);
        last_result = false;
        return false;
    }
    close(fd);

    // 精简架构匹配逻辑，提前终止遍历
    uint16_t elf_machine = ELF_FIELD(elf_header, machine);
    int host_elf_machine[] = HOST_ELF_MACHINE;
    for (int i = 0; host_elf_machine[i] != 0; i++) {
        if (host_elf_machine[i] == elf_machine) {
            VERBOSE(tracee, 1, "'%s' is a host ELF", host_path);
            strncpy(last_path, host_path, PATH_MAX-1);
            last_result = true;
            return true;
        }
    }

    strncpy(last_path, host_path, PATH_MAX-1);
    last_result = false;
    return false;
}
