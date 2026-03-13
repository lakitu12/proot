/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
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

#ifndef TRACEE_ABI_H
#define TRACEE_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "arch.h"
#include "attribute.h"

typedef enum {
	ABI_DEFAULT = 0,
	ABI_2,   /* ARM32 on AArch64 */
	NB_MAX_ABIS
} Abi;

// 纯 ARM64，直接保留 AArch64 逻辑
static inline Abi get_abi(const Tracee *tracee)
{
	return tracee->is_aarch32 ? ABI_2 : ABI_DEFAULT;
}

static inline bool is_32on64_mode(const Tracee *tracee)
{
	return tracee->is_aarch32;
}

static inline size_t sizeof_word(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? sizeof(uint32_t) : sizeof(word_t);
}

static inline off_t offsetof_stat_uid(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? OFFSETOF_STAT_UID_32 : offsetof(struct stat, st_uid);
}

static inline off_t offsetof_stat_gid(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? OFFSETOF_STAT_GID_32 : offsetof(struct stat, st_gid);
}

#endif /* TRACEE_ABI_H */
