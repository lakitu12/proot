/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <cassert>
#include <cstring>
#include <cerrno>
#include <climits>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"

#ifdef __cplusplus
}
#endif

extern "C" int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
    assert(tracee != nullptr);
    assert(path != nullptr);

    const word_t src = peek_reg(tracee, CURRENT, reg);
    if (src == 0) {
        path[0] = '\0';
        return 0;
    }

    const int size = read_path(tracee, path, src);
    if (size < 0)
        return size;

    path[size] = '\0';
    return size;
}

extern "C" int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg)
{
    assert(tracee != nullptr);
    assert(tracer_ptr != nullptr);
    assert(size > 0);

    const word_t tracee_ptr = alloc_mem(tracee, size);
    if (tracee_ptr == 0)
        return -EFAULT;

    const int status = write_data(tracee, tracee_ptr, tracer_ptr, size);
    if (status < 0)
        return status;

    poke_reg(tracee, reg, tracee_ptr);
    return 0;
}

extern "C" int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg)
{
    assert(tracee != nullptr);
    assert(path != nullptr);

    return set_sysarg_data(tracee, path, strlen(path) + 1, reg);
}

extern "C" void translate_syscall(Tracee *tracee)
{
    assert(tracee != nullptr);
    assert(tracee->exe != nullptr);

    const bool is_enter_stage = IS_IN_SYSENTER(tracee);

    if (fetch_regs(tracee) < 0)
        return;

    int suppressed_syscall_status = 0;

    if (is_enter_stage) {
        tracee->restore_original_regs = false;

        if (!tracee->chain.syscalls) {
            save_current_regs(tracee, ORIGINAL);
            const int status = translate_syscall_enter(tracee);
            save_current_regs(tracee, MODIFIED);

            if (status < 0) {
                set_sysnum(tracee, PR_void);
                poke_reg(tracee, SYSARG_RESULT, static_cast<word_t>(status));
                tracee->status = status;
            } else {
                tracee->status = 1;
            }
        } else {
            tracee->restart_how = PTRACE_SYSCALL;
        }

        if (tracee->restart_how == PTRACE_CONT) {
            suppressed_syscall_status = tracee->status;
            tracee->status = 0;
            poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, STACK_POINTER));
        }
    }
    else {
        tracee->restore_original_regs = true;

        if (!tracee->chain.syscalls) {
            translate_syscall_exit(tracee);
        }

        tracee->status = 0;

        if (tracee->chain.syscalls)
            chain_next_syscall(tracee);
    }

    const bool override_sysnum = is_enter_stage && !tracee->chain.syscalls;
    int push_regs_status = push_specific_regs(tracee, override_sysnum);

    if (push_regs_status < 0 && override_sysnum) {
        const word_t orig_sysnum = peek_reg(tracee, ORIGINAL, SYSARG_NUM);
        const word_t curr_sysnum = peek_reg(tracee, CURRENT, SYSARG_NUM);

        if (orig_sysnum != curr_sysnum) {
            if (curr_sysnum != SYSCALL_AVOIDER) {
                restart_current_syscall_as_chained(tracee);
            }
            else if (suppressed_syscall_status != 0) {
                tracee->status = suppressed_syscall_status;
                tracee->restart_how = PTRACE_SYSCALL;
            }

            poke_reg(tracee, SYSARG_1, static_cast<word_t>(-1));
            poke_reg(tracee, SYSARG_2, static_cast<word_t>(-1));
            poke_reg(tracee, SYSARG_3, static_cast<word_t>(-1));
            poke_reg(tracee, SYSARG_4, static_cast<word_t>(-1));
            poke_reg(tracee, SYSARG_5, static_cast<word_t>(-1));
            poke_reg(tracee, SYSARG_6, static_cast<word_t>(-1));

            if (get_sysnum(tracee, ORIGINAL) == PR_brk) {
                poke_reg(tracee, SYSARG_1, 0);
            }

            push_regs_status = push_specific_regs(tracee, false);
            if (push_regs_status != 0)
                note(tracee, WARNING, SYSTEM, "can't set tracee registers");
        }
    }
}