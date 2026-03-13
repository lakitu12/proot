/*
 * Optimized hidden files extension
 * Only keeps essential open/readdir hooks with minimal logic
 */

#include "extension/extension.h"
#include "tracee/mem.h"
#include <string.h>

/* Hidden file prefix */
#define HIDDEN_PREFIX ".proot"

/**
 * Optimized callback function for hidden files extension.
 * Uses simple strcmp for 1-line comparison logic.
 */
int hidden_files_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* Only register essential syscalls */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_getdents,    FILTER_SYSEXIT },
            { PR_getdents64,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_EXIT_END: {
        Tracee *tracee = TRACEE(extension);
        int sysnum = get_sysnum(tracee, ORIGINAL);
        
        if (sysnum == PR_getdents || sysnum == PR_getdents64) {
            unsigned int res = peek_reg(tracee, CURRENT, SYSARG_RESULT);
            if (res <= 0) {
                return 0;
            }

            word_t orig_start = peek_reg(tracee, CURRENT, SYSARG_2);
            unsigned int count = peek_reg(tracee, CURRENT, SYSARG_3);
            char buffer[count];

            int status = read_data(tracee, buffer, orig_start, res);
            if (status < 0) {
                return 0;  // Skip on error
            }

            char *pos = buffer;  // Position in output buffer
            char *ptr = buffer;  // Position in input buffer
            unsigned int nleft = 0;  // Bytes in output buffer

            if (sysnum == PR_getdents64) {
                while (ptr < buffer + res) {
                    struct linux_dirent64 {
                        unsigned long long d_ino;
                        long long d_off;
                        unsigned short d_reclen;
                        unsigned char d_type;
                        char d_name[];
                    } *curr = (struct linux_dirent64 *)ptr;

                    // 1-line strcmp logic for hidden file detection
                    if (strncmp(curr->d_name, HIDDEN_PREFIX, sizeof(HIDDEN_PREFIX)-1) != 0) {
                        // Copy non-hidden entry
                        memcpy(pos, ptr, curr->d_reclen);
                        pos += curr->d_reclen;
                        nleft += curr->d_reclen;
                    }
                    ptr += curr->d_reclen;
                }
            } else { // PR_getdents
                while (ptr < buffer + res) {
                    struct linux_dirent {
                        unsigned long d_ino;
                        unsigned long d_off;
                        unsigned short d_reclen;
                        char d_name[];
                    } *curr = (struct linux_dirent *)ptr;

                    // 1-line strcmp logic for hidden file detection
                    if (strncmp(curr->d_name, HIDDEN_PREFIX, sizeof(HIDDEN_PREFIX)-1) != 0) {
                        // Copy non-hidden entry
                        memcpy(pos, ptr, curr->d_reclen);
                        pos += curr->d_reclen;
                        nleft += curr->d_reclen;
                    }
                    ptr += curr->d_reclen;
                }
            }

            // Update results if any files were filtered
            if (nleft > 0 && nleft != res) {
                write_data(tracee, orig_start, buffer, nleft);
                poke_reg(tracee, SYSARG_RESULT, nleft);
            }
        }
        return 0;
    }

    default:
        return 0;
    }
}