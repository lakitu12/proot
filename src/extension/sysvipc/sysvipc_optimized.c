/**
 * Optimized SysV IPC extension
 * Only provides direct forwarding of IPC system calls to kernel
 * No parsing, no checks, no complex logic
 */

#include "extension/extension.h"
#include <sys/syscall.h>
#include <unistd.h>

/**
 * Simple callback that just allows all SysV IPC calls to pass through to kernel
 * This eliminates all complex handling, data structures, and state management
 */
int sysvipc_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
    switch (event) {
    case INITIALIZATION:
    {
        // Register all SysV IPC syscalls to be forwarded directly
        static FilteredSysnum filtered_sysnums[] = {
            { PR_msgget,    0 },
            { PR_msgsnd,    0 },
            { PR_msgrcv,    0 },
            { PR_msgctl,    0 },
            { PR_semget,    0 },
            { PR_semop,     0 },
            { PR_semtimedop, 0 },
            { PR_semctl,    0 },
            { PR_shmget,    0 },
            { PR_shmat,     0 },
            { PR_shmdt,     0 },
            { PR_shmctl,    0 },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_START:
    {
        // Directly return 0 to let syscall pass through to kernel
        // No complex processing, no internal state, no checks
        return 0;
    }

    case SYSCALL_EXIT_END:
    {
        // Directly return 0, no post-processing needed
        return 0;
    }

    case INHERIT_PARENT:
        // Allow inheritance for sub reconfiguration
        return 1;

    default:
        return 0;
    }
}