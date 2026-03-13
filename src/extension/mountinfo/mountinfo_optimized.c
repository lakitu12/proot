#include "extension/extension.h"
#include <limits.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* 简化的mountinfo处理回调函数
 * 直接使用标准库函数，移除所有自制解析、缓存和结构封装
 */
int mountinfo_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case TRANSLATED_PATH:
    {
        Tracee *tracee = TRACEE(extension);
        Sysnum num = get_sysnum(tracee, ORIGINAL);
        
        if (num == PR_open || num == PR_openat) {
            char *path = (char*) data1;
            
            // 检查是否是 /proc/<PID>/mountinfo 路径
            size_t len = strlen(path);
            if (len > (6 + 10) &&
                0 == strncmp(path, "/proc/", 6) &&
                0 == strcmp(path + (len - 10), "/mountinfo")) {
                
                // 提取PID
                char *path_end = NULL;
                long target_pid = strtol(path + 6, &path_end, 10);
                
                if (path_end != path + (len - 10) || target_pid <= 0 || target_pid > INT_MAX) {
                    return 0; // 不是有效的PID格式，直接返回
                }

                // 使用标准库realpath函数简化路径处理
                char resolved_path[PATH_MAX];
                if (realpath(path, resolved_path) != NULL) {
                    // 检查是否是需要特殊处理的路径
                    // 这里简化处理，只做最基本的路径检查
                    if (strstr(resolved_path, "/data") != NULL) {
                        // 创建临时文件，使用标准库函数
                        char temp_path[PATH_MAX];
                        snprintf(temp_path, sizeof(temp_path), "/tmp/mountinfo_%ld", target_pid);
                        
                        // 这里简化处理，直接返回临时文件路径
                        // 在实际应用中，可以使用更简单的方式创建和处理临时文件
                        strncpy(path, temp_path, PATH_MAX - 1);
                        path[PATH_MAX - 1] = '\0';
                    }
                }
            }
        }
        return 0;
    }

    default:
        return 0;
    }
}