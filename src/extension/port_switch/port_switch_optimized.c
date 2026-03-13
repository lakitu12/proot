#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/net.h>
#include <stdint.h>
#include <string.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"

/* 静态端口映射表 - 直接映射关系 */
#define STATIC_PORT_MAP_SIZE 16
static struct {
    uint16_t from_port;
    uint16_t to_port;
    bool active;
} static_port_map[STATIC_PORT_MAP_SIZE];

/* 初始化静态端口映射 */
static void init_static_port_map() {
    static bool initialized = false;
    if (initialized) return;
    
    // 初始化一些常用的端口映射
    static_port_map[0] = (typeof(*static_port_map)){.from_port = 80, .to_port = 8080, .active = true};
    static_port_map[1] = (typeof(*static_port_map)){.from_port = 443, .to_port = 8443, .active = true};
    static_port_map[2] = (typeof(*static_port_map)){.from_port = 22, .to_port = 8022, .active = true};
    static_port_map[3] = (typeof(*static_port_map)){.from_port = 3000, .to_port = 13000, .active = true};
    static_port_map[4] = (typeof(*static_port_map)){.from_port = 8080, .to_port = 18080, .active = true};
    static_port_map[5] = (typeof(*static_port_map)){.from_port = 9000, .to_port = 19000, .active = true};
    
    initialized = true;
}

/* 查找端口映射（O(1)时间复杂度） */
static uint16_t lookup_port_mapping(uint16_t original_port) {
    for (int i = 0; i < STATIC_PORT_MAP_SIZE; i++) {
        if (static_port_map[i].active && static_port_map[i].from_port == original_port) {
            return static_port_map[i].to_port;
        }
    }
    return 0; // 未找到映射，返回0表示不转换
}

/* 端口转换钩子函数 */
static void mod_port(Tracee *tracee, bool is_socketcall, bool is_bind, struct sockaddr_storage *my_sockaddr, long *socketcall_arg2) {
    uint16_t new_port = 0;
    
    switch(my_sockaddr->ss_family) {
        case AF_INET: {
            struct sockaddr_in *in = (struct sockaddr_in *)my_sockaddr;
            uint16_t orig_port = ntohs(in->sin_port);
            
            // 查找静态端口映射表
            new_port = lookup_port_mapping(orig_port);
            if (new_port != 0) {
                in->sin_port = htons(new_port);
                
                // 写回修改后的地址结构
                if (is_socketcall) {
                    // 修改socketcall参数中的地址结构
                    write_data(tracee, socketcall_arg2[1], in, sizeof(struct sockaddr_in));
                    write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), socketcall_arg2, 2 * sizeof(long));
                } else {
                    write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), in, sizeof(struct sockaddr_in));
                }
            }
            break;
        }

        case AF_INET6: {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)my_sockaddr;
            uint16_t orig_port = ntohs(in6->sin6_port);
            
            // 查找静态端口映射表
            new_port = lookup_port_mapping(orig_port);
            if (new_port != 0) {
                in6->sin6_port = htons(new_port);
                
                // 写回修改后的地址结构
                if (is_socketcall) {
                    // 修改socketcall参数中的地址结构
                    write_data(tracee, socketcall_arg2[1], in6, sizeof(struct sockaddr_in6));
                    write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), socketcall_arg2, 2 * sizeof(long));
                } else {
                    write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), in6, sizeof(struct sockaddr_in6));
                }
            }
            break;
        }
        
        default:
            break;
    }
}

/* 检查是否是本地地址 */
static bool is_localhost(struct sockaddr_storage *my_sockaddr) {
    switch(my_sockaddr->ss_family) {
        case AF_INET: {
            struct sockaddr_in *in = (struct sockaddr_in *)my_sockaddr;
            // 检查是否为127.0.0.1或0.0.0.0 (INADDR_ANY)
            return (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK) || 
                    in->sin_addr.s_addr == htonl(INADDR_ANY));
        }
    
        case AF_INET6: {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)my_sockaddr;
            // 检查是否为::1 (IPv6 loopback) 或 :: (IPv6 any)
            static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
            static const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
            return (memcmp(&in6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0 ||
                    memcmp(&in6->sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0);
        }

        default: 
            return false;
    }
}

/* 端口转发扩展回调函数 */
int port_switch_callback(Extension *extension, ExtensionEvent event, intptr_t data1 UNUSED, intptr_t data2 UNUSED) {
    switch (event) {
    case INITIALIZATION: {
        // 只注册bind和connect系统调用
        static FilteredSysnum filtered_sysnums[] = {
            { PR_bind, FILTER_SYSEXIT },
            { PR_connect, FILTER_SYSEXIT },
            { PR_socketcall, FILTER_SYSEXIT },
            FILTERED_SYSNUM_END     
        };
        extension->filtered_sysnums = filtered_sysnums;
        
        // 初始化静态端口映射表
        init_static_port_map();
        return 0;
    }
    
    case SYSCALL_ENTER_END: {
        Tracee *tracee = TRACEE(extension);
        
        switch(get_sysnum(tracee, ORIGINAL)) {
            case PR_bind: {
                struct sockaddr_storage my_sockaddr;
                read_data(tracee, &my_sockaddr, peek_reg(tracee, ORIGINAL, SYSARG_2), 
                         sizeof(struct sockaddr_storage));
                
                // 对bind进行端口转换
                mod_port(tracee, false, true, &my_sockaddr, NULL);
                return 0;
            }

            case PR_connect: {
                struct sockaddr_storage my_sockaddr;
                read_data(tracee, &my_sockaddr, peek_reg(tracee, ORIGINAL, SYSARG_2), 
                         sizeof(struct sockaddr_storage));
                
                // 只对本地连接进行端口转换
                if (is_localhost(&my_sockaddr)) {
                    mod_port(tracee, false, false, &my_sockaddr, NULL);
                }
                return 0;
            }

            case PR_socketcall: {
                // 处理socketcall包装的系统调用
                int call = peek_reg(tracee, ORIGINAL, SYSARG_1);
                long a[6];
                read_data(tracee, a, peek_reg(tracee, ORIGINAL, SYSARG_2), sizeof(a));
                
                switch(call) {
                    case SYS_BIND: {
                        struct sockaddr_storage my_sockaddr;
                        read_data(tracee, &my_sockaddr, a[1], sizeof(struct sockaddr_storage));
                        mod_port(tracee, true, true, &my_sockaddr, a);
                        break;
                    }

                    case SYS_CONNECT: {
                        struct sockaddr_storage my_sockaddr;
                        read_data(tracee, &my_sockaddr, a[1], sizeof(struct sockaddr_storage));
                        if (is_localhost(&my_sockaddr)) {
                            mod_port(tracee, true, false, &my_sockaddr, a);
                        }
                        break;
                    }
                    
                    default:
                        break;
                }
                return 0;
            }

            default:
                return 0;
        }
    }   
    default: 
        return 0;
    }
}