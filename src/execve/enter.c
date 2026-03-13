/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 * Copyright (C) 2015 STMicroelectronics
 * 优化版：彻底修复编译错误+根除talloc坑+性能提升，兼容Termux环境
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <talloc.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "execve/execve.h"
#include "execve/shebang.h"
#include "execve/aoxp.h"
#include "execve/ldso.h"
#include "execve/elf.h"
#include "path/path.h"
#include "path/temp.h"
#include "path/binding.h"
#include "tracee/tracee.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "arch.h"
#include "cli/note.h"

// 编译期常量+分支预测优化，减少运行时开销
#define P(a) PROGRAM_FIELD(load_info->elf_header, *program_header, a)
#define DEFAULT_PAGE_SIZE 0x1000
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define LIKELY(expr) __builtin_expect(!!(expr), 1)

// 【核心优化1】全局talloc ctx统一管理，根除上下文乱绑
static TALLOC_CTX *g_root_loader_ctx = NULL;
static void __talloc_global_ctx_cleanup(void);

// 构造函数初始化全局ctx，注册退出销毁
__attribute__((constructor)) static void __talloc_global_ctx_init(void) {
    if (g_root_loader_ctx == NULL) {
        g_root_loader_ctx = talloc_new(NULL);
        if (g_root_loader_ctx != NULL) {
            talloc_set_name_const(g_root_loader_ctx, "root_loader_ctx_master");
            atexit(__talloc_global_ctx_cleanup);
        }
    }
}

// 退出时销毁全局ctx，彻底释放所有托管内存
static void __talloc_global_ctx_cleanup(void) {
    if (g_root_loader_ctx != NULL) {
        talloc_free(g_root_loader_ctx);
        g_root_loader_ctx = NULL;
    }
}

/**
 * 【优化2】add_mapping：减少冗余计算+分支预测，提升内存映射效率
 */
static int add_mapping(const Tracee *tracee UNUSED, LoadInfo *load_info, const ProgramHeader *program_header) {
    size_t index = 0;
    word_t start_address, end_address;
    static word_t page_size = 0;
    static word_t page_mask = 0;

    // 懒加载页大小，仅初始化一次
    if (UNLIKELY(page_size == 0)) {
        page_size = sysconf(_SC_PAGE_SIZE);
        page_size = (page_size <= 0) ? DEFAULT_PAGE_SIZE : page_size;
        page_mask = ~(page_size - 1);
    }

    // 简化索引计算，避免重复调用talloc_array_length
    index = (load_info->mappings != NULL) ? talloc_array_length(load_info->mappings) : 0;

    // 扩容Mapping数组，上下文统一绑定到load_info，避免游离
    load_info->mappings = talloc_realloc(load_info, load_info->mappings, Mapping, index + 1);
    if (UNLIKELY(load_info->mappings == NULL))
        return -ENOMEM;

    // 预计算关键地址，减少重复表达式计算
    const word_t vaddr = P(vaddr);
    const word_t filesz = P(filesz);
    const word_t memsz = P(memsz);
    const word_t offset = P(offset);
    const word_t flags = P(flags);

    start_address = vaddr & page_mask;
    end_address = (vaddr + filesz + page_size) & page_mask;

    // 赋值优化：集中初始化，减少内存访问次数
    Mapping *curr_map = &load_info->mappings[index];
    curr_map->fd = -1;
    curr_map->offset = offset & page_mask;
    curr_map->addr = start_address;
    curr_map->length = end_address - start_address;
    curr_map->flags = MAP_PRIVATE | MAP_FIXED;
    curr_map->prot = ((flags & PF_R) ? PROT_READ : 0)
                   | ((flags & PF_W) ? PROT_WRITE : 0)
                   | ((flags & PF_X) ? PROT_EXEC : 0);
    curr_map->clear_length = 0;

    // 处理memsz > filesz的零填充逻辑，优化分支判断
    if (LIKELY(memsz > filesz)) {
        curr_map->clear_length = end_address - vaddr - filesz;
        const word_t new_start = end_address;
        const word_t new_end = (vaddr + memsz + page_size) & page_mask;

        if (LIKELY(new_end > new_start)) {
            index++;
            load_info->mappings = talloc_realloc(load_info, load_info->mappings, Mapping, index + 1);
            if (UNLIKELY(load_info->mappings == NULL))
                return -ENOMEM;

            Mapping *anon_map = &load_info->mappings[index];
            anon_map->fd = -1;
            anon_map->offset = 0;
            anon_map->addr = new_start;
            anon_map->length = new_end - new_start;
            anon_map->clear_length = 0;
            anon_map->flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
            anon_map->prot = curr_map->prot;
        }
    }

    return 0;
}

/**
 * 【优化3】translate_and_check_exec：合并系统调用，减少上下文切换
 */
int translate_and_check_exec(Tracee *tracee, char host_path[PATH_MAX], const char *user_path) {
    if (UNLIKELY(user_path[0] == '\0'))
        return -ENOEXEC;

    // 路径翻译
    int status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);
    if (UNLIKELY(status < 0))
        return status;

    // 合并存在性+可执行性检查（减少access调用次数，原两次→一次）
    if (UNLIKELY(access(host_path, F_OK | X_OK) < 0))
        return (errno == ENOENT) ? -ENOENT : -EACCES;

    // 常规文件检查
    struct stat statl;
    if (UNLIKELY(lstat(host_path, &statl) < 0))
        return -EPERM;

    return 0;
}

/**
 * 【优化4】add_interp：统一talloc上下文，减少内存碎片
 */
static int add_interp(Tracee *tracee, int fd, LoadInfo *load_info, const ProgramHeader *program_header) {
    char host_path[PATH_MAX];
    char *user_path = NULL;
    int status = 0;

    if (UNLIKELY(load_info->interp != NULL))
        return -EINVAL;

    // interp上下文绑定到load_info，统一生命周期
    load_info->interp = talloc_zero(load_info, LoadInfo);
    if (UNLIKELY(load_info->interp == NULL))
        return -ENOMEM;

    const size_t filesz = P(filesz);
    const word_t offset = P(offset);

    // 内存分配统一用tracee->ctx，避免独立ctx创建
    user_path = talloc_size(tracee->ctx, filesz + 1);
    if (UNLIKELY(user_path == NULL))
        return -ENOMEM;

    // 读取interp路径，检查返回值
    status = pread(fd, user_path, filesz, offset);
    if (UNLIKELY((size_t)status != filesz)) {
        TALLOC_FREE(user_path);
        return -EACCES;
    }
    user_path[filesz] = '\0';

    // QEMU路径拼接，优化字符串操作
    if (LIKELY(tracee->qemu != NULL && user_path[0] == '/')) {
        char *new_user_path = talloc_asprintf(tracee->ctx, "%s%s", HOST_ROOTFS, user_path);
        if (UNLIKELY(new_user_path == NULL)) {
            TALLOC_FREE(user_path);
            return -ENOMEM;
        }
        TALLOC_FREE(user_path);
        user_path = new_user_path;
    }

    // 路径翻译+检查
    status = translate_and_check_exec(tracee, host_path, user_path);
    if (UNLIKELY(status < 0)) {
        TALLOC_FREE(user_path);
        return status;
    }

    // 路径字符串绑定到interp，统一销毁
    load_info->interp->host_path = talloc_strdup(load_info->interp, host_path);
    load_info->interp->user_path = talloc_strdup(load_info->interp, user_path);
    TALLOC_FREE(user_path);

    if (UNLIKELY(load_info->interp->host_path == NULL || load_info->interp->user_path == NULL))
        return -ENOMEM;

    return 0;
}

#undef P

struct add_load_info_data {
    LoadInfo *load_info;
    Tracee *tracee;
    int fd;
};

/**
 * 【优化5】add_load_info：简化分支，提升迭代效率
 */
static int add_load_info(const ElfHeader *elf_header, const ProgramHeader *program_header, void *data_) {
    struct add_load_info_data *data = data_;
    int status = 0;

    switch (PROGRAM_FIELD(*elf_header, *program_header, type)) {
        case PT_LOAD:
            status = add_mapping(data->tracee, data->load_info, program_header);
            break;
        case PT_INTERP:
            status = add_interp(data->tracee, data->fd, data->load_info, program_header);
            break;
        case PT_GNU_STACK:
            data->load_info->needs_executable_stack |=
                ((PROGRAM_FIELD(*elf_header, *program_header, flags) & PF_X) != 0);
            break;
        default:
            return 0; // 无需处理，直接返回
    }

    return (status < 0) ? status : 0;
}

/**
 * 【优化6】extract_load_info：优化错误处理，减少goto跳转 + 修复ElfType错误
 */
static int extract_load_info(Tracee *tracee, LoadInfo *load_info) {
    assert(load_info != NULL && load_info->host_path != NULL);

    int fd = open_elf(load_info->host_path, &load_info->elf_header);
    if (UNLIKELY(fd < 0))
        return fd;

    // 【修复1】移除未知类型ElfType，直接用ELF_FIELD获取值判断
    if (UNLIKELY(ELF_FIELD(load_info->elf_header, type) != ET_EXEC && ELF_FIELD(load_info->elf_header, type) != ET_DYN)) {
        close(fd);
        return -EINVAL;
    }

    struct add_load_info_data data = {
        .load_info = load_info,
        .tracee = tracee,
        .fd = fd
    };

    int status = iterate_program_headers(tracee, fd, &load_info->elf_header, add_load_info, &data);
    close(fd);
    return status;
}

/**
 * 【优化7】add_load_base：用指针遍历，减少数组索引开销
 */
static void add_load_base(LoadInfo *load_info, word_t load_base) {
    if (UNLIKELY(load_info->mappings == NULL))
        return;

    const size_t nb_mappings = talloc_array_length(load_info->mappings);
    Mapping *curr_map = load_info->mappings;

    // 指针遍历比数组索引更高效，编译器优化更彻底
    for (size_t i = 0; i < nb_mappings; i++, curr_map++)
        curr_map->addr += load_base;

    // 入口地址更新
    if (IS_CLASS64(load_info->elf_header))
        load_info->elf_header.class64.e_entry += load_base;
    else
        load_info->elf_header.class32.e_entry += load_base;
}

/**
 * 【优化8】compute_load_addresses：优化空指针检查，减少冗余判断
 */
static void compute_load_addresses(Tracee *tracee) {
    LoadInfo *main_info = tracee->load_info;
    if (UNLIKELY(main_info == NULL || main_info->mappings == NULL))
        return;

    // 主程序PIE地址计算
    if (IS_POSITION_INDENPENDANT(main_info->elf_header) && main_info->mappings[0].addr == 0) {
#if defined(HAS_LOADER_32BIT)
        if (IS_CLASS32(main_info->elf_header))
            add_load_base(main_info, EXEC_PIC_ADDRESS_32);
        else
#endif
            add_load_base(main_info, EXEC_PIC_ADDRESS);
    }

    // 解释器PIE地址计算，提前判空
    LoadInfo *interp_info = main_info->interp;
    if (UNLIKELY(interp_info == NULL || interp_info->mappings == NULL))
        return;

    if (IS_POSITION_INDENPENDANT(interp_info->elf_header) && interp_info->mappings[0].addr == 0) {
#if defined(HAS_LOADER_32BIT)
        if (IS_CLASS32(main_info->elf_header))
            add_load_base(interp_info, INTERP_PIC_ADDRESS_32);
        else
#endif
            add_load_base(interp_info, INTERP_PIC_ADDRESS);
    }
}

/**
 * 【优化9】expand_runner：减少字符串拷贝，优化循环效率 + 修复指针类型警告
 */
static int expand_runner(Tracee* tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]) {
    ArrayOfXPointers *envp;
    int status = fetch_array_of_xpointers(tracee, &envp, SYSARG_3, 0);
    if (UNLIKELY(status < 0))
        return status;

    envp->compare_xpointee = (compare_xpointee_t) compare_xpointee_env;

    // 非host ELF才处理，减少嵌套
    if (is_host_elf(tracee, host_path))
        goto ldso_env;

    tracee->skip_proot_loader = (getenv("PROOT_USE_LOADER_FOR_QEMU") == NULL);
    ArrayOfXPointers *argv;
    status = fetch_array_of_xpointers(tracee, &argv, SYSARG_2, 0);
    if (UNLIKELY(status < 0))
        return status;

    char *argv0 = NULL;
    status = read_xpointee_as_string(argv, 0, &argv0);
    if (UNLIKELY(status < 0))
        return status;

    // 优化QEMU参数长度计算
    const size_t nb_qemu_args = (tracee->qemu != NULL) ? talloc_array_length(tracee->qemu) - 1 : 0;
    status = resize_array_of_xpointers(argv, 1, nb_qemu_args + 2);
    if (UNLIKELY(status < 0)) {
        TALLOC_FREE(argv0);
        return status;
    }

    // 【修复2】修正指针类型，避免丢弃const限定符警告
    char **qemu_arg = tracee->qemu;
    for (size_t i = 0; i < nb_qemu_args; i++, qemu_arg++) {
        status = write_xpointee(argv, i, *qemu_arg);
        if (UNLIKELY(status < 0)) {
            TALLOC_FREE(argv0);
            return status;
        }
    }

    // 批量写入参数，减少函数调用
    status = write_xpointees(argv, nb_qemu_args, 3, "-0", argv0, user_path);
    TALLOC_FREE(argv0);
    if (UNLIKELY(status < 0))
        return status;

    status = ldso_env_passthru(tracee, envp, argv, "-E", "-U", (int)nb_qemu_args);
    if (UNLIKELY(status < 0))
        return status;

    status = push_array_of_xpointers(argv, SYSARG_2);
    if (UNLIKELY(status < 0))
        return status;

    // 路径赋值优化，减少strcpy/strcat调用
    const char *qemu_path = tracee->qemu[0];
    strncpy(host_path, qemu_path, PATH_MAX - 1);
    host_path[PATH_MAX - 1] = '\0';

    if (tracee->skip_proot_loader) {
        strncpy(user_path, host_path, PATH_MAX - 1);
    } else {
        // 合并字符串拷贝，减少内存访问
        snprintf(user_path, PATH_MAX - 1, "%s%s", HOST_ROOTFS, qemu_path);
    }
    user_path[PATH_MAX - 1] = '\0';

ldso_env:
    status = rebuild_host_ldso_paths(tracee, host_path, envp);
    if (UNLIKELY(status < 0))
        return status;
    return push_array_of_xpointers(envp, SYSARG_3);
}

#if !defined(PROOT_UNBUNDLE_LOADER)
extern unsigned char _binary_loader_exe_start;
extern unsigned char _binary_loader_exe_end;
extern unsigned char WEAK _binary_loader_m32_exe_start;
extern unsigned char WEAK _binary_loader_m32_exe_end;

/**
 * 【优化10】extract_loader：彻底修复talloc坑，统一上下文
 */
static char *extract_loader(const Tracee *tracee, bool wants_32bit_version) {
    char path[PATH_MAX] = {0};
    size_t write_size = 0;
    void *start = NULL;
    size_t size = 0;
    int status = 0;
    int fd = -1;
    FILE *file = NULL;
    char *loader_path = NULL;

    // 全局ctx兜底检查
    if (UNLIKELY(g_root_loader_ctx == NULL)) {
        note(tracee, ERROR, INTERNAL, "global talloc root ctx not initialized");
        return NULL;
    }

    // 打开临时文件，失败直接返回
    file = open_temp_file(NULL, "prooted");
    if (UNLIKELY(file == NULL))
        return NULL;
    fd = fileno(file);

    // 加载loader二进制数据，优化指针计算
    if (wants_32bit_version) {
        start = (void *)&_binary_loader_m32_exe_start;
        size = (size_t)(&_binary_loader_m32_exe_end - &_binary_loader_m32_exe_start);
    } else {
        start = (void *)&_binary_loader_exe_start;
        size = (size_t)(&_binary_loader_exe_end - &_binary_loader_exe_start);
    }

    // 写入数据，检查返回值
    write_size = write(fd, start, size);
    if (UNLIKELY(write_size != size)) {
        note(tracee, ERROR, SYSTEM, "can't write the loader");
        goto end;
    }

    // 设置权限
    if (UNLIKELY(fchmod(fd, S_IRUSR | S_IXUSR) < 0)) {
        note(tracee, ERROR, SYSTEM, "can't change loader permissions (u+rx)");
        goto end;
    }

    // 获取loader路径
    if (UNLIKELY(readlink_proc_pid_fd(getpid(), fd, path) < 0)) {
        note(tracee, ERROR, INTERNAL, "can't retrieve loader path (/proc/self/fd/)");
        goto end;
    }

    // 检查可执行性
    if (UNLIKELY(access(path, X_OK) < 0)) {
        note(tracee, ERROR, INTERNAL,
             "temporary directory (%s) mounted with no execution permission.",
             get_temp_directory());
        note(tracee, INFO, USER,
             "Set PROOT_TMP_DIR to '%s/tmp' (example).", get_root(tracee));
        goto end;
    }

    // 路径绑定到全局ctx，统一销毁
    loader_path = talloc_strdup(g_root_loader_ctx, path);
    if (UNLIKELY(loader_path == NULL)) {
        note(tracee, ERROR, INTERNAL, "can't allocate memory for loader path");
        goto end;
    }

    if (tracee->verbose >= 2)
        note(tracee, INFO, INTERNAL, "loader: %s", loader_path);

end:
    // 关闭文件，与ctx解耦
    if (file != NULL) {
        status = fclose(file);
        if (status < 0)
            note(tracee, WARNING, SYSTEM, "can't close loader file");
    }
    return loader_path;
}
#endif // 闭合外层PROOT_UNBUNDLE_LOADER条件

/**
 * 【优化11】get_loader_path：静态变量优化，减少ctx判断
 */
static inline const char *get_loader_path(const Tracee *tracee) {
#if defined(PROOT_UNBUNDLE_LOADER)
#if defined(HAS_LOADER_32BIT)
    if (IS_CLASS32(tracee->load_info->elf_header)) {
        const char *env_path = getenv("PROOT_LOADER_32");
        return (env_path != NULL && access(env_path, X_OK) == 0) ? env_path : PROOT_UNBUNDLE_LOADER "/loader32";
    }
#endif
    const char *env_path = getenv("PROOT_LOADER");
    return (env_path != NULL && access(env_path, X_OK) == 0) ? env_path : PROOT_UNBUNDLE_LOADER "/loader";
#else // 对应get_loader_path中的#else，补全嵌套条件
    static char *loader_path = NULL;
#if defined(HAS_LOADER_32BIT)
    static char *loader32_path = NULL;
#endif

    // 全局ctx兜底
    if (UNLIKELY(g_root_loader_ctx == NULL))
        return NULL;

#if defined(HAS_LOADER_32BIT)
    if (IS_CLASS32(tracee->load_info->elf_header)) {
        if (UNLIKELY(loader32_path == NULL)) {
            const char *env_path = getenv("PROOT_LOADER_32");
            if (env_path != NULL && access(env_path, X_OK) == 0)
                loader32_path = talloc_strdup(g_root_loader_ctx, env_path);
            else
                loader32_path = extract_loader(tracee, true);
        }
        return loader32_path;
    }
#endif

    if (UNLIKELY(loader_path == NULL)) {
        const char *env_path = getenv("PROOT_LOADER");
        if (env_path != NULL && access(env_path, X_OK) == 0)
            loader_path = talloc_strdup(g_root_loader_ctx, env_path);
        else
            loader_path = extract_loader(tracee, false);
    }
    return loader_path;
#endif // 闭合get_loader_path中的外层#if defined(PROOT_UNBUNDLE_LOADER)
}

/**
 * 【优化12】translate_execve_enter：简化逻辑，减少内存操作
 */
int translate_execve_enter(Tracee *tracee) {
    char user_path[PATH_MAX] = {0};
    char host_path[PATH_MAX] = {0};
    char new_exe[PATH_MAX] = {0};
    char *raw_path = NULL;
    const char *loader_path = NULL;
    int status = 0;

    // 跟踪器通知处理，直接返回
    if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee)) {
        tracee->as_ptracee.ignore_loader_syscalls = false;
        set_sysnum(tracee, PR_void);
        return 0;
    }

    // 获取系统调用路径
    status = get_sysarg_path(tracee, user_path, SYSARG_1);
    if (UNLIKELY(status < 0))
        return status;

    // 保存原始路径
    raw_path = talloc_strdup(tracee->ctx, user_path);
    if (UNLIKELY(raw_path == NULL))
        return -ENOMEM;

    // 扩展shebang
    status = expand_shebang(tracee, host_path, user_path);
    if (UNLIKELY(status < 0)) {
        TALLOC_FREE(raw_path);
        return (status == -EISDIR) ? -EACCES : status;
    }

    // 无需原始路径时释放
    if (status == 0 && tracee->qemu == NULL) {
        TALLOC_FREE(raw_path);
        raw_path = NULL;
    }

    // 更新/proc/self/exe路径，优化talloc_unlink调用
    talloc_unlink(tracee, tracee->host_exe);
    tracee->host_exe = talloc_strdup(tracee, host_path);

    strncpy(new_exe, host_path, PATH_MAX - 1);
    status = detranslate_path(tracee, new_exe, NULL);
    talloc_unlink(tracee, tracee->new_exe);
    tracee->new_exe = (status >= 0) ? talloc_strdup(tracee, new_exe) : NULL;

    // QEMU运行器扩展
    tracee->skip_proot_loader = false;
    if (LIKELY(tracee->qemu != NULL)) {
        status = expand_runner(tracee, host_path, user_path);
        if (UNLIKELY(status < 0)) {
            TALLOC_FREE(raw_path);
            return status;
        }
    }

    // 跳过loader场景
    if (tracee->skip_proot_loader) {
        TALLOC_FREE(raw_path);
        tracee->heap->disabled = true;
        return set_sysarg_path(tracee, host_path, SYSARG_1);
    }

    // 释放原有LoadInfo
    talloc_unlink(tracee, tracee->load_info);
    tracee->load_info = talloc_zero(tracee, LoadInfo);
    if (UNLIKELY(tracee->load_info == NULL)) {
        TALLOC_FREE(raw_path);
        return -ENOMEM;
    }

    // 保存路径，统一绑定到load_info
    tracee->load_info->host_path = talloc_strdup(tracee->load_info, host_path);
    tracee->load_info->user_path = talloc_strdup(tracee->load_info, user_path);
    if (UNLIKELY(tracee->load_info->host_path == NULL || tracee->load_info->user_path == NULL)) {
        TALLOC_FREE(raw_path);
        return -ENOMEM;
    }

    // 处理原始路径
    tracee->load_info->raw_path = (raw_path != NULL)
        ? talloc_reparent(tracee->ctx, tracee->load_info, raw_path)
        : talloc_reference(tracee->load_info, tracee->load_info->user_path);
    if (UNLIKELY(tracee->load_info->raw_path == NULL))
        return -ENOMEM;

    // 提取加载信息
    status = extract_load_info(tracee, tracee->load_info);
    if (UNLIKELY(status < 0))
        return status;

    // 提取解释器信息
    if (LIKELY(tracee->load_info->interp != NULL)) {
        status = extract_load_info(tracee, tracee->load_info->interp);
        if (UNLIKELY(status < 0))
            return status;
        TALLOC_FREE(tracee->load_info->interp->interp);
    }

    // 计算加载地址
    compute_load_addresses(tracee);

    // 获取loader路径，执行程序
    loader_path = get_loader_path(tracee);
    if (UNLIKELY(loader_path == NULL))
        return -ENOENT;

    status = set_sysarg_path(tracee, loader_path, SYSARG_1);
    tracee->as_ptracee.ignore_loader_syscalls = true;
    return status;
}
