#include <sys/types.h>  /* stat(2), opendir(3), */
#include <sys/stat.h>   /* stat(2), chmod(2), */
#include <unistd.h>     /* stat(2), rmdir(2), unlink(2), readlink(2), getpid(2), */
#include <errno.h>      /* errno(2), */
#include <dirent.h>     /* readdir(3), opendir(3), */
#include <string.h>     /* strcmp(3), strlen(3), */
#include <stdlib.h>     /* free(3), getenv(3), */
#include <stdio.h>      /* P_tmpdir, FILE*, fopen(3), fclose(3) */
#include <talloc.h>     /* talloc(3), */
#include <limits.h>     /* PATH_MAX */

#include "cli/note.h"

// 全局单例临时上下文：唯一管理所有临时内存，彻底杜绝零散null_context
static TALLOC_CTX *g_temp_talloc_ctx = NULL;

/**
 * 初始化全局临时talloc上下文（唯一入口，无兜底，避免创建null_context）
 */
static inline TALLOC_CTX *get_global_temp_ctx()
{
    if (g_temp_talloc_ctx == NULL) {
        g_temp_talloc_ctx = talloc_new(NULL);
        if (g_temp_talloc_ctx == NULL) {
            note(NULL, ERROR, INTERNAL, "failed to create global temp talloc context");
            abort(); // 直接终止，避免后续创建零散null_context
        }
    }
    return g_temp_talloc_ctx;
}

/**
 * 释放全局临时上下文（程序退出时调用）
 */
void free_global_temp_ctx()
{
    if (g_temp_talloc_ctx != NULL) {
        talloc_free(g_temp_talloc_ctx);
        g_temp_talloc_ctx = NULL;
    }
}

/**
 * Return the path to a directory where temporary files should be
 * created.
 * 核心修复：静态变量绑定全局上下文+删除所有talloc_new(NULL)
 */
const char *get_temp_directory()
{
    static char *temp_directory = NULL; // 改为char*，方便手动talloc_free
    char realpath_buf[PATH_MAX] = {0};
    char *tmp = NULL;
    TALLOC_CTX *ctx = get_global_temp_ctx();

    if (temp_directory != NULL)
        return temp_directory;

    // 优先获取环境变量
    const char *env_tmp = getenv("PROOT_TMP_DIR");
    if (env_tmp == NULL)
        env_tmp = P_tmpdir;

    // 解析绝对路径
    tmp = realpath(env_tmp, realpath_buf);
    if (tmp == NULL) {
        note(NULL, WARNING, SYSTEM, "can't canonicalize %s", env_tmp);
        temp_directory = talloc_strdup(ctx, env_tmp); // 绑定全局上下文
    } else {
        temp_directory = talloc_strdup(ctx, tmp); // 绑定全局上下文，无零散null_context
    }

    return temp_directory;
}

/**
 * Remove recursively the content of the current working directory.
 */
static int clean_temp_cwd()
{
    const char *temp_directory = get_temp_directory();
    const size_t length_temp_directory = strlen(temp_directory);
    int nb_errors = 0;
    DIR *dir = NULL;
    int status;

    char prefix[PATH_MAX] = {0};
    status = readlink("/proc/self/cwd", prefix, sizeof(prefix) - 1);
    if (status < 0) {
        note(NULL, WARNING, SYSTEM, "can't readlink '/proc/self/cwd'");
        nb_errors++;
        goto end;
    }
    prefix[status] = '\0';

    if (strlen(prefix) < length_temp_directory || 
        strncmp(prefix, temp_directory, length_temp_directory) != 0) {
        note(NULL, ERROR, INTERNAL,
            "trying to remove a directory outside of '%s', please report this error.", 
            temp_directory);
        nb_errors++;
        goto end;
    }

    dir = opendir(".");
    if (dir == NULL) {
        note(NULL, WARNING, SYSTEM, "can't open '.'");
        nb_errors++;
        goto end;
    }

    struct dirent *entry = NULL;
    errno = 0; // 修复：循环前重置errno，解决No child processes报错
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // 按需修改权限
        struct stat st = {0};
        if (stat(entry->d_name, &st) == 0 && (st.st_mode & 0700) != 0700) {
            status = chmod(entry->d_name, 0700);
            if (status < 0) {
                note(NULL, WARNING, SYSTEM, "cant chmod '%s'", entry->d_name);
                nb_errors++;
                continue;
            }
        }

        if (entry->d_type == DT_DIR) {
            status = chdir(entry->d_name);
            if (status < 0) {
                note(NULL, WARNING, SYSTEM, "can't chdir '%s'", entry->d_name);
                nb_errors++;
                continue;
            }

            status = clean_temp_cwd();
            if (status < 0) {
                nb_errors = -1;
                goto end;
            }
            nb_errors += status;

            status = chdir("..");
            if (status < 0) {
                note(NULL, ERROR, SYSTEM, "can't chdir to '..'");
                nb_errors = -1;
                goto end;
            }

            status = rmdir(entry->d_name);
        }
        else {
            status = unlink(entry->d_name);
        }
        if (status < 0) {
            note(NULL, WARNING, SYSTEM, "can't remove '%s'", entry->d_name);
            nb_errors++;
            continue;
        }
    }

    if (errno != 0 && errno != ECHILD) { // 修复：忽略ECHILD错误，仅报其他真实错误
        note(NULL, WARNING, SYSTEM, "can't readdir '.'");
        nb_errors++;
    }

end:
    if (dir != NULL)
        (void) closedir(dir);
    return nb_errors;
}

/**
 * Remove recursively @path.
 */
static int remove_temp_directory2(const char *path)
{
    if (path == NULL || strlen(path) == 0) {
        note(NULL, ERROR, INTERNAL, "invalid temp directory path");
        return -1;
    }

    int result = 0;
    int status;
    char cwd[PATH_MAX] = {0};

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        note(NULL, ERROR, SYSTEM, "can't get current working directory");
        return -1;
    }

    struct stat st = {0};
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        note(NULL, ERROR, SYSTEM, "%s is not a valid directory", path);
        return -1;
    }

    if ((st.st_mode & 0700) != 0700) {
        status = chmod(path, 0700);
        if (status < 0) {
            note(NULL, ERROR, SYSTEM, "can't chmod '%s'", path);
            result = -1;
            goto end;
        }
    }

    status = chdir(path);
    if (status < 0) {
        note(NULL, ERROR, SYSTEM, "can't chdir to '%s'", path);
        result = -1;
        goto end;
    }

    status = clean_temp_cwd();
    result = (status == 0 ? 0 : -1);

    status = chdir(cwd);
    if (status < 0) {
        note(NULL, ERROR, SYSTEM, "can't chdir to '%s'", cwd);
        result = -1;
        goto end;
    }

    if (rmdir(path) < 0) {
        note(NULL, ERROR, SYSTEM, "cant remove '%s'", path);
        result = -1;
    }

end:
    return result;
}

/**
 * talloc析构函数：清理目录+释放内存
 */
static int remove_temp_directory(char *path)
{
    if (path == NULL)
        return 0;
    (void) remove_temp_directory2(path);
    talloc_free(path); // 手动释放，避免内存残留
    return 0;
}

/**
 * talloc析构函数：清理文件+释放内存
 */
static int remove_temp_file(char *path)
{
    if (path == NULL)
        return 0;
    if (unlink(path) < 0)
        note(NULL, ERROR, SYSTEM, "can't remove '%s'", path);
    talloc_free(path); // 手动释放，避免内存残留
    return 0;
}

/**
 * Create a path name: "/tmp/@prefix-$PID-XXXXXX"
 * 核心修复：强制绑定全局上下文，彻底删除talloc_new(NULL) + 消除unused参数警告
 */
char *create_temp_name(TALLOC_CTX *context __attribute__((unused)), const char *prefix)
{
    if (prefix == NULL || strlen(prefix) == 0) {
        note(NULL, ERROR, INTERNAL, "invalid temp file prefix");
        return NULL;
    }

    const char *temp_directory = get_temp_directory();
    // 强制使用全局上下文，拒绝创建任何零散null_context
    TALLOC_CTX *ctx = get_global_temp_ctx();

    char *name = talloc_asprintf(ctx, "%s/%s-%d-XXXXXX", 
        temp_directory, prefix, getpid());
    if (name == NULL)
        note(NULL, ERROR, INTERNAL, "can't allocate memory for temp name");

    return name;
}

/**
 * Create a temporary directory (auto-removed)
 */
const char *create_temp_directory(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (name == NULL)
        return NULL;

    char *dir = mkdtemp(name);
    if (dir == NULL) {
        note(NULL, ERROR, SYSTEM, "can't create temporary directory");
        note(NULL, INFO, USER, "Please set PROOT_TMP_DIR env. variable to an alternate location (with write permission).");
        talloc_free(name); // 失败立即释放
        return NULL;
    }

    talloc_set_destructor(dir, remove_temp_directory);
    return dir;
}

/**
 * Create a temporary file (auto-removed)
 */
const char *create_temp_file(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (name == NULL)
        return NULL;

    int fd = mkstemp(name);
    if (fd < 0) {
        note(NULL, ERROR, SYSTEM, "can't create temporary file");
        note(NULL, INFO, USER, "Please set PROOT_TMP_DIR env. variable to an alternate location (with write permission).");
        talloc_free(name); // 失败立即释放
        return NULL;
    }

    (void)fsync(fd);
    (void)close(fd);

    talloc_set_destructor(name, remove_temp_file);
    return name;
}

/**
 * Open a temporary file (auto-removed)
 */
FILE* open_temp_file(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (name == NULL)
        return NULL;

    int fd = mkstemp(name);
    if (fd < 0) {
        note(NULL, ERROR, SYSTEM, "can't create temporary file");
        talloc_free(name);
        goto error;
    }

    talloc_set_destructor(name, remove_temp_file);
    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        note(NULL, ERROR, SYSTEM, "can't open file stream for temp file");
        goto error;
    }

    return file;

error:
    if (fd >= 0) {
        (void)fsync(fd);
        (void)close(fd);
    }
    talloc_free(name);
    return NULL;
}

// 程序启动时初始化全局上下文，退出时自动释放（无任何中间null_context）
__attribute__((constructor)) static void temp_ctx_constructor()
{
    get_global_temp_ctx(); // 唯一一次创建talloc_new(NULL)，全局复用
}

__attribute__((destructor)) static void temp_ctx_destructor()
{
    free_global_temp_ctx(); // 彻底释放全局上下文，无残留
}
