/* Automatically generated from documentation. */
#ifndef PROOT_CLI_H
#define PROOT_CLI_H

#include "cli/cli.h"

#ifndef VERSION
#define VERSION "5.2.0-scicat"
#endif

static const char *recommended_bindings[] = {
    "/etc/host.conf",        "/etc/hosts",        "/etc/hosts.equiv",
    "/etc/mtab",             "/etc/netgroup",     "/etc/networks",
    "/etc/passwd",           "/etc/group",        "/etc/nsswitch.conf",
    "/etc/resolv.conf",      "/etc/localtime",    "/dev/",
    "/sys/",                 "/proc/",            "/tmp/",
    "/run/",                 "/var/run/dbus/system_bus_socket",
    "$HOME",                 "*path*",
    NULL
};

static const char *recommended_su_bindings[] = {
    "/etc/host.conf",        "/etc/hosts",        "/etc/nsswitch.conf",
    "/etc/resolv.conf",      "/dev/",             "/sys/",
    "/proc/",                "/tmp/",             "/run/shm",
    "$HOME",                 "*path*",
    NULL
};

static int handle_option_r(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_b(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_q(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_w(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_v(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_V(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_h(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_k(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_0(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_i(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_R(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_S(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_link2symlink(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_ashmem_memfd(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_sysvipc(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_kill_on_exit(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_L(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_H(Tracee *tracee, const Cli *cli, const char *value);
static int handle_option_p(Tracee *tracee, const Cli *cli, const char *value);

static int pre_initialize_bindings(Tracee *, const Cli *, size_t, char *const *, size_t);
static int post_initialize_exe(Tracee *, const Cli *, size_t, char *const *, size_t);

static Cli proot_cli = {
    .version  = VERSION,
    .name     = "proot",
    .subtitle = "chroot, mount --bind, and binfmt_misc without privilege/setup",
    .synopsis = "proot [option] ... [command]",
    .colophon = "Visit http://proot.me for help, bug reports, suggestions...\n"
                "Copyright (C) 2015 STMicroelectronics, licensed under GPL v2 or later.",
    .logo = " _____ _____              ___\n"
            "|  __ \\  __ \\_____  _____|   |_\n"
            "|   __/     /  _  \\/  _  \\    _|\n"
            "|__|  |__|__\\_____/\\_____/\\____|",

    .pre_initialize_bindings = pre_initialize_bindings,
    .post_initialize_exe     = post_initialize_exe,

    .options = {
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-r", .separator = ' ', .value = "path" },
                { .name = "--rootfs", .separator = '=', .value = "path" },
                {}
            },
            .handler = handle_option_r,
            .description = "Use *path* as the new guest root file-system, default is /.",
            .detail = "\tThe specified path typically contains a Linux distribution where\n"
                      "\tall new programs will be confined. Use -R or -S when possible."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-b", .separator = ' ', .value = "path" },
                { .name = "--bind", .separator = '=', .value = "path" },
                { .name = "-m", .separator = ' ', .value = "path" },
                { .name = "--mount", .separator = '=', .value = "path" },
                {}
            },
            .handler = handle_option_b,
            .description = "Make the content of *path* accessible in the guest rootfs.",
            .detail = "\tBind host path to guest, syntax: -b host:guest."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-q", .separator = ' ', .value = "command" },
                { .name = "--qemu", .separator = '=', .value = "command" },
                {}
            },
            .handler = handle_option_q,
            .description = "Execute guest programs through QEMU user-mode.",
            .detail = "\tFor cross-architecture execution, emulates guest CPU."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-w", .separator = ' ', .value = "path" },
                { .name = "--pwd", .separator = '=', .value = "path" },
                { .name = "--cwd", .separator = '=', .value = "path" },
                {}
            },
            .handler = handle_option_w,
            .description = "Set initial working directory to *path*."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "--kill-on-exit", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_kill_on_exit,
            .description = "Kill all processes on command exit."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-v", .separator = ' ', .value = "value" },
                { .name = "--verbose", .separator = '=', .value = "value" },
                {}
            },
            .handler = handle_option_v,
            .description = "Set verbosity level to *value*."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-V", .separator = '\0', .value = NULL },
                { .name = "--version", .separator = '\0', .value = NULL },
                { .name = "--about", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_V,
            .description = "Print version, copyright, license and contact, then exit."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-h", .separator = '\0', .value = NULL },
                { .name = "--help", .separator = '\0', .value = NULL },
                { .name = "--usage", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_h,
            .description = "Print usage and help, then exit."
        },

        /* --- Extension options --- */
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-k", .separator = ' ', .value = "string" },
                { .name = "--kernel-release", .separator = '=', .value = "string" },
                {}
            },
            .handler = handle_option_k,
            .description = "Fake kernel release string."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-0", .separator = '\0', .value = NULL },
                { .name = "--root-id", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_0,
            .description = "Appear as root (uid/gid 0)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-i", .separator = ' ', .value = "string" },
                { .name = "--change-id", .separator = '=', .value = "string" },
                {}
            },
            .handler = handle_option_i,
            .description = "Fake uid:gid as \"uid:gid\"."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--link2symlink", .separator = '\0', .value = NULL },
                { .name = "-l", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_link2symlink,
            .description = "Replace hard links with symlinks for SELinux compatibility."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--sysvipc", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_sysvipc,
            .description = "Handle System V IPC syscalls."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--ashmem-memfd", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_ashmem_memfd,
            .description = "Emulate memfd over ashmem."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-H", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_H,
            .description = "Hide .proot.* files/dirs."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-p", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_p,
            .description = "Redirect protected ports to higher range."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-L", .separator = '\0', .value = NULL },
                {}
            },
            .handler = handle_option_L,
            .description = "Fix lstat() size for symlinks."
        },

        /* --- Alias options --- */
        {
            .class = "Alias options",
            .arguments = {
                { .name = "-R", .separator = ' ', .value = "path" },
                {}
            },
            .handler = handle_option_R,
            .description = "-r path + recommended bindings."
        },
        {
            .class = "Alias options",
            .arguments = {
                { .name = "-S", .separator = ' ', .value = "path" },
                {}
            },
            .handler = handle_option_S,
            .description = "-0 -r path + minimal safe bindings."
        },

        END_OF_OPTIONS
    }
};

#endif
