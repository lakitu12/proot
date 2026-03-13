#include <unistd.h>      /* get*id(2),  */
#include <sys/socket.h>  /* cmsghdr, */
#include <sys/types.h>   /* uid_t, gid_t, get*id(2), */
#include <linux/net.h>   /* SYS_SENDMSG, */

#include "cli/note.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "extension/fake_id0/sendmsg.h"

#define MAX_CONTROLLEN 1024

static void sendmsg_unpack_control_and_len(const Tracee *tracee, const struct msghdr *msghdr,
                                           word_t *out_control, size_t *out_controllen)
{
    if (is_32on64_mode(tracee)) {
        const char *raw = (const char *)msghdr;
        *out_control    = *(const uint32_t *)&raw[16];
        *out_controllen = *(const uint32_t *)&raw[20];
    } else {
        *out_control    = (word_t)msghdr->msg_control;
        *out_controllen = msghdr->msg_controllen;
    }
}

static void sendmsg_pack_control(const Tracee *tracee, struct msghdr *msghdr, word_t control)
{
    if (is_32on64_mode(tracee)) {
        char *raw = (char *)msghdr;
        *(uint32_t *)&raw[16] = (uint32_t)control;
    } else {
        msghdr->msg_control = (void *)control;
    }
}

static void sendmsg_unpack_cmsghdr(const Tracee *tracee, const struct cmsghdr *cmsghdr,
                                   size_t *out_len, int *out_level, int *out_type)
{
    if (is_32on64_mode(tracee)) {
        const uint32_t *p = (const uint32_t *)cmsghdr;
        *out_len   = p[0];
        *out_level = p[1];
        *out_type  = p[2];
    } else {
        *out_len   = cmsghdr->cmsg_len;
        *out_level = cmsghdr->cmsg_level;
        *out_type  = cmsghdr->cmsg_type;
    }
}

int handle_sendmsg_enter_end(Tracee *tracee, word_t sysnum)
{
    int status;
    unsigned long socketcall_args[3];
    struct msghdr msg = { 0 };
    const bool is_socketcall = (sysnum == PR_socketcall);

    size_t sizeof_msghdr  = sizeof(struct msghdr);
    size_t sizeof_cmsghdr = sizeof(struct cmsghdr);
    size_t align_mask     = sizeof(long) - 1;

    // AArch32 on ARM64 兼容布局
    if (is_32on64_mode(tracee)) {
        sizeof_msghdr  = 28;
        sizeof_cmsghdr = 12;
        align_mask     = 4 - 1;
    }

    if (!is_socketcall) {
        status = read_data(tracee, &msg, peek_reg(tracee, CURRENT, SYSARG_2), sizeof_msghdr);
        if (status < 0)
            return status;
    } else {
        const word_t call = peek_reg(tracee, CURRENT, SYSARG_1);
        if (call != SYS_SENDMSG)
            return 0;

        status = read_data(tracee, socketcall_args, peek_reg(tracee, CURRENT, SYSARG_2),
                           sizeof(socketcall_args));
        if (status < 0)
            return status;

        status = read_data(tracee, &msg, socketcall_args[1], sizeof_msghdr);
        if (status < 0)
            return status;
    }

    size_t msg_controllen;
    word_t msg_control;
    sendmsg_unpack_control_and_len(tracee, &msg, &msg_control, &msg_controllen);

    if (msg_control == 0 || msg_controllen == 0)
        return 0;
    if (msg_controllen > MAX_CONTROLLEN) {
        VERBOSE(tracee, 1, "sendmsg: msg_controllen=%zu too big", msg_controllen);
        return 0;
    }

    char cmsg_buf[msg_controllen];
    status = read_data(tracee, cmsg_buf, msg_control, msg_controllen);
    if (status < 0)
        return status;

    bool modified = false;
    size_t pos = 0;
    while (pos < msg_controllen) {
        if (msg_controllen - pos < sizeof_cmsghdr)
            return 0;

        size_t cmsg_len;
        int cmsg_level, cmsg_type;
        sendmsg_unpack_cmsghdr(tracee, (const struct cmsghdr *)&cmsg_buf[pos],
                               &cmsg_len, &cmsg_level, &cmsg_type);

        if (cmsg_len < sizeof_cmsghdr || cmsg_len > msg_controllen - pos)
            return 0;

        if (cmsg_level == SOL_SOCKET && cmsg_type == SCM_CREDENTIALS) {
            if (cmsg_len != sizeof_cmsghdr + sizeof(struct ucred))
                return 0;

            struct ucred *ucred = (struct ucred *)(cmsg_buf + pos + sizeof_cmsghdr);
            ucred->uid = getuid();
            ucred->gid = getgid();
            modified = true;
        }

        // CMSG_NXTHDR
        pos += (cmsg_len + align_mask) & ~align_mask;
    }

    if (!modified)
        return 0;

    // 重写控制数据
    msg_control = alloc_mem(tracee, msg_controllen);
    if (msg_control == 0)
        return -ENOMEM;
    status = write_data(tracee, msg_control, cmsg_buf, msg_controllen);
    if (status < 0)
        return -ENOMEM;

    // 重写 msghdr
    const word_t hdr_addr = alloc_mem(tracee, sizeof_msghdr);
    if (hdr_addr == 0)
        return -ENOMEM;
    sendmsg_pack_control(tracee, &msg, msg_control);
    status = write_data(tracee, hdr_addr, &msg, sizeof_msghdr);
    if (status < 0)
        return -ENOMEM;

    // 回写寄存器
    if (!is_socketcall) {
        poke_reg(tracee, SYSARG_2, hdr_addr);
    } else {
        socketcall_args[1] = hdr_addr;
        status = set_sysarg_data(tracee, socketcall_args, sizeof(socketcall_args), SYSARG_2);
        if (status < 0)
            return status;
    }

    return 0;
}
