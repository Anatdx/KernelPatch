/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026. All Rights Reserved.
 */

#include <ktypes.h>
#include <kputils.h>
#include <uapi/scdefs.h>
#include <predata.h>
#include <syscall.h>
#include <hook.h>
#include <accctl.h>
#include <log.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/ptrace.h>
#include <asm/current.h>

#define FSAPI_CMD_PATH "/system/bin/kpfs"
#define FSAPI_TRUE_PATH "/system/bin/true"
#define FSAPI_FALSE_PATH "/system/bin/false"
#define FSAPI_DST_PREFIX "/data/adb/"
#define FSAPI_DST_PREFIX_LEN (sizeof(FSAPI_DST_PREFIX) - 1)

#define FSAPI_PATH_LEN 512
#define FSAPI_ARG_LEN 1024
#define FSAPI_COPY_MAX_LEN (2 * 1024 * 1024)

struct fsapi_copy_args
{
    const char *src;
    const char *dst;
    umode_t mode;
};

struct fsapi_write_args
{
    const char *dst;
    const char *data;
    umode_t mode;
};

static inline bool fsapi_allowed_dst(const char *path)
{
    if (!path) return false;
    if (strncmp(path, FSAPI_DST_PREFIX, FSAPI_DST_PREFIX_LEN)) return false;
    if (!path[FSAPI_DST_PREFIX_LEN]) return false;

    const char *seg = path + FSAPI_DST_PREFIX_LEN;
    while (*seg) {
        while (*seg == '/') seg++;
        if (!*seg) break;

        const char *end = seg;
        while (*end && *end != '/') end++;
        int seg_len = (int)(end - seg);

        if ((seg_len == 1 && seg[0] == '.') || (seg_len == 2 && seg[0] == '.' && seg[1] == '.')) {
            return false;
        }

        seg = end;
    }

    return true;
}

static char __user *fsapi_str_to_user_sp(const char *data, uintptr_t *sp)
{
    int len = strlen(data) + 1;
    *sp -= len;
    *sp &= 0xFFFFFFFFFFFFFFF8;
    int cplen = compat_copy_to_user((void *)*sp, data, len);
    if (cplen > 0) return (char __user *)*sp;
    return 0;
}

static void fsapi_exec_result(int is_compat, char **__user u_filename_p, char **__user uargv, bool ok)
{
    uintptr_t sp = current_user_stack_pointer();
    const char *cmd = ok ? FSAPI_TRUE_PATH : FSAPI_FALSE_PATH;
    char __user *ucmd = fsapi_str_to_user_sp(cmd, &sp);
    if (!ucmd || IS_ERR(ucmd)) return;
    *u_filename_p = ucmd;
    set_user_arg_ptr((void *)(uintptr_t)is_compat, *uargv, 0, (uintptr_t)ucmd);
    set_user_arg_ptr((void *)(uintptr_t)is_compat, *uargv, 1, 0);
}

static int fsapi_write_file(const char *path, const void *data, size_t len, umode_t mode)
{
    if (!path || !data) return -EINVAL;

    int flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    struct file *fp = filp_open(path, flags, mode);
    if (!fp || IS_ERR(fp)) return PTR_ERR(fp);

    loff_t off = 0;
    ssize_t wlen = kernel_write(fp, data, len, &off);
    filp_close(fp, 0);
    if (wlen < 0) return (int)wlen;
    if ((size_t)wlen != len) return -EIO;
    if (off != len) return -EIO;
    return 0;
}

static int fsapi_copy_file(const char *src, const char *dst, umode_t mode)
{
    if (!src || !dst) return -EINVAL;

    int src_flags = O_RDONLY;
#ifdef O_NOFOLLOW
    src_flags |= O_NOFOLLOW;
#endif
    struct file *in = filp_open(src, src_flags, 0);
    if (!in || IS_ERR(in)) return PTR_ERR(in);

    loff_t len = vfs_llseek(in, 0, SEEK_END);
    if (len < 0) {
        filp_close(in, 0);
        return (int)len;
    }
    if (len > FSAPI_COPY_MAX_LEN) {
        filp_close(in, 0);
        return -EFBIG;
    }
    vfs_llseek(in, 0, SEEK_SET);

    size_t buf_len = len > 0 ? len : 1;
    void *buf = vmalloc(buf_len);
    if (!buf) {
        filp_close(in, 0);
        return -ENOMEM;
    }

    loff_t pos = 0;
    ssize_t rlen = kernel_read(in, buf, len, &pos);
    filp_close(in, 0);
    if (rlen < 0) {
        kvfree(buf);
        return (int)rlen;
    }
    if (rlen != len) {
        kvfree(buf);
        return -EIO;
    }

    int rc = fsapi_write_file(dst, buf, len, mode);
    kvfree(buf);
    return rc;
}

static int fsapi_do_copy(void *udata)
{
    struct fsapi_copy_args *arg = (struct fsapi_copy_args *)udata;
    return fsapi_copy_file(arg->src, arg->dst, arg->mode);
}

static int fsapi_do_write(void *udata)
{
    struct fsapi_write_args *arg = (struct fsapi_write_args *)udata;
    return fsapi_write_file(arg->dst, arg->data, strlen(arg->data), arg->mode);
}

static int fsapi_run_as_kernel(int (*fn)(void *), void *udata)
{
    if (!kfunc(prepare_kernel_cred) || !kfunc(override_creds) || !kfunc(revert_creds)) {
        return -ENOSYS;
    }

    struct cred *kcred = kfunc(prepare_kernel_cred)(0);
    if (!kcred || IS_ERR(kcred)) return PTR_ERR(kcred);

    const struct cred *old = kfunc(override_creds)(kcred);
    set_priv_sel_allow(current, true);
    int rc = fn(udata);
    set_priv_sel_allow(current, false);
    kfunc(revert_creds)(old);
    return rc;
}

static int fsapi_parse_mode(const char *text, umode_t *mode)
{
    if (!text || !text[0]) return 0;
    unsigned long long val = 0;
    if (kstrtoull(text, 8, &val)) return -EINVAL;
    *mode = (umode_t)(val & 0777);
    return 0;
}

static const char *fsapi_dup_arg(int is_compat, char **__user uargv, int index, int max_len)
{
    const char __user *ua = get_user_arg_ptr((void *)(uintptr_t)is_compat, *uargv, index);
    if (!ua || IS_ERR(ua)) return 0;
    const char *arg = strndup_user(ua, max_len);
    if (IS_ERR(arg)) return 0;
    return arg;
}

static int fsapi_handle(char **__user u_filename_p, char **__user uargv, int is_compat)
{
    if (!kp_feature_enabled(KP_FEATURE_FS_API)) return 0;

    char filename[FSAPI_PATH_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return 0;
    if (strcmp(filename, FSAPI_CMD_PATH)) return 0;

    int rc = -EINVAL;
    bool matched = true;
    const char *cmd = 0;
    const char *arg1 = 0;
    const char *arg2 = 0;
    const char *arg3 = 0;
    char key[SUPER_KEY_LEN];
    key[0] = '\0';

    const char __user *ukey = get_user_arg_ptr((void *)(uintptr_t)is_compat, *uargv, 1);
    if (!ukey || IS_ERR(ukey)) goto out;
    if (compat_strncpy_from_user(key, ukey, sizeof(key)) <= 0) goto out;
    if (auth_superkey(key)) {
        rc = -EACCES;
        goto out;
    }

    cmd = fsapi_dup_arg(is_compat, uargv, 2, 64);
    if (!cmd) goto out;

    umode_t mode = 0600;
    if (!strcmp(cmd, "copy")) {
        arg1 = fsapi_dup_arg(is_compat, uargv, 3, FSAPI_PATH_LEN);
        arg2 = fsapi_dup_arg(is_compat, uargv, 4, FSAPI_PATH_LEN);
        arg3 = fsapi_dup_arg(is_compat, uargv, 5, 16);
        if (!arg1 || !arg2 || !fsapi_allowed_dst(arg2)) {
            rc = -EPERM;
            goto out;
        }
        rc = fsapi_parse_mode(arg3, &mode);
        if (rc) goto out;

        struct fsapi_copy_args cargs = { arg1, arg2, mode };
        rc = fsapi_run_as_kernel(fsapi_do_copy, &cargs);
    } else if (!strcmp(cmd, "write")) {
        arg1 = fsapi_dup_arg(is_compat, uargv, 3, FSAPI_PATH_LEN);
        arg2 = fsapi_dup_arg(is_compat, uargv, 4, FSAPI_ARG_LEN);
        arg3 = fsapi_dup_arg(is_compat, uargv, 5, 16);
        if (!arg1 || !arg2 || !fsapi_allowed_dst(arg1)) {
            rc = -EPERM;
            goto out;
        }
        rc = fsapi_parse_mode(arg3, &mode);
        if (rc) goto out;

        struct fsapi_write_args wargs = { arg1, arg2, mode };
        rc = fsapi_run_as_kernel(fsapi_do_write, &wargs);
    } else {
        rc = -ENOSYS;
    }

out:
    if (cmd) kfree((void *)cmd);
    if (arg1) kfree((void *)arg1);
    if (arg2) kfree((void *)arg2);
    if (arg3) kfree((void *)arg3);

    fsapi_exec_result(is_compat, u_filename_p, uargv, rc == 0);
    if (rc) {
        log_boot("fsapi cmd failed: rc=%d\n", rc);
    }

    return matched;
}

static void fsapi_before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    fsapi_handle((char **)arg0p, (char **)arg1p, (int)(uintptr_t)udata);
}

static void fsapi_before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    fsapi_handle((char **)arg1p, (char **)arg2p, (int)(uintptr_t)udata);
}

int fsapi_install()
{
    hook_err_t rc = 0;

    rc = hook_syscalln(__NR_execve, 3, fsapi_before_execve, 0, (void *)0);
    log_boot("hook fsapi __NR_execve rc: %d\n", rc);
    if (rc) return rc;

    rc = hook_syscalln(__NR_execveat, 5, fsapi_before_execveat, 0, (void *)0);
    log_boot("hook fsapi __NR_execveat rc: %d\n", rc);
    if (rc) return rc;

    rc = hook_compat_syscalln(11, 3, fsapi_before_execve, 0, (void *)1);
    log_boot("hook fsapi 32 __NR_execve rc: %d\n", rc);

    return rc;
}

int fsapi_uninstall()
{
    unhook_syscalln(__NR_execve, fsapi_before_execve, 0);
    unhook_syscalln(__NR_execveat, fsapi_before_execveat, 0);
    unhook_compat_syscalln(11, fsapi_before_execve, 0);
    log_boot("unhook fsapi execve/execveat done\n");
    return 0;
}
