/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026. All Rights Reserved.
 */

#include <predata.h>
#include <policy.h>
#include <log.h>
#include <uapi/asm-generic/errno.h>

int task_observer();
int task_observer_deinit();
int bypass_kcfi();
int bypass_kcfi_deinit();
int bypass_selinux();
int bypass_selinux_deinit();
int supercall_install();
int supercall_uninstall();
int fsapi_install();
int fsapi_uninstall();
int kstorage_init();
int su_compat_init();
int su_compat_deinit();

#ifdef ANDROID
int android_user_init();
int android_user_deinit();
int android_sepolicy_flags_fix();
int android_sepolicy_flags_unfix();
#endif

static uint32_t runtime_ready_flags = 0;

void kp_policy_mark_component_ready(uint32_t feature, bool ready)
{
    if (!feature) return;
    if (ready) {
        runtime_ready_flags |= feature;
    } else {
        runtime_ready_flags &= ~feature;
    }
}

static int policy_ensure_feature(uint32_t target_flags, uint32_t feature, int (*install_fn)(), const char *name)
{
    if (!(target_flags & feature)) return 0;
    if (runtime_ready_flags & feature) return 0;

    int rc = install_fn();
    log_boot("policy ensure %s rc: %d\n", name, rc);
    if (rc) return rc;

    runtime_ready_flags |= feature;
    return 0;
}

static int policy_disable_feature(uint32_t old_flags, uint32_t target_flags, uint32_t feature, int (*deinit_fn)(),
                                  const char *name)
{
    if (!(old_flags & feature)) return 0;
    if (target_flags & feature) return 0;
    if (!(runtime_ready_flags & feature)) return 0;

    int rc = 0;
    if (deinit_fn) {
        rc = deinit_fn();
    }
    log_boot("policy disable %s rc: %d\n", name, rc);
    if (rc) return rc;

    runtime_ready_flags &= ~feature;
    return 0;
}

static int kp_policy_ensure_runtime(uint32_t target_flags)
{
    int rc = 0;

    rc = policy_ensure_feature(target_flags, KP_FEATURE_KCFI_BYPASS, bypass_kcfi, "kcfi_bypass");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_SUPERCALL, supercall_install, "supercall");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_FS_API, fsapi_install, "fs_api");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_KSTORAGE, kstorage_init, "kstorage");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_TASK_OBSERVER, task_observer, "task_observer");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_SELINUX_BYPASS, bypass_selinux, "selinux_bypass");
    if (rc) return rc;
    rc = policy_ensure_feature(target_flags, KP_FEATURE_SU_COMPAT, su_compat_init, "su_compat");
    if (rc) return rc;

#ifdef ANDROID
    if (target_flags & KP_FEATURE_SU) {
        rc = policy_ensure_feature(target_flags, KP_FEATURE_SU, android_sepolicy_flags_fix, "android_sepolicy_fix");
        if (rc) return rc;
    }
    rc = policy_ensure_feature(target_flags, KP_FEATURE_ANDROID_USER, android_user_init, "android_user");
    if (rc) return rc;
#endif

    return 0;
}

static int kp_policy_disable_runtime(uint32_t old_flags, uint32_t target_flags)
{
    int rc = 0;

#ifdef ANDROID
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_ANDROID_USER, android_user_deinit, "android_user");
    if (rc) return rc;
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_SU, android_sepolicy_flags_unfix,
                                "android_sepolicy_fix");
    if (rc) return rc;
#endif

    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_SU_COMPAT, su_compat_deinit, "su_compat");
    if (rc) return rc;
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_SELINUX_BYPASS, bypass_selinux_deinit,
                                "selinux_bypass");
    if (rc) return rc;
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_TASK_OBSERVER, task_observer_deinit,
                                "task_observer");
    if (rc) return rc;
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_FS_API, fsapi_uninstall, "fs_api");
    if (rc) return rc;
    rc = policy_disable_feature(old_flags, target_flags, KP_FEATURE_KCFI_BYPASS, bypass_kcfi_deinit, "kcfi_bypass");
    if (rc) return rc;

    // Keep supercall/kstorage installed to preserve control plane and state.
    return 0;
}

int kp_policy_apply_flags(uint32_t requested_flags)
{
    uint32_t old_flags = kp_feature_flags;
    uint32_t new_flags = kp_normalize_feature_flags(requested_flags);

    kp_apply_feature_flags(new_flags);

    int rc = kp_policy_ensure_runtime(new_flags);
    if (rc) {
        log_boot("policy apply partial rc=%d old=0x%x now=0x%x\n", rc, old_flags, kp_feature_flags);
        return rc;
    }

    rc = kp_policy_disable_runtime(old_flags, new_flags);
    if (rc) {
        log_boot("policy disable partial rc=%d old=0x%x now=0x%x\n", rc, old_flags, kp_feature_flags);
        return rc;
    }

    log_boot("policy apply flags old=0x%x new=0x%x\n", old_flags, kp_feature_flags);
    return 0;
}

int kp_policy_apply_profile(int profile)
{
    uint32_t flags = kp_policy_profile_flags(profile);
    if (!flags) return -EINVAL;
    return kp_policy_apply_flags(flags);
}
