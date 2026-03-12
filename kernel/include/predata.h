/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PREDATA_H_
#define _KP_PREDATA_H_

#include <ktypes.h>
#include <preset.h>

extern struct patch_config *patch_config;
extern setup_header_t *setup_header;

#define KP_FEATURE_KCFI_BYPASS (1u << 0)
#define KP_FEATURE_TASK_OBSERVER (1u << 1)
#define KP_FEATURE_SELINUX_BYPASS (1u << 2)
#define KP_FEATURE_SUPERCALL (1u << 3)
#define KP_FEATURE_KSTORAGE (1u << 4)
#define KP_FEATURE_SU (1u << 5)
#define KP_FEATURE_SU_COMPAT (1u << 6)
#define KP_FEATURE_ANDROID_USER (1u << 7)

extern uint32_t kp_feature_flags;

static inline bool kp_feature_enabled(uint32_t feature)
{
    return !!(kp_feature_flags & feature);
}

static inline bool kp_su_mode_enabled()
{
    return kp_feature_enabled(KP_FEATURE_SU);
}

int auth_superkey(const char *key);
void reset_superkey(const char *key);
void enable_auth_root_key(bool enable);
const char *get_superkey();
const char *get_build_time();
uint64_t rand_next();

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *data, void *udata),
                       void *udata);

void predata_init();

#endif
