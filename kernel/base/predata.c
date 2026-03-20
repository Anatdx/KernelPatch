/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <common.h>
#include <log.h>
#include <predata.h>
#include <sha256.h>
#include <symbol.h>

#include "baselib.h"
#include "pgtable.h"
#include "start.h"

extern start_preset_t start_preset;

static char *superkey = 0;
static char *root_superkey = 0;

struct patch_config *patch_config = 0;
KP_EXPORT_SYMBOL(patch_config);

uint32_t kp_feature_flags = 0;
KP_EXPORT_SYMBOL(kp_feature_flags);

static const char bstr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static uint64_t _rand_next = 1000000007;
static bool enable_root_key = false;

#define FEATURE_PROFILE_MINIMAL (KP_FEATURE_KCFI_BYPASS | KP_FEATURE_SUPERCALL | KP_FEATURE_KSTORAGE)
#define FEATURE_PROFILE_ROOTFUL                                                                       \
    (FEATURE_PROFILE_MINIMAL | KP_FEATURE_TASK_OBSERVER | KP_FEATURE_SELINUX_BYPASS | KP_FEATURE_SU | \
     KP_FEATURE_SU_COMPAT | KP_FEATURE_ANDROID_USER)
#define FEATURE_PROFILE_KPM_SUPPORT (FEATURE_PROFILE_MINIMAL)
#define FEATURE_PROFILE_FULL (FEATURE_PROFILE_ROOTFUL | KP_FEATURE_FS_API)

static void set_feature_flag(uint32_t feature, bool enable)
{
    if (enable) {
        kp_feature_flags |= feature;
    } else {
        kp_feature_flags &= ~feature;
    }
}

static void apply_mode_no_su()
{
    kp_feature_flags &= ~(KP_FEATURE_SU | KP_FEATURE_SU_COMPAT | KP_FEATURE_ANDROID_USER);
    kp_feature_flags &= ~(KP_FEATURE_TASK_OBSERVER | KP_FEATURE_SELINUX_BYPASS);
}

static int parse_bool_text(const char *value, bool *out)
{
    if (!value || !value[0]) return -1;
    if (!lib_strcasecmp(value, "1") || !lib_strcasecmp(value, "y") || !lib_strcasecmp(value, "yes") ||
        !lib_strcasecmp(value, "on") || !lib_strcasecmp(value, "true") || !lib_strcasecmp(value, "enable") ||
        !lib_strcasecmp(value, "enabled")) {
        *out = true;
        return 0;
    }

    if (!lib_strcasecmp(value, "0") || !lib_strcasecmp(value, "n") || !lib_strcasecmp(value, "no") ||
        !lib_strcasecmp(value, "off") || !lib_strcasecmp(value, "false") || !lib_strcasecmp(value, "disable") ||
        !lib_strcasecmp(value, "disabled")) {
        *out = false;
        return 0;
    }

    return -1;
}

static uint32_t feature_from_name(const char *name)
{
    if (!name || !name[0]) return 0;
    if (!lib_strcmp(name, "kcfi") || !lib_strcmp(name, "kcfi_bypass")) return KP_FEATURE_KCFI_BYPASS;
    if (!lib_strcmp(name, "task") || !lib_strcmp(name, "task_observer")) return KP_FEATURE_TASK_OBSERVER;
    if (!lib_strcmp(name, "selinux") || !lib_strcmp(name, "selinux_bypass")) return KP_FEATURE_SELINUX_BYPASS;
    if (!lib_strcmp(name, "supercall")) return KP_FEATURE_SUPERCALL;
    if (!lib_strcmp(name, "kstorage")) return KP_FEATURE_KSTORAGE;
    if (!lib_strcmp(name, "fsapi") || !lib_strcmp(name, "fs_api")) return KP_FEATURE_FS_API;
    if (!lib_strcmp(name, "su")) return KP_FEATURE_SU;
    if (!lib_strcmp(name, "su_compat")) return KP_FEATURE_SU_COMPAT;
    if (!lib_strcmp(name, "android_user")) return KP_FEATURE_ANDROID_USER;
    return 0;
}

uint32_t kp_policy_profile_flags(int profile)
{
    switch (profile) {
    case KP_POLICY_PROFILE_MINIMAL:
        return FEATURE_PROFILE_MINIMAL;
    case KP_POLICY_PROFILE_ROOTFUL:
        return FEATURE_PROFILE_ROOTFUL;
    case KP_POLICY_PROFILE_KPM_SUPPORT:
        return FEATURE_PROFILE_KPM_SUPPORT;
    case KP_POLICY_PROFILE_FULL:
        return FEATURE_PROFILE_FULL;
    default:
        return 0;
    }
}
KP_EXPORT_SYMBOL(kp_policy_profile_flags);

static void apply_feature_profile(const char *profile)
{
    if (!profile || !profile[0]) return;
    if (!lib_strcasecmp(profile, "minimal")) {
        kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_MINIMAL);
        return;
    }

    if (!lib_strcasecmp(profile, "rootful") || !lib_strcasecmp(profile, "legacy")) {
        kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_ROOTFUL);
        return;
    }

    if (!lib_strcasecmp(profile, "kpm") || !lib_strcasecmp(profile, "kpm-support") ||
        !lib_strcasecmp(profile, "kpm_support")) {
        kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_KPM_SUPPORT);
        return;
    }

    if (!lib_strcasecmp(profile, "full")) {
        kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_FULL);
        return;
    }

    if (!lib_strcasecmp(profile, "no-su") || !lib_strcasecmp(profile, "nosu")) {
        kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_MINIMAL);
        apply_mode_no_su();
        return;
    }

    log_boot("unknown feature profile: %s\n", profile);
}

static void apply_additional_kv(const char *key, const char *value)
{
    if (!lib_strcmp(key, "policy")) {
        if (!lib_strcasecmp(value, "no-su")) {
            apply_mode_no_su();
            return;
        }
        apply_feature_profile(value);
        return;
    }

    if (!lib_strcmp(key, "mode")) {
        if (!lib_strcasecmp(value, "no-su")) {
            apply_mode_no_su();
            return;
        }
        apply_feature_profile(value);
        return;
    }

    if (!lib_strcmp(key, "profile") || !lib_strcmp(key, "hook.profile")) {
        apply_feature_profile(value);
        return;
    }

    if (!lib_strcmp(key, "no_su")) {
        bool enabled = false;
        if (!parse_bool_text(value, &enabled) && enabled) {
            apply_mode_no_su();
            return;
        }
    }

    if (!lib_strcmp(key, "hook.panic") || !lib_strcmp(key, "hook.init") || !lib_strcmp(key, "hook.kernel_init") ||
        !lib_strcmp(key, "hook.kpm_event")) {
        log_boot("ignore stage1 additional: %s=%s\n", key, value);
        return;
    }

    if (!lib_strncmp(key, "feature.", 8)) {
        const char *feature_name = key + 8;
        uint32_t feature = feature_from_name(feature_name);
        bool enabled = false;
        if (!feature || parse_bool_text(value, &enabled)) {
            log_boot("ignore additional: %s=%s\n", key, value);
            return;
        }
        set_feature_flag(feature, enabled);
        return;
    }

    log_boot("unknown additional: %s=%s\n", key, value);
}

static bool read_policy_slot(kp_policy_slot_t *slot)
{
    lib_memcpy(slot, start_preset.additional, sizeof(*slot));
    return slot->magic == KP_POLICY_SLOT_MAGIC;
}

static int policy_text_offset(const kp_policy_slot_t *slot, bool has_slot)
{
    if (!has_slot) return 0;
    if (slot->size >= KP_POLICY_SLOT_SIZE && slot->size <= ADDITIONAL_LEN) {
        return slot->size;
    }
    return KP_ADDITIONAL_TEXT_OFFSET;
}

static void apply_policy_slot(const kp_policy_slot_t *slot, bool has_slot)
{
    if (!has_slot) return;

    if (slot->version != KP_POLICY_SLOT_VERSION) {
        log_boot("ignore policy slot version=%u size=%u\n", slot->version, slot->size);
        return;
    }

    uint32_t flags = 0;
    if (slot->profile <= KP_POLICY_PROFILE_FULL) {
        flags = kp_policy_profile_flags((int)slot->profile);
    }
    if (slot->feature_flags) {
        flags = slot->feature_flags;
    }
    if (!flags) {
        log_boot("ignore empty policy slot profile=%u flags=0x%x\n", slot->profile, slot->feature_flags);
        return;
    }

    kp_feature_flags = flags;
    log_boot("policy slot profile=%u flags=0x%x size=%u\n", slot->profile, slot->feature_flags, slot->size);
}

static void parse_additional(int start_offset)
{
    const char *addition = start_preset.additional;
    const char *pos = addition + start_offset;
    const char *end = addition + ADDITIONAL_LEN;

    while (pos < end) {
        int len = (uint8_t)(*pos);
        if (!len) break;
        pos++;
        if (pos + len > end) {
            log_boot("broken additional item, len=%d\n", len);
            break;
        }

        char kv[128];
        int kvlen = len < (int)sizeof(kv) - 1 ? len : (int)sizeof(kv) - 1;
        lib_memcpy(kv, pos, kvlen);
        kv[kvlen] = '\0';

        char *eq = lib_strchr(kv, '=');
        if (eq && eq != kv && eq[1]) {
            *eq = '\0';
            apply_additional_kv(kv, eq + 1);
        } else {
            log_boot("ignore malformed additional: %s\n", kv);
        }
        pos += len;
    }
}

uint32_t kp_normalize_feature_flags(uint32_t flags)
{
    if (flags & (KP_FEATURE_SU_COMPAT | KP_FEATURE_ANDROID_USER)) {
        flags |= KP_FEATURE_SU;
    }

    if (flags & KP_FEATURE_ANDROID_USER) {
        flags |= KP_FEATURE_SU_COMPAT;
    }

    if (flags & KP_FEATURE_SU) {
        flags |= KP_FEATURE_SUPERCALL;
        flags |= KP_FEATURE_KSTORAGE;
    }

    if (!(flags & KP_FEATURE_SUPERCALL)) {
        flags &= ~(KP_FEATURE_SU | KP_FEATURE_SU_COMPAT | KP_FEATURE_ANDROID_USER);
    }

    return flags;
}
KP_EXPORT_SYMBOL(kp_normalize_feature_flags);

void kp_apply_feature_flags(uint32_t flags)
{
    kp_feature_flags = kp_normalize_feature_flags(flags);
    dsb(ish);
}
KP_EXPORT_SYMBOL(kp_apply_feature_flags);

int auth_superkey(const char *key)
{
    int rc = 0;
    for (int i = 0; superkey[i]; i++) {
        rc |= (superkey[i] ^ key[i]);
    }
    if (!rc) goto out;

    if (!enable_root_key) goto out;

    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)key, lib_strnlen(key, SUPER_KEY_LEN));
    sha256_final(&ctx, hash);
    int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
    rc = lib_memcmp(root_superkey, hash, len);

    static bool first_time = true;
    if (!rc && first_time) {
        first_time = false;
        reset_superkey(key);
        enable_root_key = false;
    }

out:
    return !!rc;
}

void reset_superkey(const char *key)
{
    lib_strlcpy(superkey, key, SUPER_KEY_LEN);
    dsb(ish);
}

void enable_auth_root_key(bool enable)
{
    enable_root_key = enable;
}

uint64_t rand_next()
{
    _rand_next = 1103515245 * _rand_next + 12345;
    return _rand_next;
}

const char *get_superkey()
{
    return superkey;
}

const char *get_build_time()
{
    return setup_header->compile_time;
}

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *con, void *udata),
                       void *udata)
{
    int rc = 0;
    uint64_t item_addr = _kp_extra_start;
    while (item_addr < _kp_extra_end) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_addr;
        if (item->type == EXTRA_TYPE_NONE) break;
        for (int i = 0; i < sizeof(item->magic); i++) {
            if (item->magic[i] != EXTRA_HDR_MAGIC[i]) break;
        }
        const char *args = item->args_size > 0 ? (const char *)(item_addr + sizeof(patch_extra_item_t)) : 0;
        const void *con = (void *)(item_addr + sizeof(patch_extra_item_t) + item->args_size);
        rc = callback(item, args, con, udata);
        if (rc) break;
        item_addr += sizeof(patch_extra_item_t);
        item_addr += item->args_size;
        item_addr += item->con_size;
    }
    return rc;
}

void predata_init()
{
    kp_policy_slot_t policy_slot = { 0 };
    bool has_policy_slot = false;
    int text_offset = 0;

    superkey = (char *)start_preset.superkey;
    root_superkey = (char *)start_preset.root_superkey;
    char *compile_time = start_preset.header.compile_time;

    _rand_next *= kernel_va;
    _rand_next *= kver;
    _rand_next *= kpver;
    _rand_next *= _kp_region_start;
    _rand_next *= _kp_region_end;
    if (*(uint64_t *)compile_time) _rand_next *= *(uint64_t *)compile_time;
    if (*(uint64_t *)(superkey)) _rand_next *= *(uint64_t *)(superkey);
    if (*(uint64_t *)(root_superkey)) _rand_next *= *(uint64_t *)(root_superkey);

    enable_root_key = false;

    if (lib_strnlen(superkey, SUPER_KEY_LEN) <= 0) {
        enable_root_key = true;
        int len = SUPER_KEY_LEN > 16 ? 16 : SUPER_KEY_LEN;
        len--;
        for (int i = 0; i < len; ++i) {
            uint64_t rand = rand_next() % (sizeof(bstr) - 1);
            superkey[i] = bstr[rand];
        }
    }
    log_boot("gen rand key: %s\n", superkey);

    patch_config = &start_preset.patch_config;

    for (uintptr_t *p = (uintptr_t *)patch_config; (uint8_t *)p < (uint8_t *)&patch_config->patch_su_config; p++) {
        if (*p) *p += kernel_va;
    }

    kp_feature_flags = kp_policy_profile_flags(KP_POLICY_PROFILE_MINIMAL);

    has_policy_slot = read_policy_slot(&policy_slot);
    text_offset = policy_text_offset(&policy_slot, has_policy_slot);
    apply_policy_slot(&policy_slot, has_policy_slot);
    parse_additional(text_offset);
    kp_feature_flags = kp_normalize_feature_flags(kp_feature_flags);

    log_boot("feature flags=0x%x policy_slot=%d text_offset=0x%x su=%d su_compat=%d android_user=%d "
             "selinux_bypass=%d task_observer=%d fs_api=%d\n",
             kp_feature_flags, has_policy_slot, text_offset, kp_feature_enabled(KP_FEATURE_SU),
             kp_feature_enabled(KP_FEATURE_SU_COMPAT), kp_feature_enabled(KP_FEATURE_ANDROID_USER),
             kp_feature_enabled(KP_FEATURE_SELINUX_BYPASS), kp_feature_enabled(KP_FEATURE_TASK_OBSERVER),
             kp_feature_enabled(KP_FEATURE_FS_API));

    dsb(ish);
}
