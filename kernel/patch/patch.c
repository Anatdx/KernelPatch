#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <accctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <syscall.h>
#include <module.h>
#include <predata.h>
#include <policy.h>
#include <linux/string.h>

#define KP_LOCAL_INIT_KCFI_BYPASS (1u << 0)
#define KP_LOCAL_INIT_SELINUX_BYPASS (1u << 1)
#define KP_LOCAL_INIT_TASK_OBSERVER (1u << 2)
#define KP_LOCAL_INIT_SUPERCALL (1u << 3)
#define KP_LOCAL_INIT_FS_API (1u << 4)
#define KP_LOCAL_INIT_KSTORAGE (1u << 5)
#define KP_LOCAL_INIT_SU_COMPAT (1u << 6)
#define KP_LOCAL_INIT_RESOLVE_PT_REGS (1u << 7)
#define KP_LOCAL_INIT_ANDROID_SEPOLICY_FIX (1u << 8)
#define KP_LOCAL_INIT_ANDROID_USER (1u << 9)

static uint32_t kp_local_boot_init_mask(uint32_t flags)
{
    uint32_t mask = KP_LOCAL_INIT_RESOLVE_PT_REGS;

    if (flags & KP_FEATURE_KCFI_BYPASS) mask |= KP_LOCAL_INIT_KCFI_BYPASS;
    if (flags & KP_FEATURE_SELINUX_BYPASS) mask |= KP_LOCAL_INIT_SELINUX_BYPASS;
    if (flags & KP_FEATURE_TASK_OBSERVER) mask |= KP_LOCAL_INIT_TASK_OBSERVER;
    if (flags & KP_FEATURE_SUPERCALL) mask |= KP_LOCAL_INIT_SUPERCALL;
    if (flags & KP_FEATURE_FS_API) mask |= KP_LOCAL_INIT_FS_API;
    if (flags & KP_FEATURE_KSTORAGE) mask |= KP_LOCAL_INIT_KSTORAGE;
    if (flags & KP_FEATURE_SU_COMPAT) mask |= KP_LOCAL_INIT_SU_COMPAT;
#ifdef ANDROID
    if (flags & KP_FEATURE_SU) mask |= KP_LOCAL_INIT_ANDROID_SEPOLICY_FIX;
    if (flags & KP_FEATURE_ANDROID_USER) mask |= KP_LOCAL_INIT_ANDROID_USER;
#endif
    return mask;
}

static inline bool kp_local_init_enabled(uint32_t mask, uint32_t feature)
{
    return !!(mask & feature);
}

void print_bootlog()
{
    const char *log = get_boot_log();
    char buf[1024];
    int off = 0;
    char c;
    for (int i = 0; (c = log[i]); i++) {
        if (c == '\n') {
            buf[off++] = c;
            buf[off] = '\0';

            printk("KP %s", buf);
            off = 0;
        } else {
            buf[off++] = log[i];
        }
    }
}

void before_panic(hook_fargs12_t *args, void *udata)
{
    printk("==== Start KernelPatch for Kernel panic ====\n");
    print_bootlog();
    printk("==== End KernelPatch for Kernel panic ====\n");
}

void linux_misc_symbol_init();
void linux_libs_symbol_init();
void hotpatch_symbol_init();

int resolve_struct();
int task_observer();
int hotpatch_init();
int bypass_kcfi();
int bypass_selinux();
int resolve_pt_regs();
int supercall_install();
int fsapi_install();
void module_init();
void syscall_init();
int kstorage_init();
int su_compat_init();

#ifdef ANDROID
int android_user_init();
int android_sepolicy_flags_fix();
#endif

static void before_rest_init(hook_fargs4_t *args, void *udata)
{
    int rc = 0;
    const uint32_t init_mask = kp_local_boot_init_mask(kp_feature_flags);
    log_boot("entering init ...\n");
    log_boot("local init mask=0x%x feature flags=0x%x\n", init_mask, kp_feature_flags);

    if ((rc = hotpatch_init())) goto out;
    log_boot("hotpatch_init done: %d\n", rc);

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_KCFI_BYPASS)) {
        if ((rc = bypass_kcfi())) {
            kp_policy_mark_component_ready(KP_FEATURE_KCFI_BYPASS, false);
            goto out;
        }
        kp_policy_mark_component_ready(KP_FEATURE_KCFI_BYPASS, true);
        log_boot("bypass_kcfi done: %d\n", rc);
    } else {
        kp_policy_mark_component_ready(KP_FEATURE_KCFI_BYPASS, false);
        log_boot("skip bypass_kcfi\n");
    }

    if ((rc = resolve_struct())) goto out;
    log_boot("resolve_struct done: %d\n", rc);

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_SELINUX_BYPASS)) {
        if ((rc = bypass_selinux())) {
            kp_policy_mark_component_ready(KP_FEATURE_SELINUX_BYPASS, false);
            goto out;
        }
        kp_policy_mark_component_ready(KP_FEATURE_SELINUX_BYPASS, true);
        log_boot("bypass_selinux done: %d\n", rc);
    } else {
        log_boot("skip bypass_selinux\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_TASK_OBSERVER)) {
        if ((rc = task_observer())) {
            kp_policy_mark_component_ready(KP_FEATURE_TASK_OBSERVER, false);
            goto out;
        }
        kp_policy_mark_component_ready(KP_FEATURE_TASK_OBSERVER, true);
        log_boot("task_observer done: %d\n", rc);
    } else {
        log_boot("skip task_observer\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_SUPERCALL)) {
        rc = supercall_install();
        kp_policy_mark_component_ready(KP_FEATURE_SUPERCALL, rc == 0);
        log_boot("supercall_install done: %d\n", rc);
    } else {
        log_boot("skip supercall_install\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_FS_API)) {
        rc = fsapi_install();
        kp_policy_mark_component_ready(KP_FEATURE_FS_API, rc == 0);
        log_boot("fsapi_install done: %d\n", rc);
    } else {
        log_boot("skip fsapi_install\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_KSTORAGE)) {
        rc = kstorage_init();
        kp_policy_mark_component_ready(KP_FEATURE_KSTORAGE, rc == 0);
        log_boot("kstorage_init done: %d\n", rc);
    } else {
        log_boot("skip kstorage_init\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_SU_COMPAT)) {
        rc = su_compat_init();
        kp_policy_mark_component_ready(KP_FEATURE_SU_COMPAT, rc == 0);
        log_boot("su_compat_init done: %d\n", rc);
    } else {
        log_boot("skip su_compat_init\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_RESOLVE_PT_REGS)) {
        rc = resolve_pt_regs();
        log_boot("resolve_pt_regs done: %d\n", rc);
    } else {
        log_boot("skip resolve_pt_regs\n");
    }

#ifdef ANDROID
    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_ANDROID_SEPOLICY_FIX)) {
        rc = android_sepolicy_flags_fix();
        kp_policy_mark_android_sepolicy_fix_ready(rc == 0);
        log_boot("android_sepolicy_flags_fix done: %d\n", rc);
    } else {
        kp_policy_mark_android_sepolicy_fix_ready(false);
        log_boot("skip android_sepolicy_flags_fix\n");
    }

    if (kp_local_init_enabled(init_mask, KP_LOCAL_INIT_ANDROID_USER)) {
        rc = android_user_init();
        kp_policy_mark_component_ready(KP_FEATURE_ANDROID_USER, rc == 0);
        log_boot("android_user_init done: %d\n", rc);
    } else {
        log_boot("skip android_user_init\n");
    }
#endif

out:
    return;
}

static int extra_event_pre_kernel_init(const patch_extra_item_t *extra, const char *args, const void *data, void *udata)
{
    if (extra->type == EXTRA_TYPE_KPM) {
        if (!strcmp(EXTRA_EVENT_PRE_KERNEL_INIT, extra->event) || !extra->event[0]) {
            int rc = load_module(data, extra->con_size, args, EXTRA_EVENT_PRE_KERNEL_INIT, 0);
            log_boot("load kpm: %s, rc: %d\n", extra->name, rc);
        }
    }
    return 0;
}

static void before_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_KERNEL_INIT);
    on_each_extra_item(extra_event_pre_kernel_init, 0);
}

static void after_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_POST_KERNEL_INIT);
}

int patch()
{
    linux_libs_symbol_init();
    linux_misc_symbol_init();
    hotpatch_symbol_init();
    module_init();
    syscall_init();

    hook_err_t rc = 0;

    unsigned long panic_addr = patch_config->panic;
    logkd("panic addr: %llx\n", panic_addr);
#ifdef DEBUG
    if (panic_addr) {
        rc = hook_wrap12((void *)panic_addr, before_panic, 0, 0);
        log_boot("hook panic rc: %d\n", rc);
    }
#else
    log_boot("skip hook panic addr: %llx\n", panic_addr);
#endif
    if (rc) return rc;

    // rest_init or cgroup_init
    unsigned long init_addr = patch_config->rest_init;
    if (!init_addr) init_addr = patch_config->cgroup_init;
    if (init_addr) {
        rc = hook_wrap4((void *)init_addr, before_rest_init, 0, (void *)init_addr);
        log_boot("hook rest_init rc: %d\n", rc);
    } else {
        log_boot("missing rest_init/cgroup_init addr\n");
    }
    if (rc) return rc;

    // kernel_init
    unsigned long kernel_init_addr = patch_config->kernel_init;
    if (kernel_init_addr) {
        rc = hook_wrap4((void *)kernel_init_addr, before_kernel_init, after_kernel_init, 0);
        log_boot("hook kernel_init rc: %d\n", rc);
    } else {
        log_boot("missing kernel_init addr\n");
    }

    return rc;
}
