# KernelPatch Policy Matrix (v1)

| Profile | Stage1 Hooks (early boot) | Stage2 Install Set (before_rest_init) | Hot Policy Scope | Notes |
|---|---|---|---|---|
| minimal | rest_init/cgroup_init | hotpatch_init, kcfi_bypass, resolve_struct, supercall, kstorage, resolve_pt_regs | feature flags only | Default baseline. No SU chain. kernel_init hook off. panic hook off by default; enable in debug with `hook.panic=1`. |
| rootful | rest_init/cgroup_init | minimal + task_observer, selinux_bypass, su_compat, android_sepolicy_flags_fix, android_user | feature flags only | Full root capability on top of minimal path. |
| kpm-support | rest_init/cgroup_init + kernel_init | minimal + KPM pre/post-kernel-init event pipeline | feature flags only | Use when KPM requires `pre-kernel-init` / `post-kernel-init` events. |
| full | rest_init/cgroup_init + kernel_init (+ panic optional) | rootful + fsapi | feature flags only | Experimental/high-risk profile; keep fsapi opt-in. |

## Current Implementation Rules
- Default profile is `minimal`.
- Stage1 hook install is controlled by `kp_stage1_hook_flags`.
- `panic` hook is not mandatory for function; enable during debug runs.
- Hot policy (`policy_apply_*`) changes feature set only; it does not rewire stage1 anchor hooks in-place.
