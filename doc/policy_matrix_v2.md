# KernelPatch Boot Plan Matrix (v2)

This document replaces the "feature closure decides boot behavior" mindset with
"profile resolves to a frozen boot plan before stage1 init starts".

The goal is to keep the modern policy model while making cold boot deterministic:

- `apd` writes the target profile and additions into the image.
- `kpimg` resolves them during `predata_init()`.
- `before_rest_init()` executes a fixed plan for this boot.
- hot policy may extend or shrink runtime features later, but it must not
  redefine the cold-boot branch that was already chosen.

## Design Invariants

1. Cold boot does not transition between profiles.
2. The boot profile is resolved exactly once, before `before_rest_init()`.
3. Stage1 anchor hooks are chosen by the boot plan resolver, not by runtime
   policy.
4. `rootless` is the control-plane baseline: `supercall + kstorage`.
5. `SU` is not a standalone boot model. A rootful boot plan must include the
   extra prerequisites needed by the SU path.
6. Runtime policy is a post-boot layer. It may reuse the same components, but
   it must not force cold boot to "start as A, then morph into B".

## Layer Split

### 1. Boot Plan Resolver

Location: `kernel/base/predata.c`

Responsibilities:

- parse profile aliases such as `legacy`, `rootful`, `full`, `minimal`, `no-su`
- parse additive keys from `start_preset.additional`
- resolve the final profile into a frozen boot plan
- emit:
  - `boot_plan_id`
  - `kp_stage1_hook_flags`
  - ordered init mask for `before_rest_init()`
  - ordered init mask for `before_kernel_init()`

The resolver may still use feature flags internally, but they are derived from
the chosen boot plan. They are no longer treated as an open-ended closure that
keeps changing during cold boot.

### 2. Boot Executor

Location: `kernel/patch/patch.c`

Responsibilities:

- install the stage1 anchor hooks selected by the boot plan
- execute the fixed init sequence for the chosen plan
- not perform profile upgrades, downgrades, or deferred boot-profile flips

### 3. Runtime Policy Layer

Location: `kernel/patch/common/policy.c`

Responsibilities:

- hot apply or hot remove runtime features after the boot baseline is up
- reuse already-installed safe baselines when possible
- never redefine which cold-boot branch this boot should have taken

## Boot Plans

### Boot-time Component Groups

Common baseline:

1. `hotpatch_init`
2. `bypass_kcfi`
3. `resolve_struct`

Rootless control plane:

1. `supercall_install`
2. `kstorage_init`

Rootful prerequisites:

1. `bypass_selinux`
2. `task_observer`
3. `su_compat_init`
4. `android_sepolicy_flags_fix`

Full extras:

1. `android_user_init`
2. `fsapi_install`

KPM event pipeline:

1. `kernel_init` stage1 hook
2. `pre-kernel-init` and `post-kernel-init` extra events

Auxiliary helpers:

- `panic` hook is debug-oriented and optional.
- `resolve_pt_regs` is treated as an auxiliary runtime helper, not a
  profile-defining boot discriminator. It should be attached only when the
  implementation path explicitly needs it.

## Frozen Profile Matrix

| Profile | Stage1 Hooks | `before_rest_init()` Ordered Init | `before_kernel_init()` | Runtime Scope | Notes |
|---|---|---|---|---|---|
| `minimal` / `rootless` / `no-su` | `INIT` | common baseline -> rootless control plane | none | may hot-apply rootful or full later | default safe baseline |
| `legacy` / `rootful` | `INIT` | common baseline -> `bypass_selinux` -> `task_observer` -> rootless control plane -> `su_compat_init` -> `android_sepolicy_flags_fix` | none | may hot-upgrade to full later | cold boot must enter rootful directly, not via rootless |
| `kpm-support` | `INIT + KERNEL_INIT` | common baseline -> rootless control plane | KPM pre/post-kernel-init events only | may hot-apply rootful/full later | dedicated profile when pre-kernel-init KPM events are needed |
| `full` | `INIT + KERNEL_INIT` | common baseline -> `bypass_selinux` -> `task_observer` -> rootless control plane -> `su_compat_init` -> `android_sepolicy_flags_fix` -> full extras | KPM pre/post-kernel-init events | broadest hot policy scope | highest risk profile |

## Ordering Rules

### Cold Boot Rules

1. Resolve the profile before stage1 starts.
2. Do not switch profile inside `before_rest_init()`.
3. Do not enter `rootful` by "boot as rootless, then upgrade on first exec".
4. Do not enter `rootless` by "boot as rootful, then downgrade later".
5. The chosen profile must be explainable from image metadata alone.

### Runtime Rules

1. Hot policy may add or remove components after the boot baseline is stable.
2. Hot policy operates against the already-selected boot baseline.
3. Stage1 anchor hooks are not rewritten in-place by runtime policy.
4. Runtime policy must preserve the control plane needed to recover from a bad
   policy switch.

## Mapping Rules

These mappings are resolver rules, not post-hoc guesses in the boot executor:

- `minimal`, `rootless`, `no-su` -> `BOOT_PLAN_MINIMAL`
- `legacy`, `rootful` -> `BOOT_PLAN_ROOTFUL`
- `kpm`, `kpm-support`, `kpm_support` -> `BOOT_PLAN_KPM_SUPPORT`
- `full` -> `BOOT_PLAN_FULL`

## Current Divergences To Remove

The current implementation still has a few boot-time mismatches that this
matrix is meant to eliminate:

1. `SU` currently normalizes to `SUPERCALL + KSTORAGE` only.
2. cold boot still mixes profile resolution with runtime-policy readiness.
3. deferred boot-profile flips exist in the cold-boot path.
4. `before_kernel_init()` currently does more than KPM event dispatch for some
   profiles.

## Implementation Follow-up

1. Introduce an explicit boot-plan id and boot-plan masks in `predata.h`.
2. Move all profile resolution into `predata_init()`.
3. Make `patch.c` consume the resolved boot plan rather than infer behavior
   from mutable feature flags.
4. Restrict `policy.c` to post-boot hot transitions.
