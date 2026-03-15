/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026. All Rights Reserved.
 */

#ifndef _KP_POLICY_H_
#define _KP_POLICY_H_

#include <ktypes.h>

void kp_policy_mark_component_ready(uint32_t feature, bool ready);
int kp_policy_apply_flags(uint32_t requested_flags);
int kp_policy_apply_profile(int profile);

#endif
