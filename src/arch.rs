// SPDX-License-Identifier: MIT
// Adapted from rzfs @ea41cf0b5b29 (dual GPL-2.0 OR MIT; MIT elected); see NOTICE.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) mod x86_any;
