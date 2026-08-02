//! Architecture-specific code.
//!
//! x86_64 is the only implemented target. AArch64 is a stated secondary
//! architecture in the PRD but is out of scope until the core is stable.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
