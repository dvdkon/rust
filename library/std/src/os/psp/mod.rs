//! Platform-specific extensions to `std` for PSP.

#![doc(cfg(target_os = "psp"))]
#![unstable(feature = "psp_std", issue = "none")]

pub mod ffi;
