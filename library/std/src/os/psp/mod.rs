//! Platform-specific extensions to `std` for PSP.

#![doc(cfg(target_os = "psp"))]
#![unstable(feature = "psp_std", issue = "none")]

pub mod ffi;

// Ugly re-export of psp_sys to avoid duplicate entries in the dependency
// tree, causing linking issues with duplicate symbols.
pub use psp_sys as sys;
