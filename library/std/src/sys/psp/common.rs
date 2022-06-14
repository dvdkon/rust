use super::args;
use crate::env::set_current_dir;
use crate::io;
use crate::os::psp::ffi::OsStringExt;
use crate::path::PathBuf;

pub mod memchr {
    pub use core::slice::memchr::{memchr, memrchr};
}

#[path = "../unix/os_str.rs"]
pub mod os_str;

// This is not necessarily correct. May want to consider making it part of the
// spec definition?
use crate::os::raw::c_char;

pub unsafe fn init(argc: isize, argv: *const *const u8) {
    // First of all, the arguments types of this function are incorrect, but it's easier to cast
    // them here instead of fixing `std`.
    let argc = argc as usize;
    let argv = argv as *const u8;

    args::init(argc, argv);

    // Init CWD based on the first argument
    if let Some(arg0) = args::args().next() {
        let mut arg0: PathBuf = arg0.into();
        arg0.pop();
        let _ = set_current_dir(arg0);
    }
}

pub unsafe fn cleanup() {}

pub fn unsupported<T>() -> io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "operation not supported on this platform")
}

pub fn decode_error_kind(_code: i32) -> io::ErrorKind {
    io::ErrorKind::Other
}

pub fn abort_internal() -> ! {
    core::intrinsics::abort();
}

pub fn hashmap_random_keys() -> (u64, u64) {
    (1, 2)
}

// This enum is used as the storage for a bunch of types which can't actually
// exist.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Void {}

extern "C" {
    /// Provided by libc or compiler_builtins.
    pub fn strlen(s: *const c_char) -> usize;
}
