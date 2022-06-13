use super::{unsupported, Void};
use crate::error::Error as StdError;
use crate::ffi::{CString, OsStr, OsString};
use crate::fmt;
use crate::io;
use crate::os::psp::ffi::OsStrExt;
use crate::path::{self, PathBuf};

static mut CWD: Option<CString> = None;

pub fn errno() -> i32 {
    0
}

pub fn error_string(_errno: i32) -> String {
    "operation successful".to_string()
}

pub fn getcwd() -> io::Result<PathBuf> {
    // Safety: PSP does not have concurrent threads
    unsafe { CWD.as_ref() }
        .map(|c| PathBuf::from(OsStr::from_bytes(c.to_bytes())))
        .ok_or(io::const_io_error!(io::ErrorKind::Other, "current directory is not set",))
}

pub fn chdir(path: &path::Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let result = unsafe { libc::sceIoChdir(path.as_ptr() as *const u8) };
    if result < 0 {
        // TODO propagate the error code
        return Err(io::const_io_error!(io::ErrorKind::Other, "could not set current directory",));
    }
    // Safety: PSP does not have concurrent threads
    unsafe { CWD = Some(path.to_owned()) };
    Ok(())
}

pub struct SplitPaths<'a>(&'a Void);

pub fn split_paths(_unparsed: &OsStr) -> SplitPaths<'_> {
    panic!("unsupported")
}

impl<'a> Iterator for SplitPaths<'a> {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> {
        match *self.0 {}
    }
}

#[derive(Debug)]
pub struct JoinPathsError;

pub fn join_paths<I, T>(_paths: I) -> Result<OsString, JoinPathsError>
where
    I: Iterator<Item = T>,
    T: AsRef<OsStr>,
{
    Err(JoinPathsError)
}

impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "not supported on this platform yet".fmt(f)
    }
}

impl StdError for JoinPathsError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "not supported on this platform yet"
    }
}

pub fn current_exe() -> io::Result<PathBuf> {
    unsupported()
}

pub struct Env(Void);

impl Iterator for Env {
    type Item = (OsString, OsString);
    fn next(&mut self) -> Option<(OsString, OsString)> {
        match self.0 {}
    }
}

pub fn env() -> Env {
    panic!("not supported on this platform")
}

pub fn getenv(_: &OsStr) -> Option<OsString> {
    None
}

pub fn setenv(_: &OsStr, _: &OsStr) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Other, "cannot set env vars on this platform"))
}

pub fn unsetenv(_: &OsStr) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Other, "cannot unset env vars on this platform"))
}

pub fn temp_dir() -> PathBuf {
    panic!("no filesystem on this platform")
}

pub fn home_dir() -> Option<PathBuf> {
    None
}

pub fn exit(_code: i32) -> ! {
    crate::intrinsics::abort()
}

pub fn getpid() -> u32 {
    panic!("no pids on this platform")
}
