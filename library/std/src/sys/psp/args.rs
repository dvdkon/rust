use super::common::strlen;
use crate::ffi::{OsStr, OsString};
use crate::os::psp::ffi::OsStrExt;
use crate::os::raw::c_char;

// PSP does not have concurrent threads, so static mut is fine.
static mut ARGC: usize = 0;
static mut ARGV: *const u8 = crate::ptr::null();

#[derive(Debug)]
pub struct Args {
    pos: usize,
}

pub fn args() -> Args {
    Args { pos: 0 }
}

pub unsafe fn init(argc: usize, argv: *const u8) {
    ARGC = argc;
    ARGV = argv;
}

pub unsafe fn cleanup() {}

impl Iterator for Args {
    type Item = OsString;
    fn next(&mut self) -> Option<OsString> {
        unsafe {
            if self.pos >= ARGC {
                return None;
            }
            let len = strlen(ARGV.add(self.pos) as *const c_char);
            let arg = OsStr::from_bytes(crate::slice::from_raw_parts(ARGV.add(self.pos), len));
            self.pos += len + 1;
            Some(arg.to_owned())
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl ExactSizeIterator for Args {
    fn len(&self) -> usize {
        // FIXME
        0
    }
}

impl DoubleEndedIterator for Args {
    fn next_back(&mut self) -> Option<OsString> {
        // FIXME
        None
    }
}
