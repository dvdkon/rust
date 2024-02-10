use crate::ffi::{c_void, CStr, CString, OsStr, OsString};
use crate::fmt;
use crate::hash::Hash;
use crate::io::{self, IoSlice, IoSliceMut, SeekFrom, BorrowedCursor};
use crate::os::psp::ffi::OsStrExt;
use crate::path::{Path, PathBuf};
use crate::sys::io::cvt_io_error;
use crate::sys::time::SystemTime;
use crate::sys::unsupported;
pub use crate::sys_common::fs::try_exists;

pub struct File {
    fd: psp_sys::SceUid,
    // necessary because we don't have fstat et al
    path: CString,
}

#[derive(Copy, Clone)]
pub struct FileAttr(psp_sys::SceIoStat);

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FileTimes {
    ctime: psp_sys::ScePspDateTime,
    atime: psp_sys::ScePspDateTime,
    mtime: psp_sys::ScePspDateTime,
}

pub struct ReadDir(psp_sys::SceUid);

pub struct DirEntry(psp_sys::SceIoDirent);

#[derive(Clone, Debug)]
pub struct OpenOptions {
    flags: psp_sys::IoOpenFlags,
    perms: psp_sys::IoPermissions,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct FilePermissions(psp_sys::IoPermissions);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FileType(_FileType);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum _FileType {
    Symlink,
    Directory,
    File,
}

#[derive(Debug)]
pub struct DirBuilder {
    mode: i32,
}

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.0.st_size as u64
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions(self.0.st_mode.permissions())
    }

    pub fn file_type(&self) -> FileType {
        if self.0.st_attr.contains(psp_sys::IoStatAttr::IFLNK) {
            return FileType(_FileType::Symlink);
        }
        if self.0.st_attr.contains(psp_sys::IoStatAttr::IFDIR) {
            return FileType(_FileType::Directory);
        }
        if self.0.st_attr.contains(psp_sys::IoStatAttr::IFREG) {
            return FileType(_FileType::File);
        }
        unreachable!()
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        SystemTime::try_from_psp_time(&self.0.st_mtime)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid file modification date"))
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        SystemTime::try_from_psp_time(&self.0.st_atime)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid file access date"))
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        SystemTime::try_from_psp_time(&self.0.st_ctime)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid file creation date"))
    }
}

impl fmt::Debug for FileAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAttr")
            .field("mode", &self.0.st_mode)
            .field("attr", &self.0.st_attr)
            .field("size", &self.0.st_size)
            .field("ctime", &self.0.st_ctime)
            .field("atime", &self.0.st_atime)
            .field("mtime", &self.0.st_mtime)
            .finish()
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        self.0 & 0o222 == 0
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            self.0 &= !0o222
        } else {
            self.0 |= 0o222;
        }
    }
}

impl fmt::Debug for FilePermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FilePermissions(0o{:o})", self.0))
    }
}

impl FileTimes {
    // TODO: Change SystemTime internal repr so we can implement these reasonably
    pub fn set_accessed(&mut self, t: SystemTime) {
        unimplemented!()
    }

    pub fn set_modified(&mut self, t: SystemTime) {
        unimplemented!()
    }

    pub fn set_created(&mut self, t: SystemTime) {
        unimplemented!()
    }
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        match self.0 {
            _FileType::Directory => true,
            _ => false,
        }
    }

    pub fn is_file(&self) -> bool {
        match self.0 {
            _FileType::File => true,
            _ => false,
        }
    }

    pub fn is_symlink(&self) -> bool {
        match self.0 {
            _FileType::Symlink => true,
            _ => false,
        }
    }
}

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadDir").field("fd", &self.0.0).finish()
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        unsafe { psp_sys::sceIoDclose(self.0) };
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        let mut dirent: psp_sys::SceIoDirent = unsafe { core::mem::zeroed() };
        let result = unsafe { psp_sys::sceIoDread(self.0, &mut dirent) };
        if result < 0 {
            return Some(Err(cvt_io_error(result)));
        } else {
            let remaining = result;
            if remaining > 0 { Some(Ok(DirEntry(dirent))) } else { None }
        }
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        unimplemented!()
    }

    pub fn file_name(&self) -> OsString {
        let s = CStr::from_bytes_until_nul(&self.0.d_name).unwrap();
        OsStr::from_bytes(s.to_bytes()).to_owned()
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        Ok(FileAttr(self.0.d_stat))
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        if self.0.d_stat.st_attr.contains(psp_sys::IoStatAttr::IFLNK) {
            return Ok(FileType(_FileType::Symlink));
        }
        if self.0.d_stat.st_attr.contains(psp_sys::IoStatAttr::IFDIR) {
            return Ok(FileType(_FileType::Directory));
        }
        if self.0.d_stat.st_attr.contains(psp_sys::IoStatAttr::IFREG) {
            return Ok(FileType(_FileType::File));
        }
        unreachable!()
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions { flags: psp_sys::IoOpenFlags::empty(), perms: 0o666 }
    }

    pub fn read(&mut self, read: bool) {
        if read {
            self.flags |= psp_sys::IoOpenFlags::RD_ONLY;
        }
    }
    pub fn write(&mut self, write: bool) {
        if write {
            self.flags |= psp_sys::IoOpenFlags::WR_ONLY;
        }
    }
    pub fn append(&mut self, append: bool) {
        if append {
            self.flags |= psp_sys::IoOpenFlags::APPEND;
        }
    }
    pub fn truncate(&mut self, truncate: bool) {
        if truncate {
            self.flags |= psp_sys::IoOpenFlags::TRUNC;
        }
    }
    pub fn create(&mut self, create: bool) {
        if create {
            self.flags |= psp_sys::IoOpenFlags::CREAT;
        }
    }
    pub fn create_new(&mut self, create_new: bool) {
        if create_new {
            self.flags |= psp_sys::IoOpenFlags::CREAT | psp_sys::IoOpenFlags::EXCL;
        }
    }
}

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        let cstring = cstring(path)?;
        let open_result = unsafe {
            psp_sys::sceIoOpen(cstring.as_c_str().as_ptr() as *const u8, opts.flags, opts.perms)
        };
        if open_result.0 < 0 {
            return Err(cvt_io_error(open_result.0));
        } else {
            Ok(File { fd: open_result, path: cstring })
        }
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        let mut stat: psp_sys::SceIoStat = unsafe { core::mem::zeroed() };
        let stat_result = unsafe { psp_sys::sceIoGetstat(self.path.as_ptr() as *const u8, &mut stat) };
        if stat_result < 0 {
            return Err(cvt_io_error(stat_result));
        } else {
            Ok(FileAttr(stat))
        }
    }

    pub fn fsync(&self) -> io::Result<()> {
        // kind of jank way of getting just the device name out of the path ie "ms0:"
        // TODO relative paths?
        let device_name = CString::new(
            self.path
                .to_str()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "Path could not be referenced as str")
                })?
                .split("/")
                .next()
                .unwrap(),
        )
        .unwrap();
        let result = unsafe { psp_sys::sceIoSync(device_name.as_c_str().as_ptr() as *const u8, 0) };
        if result < 0 {
            return Err(cvt_io_error(result));
        } else {
            Ok(())
        }
    }

    pub fn datasync(&self) -> io::Result<()> {
        self.fsync()
    }

    pub fn truncate(&self, size: u64) -> io::Result<()> {
        let mut stat: psp_sys::SceIoStat = unsafe { core::mem::zeroed() };
        stat.st_size = size as i64;
        let result =
            unsafe { psp_sys::sceIoChstat(self.path.as_ptr() as *const u8, &mut stat, 0x0004) };
        if result < 0 {
            return Err(cvt_io_error(result));
        } else {
            Ok(())
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let read_result =
            unsafe { psp_sys::sceIoRead(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        if read_result < 0 {
            return Err(cvt_io_error(read_result));
        } else {
            Ok(read_result as usize)
        }
    }

    pub fn read_buf(&self, buf: BorrowedCursor<'_>) -> io::Result<()> {
        io::default_read_buf(|buf| self.read(buf), buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        io::default_read_vectored(|b| self.read(b), bufs)
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let write_result =
            unsafe { psp_sys::sceIoWrite(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if write_result < 0 {
            return Err(cvt_io_error(write_result));
        } else {
            Ok(write_result as usize)
        }
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        io::default_write_vectored(|buf| self.write(buf), bufs)
    }

    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let (whence, pos) = match pos {
            SeekFrom::Start(off) => (psp_sys::IoWhence::Set, off as i64),
            SeekFrom::End(off) => (psp_sys::IoWhence::End, off),
            SeekFrom::Current(off) => (psp_sys::IoWhence::Cur, off),
        };
        let result = unsafe { psp_sys::sceIoLseek(self.fd, pos, whence) };
        if result < 0 {
            return Err(cvt_io_error(result as i32));
        } else {
            Ok(result as u64)
        }
    }

    pub fn duplicate(&self) -> io::Result<File> {
        unsupported()
    }

    pub fn set_permissions(&self, perm: FilePermissions) -> io::Result<()> {
        let mut stat: psp_sys::SceIoStat = unsafe { core::mem::zeroed() };
        let getstat_result =
            unsafe { psp_sys::sceIoGetstat(self.path.as_ptr() as *const u8, &mut stat) };
        if getstat_result < 0 {
            return Err(cvt_io_error(getstat_result));
        } else {
            let non_perm_mode_bits = stat.st_mode.kind();
            stat.st_mode = non_perm_mode_bits | psp_sys::IoStatMode::from_bits_retain(perm.0);
            let chstat_result =
                unsafe { psp_sys::sceIoChstat(self.path.as_ptr() as *const u8, &mut stat, 0x0001) };
            if chstat_result < 0 {
                return Err(cvt_io_error(chstat_result));
            } else {
                Ok(())
            }
        }
    }

    pub fn set_times(&self, times: FileTimes) -> io::Result<()> {
        let mut stat = psp_sys::SceIoStat {
            st_mode: psp_sys::IoStatMode::empty(),
            st_attr: psp_sys::IoStatAttr::empty(),
            st_size: 0,
            st_ctime: times.ctime,
            st_atime: times.atime,
            st_mtime: times.mtime,
            st_private: [0,0,0,0,0,0],
        };
        let res = unsafe {
            psp_sys::sceIoChstat(self.path.as_ptr() as *const u8,
                                 &mut stat, 0x8 | 0x10 | 0x20)
        };
        if res < 0 {
            Err(cvt_io_error(res))
        } else {
            Ok(())
        }
    }

    pub fn diverge(&self) -> ! {
        unimplemented!()
    }
}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder { mode: 0o777 }
    }

    pub fn mkdir(&self, p: &Path) -> io::Result<()> {
        let cstring = cstring(p)?;
        let result =
            unsafe { psp_sys::sceIoMkdir(cstring.as_c_str().as_ptr() as *const u8, self.mode) };
        if result < 0 {
            return Err(cvt_io_error(result));
        } else {
            Ok(())
        }
    }
}

fn cstring(path: &Path) -> io::Result<CString> {
    Ok(CString::new(
        path.to_str().ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Path to str failed"))?,
    )?)
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("fd", &self.fd.0).field("path", &self.path).finish()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { psp_sys::sceIoClose(self.fd) };
    }
}

pub fn readdir(p: &Path) -> io::Result<ReadDir> {
    let cstring = cstring(p)?;
    let open_result = unsafe { psp_sys::sceIoDopen(cstring.as_c_str().as_ptr() as *const u8) };
    if open_result.0 < 0 {
        return Err(cvt_io_error(open_result.0));
    } else {
        Ok(ReadDir(open_result))
    }
}

pub fn unlink(p: &Path) -> io::Result<()> {
    let cstring = cstring(p)?;
    let result = unsafe { psp_sys::sceIoRemove(cstring.as_c_str().as_ptr() as *const u8) };
    if result < 0 {
        return Err(cvt_io_error(result));
    } else {
        Ok(())
    }
}

pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    let cstring_old = cstring(old)?;
    let cstring_new = cstring(new)?;
    let rename_result = unsafe {
        psp_sys::sceIoRename(
            cstring_old.as_c_str().as_ptr() as *const u8,
            cstring_new.as_c_str().as_ptr() as *const u8,
        )
    };
    if rename_result < 0 {
        return Err(cvt_io_error(rename_result));
    } else {
        Ok(())
    }
}

pub fn set_perm(p: &Path, perm: FilePermissions) -> io::Result<()> {
    let cstring = cstring(p)?;
    let mut stat: psp_sys::SceIoStat = unsafe { core::mem::zeroed() };
    let getstat_result =
        unsafe { psp_sys::sceIoGetstat(cstring.as_c_str().as_ptr() as *const u8, &mut stat) };
    if getstat_result < 0 {
        return Err(cvt_io_error(getstat_result));
    } else {
        let non_perm_mode_bits = stat.st_mode.kind();
        stat.st_mode = non_perm_mode_bits | psp_sys::IoStatMode::from_bits_retain(perm.0);
        let chstat_result = unsafe {
            psp_sys::sceIoChstat(cstring.as_c_str().as_ptr() as *const u8, &mut stat, 0x0001)
        };
        if chstat_result < 0 {
            return Err(cvt_io_error(chstat_result));
        } else {
            Ok(())
        }
    }
}

pub fn rmdir(p: &Path) -> io::Result<()> {
    let cstring = cstring(p)?;
    let rm_result = unsafe { psp_sys::sceIoRmdir(cstring.as_c_str().as_ptr() as *const u8) };
    if rm_result < 0 {
        return Err(cvt_io_error(rm_result));
    } else {
        Ok(())
    }
}

pub use crate::sys_common::fs::remove_dir_all;

pub fn readlink(_p: &Path) -> io::Result<PathBuf> {
    unsupported()
}

pub fn symlink(_src: &Path, _dst: &Path) -> io::Result<()> {
    unsupported()
}

pub fn link(_src: &Path, _dst: &Path) -> io::Result<()> {
    unsupported()
}

pub fn stat(p: &Path) -> io::Result<FileAttr> {
    let cstring = cstring(p)?;
    let mut stat: psp_sys::SceIoStat = unsafe { core::mem::zeroed() };
    let stat_result =
        unsafe { psp_sys::sceIoGetstat(cstring.as_c_str().as_ptr() as *const u8, &mut stat) };
    if stat_result < 0 {
        return Err(cvt_io_error(stat_result));
    } else {
        Ok(FileAttr(stat))
    }
}

pub fn lstat(_p: &Path) -> io::Result<FileAttr> {
    unsupported()
}

pub fn canonicalize(_p: &Path) -> io::Result<PathBuf> {
    unsupported()
}

pub use crate::sys_common::fs::copy;
