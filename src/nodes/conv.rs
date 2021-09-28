// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

use fuser::TimeOrNow;
use nix::{errno, fcntl, sys};
use nix::sys::time::{TimeVal, TimeValLike};
use nodes::{KernelError, NodeResult};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::SystemTime;

const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;

// /// Fixed point in time to use when we fail to interpret file system supplied timestamps.
// const BAD_TIME: Timespec = Timespec { sec: 0, nsec: 0 };

// /// Converts a `time::Timespec` object into a `std::time::SystemTime`.
// pub fn timespec_to_system_time(spec: Timespec) -> SystemTime {
//     SystemTime::UNIX_EPOCH.checked_add(
//         Duration::from_secs(spec.sec as u64)
//             .checked_add(Duration::from_nanos(spec.nsec as u64))
//             .expect("Time overflow")).expect("Time overflow")
// }


/// Converts a `std::time::SystemTime` object into a `sys::time::TimeSpec`.
pub fn system_time_to_nix_timespec(val: SystemTime) -> sys::time::TimeSpec {
    let since_epoch = val.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let nanos_since_epoch =
        NANOSECONDS_PER_SECOND
            .checked_mul(since_epoch.as_secs() as i64)
            .expect("Time overflow: seconds")
            .checked_add(since_epoch.subsec_nanos() as i64)
            .expect("Time overflow: nanoseconds");
    sys::time::TimeSpec::nanoseconds(nanos_since_epoch)
}

/// Converts a `std::time::SystemTime` object into a `sys::time::TimeVal`.
pub fn system_time_to_timeval(val: SystemTime) -> TimeVal {
    // TODO(wilhelm): Check this
    let since_epoch = val.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let nanos_since_epoch =
        NANOSECONDS_PER_SECOND
            .checked_mul(since_epoch.as_secs() as i64)
            .expect("Time overflow: seconds")
            .checked_add(since_epoch.subsec_nanos() as i64)
            .expect("Time overflow: nanoseconds");
    sys::time::TimeVal::nanoseconds(nanos_since_epoch)
}

// Converts a `fuser::TimeNow` to `std::time::SystemTime`.
pub fn time_or_now_to_system_time(val: TimeOrNow) -> SystemTime {
    match val {
        TimeOrNow::SpecificTime(system_time) => system_time,
        TimeOrNow::Now => SystemTime::now(),
    }
}

pub fn system_time_with_second_resolution() -> SystemTime {
    let now = SystemTime::now();
    let duration = now.duration_since(SystemTime::UNIX_EPOCH).expect("Time overflow");
    SystemTime::UNIX_EPOCH.checked_add(duration).expect("Time overflow")
}

/// Converts a file type as returned by the file system to a FUSE file type.
///
/// `path` is the file from which the file type was originally extracted and is only for debugging
/// purposes.
///
/// If the given file type cannot be mapped to a FUSE file type (because we don't know about that
/// type or, most likely, because the file type is bogus), logs a warning and returns a regular
/// file type with the assumption that most operations should work on it.
pub fn filetype_fs_to_fuse(path: &Path, fs_type: fs::FileType) -> fuser::FileType {
    if fs_type.is_block_device() {
        fuser::FileType::BlockDevice
    } else if fs_type.is_char_device() {
        fuser::FileType::CharDevice
    } else if fs_type.is_dir() {
        fuser::FileType::Directory
    } else if fs_type.is_fifo() {
        fuser::FileType::NamedPipe
    } else if fs_type.is_file() {
        fuser::FileType::RegularFile
    } else if fs_type.is_socket() {
        fuser::FileType::Socket
    } else if fs_type.is_symlink() {
        fuser::FileType::Symlink
    } else {
        warn!("File system returned invalid file type {:?} for {:?}", fs_type, path);
        fuser::FileType::RegularFile
    }
}

/// Converts metadata attributes supplied by the file system to a FUSE file attributes tuple.
///
/// `inode` is the value of the FUSE inode (not the value of the inode supplied within `attr`) to
/// fill into the returned file attributes.  `path` is the file from which the attributes were
/// originally extracted and is only for debugging purposes.  `nlink` is the number of links to
/// expose, which is a sandboxfs-internal property and does not match the on-disk value included
/// in `attr`.
///
/// Any errors encountered along the conversion process are logged and the corresponding field is
/// replaced by a reasonable value that should work.  In other words: all errors are swallowed.
pub fn attr_fs_to_fuse(path: &Path, inode: u64, nlink: u32, attr: &fs::Metadata) -> fuser::FileAttr {
    let len = if attr.is_dir() {
        2  // TODO(jmmv): Reevaluate what directory sizes should be.
    } else {
        attr.len()
    };

    // TODO(https://github.com/bazelbuild/sandboxfs/issues/43): Using the underlying ctimes is
    // slightly wrong because the ctimes track changes to the inodes.  In most cases, operations
    // that flow via sandboxfs will affect the underlying ctime and propagate through here, which is
    // fine, but other operations are purely in-memory.  To properly handle those cases, we should
    // have our own ctime handling.

    let perm = match attr.permissions().mode() {
        // TODO(https://github.com/rust-lang/rust/issues/51577): Drop :: prefix.
        mode if mode > u32::from(::std::u16::MAX) => {
            warn!("File system returned mode {} for {:?}, which is too large; set to 0400",
                mode, path);
            0o400
        },
        mode => (mode as u16) & !(sys::stat::SFlag::S_IFMT.bits() as u16),
    };

    let rdev = match attr.rdev() {
        // TODO(https://github.com/rust-lang/rust/issues/51577): Drop :: prefix.
        rdev if rdev > u64::from(::std::u32::MAX) => {
            warn!("File system returned rdev {} for {:?}, which is too large; set to 0",
                rdev, path);
            0
        },
        rdev => rdev as u32,
    };

    // TODO(bierbaum): Figure out something better to do when atime, mtime, or crtime have
    // no value.
    fuser::FileAttr {
        ino: inode,
        kind: filetype_fs_to_fuse(path, attr.file_type()),
        nlink: nlink,
        size: len,
        blocks: 0, // TODO(jmmv): Reevaluate what blocks should be.
        blksize: 0,
        atime: attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
        mtime: attr.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        ctime: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
        crtime: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
        perm: perm,
        uid: attr.uid(),
        gid: attr.gid(),
        rdev: rdev,
        flags: 0,
    }
}

/// Converts a set of `flags` bitmask to an `fs::OpenOptions`.
///
/// `allow_writes` indicates whether the file to be opened supports writes or not.  If the flags
/// don't match this condition, then this returns an error.
pub fn flags_to_openoptions(flags: i32, allow_writes: bool) -> NodeResult<fs::OpenOptions> {
    let oflag = fcntl::OFlag::from_bits_truncate(flags);

    let mut options = fs::OpenOptions::new();
    options.read(true);
    if oflag.contains(fcntl::OFlag::O_WRONLY) | oflag.contains(fcntl::OFlag::O_RDWR) {
        if !allow_writes {
            return Err(KernelError::from_errno(errno::Errno::EPERM));
        }
        if oflag.contains(fcntl::OFlag::O_WRONLY) {
            options.read(false);
        }
        options.write(true);
    }
    options.custom_flags(flags);
    Ok(options)
}

/// Asserts that two FUSE file attributes are equal.
//
// TODO(jmmv): Remove once rust-fuse 0.4 is released as it will derive Eq for FileAttr.
pub fn fileattrs_eq(attr1: &fuser::FileAttr, attr2: &fuser::FileAttr) -> bool {
    attr1.ino == attr2.ino
        && attr1.kind == attr2.kind
        && attr1.nlink == attr2.nlink
        && attr1.size == attr2.size
        && attr1.blocks == attr2.blocks
        && attr1.atime == attr2.atime
        && attr1.mtime == attr2.mtime
        && attr1.ctime == attr2.ctime
        && attr1.crtime == attr2.crtime
        && attr1.perm == attr2.perm
        && attr1.uid == attr2.uid
        && attr1.gid == attr2.gid
        && attr1.rdev == attr2.rdev
        && attr1.flags == attr2.flags
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::{unistd};
    use nix::sys::time::TimeValLike;
    use sys::time::TimeSpec;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::ops::Add;
    use std::os::unix;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Creates a file at `path` with the given `content` and closes it.
    fn create_file(path: &Path, content: &str) {
        let mut file = File::create(path).expect("Test file creation failed");
        let written = file.write(content.as_bytes()).expect("Test file data write failed");
        assert_eq!(content.len(), written, "Test file wasn't fully written");
    }

    #[test]
    fn test_system_time_to_nix_timespec() {
        let seconds = Duration::from_secs(123456789);
        let nanos = Duration::from_nanos(54321);
        let system_time =
            SystemTime::UNIX_EPOCH.checked_add(seconds).unwrap().checked_add(nanos).unwrap();
        let spec = {
            TimeSpec::seconds(seconds.as_secs() as i64)
                .add(TimeSpec::nanoseconds(nanos.as_nanos() as i64))
        };
        assert_eq!(system_time_to_nix_timespec(system_time), spec);
    }

    #[test]
    fn test_system_time_to_timeval() {
        let seconds = Duration::from_secs(123456789);
        let nanos = Duration::from_nanos(54321);
        let system_time =
            SystemTime::UNIX_EPOCH.checked_add(seconds).unwrap().checked_add(nanos).unwrap();
        let spec = {
            TimeVal::seconds(seconds.as_secs() as i64)
                .add(TimeVal::nanoseconds(nanos.as_nanos() as i64))
        };
        assert_eq!(system_time_to_timeval(system_time), spec);
    }

    #[test]
    fn test_attr_fs_to_fuse_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("root");
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("subdir1")).unwrap();
        fs::create_dir(path.join("subdir2")).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        sys::stat::utimes(&path, &sys::time::TimeVal::seconds(12345),
            &sys::time::TimeVal::seconds(678)).unwrap();

        let atime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(12345)).unwrap();
        let mtime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(678)).unwrap();
        let bad_time = SystemTime::UNIX_EPOCH;

        let exp_attr = fuser::FileAttr {
            ino: 1234,  // Ensure underlying inode is not propagated.
            kind: fuser::FileType::Directory,
            nlink: 56, // TODO(jmmv): Should this account for subdirs?
            size: 2,
            blocks: 0,
            blksize: 0,
            atime: atime,
            mtime: mtime,
            ctime: bad_time,
            crtime: bad_time,
            perm: 0o750,
            uid: unistd::getuid().as_raw(),
            gid: unistd::getgid().as_raw(),
            rdev: 0,
            flags: 0,
        };

        let mut attr = attr_fs_to_fuse(&path, 1234, 56, &fs::symlink_metadata(&path).unwrap());
        // We cannot really make any useful assertions on ctime and crtime as these cannot be
        // modified and may not be queryable, so stub them out.
        attr.ctime = bad_time;
        attr.crtime = bad_time;
        assert!(fileattrs_eq(&exp_attr, &attr));
    }

    #[test]
    fn test_attr_fs_to_fuse_regular() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        let content = "Some text\n";
        create_file(&path, content);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        sys::stat::utimes(&path, &sys::time::TimeVal::seconds(54321),
            &sys::time::TimeVal::seconds(876)).unwrap();

        let atime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(54321)).unwrap();
        let mtime = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(876)).unwrap();
        let bad_time = SystemTime::UNIX_EPOCH;

        let exp_attr = fuser::FileAttr {
            ino: 42,  // Ensure underlying inode is not propagated.
            kind: fuser::FileType::RegularFile,
            nlink: 50,
            size: content.len() as u64,
            blocks: 0,
            blksize: 0,
            atime: atime,
            mtime: mtime,
            ctime: bad_time,
            crtime: bad_time,
            perm: 0o640,
            uid: unistd::getuid().as_raw(),
            gid: unistd::getgid().as_raw(),
            rdev: 0,
            flags: 0,
        };

        let mut attr = attr_fs_to_fuse(&path, 42, 50, &fs::symlink_metadata(&path).unwrap());
        // We cannot really make any useful assertions on ctime and crtime as these cannot be
        // modified and may not be queryable, so stub them out.
        attr.ctime = bad_time;
        attr.crtime = bad_time;
        assert!(fileattrs_eq(&exp_attr, &attr));
    }

    #[test]
    fn test_flags_to_openoptions_rdonly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        create_file(&path, "original content");

        let flags = fcntl::OFlag::O_RDONLY.bits();
        let openoptions = flags_to_openoptions(flags, false).unwrap();
        let mut file = openoptions.open(&path).unwrap();

        write!(file, "foo").expect_err("Write to read-only file succeeded");

        let mut buf = String::new();
        file.read_to_string(&mut buf).expect("Read from read-only file failed");
        assert_eq!("original content", buf);
    }

    #[test]
    fn test_flags_to_openoptions_wronly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        create_file(&path, "");

        let flags = fcntl::OFlag::O_WRONLY.bits();
        flags_to_openoptions(flags, false).expect_err("Writability permission not respected");
        let openoptions = flags_to_openoptions(flags, true).unwrap();
        let mut file = openoptions.open(&path).unwrap();

        let mut buf = String::new();
        file.read_to_string(&mut buf).expect_err("Read from write-only file succeeded");

        write!(file, "foo").expect("Write to write-only file failed");
    }

    #[test]
    fn test_flags_to_openoptions_rdwr() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        create_file(&path, "some content");

        let flags = fcntl::OFlag::O_RDWR.bits();
        flags_to_openoptions(flags, false).expect_err("Writability permission not respected");
        let openoptions = flags_to_openoptions(flags, true).unwrap();
        let mut file = openoptions.open(&path).unwrap();

        let mut buf = String::new();
        file.read_to_string(&mut buf).expect("Read from read/write file failed");

        write!(file, "foo").expect("Write to read/write file failed");
    }

    #[test]
    fn test_flags_to_openoptions_custom() {
        let dir = tempdir().unwrap();
        create_file(&dir.path().join("file"), "");
        let path = dir.path().join("link");
        unix::fs::symlink("file", &path).unwrap();

        {
            let flags = fcntl::OFlag::O_RDONLY.bits();
            let openoptions = flags_to_openoptions(flags, true).unwrap();
            openoptions.open(&path).expect("Failed to open symlink target; test setup bogus");
        }

        let flags = (fcntl::OFlag::O_RDONLY | fcntl::OFlag::O_NOFOLLOW).bits();
        let openoptions = flags_to_openoptions(flags, true).unwrap();
        openoptions.open(&path).expect_err("Open of symlink succeeded");
    }
}
