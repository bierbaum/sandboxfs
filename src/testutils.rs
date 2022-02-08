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

#![cfg(test)]

use fuser;
use nix::{sys, unistd};
use std::env;
use std::fs;
use std::os::unix;
use std::path::PathBuf;
use tempfile::{tempdir, TempDir};
use users;

/// Holds a temporary directory and files of all possible kinds within it.
///
/// The directory (including all of its contents) is removed when this object is dropped.
pub struct AllFileTypes {
    #[allow(unused)] // Must retain to delay directory deletion.
    root: TempDir,

    /// Collection of test files.
    ///
    /// Tests should iterate over this vector and consume all entries to ensure all possible file
    /// types are verified everywhere.  Prefer using `match` on the key to achieve this.
    // TODO(jmmv): This would be better as a HashMap of fuser::FileType to PathBuf, but we cannot do
    // so until FileTypes are comparable (which will happen with rust-fuse 0.4).
    pub entries: Vec<(fuser::FileType, PathBuf)>,
}

impl AllFileTypes {
    /// Creates a new temporary directory with files of all possible kinds within it.
    pub fn new() -> Self {
        let root = tempdir().unwrap();

        let mut entries: Vec<(fuser::FileType, PathBuf)> = vec![];

        if unistd::getuid().is_root() {
            let block_device = root.path().join("block_device");
            sys::stat::mknod(
                &block_device,
                sys::stat::SFlag::S_IFBLK,
                sys::stat::Mode::S_IRUSR,
                50,
            )
            .unwrap();
            entries.push((fuser::FileType::BlockDevice, block_device));

            let char_device = root.path().join("char_device");
            sys::stat::mknod(
                &char_device,
                sys::stat::SFlag::S_IFCHR,
                sys::stat::Mode::S_IRUSR,
                50,
            )
            .unwrap();
            entries.push((fuser::FileType::CharDevice, char_device));
        } else {
            warn!("Not running as root; cannot create block/char devices");
        }

        let directory = root.path().join("dir");
        fs::create_dir(&directory).unwrap();
        entries.push((fuser::FileType::Directory, directory));

        let named_pipe = root.path().join("named_pipe");
        unistd::mkfifo(&named_pipe, sys::stat::Mode::S_IRUSR).unwrap();
        entries.push((fuser::FileType::NamedPipe, named_pipe));

        let regular = root.path().join("regular");
        drop(fs::File::create(&regular).unwrap());
        entries.push((fuser::FileType::RegularFile, regular));

        let socket = root.path().join("socket");
        drop(unix::net::UnixListener::bind(&socket).unwrap());
        entries.push((fuser::FileType::Socket, socket));

        let symlink = root.path().join("symlink");
        unix::fs::symlink("irrelevant", &symlink).unwrap();
        entries.push((fuser::FileType::Symlink, symlink));

        AllFileTypes { root, entries }
    }
}

/// Holds user-provided configuration details for the tests.
pub struct Config {
    /// The unprivileged user for tests that need to drop privileges.  None if unset.
    pub unprivileged_user: Option<users::User>,
}

impl Config {
    /// Queries the test configuration.
    pub fn get() -> Config {
        let unprivileged_user = env::var("UNPRIVILEGED_USER")
            .map(|name| users::get_user_by_name(&name))
            .unwrap_or(None);
        Config { unprivileged_user }
    }
}
