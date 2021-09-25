use std::{
    collections::HashSet,
    fs::File,
    io::{BufWriter, IoSlice, Write},
    os::unix::prelude::OsStrExt,
    sync::{Arc, Mutex},
};

use crate::ArcAccessLogger;

use super::AccessLogger;

/// An AccessLogger that does nothing.
#[derive(Default)]
pub struct NoAccessLogger {}


impl AccessLogger for NoAccessLogger {
    fn record_directory_access(
        &self,
        _ino: u64,
        _underlying_path: &std::path::Path,
        _attr: &std::fs::Metadata,
    ) {
    }
}

/// An AccessLogger that tracks inodes and does not record duplicate events to the underlying
/// logger.
pub struct DeduplicatingAccessLogger {
    seen_inodes: Mutex<HashSet<u64>>,
    underlying: ArcAccessLogger,
}

impl DeduplicatingAccessLogger {
    /// Create a new instance.
    pub fn new(underlying: ArcAccessLogger) -> ArcAccessLogger {
        Arc::new(Mutex::new(Self {
            seen_inodes: Mutex::new(HashSet::new()),
            underlying: underlying,
        }))
    }
}

impl AccessLogger for Mutex<DeduplicatingAccessLogger> {
    fn record_directory_access(
        &self,
        ino: u64,
        underlying_path: &std::path::Path,
        attr: &std::fs::Metadata,
    ) {
        if let Ok(locked_self) = self.lock() {
            if let Ok(mut locked_seen_inodes) = locked_self.seen_inodes.lock() {
                if locked_seen_inodes.insert(ino) {
                    locked_self.underlying.record_directory_access(ino, underlying_path, attr);
                }
            }
        }
    }
}

/// An AccessLogger that writes paths to a file.
pub struct LogFileAccessLogger {
    buffered_writer: BufWriter<File>,
}

impl LogFileAccessLogger {
    /// Create a new instance.
    pub fn new(log_file: File) -> Self {
        let buffered_writer = BufWriter::new(log_file);
        Self { buffered_writer }
    }
}

impl AccessLogger for Mutex<LogFileAccessLogger> {
    fn record_directory_access(
        &self,
        _ino: u64,
        underlying_path: &std::path::Path,
        attr: &std::fs::Metadata,
    ) {
        if !attr.is_dir() {
            return;
        }
        if let Ok(mut locked_self) = self.lock() {
            let slice = IoSlice::new(&mut underlying_path.as_os_str().as_bytes());
            let endline = IoSlice::new(b"\n");
            locked_self.buffered_writer
                .write_vectored(&[slice, endline])
                .expect("writing to the access log failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        os::unix::prelude::MetadataExt,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use tempfile::tempdir;

    use crate::nodes::AccessLogger;

    use super::{DeduplicatingAccessLogger, LogFileAccessLogger};

    pub(crate) struct CountingAccessLogger {
        count: AtomicUsize,
    }

    impl CountingAccessLogger {
        pub fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl Default for CountingAccessLogger {
        fn default() -> Self {
            Self {
                count: AtomicUsize::new(0),
            }
        }
    }

    impl AccessLogger for Mutex<CountingAccessLogger> {
        fn record_directory_access(
            &self,
            _ino: u64,
            _underlying_path: &std::path::Path,
            _attr: &std::fs::Metadata,
        ) {
            if let Ok(locked_self) = self.lock() {
                locked_self.count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn test_deduplicating_access_logger() {
        let dir = tempdir().expect("Failed to create temporary directory");
        let metadata = std::fs::metadata(dir.path()).unwrap();

        let count = Arc::from(Mutex::new(CountingAccessLogger::default()));
        let dedup =
        Arc::new(Mutex::new(DeduplicatingAccessLogger::new(count)));

        let read_count = || -> usize { count.lock().unwrap().count() };
        assert_eq!(read_count(), 0);
        dedup.lock().unwrap().record_directory_access(metadata.ino(), dir.path(), &metadata);
        assert_eq!(read_count(), 1);
        dedup.lock().unwrap().record_directory_access(metadata.ino(), dir.path(), &metadata);
        assert_eq!(read_count(), 1);
    }

    #[test]
    fn test_log_file_access_logger() {
        let dir = tempdir().expect("Failed to create temporary directory");
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(subdir.as_path()).expect("Failed to create subdirectory");
        let metadata = std::fs::metadata(subdir.as_path()).unwrap();

        let log_file_path = dir.path().join("log_file");
        let file = File::create(log_file_path.as_path()).expect("Failed to open log file");
        {
            let access_logger = Mutex::new(LogFileAccessLogger::new(file));
            access_logger.record_directory_access(metadata.ino(), subdir.as_path(), &metadata);
        }
        let actual = String::from_utf8(
            std::fs::read(log_file_path.as_path()).expect("Failed to read log file"),
        )
        .unwrap();
        let expected = {
            let mut s = subdir.as_path().to_str().unwrap().to_owned();
            s.push('\n');
            s
        };

        assert_eq!(actual, expected);
    }
}
