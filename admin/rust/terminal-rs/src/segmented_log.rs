//! Recoverable output for one PTY instance. Offsets count payload bytes, not
//! framing bytes. A successful append is visible to replay before publication
//! to subscribers. This promises process-crash recovery, not power-loss durability.

use fs2::FileExt as LockFileExt;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"SYPTYLG\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 20;
const HEADER_LEN: u64 = HEADER_BYTES as u64;
const RECORD_HEADER_BYTES: usize = 8;
const RECORD_HEADER_LEN: u64 = RECORD_HEADER_BYTES as u64;

#[derive(Clone, Copy, Debug)]
pub struct LogLimits {
    /// Physical bytes including record and segment headers. One record may
    /// exceed the segment target, but must fit inside the retention budget.
    pub segment_bytes: u64,
    /// Physical bytes after successful retention. Appending may temporarily
    /// exceed this by one segment header plus one bounded record.
    pub retained_bytes: u64,
    pub max_record_bytes: u32,
}

impl Default for LogLimits {
    fn default() -> Self {
        Self {
            segment_bytes: 512 * 1024,
            retained_bytes: 32 * 1024 * 1024,
            max_record_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct AppendResult {
    pub end_offset: u64,
    /// The append committed even if retention failed. Callers must not retry
    /// the output bytes; report degraded retention separately.
    pub retention_error: Option<io::Error>,
}

#[derive(Debug)]
pub struct ReplayChunk {
    pub base_offset: u64,
    pub end_offset: u64,
    pub start_offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum ReplayRead {
    /// No payload is returned until the caller explicitly advances past the
    /// lost interval. A transport must publish this gap before requesting data.
    Gap {
        from: u64,
        to: u64,
        end_offset: u64,
    },
    Data(ReplayChunk),
}

#[derive(Clone)]
struct Record {
    start: u64,
    physical: u64,
    len: u32,
}

struct Segment {
    path: PathBuf,
    file: Arc<File>,
    start: u64,
    end: u64,
    physical_end: u64,
    records: Vec<Record>,
}

struct State {
    segments: VecDeque<Segment>,
    end: u64,
    physical_bytes: u64,
    write_failed: bool,
}

pub struct SegmentedLog {
    directory: PathBuf,
    limits: LogLimits,
    state: Mutex<State>,
    // Never unlink: replacing a locked inode would allow a second writer.
    writer_lock: File,
}

impl Drop for SegmentedLog {
    fn drop(&mut self) {
        // Closing this descriptor alone may leave the lock held by a copy
        // inherited during a concurrent fork/exec. Release ownership explicitly
        // while retaining the inode, so reopening does not spuriously fail.
        let _ = LockFileExt::unlock(&self.writer_lock);
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checksum(len: u32, bytes: &[u8]) -> u32 {
    let mut hash = crc32fast::Hasher::new();
    hash.update(&len.to_be_bytes());
    hash.update(bytes);
    hash.finalize()
}

fn segment_path(directory: &Path, start: u64) -> PathBuf {
    directory.join(format!("{start:020}.seg"))
}

impl SegmentedLog {
    /// The caller supplies a private directory unique to a session instance.
    /// Acquires an OS writer lock before inspecting or repairing any files.
    pub fn open(directory: &Path, limits: LogLimits) -> io::Result<Self> {
        if limits.segment_bytes == 0
            || limits.retained_bytes < limits.segment_bytes
            || limits.retained_bytes
                < HEADER_LEN + RECORD_HEADER_LEN + u64::from(limits.max_record_bytes)
            || limits.max_record_bytes == 0
            || limits.max_record_bytes > 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid log limits",
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        // Rust OpenOptions keeps O_CLOEXEC when adding custom O_NOFOLLOW.
        // Both are required: spawned shells must not retain the writer lock.
        let writer_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(".writer.lock"))?;
        LockFileExt::try_lock_exclusive(&writer_lock)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 log filename"))?;
            if name == ".writer.lock" || name == ".next" {
                continue;
            }
            let digits = name
                .strip_suffix(".seg")
                .ok_or_else(|| invalid("unexpected log file"))?;
            if digits.len() != 20 || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid("invalid segment filename"));
            }
            let start = digits
                .parse::<u64>()
                .map_err(|_| invalid("segment offset overflow"))?;
            paths.push((start, entry.path()));
        }
        paths.sort_by_key(|(start, _)| *start);
        let mut segments = VecDeque::new();
        let mut end = None;
        for (index, (start, path)) in paths.iter().enumerate() {
            if end.is_some_and(|previous| previous != *start) {
                return Err(invalid("non-contiguous log segments"));
            }
            let last = index + 1 == paths.len();
            let segment = recover_segment(path, *start, last, limits.max_record_bytes)?;
            if !last && segment.end == segment.start {
                return Err(invalid("empty closed segment"));
            }
            end = Some(segment.end);
            segments.push_back(segment);
        }
        // An interrupted segment-header write was never published. It has no
        // payload and cannot be the authority for an acknowledged offset.
        match fs::remove_file(directory.join(".next")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let end = end.unwrap_or(0);
        if segments.is_empty() {
            segments.push_back(create_segment(directory, end)?);
        }
        let physical_bytes = segments.iter().try_fold(0u64, |total, segment| {
            total
                .checked_add(segment.physical_end)
                .ok_or_else(|| invalid("log size overflow"))
        })?;
        Ok(Self {
            directory: directory.to_owned(),
            limits,
            state: Mutex::new(State {
                segments,
                end,
                physical_bytes,
                write_failed: false,
            }),
            writer_lock,
        })
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))
    }

    pub fn bounds(&self) -> io::Result<(u64, u64)> {
        let state = self.lock()?;
        Ok((
            state
                .segments
                .front()
                .ok_or_else(|| invalid("missing active segment"))?
                .start,
            state.end,
        ))
    }

    pub fn append(&self, bytes: &[u8]) -> io::Result<AppendResult> {
        self.append_using(bytes, |mut file, record| file.write_all(record))
    }

    fn append_using(
        &self,
        bytes: &[u8],
        write_record: impl FnOnce(&File, &[u8]) -> io::Result<()>,
    ) -> io::Result<AppendResult> {
        if bytes.len() > self.limits.max_record_bytes as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record exceeds limit",
            ));
        }
        let mut state = self.lock()?;
        if state.write_failed {
            return Err(io::Error::other(
                "log requires recovery after write failure",
            ));
        }
        if bytes.is_empty() {
            return Ok(AppendResult {
                end_offset: state.end,
                retention_error: None,
            });
        }
        let len = u32::try_from(bytes.len()).map_err(|_| invalid("record length overflow"))?;
        let end = state
            .end
            .checked_add(u64::from(len))
            .ok_or_else(|| invalid("log offset overflow"))?;
        let active = state.segments.back().expect("active segment");
        if active.end > active.start
            && active.physical_end + RECORD_HEADER_LEN + u64::from(len) > self.limits.segment_bytes
        {
            let next = create_segment(&self.directory, state.end)?;
            state.segments.push_back(next);
            state.physical_bytes += HEADER_LEN;
        }
        let active = state.segments.back_mut().expect("active segment");
        let mut record = Vec::with_capacity(bytes.len() + RECORD_HEADER_BYTES);
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(&checksum(len, bytes).to_be_bytes());
        record.extend_from_slice(bytes);
        // A partial write poisons this writer. Recovery is explicit; another
        // append must never put valid bytes after a torn record.
        if let Err(error) = write_record(&active.file, &record) {
            state.write_failed = true;
            return Err(error);
        }
        active.records.push(Record {
            start: active.end,
            physical: active.physical_end + RECORD_HEADER_LEN,
            len,
        });
        active.end = end;
        active.physical_end += record.len() as u64;
        state.end = end;
        state.physical_bytes += record.len() as u64;
        let retention_error = prune(&mut state, self.limits.retained_bytes).err();
        Ok(AppendResult {
            end_offset: end,
            retention_error,
        })
    }

    /// Takes a bounded snapshot under the writer lock, then reads with pread.
    /// Open descriptors keep removed segments valid for this one read. Neither
    /// disk reads nor subsequent socket sends hold the append/retention lock.
    pub fn read(&self, next_offset: u64, max_bytes: usize) -> io::Result<ReplayRead> {
        if max_bytes == 0 || max_bytes > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid replay chunk limit",
            ));
        }
        let (base, end, start, reads) = {
            let state = self.lock()?;
            if next_offset > state.end {
                return Err(invalid("cursor beyond committed log"));
            }
            let base = state
                .segments
                .front()
                .ok_or_else(|| invalid("missing active segment"))?
                .start;
            if next_offset < base {
                return Ok(ReplayRead::Gap {
                    from: next_offset,
                    to: base,
                    end_offset: state.end,
                });
            }
            let start = next_offset;
            let stop = start.saturating_add(max_bytes as u64).min(state.end);
            let mut reads = Vec::new();
            for segment in &state.segments {
                if segment.end <= start || segment.start >= stop {
                    continue;
                }
                let first = segment
                    .records
                    .partition_point(|r| r.start + u64::from(r.len) <= start);
                for record in &segment.records[first..] {
                    if record.start >= stop {
                        break;
                    }
                    let from = start.max(record.start);
                    let to = stop.min(record.start + u64::from(record.len));
                    reads.push((
                        Arc::clone(&segment.file),
                        record.physical + from - record.start,
                        usize::try_from(to - from)
                            .map_err(|_| invalid("replay length overflow"))?,
                    ));
                }
            }
            (base, state.end, start, reads)
        };
        let mut bytes = Vec::with_capacity(max_bytes);
        for (file, physical, len) in reads {
            let offset = bytes.len();
            bytes.resize(offset + len, 0);
            file.read_exact_at(&mut bytes[offset..], physical)?;
        }
        Ok(ReplayRead::Data(ReplayChunk {
            base_offset: base,
            end_offset: end,
            start_offset: start,
            bytes,
        }))
    }
}

fn create_segment(directory: &Path, start: u64) -> io::Result<Segment> {
    let path = segment_path(directory, start);
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "segment already exists",
        ));
    }
    let staging = directory.join(".next");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staging)?;
    file.write_all(MAGIC)?;
    file.write_all(&VERSION.to_be_bytes())?;
    file.write_all(&start.to_be_bytes())?;
    fs::rename(staging, &path)?;
    Ok(Segment {
        path,
        file: Arc::new(file),
        start,
        end: start,
        physical_end: HEADER_LEN,
        records: Vec::new(),
    })
}

fn recover_segment(path: &Path, start: u64, last: bool, max_record: u32) -> io::Result<Segment> {
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut header = [0u8; HEADER_BYTES];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC
        || u32::from_be_bytes(header[8..12].try_into().expect("version")) != VERSION
        || u64::from_be_bytes(header[12..20].try_into().expect("offset")) != start
    {
        return Err(invalid("segment header mismatch"));
    }
    let size = file.metadata()?.len();
    let mut physical = HEADER_LEN;
    let mut end = start;
    let mut records = Vec::new();
    while physical < size {
        if size - physical < RECORD_HEADER_LEN {
            if !last {
                return Err(invalid("torn closed segment"));
            }
            file.set_len(physical)?;
            break;
        }
        let mut framing = [0u8; RECORD_HEADER_BYTES];
        file.read_exact(&mut framing)?;
        let len = u32::from_be_bytes(framing[..4].try_into().expect("length"));
        if len == 0 || len > max_record {
            return Err(invalid("invalid record length"));
        }
        if size - physical - RECORD_HEADER_LEN < u64::from(len) {
            if !last {
                return Err(invalid("torn closed segment"));
            }
            file.set_len(physical)?;
            break;
        }
        let mut bytes = vec![0; len as usize];
        file.read_exact(&mut bytes)?;
        let expected = u32::from_be_bytes(framing[4..].try_into().expect("checksum"));
        if checksum(len, &bytes) != expected {
            return Err(invalid("record checksum mismatch"));
        }
        records.push(Record {
            start: end,
            physical: physical + RECORD_HEADER_LEN,
            len,
        });
        end = end
            .checked_add(u64::from(len))
            .ok_or_else(|| invalid("log offset overflow"))?;
        physical += RECORD_HEADER_LEN + u64::from(len);
    }
    Ok(Segment {
        path: path.to_owned(),
        file: Arc::new(file),
        start,
        end,
        physical_end: physical,
        records,
    })
}

fn prune(state: &mut State, retained_bytes: u64) -> io::Result<()> {
    // Oldest first: interruption leaves a contiguous suffix. Never remove the
    // active segment, including when it is empty; its name retains the cursor.
    while state.segments.len() > 1 && state.physical_bytes > retained_bytes {
        fs::remove_file(&state.segments.front().expect("segment").path)?;
        state.physical_bytes -= state.segments.pop_front().expect("segment").physical_end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(log: &SegmentedLog, offset: u64, limit: usize) -> ReplayChunk {
        match log.read(offset, limit).unwrap() {
            ReplayRead::Data(chunk) => chunk,
            gap @ ReplayRead::Gap { .. } => panic!("unexpected gap: {gap:?}"),
        }
    }

    fn limits() -> LogLimits {
        LogLimits {
            segment_bytes: 40,
            retained_bytes: 144,
            max_record_bytes: 64,
        }
    }

    #[test]
    fn replay_crosses_records_segments_and_reopen_with_stable_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        log.append(b"abcdefgh").unwrap();
        log.append(b"ijklmnop").unwrap();
        log.append(b"qrstuvwx").unwrap();
        let chunk = data(&log, 5, 13);
        assert_eq!(chunk.bytes, b"fghijklmnopqr");
        assert_eq!(
            (chunk.base_offset, chunk.start_offset, chunk.end_offset),
            (0, 5, 24)
        );
        drop(log);
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        assert_eq!(log.bounds().unwrap(), (0, 24));
        log.append(b"yz").unwrap();
        assert_eq!(data(&log, 18, 64).bytes, b"stuvwxyz");
    }

    #[test]
    fn every_torn_append_cut_recovers_only_complete_records_and_rejects_more_writes() {
        let payload = b"second-record";
        for cut in 0..payload.len() + RECORD_HEADER_BYTES {
            let dir = tempfile::tempdir().unwrap();
            let mut config = limits();
            config.segment_bytes = 64;
            config.retained_bytes = 128;
            let log = SegmentedLog::open(dir.path(), config).unwrap();
            log.append(b"first").unwrap();
            let failed = log.append_using(payload, |mut file, record| {
                file.write_all(&record[..cut])?;
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            });
            assert!(failed.is_err(), "cut {cut}");
            assert_eq!(log.bounds().unwrap(), (0, 5));
            assert!(log.append(b"must-not-follow-a-torn-record").is_err());
            assert_eq!(data(&log, 0, 64).bytes, b"first");
            drop(log);
            let log = SegmentedLog::open(dir.path(), config).unwrap();
            assert_eq!(data(&log, 0, 64).bytes, b"first", "cut {cut}");
            log.append(b"after-recovery").unwrap();
            assert_eq!(data(&log, 0, 64).bytes, b"firstafter-recovery");
        }
    }

    #[test]
    fn interrupted_segment_publication_never_creates_a_visible_partial_header() {
        for cut in 0..HEADER_BYTES {
            let dir = tempfile::tempdir().unwrap();
            let log = SegmentedLog::open(dir.path(), limits()).unwrap();
            log.append(b"retained").unwrap();
            drop(log);
            fs::write(dir.path().join(".next"), vec![0; cut]).unwrap();
            let log = SegmentedLog::open(dir.path(), limits()).unwrap();
            assert_eq!(data(&log, 0, 64).bytes, b"retained");
            assert!(!dir.path().join(".next").exists());
        }
    }

    #[test]
    fn retention_returns_an_explicit_gap_and_keeps_offsets_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        for byte in 0u8..20 {
            log.append(&[byte; 8]).unwrap();
        }
        assert!(matches!(
            log.read(0, 1024).unwrap(),
            ReplayRead::Gap {
                from: 0,
                to: 128,
                end_offset: 160
            }
        ));
        let chunk = data(&log, 128, 1024);
        assert_eq!(
            (chunk.base_offset, chunk.start_offset, chunk.end_offset),
            (128, 128, 160)
        );
        assert_eq!(
            chunk.bytes,
            (16u8..20).flat_map(|byte| [byte; 8]).collect::<Vec<_>>()
        );
        drop(log);
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        assert_eq!(log.bounds().unwrap(), (128, 160));
        assert_eq!(log.append(b"continue").unwrap().end_offset, 168);
        assert_eq!(data(&log, 160, 64).bytes, b"continue");
    }

    #[test]
    fn retention_interrupted_after_each_unlink_leaves_a_contiguous_suffix() {
        for removed in 0..4 {
            let dir = tempfile::tempdir().unwrap();
            let mut config = limits();
            config.retained_bytes = 1024;
            let log = SegmentedLog::open(dir.path(), config).unwrap();
            for byte in 0u8..4 {
                log.append(&[byte; 8]).unwrap();
            }
            drop(log);
            // Named failure point: process dies after the Nth oldest unlink.
            // The active segment is never eligible for deletion.
            for index in 0..removed {
                fs::remove_file(segment_path(dir.path(), index * 8)).unwrap();
            }
            let log = SegmentedLog::open(dir.path(), config).unwrap();
            assert_eq!(log.bounds().unwrap(), (removed * 8, 32));
            assert_eq!(
                data(&log, removed * 8, 64).bytes,
                (u8::try_from(removed).unwrap()..4)
                    .flat_map(|byte| [byte; 8])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn corruption_closed_tail_gaps_and_wrong_versions_fail_closed() {
        for failure in [
            "checksum",
            "closed-tail",
            "gap",
            "version",
            "offset",
            "oversize",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let log = SegmentedLog::open(dir.path(), limits()).unwrap();
            for _ in 0..3 {
                log.append(b"abcdefgh").unwrap();
            }
            drop(log);
            let path = segment_path(dir.path(), 0);
            match failure {
                "checksum" => {
                    let mut data = fs::read(&path).unwrap();
                    data[28] ^= 1;
                    fs::write(&path, data).unwrap();
                }
                "closed-tail" => {
                    OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(HEADER_LEN + 5)
                        .unwrap();
                }
                "gap" => {
                    fs::remove_file(segment_path(dir.path(), 8)).unwrap();
                }
                "version" => {
                    let mut data = fs::read(&path).unwrap();
                    data[11] = 2;
                    fs::write(&path, data).unwrap();
                }
                "offset" => {
                    fs::rename(&path, segment_path(dir.path(), 1)).unwrap();
                }
                "oversize" => {
                    let mut data = fs::read(&path).unwrap();
                    data[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
                    fs::write(&path, data).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                SegmentedLog::open(dir.path(), limits()).is_err(),
                "{failure}"
            );
        }
    }

    #[test]
    fn second_writer_cannot_touch_live_files_or_lock_inode() {
        let dir = tempfile::tempdir().unwrap();
        let first = SegmentedLog::open(dir.path(), limits()).unwrap();
        first.append(b"original").unwrap();
        let before = fs::read(segment_path(dir.path(), 0)).unwrap();
        assert!(SegmentedLog::open(dir.path(), limits()).is_err());
        assert_eq!(fs::read(segment_path(dir.path(), 0)).unwrap(), before);
        assert_eq!(data(&first, 0, 64).bytes, b"original");
        drop(first);
        assert!(SegmentedLog::open(dir.path(), limits()).is_ok());
    }

    #[test]
    fn replay_is_bounded_and_rejects_future_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        assert!(log.append(&[0; 65]).is_err());
        log.append(b"abc").unwrap();
        assert!(log.read(4, 64).is_err());
        assert!(log.read(0, 0).is_err());
        assert!(log.read(0, usize::MAX).is_err());
        assert_eq!(data(&log, 1, 1).bytes, b"b");
        assert!(data(&log, 3, 1).bytes.is_empty());
    }

    #[test]
    fn one_byte_appends_obey_the_physical_retention_budget() {
        let dir = tempfile::tempdir().unwrap();
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        for _ in 0..1000 {
            assert!(log.append(b"x").unwrap().retention_error.is_none());
            let physical: u64 = fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().metadata().unwrap().len())
                .sum();
            assert!(
                physical <= limits().retained_bytes,
                "physical bytes: {physical}"
            );
        }
        let (base, end) = log.bounds().unwrap();
        assert!(base > 900);
        assert_eq!(end, 1000);
        assert!(
            matches!(log.read(0, 64).unwrap(), ReplayRead::Gap { from: 0, to, .. } if to == base)
        );
        drop(log);
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        assert_eq!(log.bounds().unwrap(), (base, end));
    }

    #[test]
    fn dropping_writer_releases_lock_even_with_a_duplicated_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let log = SegmentedLog::open(dir.path(), limits()).unwrap();
        // Models a descriptor inherited during another thread's fork/exec
        // window. Close-on-exec does not close it until that exec happens.
        let inherited = log.writer_lock.try_clone().unwrap();
        drop(log);
        let reopened = SegmentedLog::open(dir.path(), limits());
        assert!(reopened.is_ok(), "owner drop must explicitly unlock");
        drop(inherited);
    }
}
