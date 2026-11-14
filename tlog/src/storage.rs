//! Crash-safe append-only storage for the transparency log.
//!
//! Layout inside the data directory:
//!   leaves.dat      append-only records: u32 LE length + payload
//!   level_00.dat    32-byte hashes, level 0 = leaf hashes
//!   level_01.dat    level 1 interior nodes, ...
//!   commit / commit.tmp   16 bytes: tree_size (u64 LE) + leaves.dat length (u64 LE)
//!
//! Durability protocol per commit:
//!   1. append buffered records to leaves.dat and node hashes to level files
//!   2. fsync leaves.dat and every touched level file
//!   3. write commit.tmp, fsync, rename to commit, fsync the directory
//!
//! Recovery on open: read `commit`; any data beyond the committed size (from a
//! crash between steps 1 and 3) is truncated. A shorter file means real
//! corruption and is an error.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::merkle::{self, NodeSource, HASH_LEN};

const MAX_RECORD: usize = 64 * 1024 * 1024;

pub struct LogStorage {
    dir: PathBuf,
    leaves: File,
    offsets: Vec<u64>, // byte offset of each record in leaves.dat
    leaves_len: u64,
    levels: Vec<File>,
    counts: Vec<u64>, // committed+buffered node count per level
    size: u64,
    leaves_buf: Vec<u8>,
    level_bufs: Vec<Vec<u8>>,
}

fn corrupt(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("corrupt log: {}", msg))
}

impl LogStorage {
    pub fn open(dir: &Path) -> io::Result<LogStorage> {
        fs::create_dir_all(dir)?;
        // Discard a stale commit.tmp: it was never renamed, so the old commit stands.
        let tmp = dir.join("commit.tmp");
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        let (size, leaves_len) = match fs::read(dir.join("commit")) {
            Ok(b) if b.len() == 16 => (
                u64::from_le_bytes(b[0..8].try_into().unwrap()),
                u64::from_le_bytes(b[8..16].try_into().unwrap()),
            ),
            Ok(_) => return Err(corrupt("bad commit file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (0, 0),
            Err(e) => return Err(e),
        };

        // leaves.dat: truncate crash leftovers, then rebuild the offset index.
        let leaves_path = dir.join("leaves.dat");
        let leaves = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&leaves_path)?;
        let actual = leaves.metadata()?.len();
        if actual < leaves_len {
            return Err(corrupt("leaves.dat shorter than committed size"));
        }
        if actual > leaves_len {
            leaves.set_len(leaves_len)?;
        }
        let offsets = scan_leaves(&leaves, size, leaves_len)?;

        // level files: expected length is exactly floor(size / 2^level) * 32.
        let nlevels = if size == 0 {
            0
        } else {
            (64 - (size - 1).leading_zeros()) as usize
        };
        let mut levels = Vec::new();
        let mut counts = Vec::new();
        for l in 0..nlevels {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(level_path(dir, l as u32))?;
            let expect = (size >> l) * HASH_LEN as u64;
            let got = f.metadata()?.len();
            if got < expect {
                return Err(corrupt(&format!("level {} file too short", l)));
            }
            if got > expect {
                f.set_len(expect)?;
            }
            levels.push(f);
            counts.push(size >> l);
        }

        Ok(LogStorage {
            dir: dir.to_path_buf(),
            leaves,
            offsets,
            leaves_len,
            levels,
            counts,
            size,
            leaves_buf: Vec::new(),
            level_bufs: (0..nlevels).map(|_| Vec::new()).collect(),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn ensure_level(&mut self, level: u32) -> io::Result<()> {
        while self.levels.len() <= level as usize {
            let l = self.levels.len() as u32;
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(level_path(&self.dir, l))?;
            self.levels.push(f);
            self.counts.push(0);
            self.level_bufs.push(Vec::new());
        }
        Ok(())
    }

    /// Buffer an append. Not durable until `commit()` succeeds.
    pub fn append(&mut self, record: &[u8]) -> io::Result<u64> {
        if record.len() > MAX_RECORD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "record too large"));
        }
        let index = self.size;
        self.leaves_buf
            .extend_from_slice(&(record.len() as u32).to_le_bytes());
        self.leaves_buf.extend_from_slice(record);

        let new_size = self.size + 1;
        self.ensure_level(0)?;
        self.level_bufs[0].extend_from_slice(&merkle::leaf_hash(record));
        self.counts[0] += 1;

        // A new node forms at level L+1 whenever new_size is a multiple of 2^(L+1).
        let mut level = 0u32;
        while new_size % (2u64 << level) == 0 {
            let c = self.counts[level as usize];
            let l = self.node_io(level, c - 2)?;
            let r = self.node_io(level, c - 1)?;
            let parent = merkle::node_hash(&l, &r);
            self.ensure_level(level + 1)?;
            self.level_bufs[(level + 1) as usize].extend_from_slice(&parent);
            self.counts[(level + 1) as usize] += 1;
            level += 1;
        }
        self.size = new_size;
        Ok(index)
    }

    /// Flush buffered appends and atomically advance the commit point.
    pub fn commit(&mut self) -> io::Result<()> {
        if self.leaves_buf.is_empty() && self.level_bufs.iter().all(|b| b.is_empty()) {
            return Ok(());
        }
        self.leaves.write_all(&self.leaves_buf)?;
        self.leaves_len += self.leaves_buf.len() as u64;
        self.leaves_buf.clear();
        for (l, buf) in self.level_bufs.iter_mut().enumerate() {
            if !buf.is_empty() {
                self.levels[l].write_all(buf)?;
                buf.clear();
            }
        }
        self.leaves.sync_data()?;
        for f in &self.levels {
            f.sync_data()?;
        }
        // Atomic commit-point update.
        let tmp = self.dir.join("commit.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&self.size.to_le_bytes())?;
            f.write_all(&self.leaves_len.to_le_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join("commit"))?;
        File::open(&self.dir)?.sync_all()?;
        // Rebuild offsets for the records we just flushed.
        self.offsets = scan_leaves(&self.leaves, self.size, self.leaves_len)?;
        Ok(())
    }

    fn node_io(&self, level: u32, index: u64) -> io::Result<[u8; HASH_LEN]> {
        let buf = &self.level_bufs[level as usize];
        let buffered = (buf.len() / HASH_LEN) as u64;
        let flushed = self.counts[level as usize] - buffered;
        let mut out = [0u8; HASH_LEN];
        if index >= flushed {
            let off = ((index - flushed) as usize) * HASH_LEN;
            out.copy_from_slice(&buf[off..off + HASH_LEN]);
        } else {
            self.levels[level as usize].read_exact_at(&mut out, index * HASH_LEN as u64)?;
        }
        Ok(out)
    }

    /// Read a record by leaf index. Only committed records are served.
    pub fn record(&self, index: u64) -> io::Result<Vec<u8>> {
        if (index as usize) >= self.offsets.len() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "index out of range"));
        }
        let off = self.offsets[index as usize];
        let mut lenb = [0u8; 4];
        self.leaves.read_exact_at(&mut lenb, off)?;
        let len = u32::from_le_bytes(lenb) as usize;
        let mut rec = vec![0u8; len];
        self.leaves.read_exact_at(&mut rec, off + 4)?;
        Ok(rec)
    }

    /// Current tree root hash.
    pub fn root(&self) -> io::Result<[u8; HASH_LEN]> {
        merkle::root(self, self.size)
            .ok_or_else(|| corrupt("missing nodes computing root"))
    }
}

impl NodeSource for LogStorage {
    fn node(&self, level: u32, index: u64) -> Option<[u8; HASH_LEN]> {
        if (level as usize) >= self.levels.len() || index >= self.counts[level as usize] {
            return None;
        }
        self.node_io(level, index).ok()
    }
}

fn level_path(dir: &Path, level: u32) -> PathBuf {
    dir.join(format!("level_{:02}.dat", level))
}

/// Rebuild the record offset index by scanning the committed leaves file.
fn scan_leaves(f: &File, size: u64, leaves_len: u64) -> io::Result<Vec<u64>> {
    let mut offsets = Vec::with_capacity(size as usize);
    // Read the whole committed region (1M records ~ tens of MB, fine in memory).
    let mut buf = vec![0u8; leaves_len as usize];
    if !buf.is_empty() {
        f.read_exact_at(&mut buf, 0)?;
    }
    let mut pos = 0usize;
    for _ in 0..size {
        if pos + 4 > buf.len() {
            return Err(corrupt("leaves.dat truncated"));
        }
        offsets.push(pos as u64);
        let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        if len > MAX_RECORD || pos + 4 + len > buf.len() {
            return Err(corrupt("bad record length"));
        }
        pos += 4 + len;
    }
    if pos as u64 != leaves_len {
        return Err(corrupt("leaves.dat length mismatch"));
    }
    Ok(offsets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tlog-store-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_commit_reopen_root_stable() {
        let dir = tempdir();
        let root1;
        {
            let mut s = LogStorage::open(&dir).unwrap();
            for i in 0..1000u32 {
                s.append(format!("rec-{}", i).as_bytes()).unwrap();
            }
            s.commit().unwrap();
            assert_eq!(s.size(), 1000);
            root1 = s.root().unwrap();
            assert_eq!(s.record(500).unwrap(), b"rec-500");
        }
        {
            let s = LogStorage::open(&dir).unwrap();
            assert_eq!(s.size(), 1000);
            assert_eq!(s.root().unwrap(), root1);
            assert_eq!(s.record(0).unwrap(), b"rec-0");
            assert_eq!(s.record(999).unwrap(), b"rec-999");
            // proofs verify against the reopened tree
            let path = merkle::audit_path(&s, 500, 1000).unwrap();
            let lh = merkle::leaf_hash(b"rec-500");
            assert!(merkle::verify_inclusion(&lh, 500, 1000, &path, &root1));
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn crash_recovery_truncates_uncommitted_tail() {
        let dir = tempdir();
        let root_committed;
        {
            let mut s = LogStorage::open(&dir).unwrap();
            for i in 0..100u32 {
                s.append(format!("rec-{}", i).as_bytes()).unwrap();
            }
            s.commit().unwrap();
            root_committed = s.root().unwrap();
        }
        // Simulate a crash mid-append: garbage bytes appended to data files,
        // commit point never advanced.
        for name in ["leaves.dat", "level_00.dat", "level_01.dat", "level_02.dat"] {
            let mut f = OpenOptions::new().append(true).open(dir.join(name)).unwrap();
            f.write_all(&[0xAB; 777]).unwrap();
        }
        drop(File::create(dir.join("commit.tmp")).unwrap()); // half-written commit tmp
        {
            let s = LogStorage::open(&dir).unwrap();
            assert_eq!(s.size(), 100);
            assert_eq!(s.root().unwrap(), root_committed);
            assert_eq!(s.record(99).unwrap(), b"rec-99");
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cross_check_root_with_naive() {
        let dir = tempdir();
        let mut s = LogStorage::open(&dir).unwrap();
        let mut leaves = Vec::new();
        for i in 0..300u32 {
            let rec = format!("artifact-{}.tar.gz:sha256:{:064x}", i, i * 7);
            leaves.push(merkle::leaf_hash(rec.as_bytes()));
            s.append(rec.as_bytes()).unwrap();
            if i % 17 == 0 {
                s.commit().unwrap();
            }
        }
        s.commit().unwrap();
        fn naive(leaves: &[[u8; 32]]) -> [u8; 32] {
            match leaves.len() {
                0 => merkle::empty_root(),
                1 => leaves[0],
                n => {
                    let k = merkle::split(n as u64) as usize;
                    merkle::node_hash(&naive(&leaves[..k]), &naive(&leaves[k..]))
                }
            }
        }
        assert_eq!(s.root().unwrap(), naive(&leaves));
        // consistency proof between two committed sizes
        let p = merkle::consistency_proof(&s, 100, 300).unwrap();
        let r100 = {
            // recompute root at size 100 naively
            naive(&leaves[..100])
        };
        assert!(merkle::verify_consistency(100, 300, &p, &r100, &s.root().unwrap()));
        fs::remove_dir_all(&dir).ok();
    }

    /// Large-scale check against a bench-produced log: set TLOG_BIG_DIR to the
    /// bench data dir. Verifies inclusion + consistency proofs at that size.
    #[test]
    fn big_log_proofs() {
        let dir = match std::env::var("TLOG_BIG_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => return, // skipped unless pointed at a big log
        };
        let s = LogStorage::open(&dir).unwrap();
        let n = s.size();
        assert!(n >= 1000);
        let root = s.root().unwrap();
        // inclusion proofs at scattered indices
        for idx in [0, 1, n / 3, n / 2, n - 2, n - 1] {
            let rec = s.record(idx).unwrap();
            let lh = merkle::leaf_hash(&rec);
            let path = merkle::audit_path(&s, idx, n).unwrap();
            assert!(merkle::verify_inclusion(&lh, idx, n, &path, &root), "inclusion failed at {}", idx);
        }
        // consistency proofs across the full range, verified against roots
        // recomputed from the same storage (root_at helper via mth_range)
        for m in [1, 2, 7, n / 2, n - 1] {
            let rm = merkle::root(&s, m).unwrap();
            let p = merkle::consistency_proof(&s, m, n).unwrap();
            assert!(merkle::verify_consistency(m, n, &p, &rm, &root), "consistency failed m={}", m);
        }
    }
}
