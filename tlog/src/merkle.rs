//! RFC 6962 Merkle tree: hashing, inclusion (audit) proofs, consistency proofs.
//!
//! Hashing scheme (RFC 6962 §2.1):
//!   MTH({})       = SHA-256("")
//!   MTH({d})      = SHA-256(0x00 || d)
//!   MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//!   where k = largest power of 2 strictly less than n.

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

pub fn leaf_hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// MTH of the empty tree: SHA-256 of the empty string.
pub fn empty_root() -> [u8; HASH_LEN] {
    Sha256::digest([]).into()
}

/// Largest power of 2 strictly less than n. Requires n >= 2.
pub fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Source of interior node hashes. `node(level, index)` returns the hash of the
/// node covering leaves [index*2^level, (index+1)*2^level).
pub trait NodeSource {
    fn node(&self, level: u32, index: u64) -> Option<[u8; HASH_LEN]>;
}

/// MTH of leaves [start, end). All complete subtrees must be present in `s`.
pub fn mth_range<S: NodeSource + ?Sized>(s: &S, start: u64, end: u64) -> Option<[u8; HASH_LEN]> {
    let len = end - start;
    debug_assert!(len >= 1);
    if len.is_power_of_two() {
        debug_assert_eq!(start % len, 0, "unaligned subtree");
        return s.node(len.trailing_zeros(), start / len);
    }
    let k = split(len);
    let l = mth_range(s, start, start + k)?;
    let r = mth_range(s, start + k, end)?;
    Some(node_hash(&l, &r))
}

/// Root of a tree of `size` leaves.
pub fn root<S: NodeSource + ?Sized>(s: &S, size: u64) -> Option<[u8; HASH_LEN]> {
    if size == 0 {
        return Some(empty_root());
    }
    mth_range(s, 0, size)
}

/// RFC 6962 §2.1.1 audit path for leaf index `m` (0-based) in a tree of size `n`.
pub fn audit_path<S: NodeSource + ?Sized>(s: &S, m: u64, n: u64) -> Option<Vec<[u8; HASH_LEN]>> {
    fn rec<S: NodeSource + ?Sized>(
        s: &S,
        m: u64,
        start: u64,
        n: u64,
        out: &mut Vec<[u8; HASH_LEN]>,
    ) -> Option<()> {
        if n == 1 {
            return Some(());
        }
        let k = split(n);
        if m < k {
            rec(s, m, start, k, out)?;
            out.push(mth_range(s, start + k, start + n)?);
        } else {
            rec(s, m - k, start + k, n - k, out)?;
            out.push(mth_range(s, start, start + k)?);
        }
        Some(())
    }
    if m >= n || n == 0 {
        return None;
    }
    let mut out = Vec::new();
    rec(s, m, 0, n, &mut out)?;
    Some(out)
}

/// Verify an inclusion proof: recompute the root from the leaf hash and path.
pub fn verify_inclusion(
    leaf: &[u8; HASH_LEN],
    m: u64,
    n: u64,
    path: &[[u8; HASH_LEN]],
    expected_root: &[u8; HASH_LEN],
) -> bool {
    fn rec(m: u64, n: u64, leaf: &[u8; HASH_LEN], path: &[[u8; HASH_LEN]], i: &mut usize) -> Option<[u8; HASH_LEN]> {
        if n == 1 {
            return Some(*leaf);
        }
        let k = split(n);
        if m < k {
            let l = rec(m, k, leaf, path, i)?;
            let r = *path.get(*i)?;
            *i += 1;
            Some(node_hash(&l, &r))
        } else {
            let r = rec(m - k, n - k, leaf, path, i)?;
            let l = *path.get(*i)?;
            *i += 1;
            Some(node_hash(&l, &r))
        }
    }
    if m >= n || n == 0 {
        return false;
    }
    let mut i = 0;
    match rec(m, n, leaf, path, &mut i) {
        Some(r) => i == path.len() && &r == expected_root,
        None => false,
    }
}

/// RFC 6962 §2.1.2 consistency proof between tree sizes `m` and `n` (0 < m <= n).
pub fn consistency_proof<S: NodeSource + ?Sized>(s: &S, m: u64, n: u64) -> Option<Vec<[u8; HASH_LEN]>> {
    // SUBPROOF(m, D_n, b) as defined in the RFC.
    fn rec<S: NodeSource + ?Sized>(
        s: &S,
        m: u64,
        start: u64,
        n: u64,
        b: bool,
        out: &mut Vec<[u8; HASH_LEN]>,
    ) -> Option<()> {
        if m == n {
            if !b {
                out.push(mth_range(s, start, start + n)?);
            }
            return Some(());
        }
        let k = split(n);
        if m <= k {
            rec(s, m, start, k, b, out)?;
            out.push(mth_range(s, start + k, start + n)?);
        } else {
            rec(s, m - k, start + k, n - k, false, out)?;
            out.push(mth_range(s, start, start + k)?);
        }
        Some(())
    }
    if m == 0 || m > n {
        return None;
    }
    if m == n {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    rec(s, m, 0, n, true, &mut out)?;
    Some(out)
}

/// Verify a consistency proof between `old_root` (size m) and `new_root` (size n).
pub fn verify_consistency(
    m: u64,
    n: u64,
    proof: &[[u8; HASH_LEN]],
    old_root: &[u8; HASH_LEN],
    new_root: &[u8; HASH_LEN],
) -> bool {
    // Reconstruct both roots from the proof. `known` carries the old root down
    // the b=true chain (where the proof contributes no hash at m == n).
    fn rec(
        m: u64,
        n: u64,
        b: bool,
        known: Option<&[u8; HASH_LEN]>,
        proof: &[[u8; HASH_LEN]],
        i: &mut usize,
    ) -> Option<([u8; HASH_LEN], [u8; HASH_LEN])> {
        if m == n {
            if b {
                let h = known?;
                return Some((*h, *h));
            }
            let h = *proof.get(*i)?;
            *i += 1;
            return Some((h, h));
        }
        let k = split(n);
        if m <= k {
            let (rm, rk) = rec(m, k, b, known, proof, i)?;
            let right = *proof.get(*i)?;
            *i += 1;
            Some((rm, node_hash(&rk, &right)))
        } else {
            let (rm2, rnk) = rec(m - k, n - k, false, None, proof, i)?;
            let left = *proof.get(*i)?;
            *i += 1;
            Some((node_hash(&left, &rm2), node_hash(&left, &rnk)))
        }
    }
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && old_root == new_root;
    }
    let mut i = 0;
    match rec(m, n, true, Some(old_root), proof, &mut i) {
        Some((rm, rn)) => i == proof.len() && &rm == old_root && &rn == new_root,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory tree computing nodes on demand from leaf hashes (naive, slow).
    struct MemTree {
        leaves: Vec<[u8; HASH_LEN]>,
    }

    impl MemTree {
        fn from_records(records: &[&[u8]]) -> Self {
            MemTree {
                leaves: records.iter().map(|r| leaf_hash(r)).collect(),
            }
        }
        fn naive_mth(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
            match leaves.len() {
                0 => empty_root(),
                1 => leaves[0],
                n => {
                    let k = split(n as u64) as usize;
                    node_hash(&Self::naive_mth(&leaves[..k]), &Self::naive_mth(&leaves[k..]))
                }
            }
        }
    }

    impl NodeSource for MemTree {
        fn node(&self, level: u32, index: u64) -> Option<[u8; HASH_LEN]> {
            let span = 1usize << level;
            let start = index as usize * span;
            let end = start + span;
            if end > self.leaves.len() {
                return None;
            }
            Some(Self::naive_mth(&self.leaves[start..end]))
        }
    }

    fn records(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("record-{}", i).into_bytes()).collect()
    }

    #[test]
    fn rfc6962_empty_and_single() {
        // MTH({}) = SHA-256("")
        assert_eq!(
            hexutil_to_hex(&empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // MTH({""}) = SHA-256(0x00) = 6e340b9c...
        let t = MemTree::from_records(&[b""]);
        assert_eq!(
            hexutil_to_hex(&t.node(0, 0).unwrap()),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    fn hexutil_to_hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn inclusion_proofs_all_sizes() {
        for n in 1..=130usize {
            let recs = records(n);
            let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
            let t = MemTree::from_records(&refs);
            let expected = MemTree::naive_mth(&t.leaves);
            assert_eq!(root(&t, n as u64).unwrap(), expected, "root mismatch n={}", n);
            for m in 0..n as u64 {
                let path = audit_path(&t, m, n as u64).unwrap();
                assert!(
                    verify_inclusion(&t.leaves[m as usize], m, n as u64, &path, &expected),
                    "inclusion failed n={} m={}",
                    n,
                    m
                );
                // tamper: flip a bit in the leaf
                let mut bad = t.leaves[m as usize];
                bad[0] ^= 1;
                assert!(!verify_inclusion(&bad, m, n as u64, &path, &expected));
                // tamper: wrong root
                let mut badroot = expected;
                badroot[31] ^= 1;
                assert!(!verify_inclusion(&t.leaves[m as usize], m, n as u64, &path, &badroot));
            }
        }
    }

    #[test]
    fn consistency_proofs_all_pairs() {
        let n = 70usize;
        let recs = records(n);
        let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
        let t = MemTree::from_records(&refs);
        let roots: Vec<[u8; 32]> = (1..=n)
            .map(|sz| MemTree::naive_mth(&t.leaves[..sz]))
            .collect();
        for m in 1..=n {
            for sz in m..=n {
                let proof = consistency_proof(&t, m as u64, sz as u64).unwrap();
                assert!(
                    verify_consistency(m as u64, sz as u64, &proof, &roots[m - 1], &roots[sz - 1]),
                    "consistency failed m={} n={}",
                    m,
                    sz
                );
                if sz > m {
                    // wrong old root must fail (rollback/rewrite detection)
                    let mut bad = roots[m - 1];
                    bad[5] ^= 0x80;
                    assert!(!verify_consistency(m as u64, sz as u64, &proof, &bad, &roots[sz - 1]));
                    // swapped roots must fail
                    assert!(!verify_consistency(m as u64, sz as u64, &proof, &roots[sz - 1], &roots[m - 1]));
                }
            }
        }
    }
}
