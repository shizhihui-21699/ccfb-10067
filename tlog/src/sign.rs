//! Signed Tree Heads (STH): Ed25519 signatures over (tree_size, root_hash, timestamp).

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::hexutil;

#[derive(Clone, Debug)]
pub struct TreeHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub timestamp: u64, // unix seconds
}

impl TreeHead {
    /// Deterministic signing payload.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 + 8 + 32 + 8);
        v.extend_from_slice(b"TLOG-STH-v1");
        v.extend_from_slice(&self.tree_size.to_be_bytes());
        v.extend_from_slice(&self.root_hash);
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v
    }

    pub fn to_json(&self, sig: &[u8; 64]) -> serde_json::Value {
        serde_json::json!({
            "tree_size": self.tree_size,
            "root_hash": hexutil::to_hex(&self.root_hash),
            "timestamp": self.timestamp,
            "signature": hexutil::to_hex(sig),
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Option<(TreeHead, [u8; 64])> {
        let th = TreeHead {
            tree_size: v.get("tree_size")?.as_u64()?,
            root_hash: hexutil::from_hex_32(v.get("root_hash")?.as_str()?)?,
            timestamp: v.get("timestamp")?.as_u64()?,
        };
        let sig = hexutil::from_hex_64(v.get("signature")?.as_str()?)?;
        Some((th, sig))
    }
}

pub fn sign(sk: &SigningKey, th: &TreeHead) -> [u8; 64] {
    sk.sign(&th.signing_bytes()).to_bytes()
}

pub fn verify(vk: &VerifyingKey, th: &TreeHead, sig: &[u8; 64]) -> bool {
    vk.verify(&th.signing_bytes(), &Signature::from_bytes(sig))
        .is_ok()
}

/// Load the server signing key from `dir`, generating a fresh one on first run.
/// Files: `key` (32 raw secret bytes, mode 0600), `key.pub` (hex public key).
pub fn load_or_create_key(dir: &Path) -> io::Result<(SigningKey, VerifyingKey)> {
    let key_path = dir.join("key");
    let pub_path = dir.join("key.pub");
    if key_path.exists() {
        let mut buf = [0u8; 32];
        fs::File::open(&key_path)?.read_exact(&mut buf)?;
        let sk = SigningKey::from_bytes(&buf);
        let vk = sk.verifying_key();
        return Ok((sk, vk));
    }
    let mut seed = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    {
        let mut f = fs::File::create(&key_path)?;
        f.write_all(&seed)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(&pub_path, hexutil::to_hex(vk.as_bytes()))?;
    Ok((sk, vk))
}

pub fn load_pubkey(path: &Path) -> io::Result<VerifyingKey> {
    let s = fs::read_to_string(path)?;
    let bytes = hexutil::from_hex(s.trim())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad pubkey hex"))?;
    if bytes.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pubkey must be 32 bytes"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tlog-sign-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (sk, vk) = load_or_create_key(&dir).unwrap();
        // reload gives the same key
        let (sk2, vk2) = load_or_create_key(&dir).unwrap();
        assert_eq!(vk.as_bytes(), vk2.as_bytes());
        drop(sk2);

        let th = TreeHead {
            tree_size: 42,
            root_hash: [7u8; 32],
            timestamp: 1_700_000_000,
        };
        let sig = sign(&sk, &th);
        assert!(verify(&vk, &th, &sig));
        // tampered head fails
        let mut th2 = th.clone();
        th2.tree_size = 43;
        assert!(!verify(&vk, &th2, &sig));
        // json roundtrip
        let j = th.to_json(&sig);
        let (th3, sig3) = TreeHead::from_json(&j).unwrap();
        assert!(verify(&vk, &th3, &sig3));
        assert_eq!(th3.tree_size, 42);
        fs::remove_dir_all(&dir).ok();
    }
}
