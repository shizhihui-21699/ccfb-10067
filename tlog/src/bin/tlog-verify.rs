//! tlog-verify: offline verification tool for the transparency log.
//!
//! Detects:
//!   tampering  — record/proof doesn't recompute to the signed root
//!   rollback   — server presents a tree smaller than one it previously signed
//!   fork       — two signed heads for the same size differ, or a tree can't
//!                prove consistency with a previously signed head
//!
//! Exit codes: 0 ok · 1 usage/io error · 2 TAMPERED · 3 ROLLBACK · 4 FORK · 5 proof required
//!
//! Commands:
//!   tlog-verify sth        --sth sth.json --pubkey key.pub
//!   tlog-verify inclusion  --proof proof.json --sth sth.json --pubkey key.pub
//!   tlog-verify consistency --old sth1.json --new sth2.json --proof cons.json --pubkey key.pub
//!   tlog-verify track      --state state.json --sth sth.json [--proof cons.json] --pubkey key.pub

use std::path::PathBuf;
use std::process::ExitCode;

use ed25519_dalek::VerifyingKey;
use tlog::hexutil;
use tlog::merkle;
use tlog::sign::{self, TreeHead};

const OK: u8 = 0;
const ERR: u8 = 1;
const TAMPERED: u8 = 2;
const ROLLBACK: u8 = 3;
const FORK: u8 = 4;
const PROOF_REQUIRED: u8 = 5;

struct Args {
    cmd: String,
    opts: std::collections::HashMap<String, String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        return Err("missing command".into());
    }
    let cmd = argv[1].clone();
    let mut opts = std::collections::HashMap::new();
    let mut i = 2;
    while i < argv.len() {
        let k = argv[i].strip_prefix("--").ok_or("bad flag")?.to_string();
        let v = argv.get(i + 1).ok_or("missing value")?.clone();
        opts.insert(k, v);
        i += 2;
    }
    Ok(Args { cmd, opts })
}

fn usage() -> ! {
    eprintln!("{}", include_str!("usage.txt"));
    std::process::exit(ERR as i32);
}

fn read_json(path: &str) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {}", path, e))
}

fn load_sth(path: &str) -> Result<(TreeHead, [u8; 64]), String> {
    let v = read_json(path)?;
    TreeHead::from_json(&v).ok_or_else(|| format!("{}: bad STH format", path))
}

fn load_pubkey(opts: &Args) -> Result<VerifyingKey, String> {
    let p = opts.opts.get("pubkey").ok_or("need --pubkey")?;
    sign::load_pubkey(&PathBuf::from(p)).map_err(|e| format!("load pubkey: {}", e))
}

fn check_sig(vk: &VerifyingKey, th: &TreeHead, sig: &[u8; 64], label: &str) -> Result<(), String> {
    if sign::verify(vk, th, sig) {
        Ok(())
    } else {
        Err(format!("{}: STH signature INVALID (forged or corrupted head)", label))
    }
}

fn parse_path_hashes(v: &serde_json::Value, key: &str) -> Result<Vec<[u8; 32]>, String> {
    let arr = v.get(key).and_then(|x| x.as_array()).ok_or(format!("missing {}", key))?;
    arr.iter()
        .map(|x| {
            x.as_str()
                .and_then(hexutil::from_hex_32)
                .ok_or_else(|| format!("bad hash in {}", key))
        })
        .collect()
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            usage();
        }
    };
    let code = match args.cmd.as_str() {
        "sth" => cmd_sth(&args),
        "inclusion" => cmd_inclusion(&args),
        "consistency" => cmd_consistency(&args),
        "track" => cmd_track(&args),
        _ => {
            eprintln!("unknown command: {}", args.cmd);
            usage();
        }
    };
    ExitCode::from(code)
}

fn cmd_sth(args: &Args) -> u8 {
    let vk = match load_pubkey(args) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let path = match args.opts.get("sth") { Some(p) => p.clone(), None => { eprintln!("need --sth"); return ERR; } };
    match load_sth(&path) {
        Ok((th, sig)) => match check_sig(&vk, &th, &sig, &path) {
            Ok(()) => {
                println!("OK: STH valid. tree_size={} root={} ts={}", th.tree_size, hexutil::to_hex(&th.root_hash), th.timestamp);
                OK
            }
            Err(e) => { println!("TAMPERED: {}", e); TAMPERED }
        },
        Err(e) => { eprintln!("error: {}", e); ERR }
    }
}

fn cmd_inclusion(args: &Args) -> u8 {
    let vk = match load_pubkey(args) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let (proof_path, sth_path) = match (args.opts.get("proof"), args.opts.get("sth")) {
        (Some(p), Some(s)) => (p.clone(), s.clone()),
        _ => { eprintln!("need --proof and --sth"); return ERR; }
    };
    let proof = match read_json(&proof_path) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let (th, sig) = match load_sth(&sth_path) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };

    if let Err(e) = check_sig(&vk, &th, &sig, &sth_path) {
        println!("TAMPERED: {}", e);
        return TAMPERED;
    }

    let index = match proof.get("index").and_then(|v| v.as_u64()) {
        Some(i) => i,
        None => { eprintln!("proof: missing index"); return ERR; }
    };
    let tree_size = proof.get("tree_size").and_then(|v| v.as_u64()).unwrap_or(th.tree_size);
    let path = match parse_path_hashes(&proof, "path") { Ok(p) => p, Err(e) => { eprintln!("error: {}", e); return ERR; } };

    // Leaf hash: recompute from record data when present, else trust leaf_hash field.
    let leaf = if let Some(dh) = proof.get("record_data_hex").and_then(|v| v.as_str()) {
        match hexutil::from_hex(dh) {
            Some(d) => merkle::leaf_hash(&d),
            None => { eprintln!("proof: bad record_data_hex"); return ERR; }
        }
    } else if let Some(lh) = proof.get("leaf_hash").and_then(|v| v.as_str()) {
        match hexutil::from_hex_32(lh) {
            Some(h) => h,
            None => { eprintln!("proof: bad leaf_hash"); return ERR; }
        }
    } else {
        eprintln!("proof: need record_data_hex or leaf_hash");
        return ERR;
    };

    // Cross-check leaf_hash field if both are present.
    if let Some(lh) = proof.get("leaf_hash").and_then(|v| v.as_str()) {
        if let Some(h) = hexutil::from_hex_32(lh) {
            if h != leaf {
                println!("TAMPERED: record data does not match claimed leaf_hash");
                return TAMPERED;
            }
        }
    }

    if tree_size != th.tree_size {
        println!("TAMPERED/INCONSISTENT: proof tree_size={} but STH tree_size={}", tree_size, th.tree_size);
        return TAMPERED;
    }

    if merkle::verify_inclusion(&leaf, index, tree_size, &path, &th.root_hash) {
        println!("OK: record #{} is included in tree size {} (root matches signed head)", index, tree_size);
        OK
    } else {
        println!("TAMPERED: inclusion proof does NOT recompute to the signed root (index={}, size={})", index, tree_size);
        TAMPERED
    }
}

fn cmd_consistency(args: &Args) -> u8 {
    let vk = match load_pubkey(args) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let (old_p, new_p, proof_p) = match (args.opts.get("old"), args.opts.get("new"), args.opts.get("proof")) {
        (Some(a), Some(b), Some(c)) => (a.clone(), b.clone(), c.clone()),
        _ => { eprintln!("need --old, --new, --proof"); return ERR; }
    };
    let (old_th, old_sig) = match load_sth(&old_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let (new_th, new_sig) = match load_sth(&new_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    if let Err(e) = check_sig(&vk, &old_th, &old_sig, &old_p) { println!("TAMPERED: {}", e); return TAMPERED; }
    if let Err(e) = check_sig(&vk, &new_th, &new_sig, &new_p) { println!("TAMPERED: {}", e); return TAMPERED; }

    if new_th.tree_size < old_th.tree_size {
        println!("ROLLBACK: new STH size {} < previously signed size {}", new_th.tree_size, old_th.tree_size);
        return ROLLBACK;
    }
    if new_th.tree_size == old_th.tree_size {
        if new_th.root_hash == old_th.root_hash {
            println!("OK: identical tree heads (size {})", old_th.tree_size);
            return OK;
        }
        println!("FORK: two signed heads at size {} with different roots!\n  old: {}\n  new: {}",
            old_th.tree_size, hexutil::to_hex(&old_th.root_hash), hexutil::to_hex(&new_th.root_hash));
        return FORK;
    }
    let proof = match read_json(&proof_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let hashes = match parse_path_hashes(&proof, "proof") { Ok(p) => p, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    if merkle::verify_consistency(old_th.tree_size, new_th.tree_size, &hashes, &old_th.root_hash, &new_th.root_hash) {
        println!("OK: tree grew consistently {} -> {} (append-only verified)", old_th.tree_size, new_th.tree_size);
        OK
    } else {
        println!("FORK/REWRITE: consistency proof INVALID between size {} and {} — the log was rewritten or forked",
            old_th.tree_size, new_th.tree_size);
        FORK
    }
}

fn cmd_track(args: &Args) -> u8 {
    let vk = match load_pubkey(args) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let (state_p, sth_p) = match (args.opts.get("state"), args.opts.get("sth")) {
        (Some(a), Some(b)) => (a.clone(), b.clone()),
        _ => { eprintln!("need --state and --sth"); return ERR; }
    };
    let (th, sig) = match load_sth(&sth_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    if let Err(e) = check_sig(&vk, &th, &sig, &sth_p) {
        println!("TAMPERED: {}", e);
        return TAMPERED;
    }

    let state_path = PathBuf::from(&state_p);
    if !state_path.exists() {
        let state = serde_json::json!({"tree_size": th.tree_size, "root_hash": hexutil::to_hex(&th.root_hash)});
        std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        println!("OK: initialized tracking state at size {}", th.tree_size);
        return OK;
    }
    let state = match read_json(&state_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let old_size = state.get("tree_size").and_then(|v| v.as_u64()).unwrap_or(0);
    let old_root = state.get("root_hash").and_then(|v| v.as_str()).and_then(hexutil::from_hex_32);
    let old_root = match old_root { Some(r) => r, None => { eprintln!("state: bad root_hash"); return ERR; } };

    if th.tree_size < old_size {
        println!("ROLLBACK: server presents size {} but we previously saw a signed head at size {}", th.tree_size, old_size);
        return ROLLBACK;
    }
    if th.tree_size == old_size {
        if th.root_hash == old_root {
            println!("OK: same head as tracked (size {})", old_size);
            return OK;
        }
        println!("FORK: signed head at size {} differs from tracked root!\n  tracked: {}\n  presented: {}",
            old_size, hexutil::to_hex(&old_root), hexutil::to_hex(&th.root_hash));
        return FORK;
    }
    // Grew: require a consistency proof.
    let proof_p = match args.opts.get("proof") {
        Some(p) => p.clone(),
        None => {
            println!("PROOF REQUIRED: tree grew {} -> {}; re-run with --proof cons.json to confirm append-only", old_size, th.tree_size);
            return PROOF_REQUIRED;
        }
    };
    let proof = match read_json(&proof_p) { Ok(v) => v, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    let hashes = match parse_path_hashes(&proof, "proof") { Ok(p) => p, Err(e) => { eprintln!("error: {}", e); return ERR; } };
    if merkle::verify_consistency(old_size, th.tree_size, &hashes, &old_root, &th.root_hash) {
        let state = serde_json::json!({"tree_size": th.tree_size, "root_hash": hexutil::to_hex(&th.root_hash)});
        std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        println!("OK: append-only verified {} -> {}, state updated", old_size, th.tree_size);
        OK
    } else {
        println!("FORK/REWRITE: consistency proof INVALID — server cannot prove the old tree is a prefix of the new one");
        FORK
    }
}
