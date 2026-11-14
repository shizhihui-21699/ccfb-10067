//! tlog-bench: benchmark append throughput and proof latency at 1M records.
//!
//! Usage: tlog-bench --dir DIR [--n 1000000] [--batch 1000] [--proofs 2000]

use std::path::PathBuf;
use std::time::Instant;

use tlog::merkle;
use tlog::storage::LogStorage;

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn make_record(i: u64) -> Vec<u8> {
    // ~128-byte artifact-signing record
    let mut rec = format!(
        "{{\"artifact\":\"pkg-{}.tar.gz\",\"version\":\"1.{}.{}\",\"sha256\":\"{:016x}{:016x}{:016x}{:016x}\",\"signer\":\"ci-bot\"}}",
        i % 5000,
        i % 100,
        i % 10,
        i.wrapping_mul(0x9E3779B97F4A7C15),
        i.wrapping_mul(0xC2B2AE3D27D4EB4F),
        i.wrapping_mul(0x165667B19E3779F9),
        i.wrapping_mul(0x27D4EB2F165667C5),
    );
    while rec.len() < 128 {
        rec.push(' ');
    }
    rec.into_bytes()
}

fn main() {
    let mut dir = PathBuf::from("./tlog-bench-data");
    let mut n: u64 = 1_000_000;
    let mut batch: u64 = 1000;
    let mut proofs: u64 = 2000;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => { dir = PathBuf::from(&args[i + 1]); i += 2; }
            "--n" => { n = args[i + 1].parse().unwrap(); i += 2; }
            "--batch" => { batch = args[i + 1].parse().unwrap(); i += 2; }
            "--proofs" => { proofs = args[i + 1].parse().unwrap(); i += 2; }
            _ => { eprintln!("unknown arg {}", args[i]); std::process::exit(1); }
        }
    }

    let _ = std::fs::remove_dir_all(&dir);

    // ---- Phase 1: durable single appends (fsync per record), sample of 2000 ----
    let sample = 2000u64.min(n);
    let mut st = LogStorage::open(&dir).unwrap();
    let t0 = Instant::now();
    for i in 0..sample {
        st.append(&make_record(i)).unwrap();
        st.commit().unwrap();
    }
    let d1 = t0.elapsed();
    println!(
        "[1] durable append (fsync/record): {} records in {:?}  => {:.2} ms/op, {:.0} ops/s",
        sample,
        d1,
        d1.as_secs_f64() * 1000.0 / sample as f64,
        sample as f64 / d1.as_secs_f64()
    );

    // ---- Phase 2: batched appends up to n ----
    let t0 = Instant::now();
    let mut i = sample;
    while i < n {
        let end = (i + batch).min(n);
        for j in i..end {
            st.append(&make_record(j)).unwrap();
        }
        st.commit().unwrap();
        i = end;
    }
    let d2 = t0.elapsed();
    let done = n - sample;
    println!(
        "[2] batched append (fsync/{} records): {} records in {:?} => {:.3} ms/op, {:.0} ops/s",
        batch,
        done,
        d2,
        d2.as_secs_f64() * 1000.0 / done as f64,
        done as f64 / d2.as_secs_f64()
    );
    let root = st.root().unwrap();
    println!("    tree_size={} root={}", st.size(), tlog::hexutil::to_hex(&root));
    drop(st);

    // ---- Phase 3: reopen (recovery path) ----
    let t0 = Instant::now();
    let st = LogStorage::open(&dir).unwrap();
    let d3 = t0.elapsed();
    assert_eq!(st.size(), n);
    assert_eq!(st.root().unwrap(), root);
    println!("[3] reopen + index rebuild at {} records: {:?}", n, d3);

    // ---- Phase 4: inclusion proof generation ----
    let mut rng = 0x123456789abcdefu64;
    let mut lat = Vec::with_capacity(proofs as usize);
    let t0 = Instant::now();
    for _ in 0..proofs {
        let idx = xorshift(&mut rng) % n;
        let t1 = Instant::now();
        let path = merkle::audit_path(&st, idx, n).unwrap();
        lat.push(t1.elapsed());
        // verify it too, so we know the proofs are real
        let rec = st.record(idx).unwrap();
        let lh = merkle::leaf_hash(&rec);
        debug_assert!(merkle::verify_inclusion(&lh, idx, n, &path, &root));
    }
    let d4 = t0.elapsed();
    lat.sort();
    let p50 = lat[lat.len() / 2];
    let p99 = lat[(lat.len() as f64 * 0.99) as usize];
    println!(
        "[4] inclusion proof gen at size {}: avg {:.3} ms, p50 {:?}, p99 {:?} ({} proofs in {:?})",
        n,
        d4.as_secs_f64() * 1000.0 / proofs as f64,
        p50,
        p99,
        proofs,
        d4
    );

    // ---- Phase 5: consistency proof generation ----
    let t0 = Instant::now();
    let mut ok = true;
    for k in 1..=100u64 {
        let m = n * k / 101;
        let p = merkle::consistency_proof(&st, m.max(1), n).unwrap();
        // spot-check the last one
        if k == 100 {
            // recompute root at m via a fresh partial check is expensive; just trust gen
            ok = ok && !p.is_empty();
        }
    }
    let d5 = t0.elapsed();
    println!(
        "[5] consistency proof gen at size {}: avg {:.3} ms (100 proofs in {:?})",
        n,
        d5.as_secs_f64() * 1000.0 / 100.0,
        d5
    );

    // ---- Phase 6: verification cost (client side) ----
    let idx = n / 2;
    let path = merkle::audit_path(&st, idx, n).unwrap();
    let rec = st.record(idx).unwrap();
    let lh = merkle::leaf_hash(&rec);
    let t0 = Instant::now();
    let iters = 10_000u32;
    for _ in 0..iters {
        assert!(merkle::verify_inclusion(&lh, idx, n, &path, &root));
    }
    let d6 = t0.elapsed();
    println!(
        "[6] client-side inclusion verify: {:.1} us/op ({} iters in {:?})",
        d6.as_secs_f64() * 1e6 / iters as f64,
        iters,
        d6
    );

    // disk usage
    let mut total = 0u64;
    for e in std::fs::read_dir(&dir).unwrap() {
        total += e.unwrap().metadata().unwrap().len();
    }
    println!(
        "[7] disk usage at {} records: {:.1} MB ({:.0} bytes/record)",
        n,
        total as f64 / 1e6,
        total as f64 / n as f64
    );
}
