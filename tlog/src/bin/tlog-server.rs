//! tlog-server: transparency log server.
//!
//! Endpoints:
//!   GET  /                     query page (HTML)
//!   POST /append               {"data": "<utf8>"} or {"data_hex": "<hex>"}
//!                              -> {index, leaf_hash, tree_size}
//!   GET  /record?index=N       -> {index, data_hex, data_utf8?, leaf_hash}
//!   GET  /proof?index=N[&size=M]
//!                              -> inclusion proof at tree size M (default: latest STH size)
//!   GET  /consistency?first=A&second=B
//!                              -> consistency proof between two tree sizes
//!   GET  /sth                  -> latest signed tree head
//!   GET  /sth/all              -> every signed tree head (fork monitoring)
//!   GET  /pubkey               -> {"pubkey": hex}
//!   POST /sign                 -> force-sign the current tree head
//!
//! Usage: tlog-server --dir DATA --addr 127.0.0.1:8080 [--sign-every N]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tlog::hexutil;
use tlog::merkle;
use tlog::sign::{self, TreeHead};
use tlog::storage::LogStorage;

struct App {
    storage: Mutex<LogStorage>,
    sths: Mutex<Vec<(TreeHead, [u8; 64])>>,
    sk: ed25519_dalek::SigningKey,
    vk_hex: String,
    sign_every: u64,
    dir: PathBuf,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

impl App {
    fn open(dir: PathBuf, sign_every: u64) -> std::io::Result<App> {
        let storage = LogStorage::open(&dir)?;
        let (sk, vk) = sign::load_or_create_key(&dir)?;
        // Load sth.log, keeping only entries consistent with the committed tree.
        let mut sths: Vec<(TreeHead, [u8; 64])> = Vec::new();
        let sth_path = dir.join("sth.log");
        let mut valid_bytes: Vec<u8> = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&sth_path) {
            for line in text.lines() {
                let keep = serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| TreeHead::from_json(&v))
                    .filter(|(th, sig)| th.tree_size <= storage.size() && sign::verify(&vk, th, sig));
                if let Some((th, sig)) = keep {
                    sths.push((th, sig));
                    valid_bytes.extend_from_slice(line.as_bytes());
                    valid_bytes.push(b'\n');
                }
            }
        }
        // If we dropped anything (crash after commit rollback, tampering), rewrite.
        let on_disk = std::fs::read(&sth_path).unwrap_or_default();
        if on_disk != valid_bytes {
            let mut f = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&sth_path)?;
            f.write_all(&valid_bytes)?;
            f.sync_all()?;
        }
        Ok(App {
            storage: Mutex::new(storage),
            sths: Mutex::new(sths),
            sk,
            vk_hex: hexutil::to_hex(vk.as_bytes()),
            sign_every,
            dir,
        })
    }

    fn maybe_sign(&self, force: bool) -> std::io::Result<()> {
        let size = self.storage.lock().unwrap().size();
        let need = {
            let sths = self.sths.lock().unwrap();
            let last = sths.last().map(|(th, _)| th.tree_size).unwrap_or(0);
            size > last && (force || (self.sign_every > 0 && size % self.sign_every == 0))
        };
        if !need {
            return Ok(());
        }
        let root = self.storage.lock().unwrap().root()?;
        let th = TreeHead {
            tree_size: size,
            root_hash: root,
            timestamp: now(),
        };
        let sig = sign::sign(&self.sk, &th);
        let line = serde_json::to_string(&th.to_json(&sig))?
            ;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.dir.join("sth.log"))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        self.sths.lock().unwrap().push((th, sig));
        Ok(())
    }
}

// ---------- minimal HTTP ----------

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end = None;
    while header_end.is_none() {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        header_end = find(&buf, b"\r\n\r\n");
        if buf.len() > 1 << 20 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header too big"));
        }
    }
    let he = header_end.unwrap();
    let head = String::from_utf8_lossy(&buf[..he]).to_string();
    let mut lines = head.lines();
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = buf[he + 4..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, Vec::new()),
    };
    Ok(Some(Request { method, path, query, body }))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (urldecode(k), urldecode(v)),
            None => (urldecode(kv), String::new()),
        })
        .collect()
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn qparam<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.query
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        ctype,
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn json_resp(stream: &mut TcpStream, v: serde_json::Value) {
    respond(stream, "200 OK", "application/json", v.to_string().as_bytes());
}

fn err_resp(stream: &mut TcpStream, status: &str, msg: &str) {
    let body = serde_json::json!({"error": msg}).to_string();
    respond(stream, status, "application/json", body.as_bytes());
}

fn handle(req: &Request, app: &Arc<App>, stream: &mut TcpStream) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => respond(stream, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()),
        ("GET", "/pubkey") => json_resp(stream, serde_json::json!({"pubkey": app.vk_hex})),
        ("GET", "/sth") => {
            let sths = app.sths.lock().unwrap();
            match sths.last() {
                Some((th, sig)) => json_resp(stream, th.to_json(sig)),
                None => err_resp(stream, "404 Not Found", "no signed tree head yet"),
            }
        }
        ("GET", "/sth/all") => {
            let sths = app.sths.lock().unwrap();
            let all: Vec<_> = sths.iter().map(|(th, sig)| th.to_json(sig)).collect();
            json_resp(stream, serde_json::Value::Array(all));
        }
        ("POST", "/sign") => {
            if let Err(e) = app.maybe_sign(true) {
                return err_resp(stream, "500 Internal Server Error", &e.to_string());
            }
            let sths = app.sths.lock().unwrap();
            match sths.last() {
                Some((th, sig)) => json_resp(stream, th.to_json(sig)),
                None => err_resp(stream, "500 Internal Server Error", "sign failed"),
            }
        }
        ("POST", "/append") => {
            let body: serde_json::Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => return err_resp(stream, "400 Bad Request", &format!("bad json: {}", e)),
            };
            let data: Vec<u8> = if let Some(h) = body.get("data_hex").and_then(|v| v.as_str()) {
                match hexutil::from_hex(h) {
                    Some(d) => d,
                    None => return err_resp(stream, "400 Bad Request", "bad data_hex"),
                }
            } else if let Some(s) = body.get("data").and_then(|v| v.as_str()) {
                s.as_bytes().to_vec()
            } else {
                return err_resp(stream, "400 Bad Request", "need data or data_hex");
            };
            let mut st = app.storage.lock().unwrap();
            let idx = match st.append(&data).and_then(|i| st.commit().map(|_| i)) {
                Ok(i) => i,
                Err(e) => return err_resp(stream, "500 Internal Server Error", &e.to_string()),
            };
            let size = st.size();
            drop(st);
            let _ = app.maybe_sign(false);
            json_resp(stream, serde_json::json!({
                "index": idx,
                "leaf_hash": hexutil::to_hex(&merkle::leaf_hash(&data)),
                "tree_size": size,
            }));
        }
        ("GET", "/record") => {
            let idx: u64 = match qparam(req, "index").and_then(|s| s.parse().ok()) {
                Some(i) => i,
                None => return err_resp(stream, "400 Bad Request", "need index"),
            };
            let st = app.storage.lock().unwrap();
            match st.record(idx) {
                Ok(rec) => {
                    let mut v = serde_json::json!({
                        "index": idx,
                        "data_hex": hexutil::to_hex(&rec),
                        "leaf_hash": hexutil::to_hex(&merkle::leaf_hash(&rec)),
                    });
                    if let Ok(s) = std::str::from_utf8(&rec) {
                        v["data_utf8"] = serde_json::Value::String(s.to_string());
                    }
                    json_resp(stream, v);
                }
                Err(_) => err_resp(stream, "404 Not Found", "no such record"),
            }
        }
        ("GET", "/proof") => {
            let idx: u64 = match qparam(req, "index").and_then(|s| s.parse().ok()) {
                Some(i) => i,
                None => return err_resp(stream, "400 Bad Request", "need index"),
            };
            let st = app.storage.lock().unwrap();
            let sth_size = app.sths.lock().unwrap().last().map(|(th, _)| th.tree_size);
            let size: u64 = match qparam(req, "size") {
                Some(s) => match s.parse() {
                    Ok(v) => v,
                    Err(_) => return err_resp(stream, "400 Bad Request", "bad size"),
                },
                None => match sth_size {
                    Some(s) => s,
                    None => st.size(),
                },
            };
            if idx >= size || size > st.size() {
                return err_resp(stream, "404 Not Found", "index not covered by that tree size");
            }
            let path = merkle::audit_path(&*st, idx, size).unwrap();
            let root = merkle::root(&*st, size).unwrap();
            let rec = st.record(idx).unwrap_or_default();
            let path_hex: Vec<String> = path.iter().map(|h| hexutil::to_hex(h)).collect();
            let sth_json = app.sths.lock().unwrap().last().map(|(th, sig)| th.to_json(sig));
            json_resp(stream, serde_json::json!({
                "index": idx,
                "tree_size": size,
                "leaf_hash": hexutil::to_hex(&merkle::leaf_hash(&rec)),
                "record_data_hex": hexutil::to_hex(&rec),
                "path": path_hex,
                "root": hexutil::to_hex(&root),
                "sth": sth_json,
            }));
        }
        ("GET", "/consistency") => {
            let first: u64 = match qparam(req, "first").and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => return err_resp(stream, "400 Bad Request", "need first"),
            };
            let second: u64 = match qparam(req, "second").and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => return err_resp(stream, "400 Bad Request", "need second"),
            };
            let st = app.storage.lock().unwrap();
            if first == 0 || first > second || second > st.size() {
                return err_resp(stream, "400 Bad Request", "need 0 < first <= second <= tree size");
            }
            let proof = merkle::consistency_proof(&*st, first, second).unwrap();
            let proof_hex: Vec<String> = proof.iter().map(|h| hexutil::to_hex(h)).collect();
            json_resp(stream, serde_json::json!({
                "first": first,
                "second": second,
                "proof": proof_hex,
            }));
        }
        _ => err_resp(stream, "404 Not Found", "unknown endpoint"),
    }
}

const PAGE: &str = include_str!("page.html");

fn main() {
    let mut dir = PathBuf::from("./tlog-data");
    let mut addr = "127.0.0.1:8080".to_string();
    let mut sign_every: u64 = 1000;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => { dir = PathBuf::from(&args[i + 1]); i += 2; }
            "--addr" => { addr = args[i + 1].clone(); i += 2; }
            "--sign-every" => { sign_every = args[i + 1].parse().unwrap(); i += 2; }
            _ => { eprintln!("unknown arg: {}", args[i]); std::process::exit(1); }
        }
    }
    let app = Arc::new(App::open(dir.clone(), sign_every).expect("failed to open log"));
    {
        let st = app.storage.lock().unwrap();
        eprintln!(
            "tlog-server: dir={} size={} sths={} pubkey={}",
            dir.display(),
            st.size(),
            app.sths.lock().unwrap().len(),
            app.vk_hex
        );
    }
    let listener = TcpListener::bind(&addr).expect("bind failed");
    eprintln!("listening on http://{}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let app = Arc::clone(&app);
                std::thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                    match read_request(&mut s) {
                        Ok(Some(req)) => handle(&req, &app, &mut s),
                        Ok(None) => {}
                        Err(_) => err_resp(&mut s, "400 Bad Request", "bad request"),
                    }
                });
            }
            Err(e) => eprintln!("accept: {}", e),
        }
    }
}
