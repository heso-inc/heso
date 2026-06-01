//! Shared support for the determinism conformance harness and its
//! corpus generator (`determinism_conformance.rs` /
//! `determinism_generate.rs`).
//!
//! Both files build `.plat` fixtures by serving a recorded cassette body
//! over a FIXED loopback port and stamping a one-step `open` plan against
//! it, so the resulting plat's embedded URL (and therefore its
//! `plat_hash`) is byte-stable across machines — the port is baked into
//! the checked-in `.plat`, and replay needs no server at all.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// The `engine{name,version}` provenance stamped into every plat body.
/// `version` is `CARGO_PKG_VERSION` (source-stable), so the manifest's
/// `engine_id` is `heso@<this>`. A mismatch between a running binary's
/// `engine_id` and the manifest's is a deliberate version bump, not a
/// determinism failure (see the harness's drift handling).
pub fn engine_id() -> String {
    // The CLI crate and the engine crate share the workspace version, so
    // `CARGO_PKG_VERSION` here equals the engine's `version`.
    format!("heso@{}", env!("CARGO_PKG_VERSION"))
}

/// Absolute path to the built `heso` binary under test.
pub fn heso_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_heso"))
}

/// Absolute path to the dependency-free `heso-verify` binary — the
/// ground-truth recompute of `plat_hash` (BLAKE3 over serde_jcs canonical
/// bytes, zero engine deps). The harness cross-checks every replay
/// against it so a producer/verifier canonicalization split fails loud.
///
/// `heso-verify` lives in a sibling crate, so `CARGO_BIN_EXE_*` is not
/// set for it and `cargo test -p heso-cli` does not auto-build it. We
/// derive its path from the `heso` binary's profile dir (both land in the
/// same `target/<profile>/`) and build it on demand the first time it is
/// requested, so the gate is self-sufficient.
pub fn heso_verify_bin() -> PathBuf {
    let mut p = heso_bin();
    p.pop();
    p.push("heso-verify");
    if cfg!(windows) {
        p.set_extension("exe");
    }
    if !p.exists() {
        ensure_heso_verify_built();
    }
    p
}

/// Build `heso-verify` once if it is not already present beside `heso`.
/// Idempotent and safe to call from multiple tests — `cargo build` no-ops
/// when the binary is up to date.
fn ensure_heso_verify_built() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "heso-verify", "--bin", "heso-verify"])
            .status()
            .expect("spawn cargo build -p heso-verify");
        assert!(status.success(), "cargo build -p heso-verify failed");
    });
}

/// The directory holding the checked-in corpus (manifest + fixtures).
pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("determinism_corpus")
}

/// Path to a corpus fixture file (HTML body, JSON sidecar, or `.plat`).
pub fn corpus_path(rel: &str) -> PathBuf {
    corpus_dir().join(rel)
}

/// The canonical origin baked into every checked-in `.plat`. It is NEVER
/// actually bound — the generator serves on an EPHEMERAL port (no
/// fixed-port `TIME_WAIT` race), captures the cassette, then rewrites the
/// volatile `http://127.0.0.1:<ephemeral>` origin to this stable string so
/// the pinned `plat_hash` is reproducible on any host. Replay (`heso run`)
/// reads the embedded cassette and never opens a socket, so the canonical
/// origin needs no listener.
pub const CANONICAL_ORIGIN: &str = "http://heso.invalid";

/// Rewrite a freshly-stamped plat so its volatile ephemeral origin
/// becomes [`CANONICAL_ORIGIN`], then re-run it through `heso run` so the
/// engine recomputes a consistent `plat_hash` over the rewritten body.
///
/// The rewrite is a plain origin-string substitution across the whole
/// plat JSON: the page URL, the cassette record URLs, the plan, and any
/// JS-captured `location.origin` value all carry the same ephemeral
/// origin, so replacing the string keeps the cassette lookup keys
/// (`method`+`url`+`body`) internally consistent — `run` still matches
/// every record. We strip `plat_hash`/`sig`, feed it through
/// `heso run --no-verify-input --no-sign`, and the output is the
/// canonical, byte-stable plat whose hash is pinned in the manifest.
pub fn canonicalize_and_recompute(stamped_plat: &[u8], ephemeral_origin: &str) -> Vec<u8> {
    let s = String::from_utf8_lossy(stamped_plat);
    let rewritten = s.replace(ephemeral_origin, CANONICAL_ORIGIN);
    let mut v: serde_json::Value =
        serde_json::from_str(&rewritten).expect("rewritten plat is json");
    if let Some(obj) = v.as_object_mut() {
        obj.remove("plat_hash");
        obj.remove("sig");
    }
    let in_path = std::env::temp_dir().join(format!(
        "heso-det-canon-{}-{}.plat",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::write(&in_path, serde_json::to_vec(&v).unwrap()).expect("write canon input");
    let out = Command::new(heso_bin())
        .args([
            "run",
            "--no-verify-input",
            "--no-sign",
            "--seed",
            "0",
            in_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn heso run for canonicalize");
    let _ = std::fs::remove_file(&in_path);
    assert!(
        out.status.success(),
        "canonicalize run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// One served route: the request path (e.g. `/` or `/data.json`) mapped
/// to a response `(content_type, body_bytes)` plus any extra response
/// headers (e.g. several `Set-Cookie` lines for the cookie-ordering
/// regression test).
#[derive(Clone, Default)]
pub struct Route {
    pub path: String,
    pub content_type: String,
    pub body: Vec<u8>,
    /// Extra raw response headers, each a `("Name", "value")` pair,
    /// emitted verbatim. `Set-Cookie` may appear multiple times.
    pub extra_headers: Vec<(String, String)>,
}

impl Route {
    /// Convenience for the common HTML route with no extra headers.
    pub fn html(path: &str, content_type: &str, body: Vec<u8>) -> Self {
        Route {
            path: path.to_owned(),
            content_type: content_type.to_owned(),
            body,
            extra_headers: Vec::new(),
        }
    }
}

/// A tiny single-purpose HTTP/1.1 server bound ONCE to a FIXED loopback
/// port, serving from a swappable route table.
///
/// `wiremock` allocates a random port, which would bake a different
/// origin (and therefore a different `plat_hash`) into the plat on every
/// run — useless for a checked-in pinned hash. This server binds a caller
/// supplied port so the stamped plat is reproducible.
///
/// Binding is done ONCE and the route table is swapped between cassettes
/// via [`Self::set_routes`]; rebinding the same port in a tight loop trips
/// `TIME_WAIT` on macOS (`Address already in use`), so a single long-lived
/// listener is the robust shape. It serves only the registered routes and
/// answers everything else with 404.
pub struct FixedServer {
    port: u16,
    routes: Arc<Mutex<Vec<Route>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FixedServer {
    /// Bind `port` on `127.0.0.1` once and start serving the initial
    /// `routes`. Blocks until the listener is accepting so a follow-up
    /// `heso stamp` never races the bind.
    ///
    /// The bind sets `SO_REUSEADDR` (+ `SO_REUSEPORT` where available) so
    /// re-binding the SAME fixed loopback port across back-to-back
    /// generation runs does not trip `TIME_WAIT` — without it the second
    /// run hits "Address already in use" or a transient connection refusal
    /// that surfaces downstream as "error sending request".
    pub fn start(port: u16, routes: Vec<Route>) -> std::io::Result<Self> {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        {
            let _ = socket.set_reuse_port(true);
        }
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        let listener: TcpListener = socket.into();
        // Read the ACTUAL bound port: callers pass 0 for an ephemeral
        // port (the robust choice — no fixed-port `TIME_WAIT` races), and
        // the corpus generator rewrites this volatile origin to a
        // canonical host in the checked-in plat.
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let routes = Arc::new(Mutex::new(routes));
        let routes_thread = routes.clone();
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // A stream accepted from a NON-BLOCKING listener can
                        // itself be non-blocking on macOS/Linux; a large
                        // body (wikipedia_html is 508 KB) would then make
                        // `write_all` return `WouldBlock` partway and abort
                        // the response — a truncated body that reqwest
                        // surfaces as "error decoding response body". Force
                        // the per-connection socket back to BLOCKING so the
                        // full body is always written.
                        let _ = stream.set_nonblocking(false);
                        // Serve each connection on its own thread so a slow
                        // graceful-close drain on one connection never
                        // stalls the accept loop.
                        let table = routes_thread.lock().unwrap_or_else(|p| p.into_inner());
                        let snapshot = table.clone();
                        drop(table);
                        thread::spawn(move || {
                            let _ = serve_one(stream, &snapshot);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        let srv = Self {
            port,
            routes,
            stop,
            handle: Some(handle),
        };
        srv.wait_ready();
        Ok(srv)
    }

    /// Block until the accept loop is live by driving a FULL throwaway
    /// request/response cycle (`GET /__ready`) and waiting for any HTTP
    /// status back. A bare `connect` succeeds off the listen backlog even
    /// before the accept thread is scheduled, so it does not prove the
    /// loop is serving; reading a response does. Without this the first
    /// `heso stamp` can race the freshly-spawned accept thread and capture
    /// an empty cassette.
    fn wait_ready(&self) {
        for _ in 0..400 {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(50)));
                if s.write_all(
                    b"GET /__ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                )
                .is_ok()
                {
                    let mut buf = [0u8; 16];
                    if let Ok(n) = s.read(&mut buf) {
                        if n > 0 && buf.starts_with(b"HTTP/1.1") {
                            return;
                        }
                    }
                }
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// Replace the served route table (used to swap cassette bodies
    /// without rebinding the port).
    pub fn set_routes(&self, routes: Vec<Route>) {
        *self.routes.lock().unwrap_or_else(|p| p.into_inner()) = routes;
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for FixedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_one(mut stream: TcpStream, routes: &[Route]) -> std::io::Result<()> {
    // Read the full request head (up to the blank line). reqwest can
    // split the request across TCP segments; reading only the first
    // segment risks parsing a partial request line, so loop until we see
    // the `\r\n\r\n` head terminator (or the client stops sending).
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(2000)));
    let mut req = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                req.extend_from_slice(&chunk[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if req.len() > 64 * 1024 {
                    break; // request head far larger than any GET we expect
                }
            }
            Err(_) => break,
        }
    }
    let head = String::from_utf8_lossy(&req);
    // Request line: `GET /path HTTP/1.1`.
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    // Strip a query string for matching (the corpus fixtures use none).
    let path_only = path.split('?').next().unwrap_or(&path);

    let route = routes.iter().find(|r| r.path == path_only);
    let empty: Vec<(String, String)> = Vec::new();
    let (status, ctype, body, extra): (&str, String, &[u8], &[(String, String)]) = match route {
        Some(r) => (
            "200 OK",
            r.content_type.clone(),
            r.body.as_slice(),
            r.extra_headers.as_slice(),
        ),
        None => ("404 Not Found", "text/plain".to_owned(), b"not found", &empty),
    };
    let mut header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    // Graceful close: shut down the write half so the client sees a clean
    // EOF, then drain any remaining client bytes until it closes. Closing
    // the socket immediately after `write_all` (the default `Drop`) can
    // RST the connection with data still in the kernel send buffer, which
    // reqwest surfaces as "error decoding response body" — a flaky,
    // load-dependent truncation. Waiting for the peer to finish reading
    // before we drop avoids that.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    while let Ok(n) = stream.read(&mut sink) {
        if n == 0 {
            break;
        }
    }
    Ok(())
}

/// One entry of the checked-in determinism corpus manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    /// Human label, matches the cassette slug.
    pub cassette: String,
    /// Path (relative to the corpus dir) of the checked-in input `.plat`.
    pub input_plat: String,
    /// Seed `heso run --seed` replays under. Always 0 for this corpus.
    pub seed: u64,
    /// The plat's `engine{name,version}` provenance, e.g. `heso@0.3.0`.
    /// Gated BEFORE the hash comparison so cross-version drift is
    /// attributable, not a silent failure.
    pub engine_id: String,
    /// The pinned 64-lowercase-hex BLAKE3 `plat_hash` every fresh replay
    /// process must reproduce. Regenerated (never hand-edited) by the
    /// `determinism_generate` blessing test after an intentional engine
    /// bump.
    pub expected_plat_hash: String,
    /// True for the JS-hydrated cassette — the only fixture that proves
    /// the QuickJS determinism path yields a stable `plat_hash` across
    /// fresh processes.
    pub hydrated: bool,
    /// True for the fixture that carries JSON-shaped `data-*` attributes
    /// routed through `body["data_attrs"]` (the `data_attrs::extract`
    /// BTreeMap ordering proof). The conformance harness asserts at least
    /// one entry has this set so a regenerate cannot silently drop the
    /// data-attr coverage. `#[serde(default)]` for pre-existing entries.
    #[serde(default)]
    pub has_data_attrs: bool,
    /// True for the fixture whose hydration REQUIRES the settle loop's
    /// virtual-clock `advance_clock` branch — a chain of non-zero timers
    /// that `run_pending_jobs` alone never fires. The harness asserts at
    /// least one entry has this set so a regenerate cannot silently drop
    /// the async-settle coverage. `#[serde(default)]` for pre-existing
    /// entries.
    #[serde(default)]
    pub requires_settle: bool,
    /// Short note on what this cassette stresses (for the manifest reader).
    pub note: String,
}

/// The whole manifest: an ordered list of corpus entries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// Reference target the pinned hashes were generated on. Single-host
    /// K-process determinism is proven here; cross-arch byte-identity is
    /// the CI matrix's job (see the corpus README).
    pub reference_target: String,
    /// The corpus entries.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn load() -> Manifest {
        let path = corpus_dir().join("manifest.json");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read manifest at {}: {e}", path.display()));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("parse manifest at {}: {e}", path.display()))
    }
}

/// Run `heso run --seed <seed> <plat>` in a fresh process and return its
/// stdout plat's `plat_hash`. Panics with the captured stderr on failure
/// so a regression names the cassette and the error.
pub fn run_replay_hash(plat: &Path, seed: u64) -> String {
    let out = Command::new(heso_bin())
        .args([
            "run",
            "--seed",
            &seed.to_string(),
            plat.to_str().unwrap(),
        ])
        .output()
        .expect("spawn heso run");
    assert!(
        out.status.success(),
        "heso run failed for {}: {}",
        plat.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("heso run stdout is a plat JSON");
    v["plat_hash"]
        .as_str()
        .expect("replayed plat carries a plat_hash")
        .to_owned()
}

/// Run the dependency-free `heso-verify <plat>` and return the hash it
/// independently recomputes. Output format is `OK plat <hash>`.
pub fn verify_recompute_hash(plat: &Path) -> String {
    let out = Command::new(heso_verify_bin())
        .arg(plat.to_str().unwrap())
        .output()
        .expect("spawn heso-verify");
    assert!(
        out.status.success(),
        "heso-verify failed for {}: {}",
        plat.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split_whitespace()
        .nth(2)
        .unwrap_or_else(|| panic!("unexpected heso-verify output: {stdout:?}"))
        .to_owned()
}

/// The running binary's `engine_id`, read from a freshly-minted bare plat
/// so the harness compares against what the binary actually stamps (not a
/// compile-time guess). We `heso open` a `data:` URL with `--no-sign`,
/// which mints a plat carrying `engine{name,version}`.
pub fn running_engine_id() -> String {
    let out = Command::new(heso_bin())
        .args(["open", "--no-sign", "data:text/html,<h1>id</h1>"])
        .output()
        .expect("spawn heso open");
    assert!(
        out.status.success(),
        "heso open failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("heso open stdout is a plat JSON");
    let name = v["engine"]["name"].as_str().unwrap_or("heso");
    let version = v["engine"]["version"]
        .as_str()
        .expect("plat carries engine.version");
    format!("{name}@{version}")
}
