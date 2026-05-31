//! Regression test for determinism Hazard 1 (audit A2): the `cookies[]`
//! array that reaches the SIGNED plat body was ordered by
//! `cookie_store`'s `HashMap` iteration order (the crate's `preserve_order`
//! feature is OFF), which the default `RandomState` randomises per process.
//! With 2+ cookies matching a request that order — and therefore the
//! `plat_hash` and signature — flipped run-to-run.
//!
//! The fix sorts the rendered cookies by `(name, domain, path)` in
//! `render_cookies` (crates/heso-cli/src/main.rs). This test serves a page
//! that sets SIX cookies whose `Set-Cookie` header order is the REVERSE of
//! sorted order, reads it with `--include cookies` across two fresh
//! processes, and asserts the emitted `cookies[]` is (a) byte-identical
//! between the two processes and (b) sorted by name — i.e. independent of
//! both `Set-Cookie` order and HashMap iteration order.
//!
//! Why an end-to-end test rather than a unit test: `render_cookies` is
//! private to the `heso` binary crate, and the hazard only matters where
//! the value is signed — the `read` surface. Spawning two fresh processes
//! is also the only way to vary the per-process HashMap seed, exactly as
//! the determinism conformance harness does.

#[path = "determinism_support/mod.rs"]
mod support;

use std::process::Command;

use support::{heso_bin, FixedServer, Route};

/// Six cookies whose names, sorted ascending, are c1..c6. We emit the
/// `Set-Cookie` headers in DESCENDING name order so neither header order
/// nor jar insertion order matches the expected sorted output.
const COOKIE_NAMES_SORTED: [&str; 6] = ["c1", "c2", "c3", "c4", "c5", "c6"];

fn cookie_page_route() -> Route {
    let body = b"<!doctype html><html><head><title>cookies</title></head><body><h1>cookie page</h1></body></html>".to_vec();
    // Set-Cookie in reverse-sorted order; all host-only, path=/ so every
    // one matches the request and lands in the same jar bucket.
    let mut headers: Vec<(String, String)> = Vec::new();
    for name in COOKIE_NAMES_SORTED.iter().rev() {
        headers.push((
            "Set-Cookie".to_owned(),
            format!("{name}=v_{name}; Path=/"),
        ));
    }
    Route {
        path: "/".to_owned(),
        content_type: "text/html; charset=utf-8".to_owned(),
        body,
        extra_headers: headers,
    }
}

/// Run `heso read --include cookies <url>` in a fresh process and return
/// the `cookies` array as a compact JSON string.
fn read_cookies_json(url: &str) -> String {
    let out = Command::new(heso_bin())
        .args(["read", "--include", "cookies", "--no-sign", url])
        .output()
        .expect("spawn heso read");
    assert!(
        out.status.success(),
        "heso read failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("read output is a plat JSON");
    let cookies = v
        .get("cookies")
        .unwrap_or_else(|| panic!("read --include cookies must emit a `cookies` field; got: {v}"));
    serde_json::to_string(cookies).expect("serialize cookies")
}

#[test]
fn cookies_array_order_is_deterministic_across_processes() {
    let server = FixedServer::start(0, vec![cookie_page_route()]).expect("bind server");
    let url = format!("{}/", server.origin());

    // Two FRESH processes → two independent HashMap RandomState seeds. The
    // pre-fix code would (probabilistically) emit a different cookies[]
    // order between them.
    let a = read_cookies_json(&url);
    let b = read_cookies_json(&url);
    drop(server);

    assert_eq!(
        a, b,
        "cookies[] order diverged between two fresh processes — the HashMap-order \
         determinism hazard is not fixed.\nA: {a}\nB: {b}"
    );

    // ... and the order is the stable sorted-by-name order, not the
    // reverse `Set-Cookie` order, proving the sort (not luck) is what
    // makes it deterministic.
    let parsed: serde_json::Value = serde_json::from_str(&a).expect("cookies json");
    let names: Vec<&str> = parsed
        .as_array()
        .expect("cookies is an array")
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        names, COOKIE_NAMES_SORTED,
        "cookies[] must be sorted by name (got {names:?}); the array reached the \
         signed plat body, so a stable order is load-bearing for plat_hash"
    );
}
