//! Corpus generator / BLESS updater for the determinism conformance
//! harness. This is NOT a gate — it is `#[ignore]`d and run by hand to
//! (re)mint the checked-in `.plat` fixtures and the pinned-hash manifest
//! whenever they legitimately change (a new cassette, or an intentional
//! `engine.version` bump that moves every `plat_hash` by design).
//!
//! Run with:
//!
//! ```text
//! cargo test -p heso-cli --test determinism_generate -- --ignored --nocapture
//! ```
//!
//! Discipline (mirrors `generate_vectors.rs` and the reseed goldens):
//! every value is COMPUTED by stamping a real cassette through the real
//! `heso` binary, never hand-authored. The generator serves each
//! cassette body on a FIXED loopback port and stamps a one-step `open`
//! plan, so the plat's embedded origin — and therefore its `plat_hash` —
//! is byte-stable and bakeable into a checked-in file. Replay (`heso run`)
//! needs no server, so the fixed port only matters here, at generation.

#[path = "determinism_support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::Command;

use support::{
    canonicalize_and_recompute, corpus_dir, corpus_path, engine_id, heso_bin, FixedServer,
    Manifest, ManifestEntry, Route, CANONICAL_ORIGIN,
};

/// Bind an EPHEMERAL port (the OS picks a free one) — the robust choice
/// that avoids fixed-port `TIME_WAIT` races across back-to-back runs. The
/// volatile origin is rewritten to [`CANONICAL_ORIGIN`] in the checked-in
/// plat, so the pinned hash is host-independent.
const EPHEMERAL: u16 = 0;

/// Reference target string recorded in the manifest. Update when the
/// pinned hashes are regenerated on a different host.
const REFERENCE_TARGET: &str = "aarch64-apple-darwin (developer machine; CI matrix is the cross-arch proof)";

/// A static-HTML cassette to fold into the corpus: its compat-tests slug.
const STATIC_CASSETTES: &[&str] = &[
    "example_com",
    "httpbin_html",
    "httpbin_forms_post",
    "hacker_news",
    "rust_lang",
    "docs_rs",
    "iana_reserved",
    "wikipedia_html",
];

fn cassettes_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("heso-compat-tests")
        .join("cassettes")
}

/// Stamp a one-step `open` plan against a running [`FixedServer`] and
/// return the resulting (ephemeral-port-baked) plat JSON bytes. `--no-sign`
/// keeps the plat bare so the pinned hash is the body hash, not a
/// signature dependent one (signing never moves `plat_hash` anyway, but a
/// bare plat is the simplest reproducible artifact). The caller rewrites
/// the ephemeral origin to the canonical host afterwards.
fn stamp_open(origin: &str) -> Vec<u8> {
    let plan = serde_json::json!([{ "verb": "open", "url": format!("{origin}/") }]);
    let plan_path = std::env::temp_dir().join(format!(
        "heso-det-gen-plan-{}-{}.json",
        std::process::id(),
        fastrand_like()
    ));
    std::fs::write(&plan_path, plan.to_string()).expect("write plan");
    let out = Command::new(heso_bin())
        .args([
            "stamp",
            "--seed",
            "0",
            "--no-sign",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn heso stamp");
    let _ = std::fs::remove_file(&plan_path);
    // `stamp` exits 1 when a step reported `partial`/`error` but STILL
    // emits a fully-formed, hashed plat on stdout (the partial capture is
    // itself a deterministic artifact). We accept the stdout as long as
    // it parses to a plat with a `plat_hash` and a non-empty cassette;
    // a hard failure (no stdout / no hash) panics.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stamp produced no plat for {origin} (exit {:?}): {} / stderr: {}",
            out.status.code(),
            e,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let records = v
        .pointer("/cassette/records")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        records >= 1,
        "stamp against {origin} captured no cassette records (exit {:?}); the fixed server is \
         not serving the fixture — step0 error: {:?} — stderr: {}",
        out.status.code(),
        v.pointer("/steps/0/error"),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// A pid+counter unique-ish suffix without pulling a new dep.
fn fastrand_like() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn read_body(slug: &str) -> Vec<u8> {
    let p = cassettes_dir().join(slug).join("body.html");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read cassette body {}: {e}", p.display()))
}

fn read_content_type(slug: &str) -> String {
    let p = cassettes_dir().join(slug).join("meta.json");
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&p).unwrap_or_else(|e| panic!("read meta {}: {e}", p.display())),
    )
    .unwrap_or_else(|e| panic!("parse meta {}: {e}", p.display()));
    meta["content_type"]
        .as_str()
        .unwrap_or("text/html; charset=utf-8")
        .to_owned()
}

fn plat_hash_of(bytes: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(bytes).expect("plat is json");
    v["plat_hash"]
        .as_str()
        .expect("stamped plat carries plat_hash")
        .to_owned()
}

#[test]
#[ignore = "blessing/regeneration step; run with --ignored to remint the corpus"]
fn determinism_generate_corpus() {
    let mut entries: Vec<ManifestEntry> = Vec::new();

    // Bind an EPHEMERAL port ONCE; swap the route table per cassette.
    let server = FixedServer::start(EPHEMERAL, Vec::new()).expect("bind ephemeral server");
    let origin = server.origin();

    // ---- static cassettes ----
    for slug in STATIC_CASSETTES {
        let body = read_body(slug);
        let ct = read_content_type(slug);
        server.set_routes(vec![Route::html("/", &ct, body)]);
        let stamped = stamp_open(&origin);
        // Rewrite the volatile ephemeral origin to the canonical host and
        // recompute the hash over the rewritten body.
        let plat = canonicalize_and_recompute(&stamped, &origin);

        let hash = plat_hash_of(&plat);
        let rel = format!("fixtures/{slug}.plat");
        std::fs::write(corpus_path(&rel), &plat).expect("write static plat");
        entries.push(ManifestEntry {
            cassette: (*slug).to_owned(),
            input_plat: rel,
            seed: 0,
            engine_id: engine_id(),
            expected_plat_hash: hash,
            hydrated: false,
            note: format!("static fetch + html5ever/scraper parse path ({slug})"),
        });
    }

    // ---- the one JS-hydrated cassette (the QuickJS determinism proof) ----
    {
        let html = std::fs::read(corpus_path("fixtures/hydrated_spa.html"))
            .expect("read hydrated fixture");
        let data = std::fs::read(corpus_path("fixtures/hydrated_spa_data.json"))
            .expect("read hydrated data");
        server.set_routes(vec![
            Route::html("/", "text/html; charset=utf-8", html),
            Route::html("/data.json", "application/json", data),
        ]);
        let stamped = stamp_open(&origin);

        // Sanity: the cassette must have captured BOTH the page fetch and
        // the JS-side fetch, and the DOM must have hydrated. A regression
        // in the determinism settle would drop the second record.
        let v0: serde_json::Value = serde_json::from_slice(&stamped).expect("plat json");
        let records = v0
            .pointer("/cassette/records")
            .and_then(|r| r.as_array())
            .expect("cassette records");
        assert_eq!(
            records.len(),
            2,
            "hydrated cassette must capture page + JS fetch; got {} records",
            records.len()
        );
        assert!(
            serde_json::to_string(&v0).unwrap().contains("hydrated-ok"),
            "hydrated DOM must be captured into the plat (settle regressed?)"
        );

        let plat = canonicalize_and_recompute(&stamped, &origin);
        // The canonical origin must have fully replaced the ephemeral one,
        // including inside the JS-captured `location.origin` value, or the
        // cassette lookup would break on replay.
        assert!(
            !String::from_utf8_lossy(&plat).contains(&origin),
            "ephemeral origin leaked into the canonical plat"
        );
        assert!(
            String::from_utf8_lossy(&plat).contains(CANONICAL_ORIGIN),
            "canonical origin missing from the rewritten plat"
        );

        let hash = plat_hash_of(&plat);
        let rel = "fixtures/hydrated_spa.plat".to_owned();
        std::fs::write(corpus_path(&rel), &plat).expect("write hydrated plat");
        entries.push(ManifestEntry {
            cassette: "hydrated_spa".to_owned(),
            input_plat: rel,
            seed: 0,
            engine_id: engine_id(),
            expected_plat_hash: hash,
            hydrated: true,
            note: "JS-hydrated: fetch()+Math.random+Date.now+UTC Date routed through plat_hash".to_owned(),
        });
    }

    let manifest = Manifest {
        reference_target: REFERENCE_TARGET.to_owned(),
        entries,
    };
    // serde_json pretty so the manifest diffs cleanly in PRs.
    let pretty = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    std::fs::write(corpus_dir().join("manifest.json"), pretty + "\n").expect("write manifest");

    eprintln!(
        "blessed determinism corpus: {} entries at engine_id {}",
        manifest.entries.len(),
        engine_id()
    );
}

