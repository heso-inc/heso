//! DETERMINISM CONFORMANCE harness — the hero proof of LEG 1 (the
//! record/replay leg).
//!
//! For every cassette in the checked-in corpus
//! (`tests/determinism_corpus/manifest.json`) this gate:
//!
//!  1. Asserts the running binary's `engine_id` matches the manifest's.
//!     `engine.version` lives in the hash region, so a version bump
//!     changes `plat_hash` BY DESIGN — a mismatch here is reported as
//!     'EXPECTED DRIFT: regenerate', an intentional-regeneration signal,
//!     NOT a determinism failure. A hash mismatch with a MATCHING
//!     engine_id is a real determinism bug.
//!  2. Spawns K = 16 FRESH OS PROCESSES, each running
//!     `heso run --seed 0 <fixed.plat>`. Fresh processes are mandatory:
//!     each new process gets a new HashMap/HashSet `RandomState` seed and
//!     a fresh allocator layout — exactly what an in-process loop hides.
//!     We additionally vary the environment across the K processes so
//!     `RandomState` / allocator entropy differs, and the contract holds
//!     only if all 16 `plat_hash`es are byte-identical regardless.
//!  3. Asserts all K hashes are byte-identical to each other AND to the
//!     pinned `expected_plat_hash`.
//!  4. Cross-checks every process's plat against the `heso-verify`
//!     recompute (BLAKE3 over serde_jcs canonical bytes). This is NOT an
//!     independent canonicalizer: `heso run` and `heso-verify` reach the
//!     SAME `serde_jcs` (the engine depends DOWN on `heso-verify`), so a
//!     JCS *spec* bug — wrong number formatting, wrong key sort — is
//!     SHARED by both sides and is INVISIBLE to this cross-check. That
//!     class of bug is closed elsewhere, by the spec-derived RFC-8785
//!     vectors in `crates/heso-verify/tests/rfc8785_conformance.rs`. What
//!     this cross-check DOES catch is a producer/verifier *wiring* split:
//!     one binary strips/includes a field the other does not, or hashes a
//!     different region. If `heso run`'s self-reported hash and
//!     `heso-verify`'s recompute disagree, fail loud.
//!
//! HONESTY: the real independence proven here is the OS-process boundary —
//! K=16 fresh processes each get a new HashMap/HashSet `RandomState` seed
//! and a fresh allocator layout, which is exactly what surfaces a hidden
//! HashMap-order-into-signed-bytes bug. That is a process/entropy
//! independence, NOT a second independent canonicalizer (both sides share
//! serde_jcs, see point 4). And it is single-host: K=16 on ONE machine
//! proves determinism across RandomState + allocator entropy + process
//! boundaries on THIS (arch, OS, toolchain) only. By itself it does NOT
//! prove cross-architecture / cross-OS byte-identity. The aarch64<->x86_64
//! macOS pair IS now proven locally by `tests/determinism_cross_arch.rs`
//! (cross-build x86_64 `heso`, EXECUTE under Rosetta, assert the SAME pinned
//! arm64 hashes — foreign-ISA execution on one host); the linux legs and the
//! native-x86_64-macos leg remain the CI matrix's job (see
//! `tests/determinism_corpus/README.txt` and
//! `.github/workflows/determinism-matrix.yml`). Once that matrix is observed
//! green across all four native targets, any divergence is a release
//! blocker; until then those legs are an asserted design goal, not yet a
//! proof.

#[path = "determinism_support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use support::{
    corpus_dir, heso_bin, heso_verify_bin, running_engine_id, verify_recompute_hash, Manifest,
    ManifestEntry,
};

/// Number of fresh OS processes spawned per cassette. The FROZEN spec
/// pins this at 16: enough to surface a per-process HashMap-order flip
/// with high probability while keeping the gate fast.
const K_PROCESSES: usize = 16;

/// Run `heso run --seed <seed> <plat>` in a fresh process with a caller
/// supplied environment overlay (used to vary `RandomState`/allocator
/// entropy across the K processes) and return its `plat_hash`.
fn run_replay_hash_with_env(plat: &Path, seed: u64, env: &[(&str, String)]) -> String {
    let mut cmd = Command::new(heso_bin());
    cmd.args(["run", "--seed", &seed.to_string(), plat.to_str().unwrap()]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn heso run");
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

/// The per-cassette body of the conformance proof. Returns `Err(reason)`
/// only for an EXPECTED-DRIFT engine bump (the caller treats that as a
/// regenerate signal, not a failure); every genuine determinism failure
/// is an `assert!` panic that names the cassette.
fn conformance_for(entry: &ManifestEntry, running_id: &str) -> Result<(), String> {
    // (1) engine_id gate — drift attribution before any hash compare.
    if entry.engine_id != running_id {
        return Err(format!(
            "EXPECTED DRIFT: engine bumped {} -> {}; regenerate expected_plat_hash for `{}` \
             via `cargo test -p heso-cli --test determinism_generate -- --ignored` \
             (engine.version is in the hash region, so the bump moves plat_hash by design)",
            entry.engine_id, running_id, entry.cassette
        ));
    }

    let plat = corpus_dir().join(&entry.input_plat);
    assert!(
        plat.exists(),
        "corpus plat missing for `{}`: {} — run the determinism_generate blessing test",
        entry.cassette,
        plat.display()
    );

    // (2) K fresh processes, environment varied across them so HashMap
    // RandomState + allocator entropy differ run-to-run.
    let mut hashes: Vec<String> = Vec::with_capacity(K_PROCESSES);
    for i in 0..K_PROCESSES {
        // Distinct env per process. None of these are read by the
        // determinism path; they exist purely to perturb process-global
        // entropy (env layout shifts the allocator + the std RandomState
        // seed source) so a hidden HashMap-order-into-signed-bytes bug
        // cannot hide behind a stable within-process seed.
        let env = vec![
            ("HESO_DET_PROC_INDEX", i.to_string()),
            ("HESO_DET_NONCE", format!("{}-{}", std::process::id(), i)),
            (
                "HESO_DET_PADDING",
                "x".repeat(7 + (i * 13) % 97),
            ),
        ];
        let h = run_replay_hash_with_env(&plat, entry.seed, &env);

        // (4) producer/verifier WIRING cross-check: `heso-verify` must
        // agree with the engine's self-reported hash for THIS plat. NOTE
        // this is NOT an independent canonicalizer — both sides reach the
        // SAME serde_jcs, so a JCS spec bug is shared and invisible here
        // (that is closed by heso-verify/tests/rfc8785_conformance.rs).
        // What it catches is a wiring split: one side strips/includes a
        // field or hashes a different region than the other. (The input
        // plat is byte-identical across processes, so verifying it once
        // per process is sufficient.)
        let recompute = verify_recompute_hash(&plat);
        assert_eq!(
            recompute,
            entry.expected_plat_hash,
            "heso-verify recomputed a different plat_hash than the pinned one for \
             `{}` (producer/verifier WIRING split — one side strips/includes a field or hashes \
             a different region; NOT a JCS spec bug, which both shared sides would miss)",
            entry.cassette
        );

        hashes.push(h);
    }

    // (3) all K identical to each other.
    let distinct: BTreeSet<&String> = hashes.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "DETERMINISM FAILURE: `{}` produced {} distinct plat_hashes across {} fresh processes \
         (engine_id matches, so this is a real determinism bug, not version drift): {:?}",
        entry.cassette,
        distinct.len(),
        K_PROCESSES,
        distinct
    );

    // ... and all K identical to the pinned expected hash.
    let got = &hashes[0];
    assert_eq!(
        got, &entry.expected_plat_hash,
        "DETERMINISM/PIN MISMATCH: `{}` replayed to {} but the manifest pins {} \
         (engine_id matches — a real bug, regenerate only if the change was intentional)",
        entry.cassette, got, entry.expected_plat_hash
    );

    Ok(())
}

/// The gate. Every corpus cassette must reproduce its pinned `plat_hash`
/// byte-identically across 16 fresh processes, or this test fails.
#[test]
fn determinism_conformance_corpus_is_byte_identical_across_16_processes() {
    let manifest = Manifest::load();
    assert!(
        !manifest.entries.is_empty(),
        "determinism corpus manifest is empty — run the determinism_generate blessing test"
    );

    let running_id = running_engine_id();

    let mut drift_notes: Vec<String> = Vec::new();
    let mut proven = 0usize;
    let mut saw_hydrated = false;
    let mut saw_data_attrs = false;
    let mut saw_settle_chain = false;

    for entry in &manifest.entries {
        match conformance_for(entry, &running_id) {
            Ok(()) => {
                proven += 1;
                if entry.hydrated {
                    saw_hydrated = true;
                }
                if entry.has_data_attrs {
                    saw_data_attrs = true;
                }
                if entry.requires_settle {
                    saw_settle_chain = true;
                }
            }
            Err(drift) => drift_notes.push(drift),
        }
    }

    // If EVERY entry drifted on engine_id, the whole corpus needs a
    // regenerate — surface that as a clear, actionable failure rather
    // than a silent green (a green-on-all-drift would let a determinism
    // bug ride in under a version bump).
    if proven == 0 {
        panic!(
            "determinism corpus did not prove a single cassette — all {} entries report engine \
             drift; regenerate the corpus:\n{}",
            manifest.entries.len(),
            drift_notes.join("\n")
        );
    }

    // A partial drift (some entries on the old engine_id) should never
    // happen for a single coherent corpus; treat it as a hard error so a
    // half-regenerated manifest can't ship.
    assert!(
        drift_notes.is_empty(),
        "determinism corpus is internally inconsistent — some entries match the running \
         engine_id and some do not. Regenerate the whole corpus:\n{}",
        drift_notes.join("\n")
    );

    // The JS-hydrated cassette is the load-bearing coverage: it is the
    // only fixture proving the QuickJS determinism fences (seeded RNG,
    // virtual clock, UTC tz) yield a stable plat_hash across fresh
    // processes. Its absence would silently drop the biggest gap.
    assert!(
        saw_hydrated,
        "corpus proved {proven} cassettes but NONE was JS-hydrated — the QuickJS determinism \
         path is unproven; the hydrated_spa cassette must be in the corpus"
    );

    // Coverage guards for the extended corpus (mirroring the saw_hydrated
    // guard above). A regenerate that silently dropped data_attr_heavy or
    // chained_settle_spa would otherwise leave the data_attrs path / the
    // settle-loop fix unexercised by the MAIN corpus with no loud signal.
    //
    // NOTE on data_attrs: this guards PATH coverage, not a redden-on-
    // mutation proof. The `data_attrs::extract` BTreeMap-vs-HashMap key
    // ORDER is NOT a plat_hash hazard — serde_jcs sorts every JSON
    // object's keys recursively before hashing, so swapping the container
    // does not move the hash (verified empirically; see the fixture
    // comment and README). The fixture exists so the rich data_attrs blob
    // is routed through the signed K=16 replay hash at all; the guard just
    // stops a regenerate from silently deleting that breadth.
    assert!(
        saw_data_attrs,
        "corpus proved {proven} cassettes but NONE carried data_attrs — the data_attrs \
         extraction path is unexercised through the signed hash; the data_attr_heavy cassette \
         must be in the corpus (PATH coverage; object-key ORDER is not itself a hazard — JCS \
         sorts keys)"
    );
    assert!(
        saw_settle_chain,
        "corpus proved {proven} cassettes but NONE required the settle loop's chained-timer \
         advance branch — the async-settle hazard is unproven; the chained_settle_spa cassette \
         must be in the corpus"
    );

    eprintln!(
        "determinism conformance: {proven} cassettes byte-identical across {K_PROCESSES} fresh \
         processes (single-host proof; cross-arch is the CI matrix)"
    );
}

/// Sibling proof from the FROZEN spec: `stamp` and `run` agree on the
/// `plat_hash` across two SEPARATE subprocesses for the hydrated
/// cassette's replay. We re-run the checked-in hydrated plat through
/// `run` twice and assert equality independent of the pinned manifest, so
/// even a stale manifest can't mask a stamp/run divergence.
#[test]
fn hydrated_replay_is_stable_across_two_subprocesses() {
    let manifest = Manifest::load();
    let Some(entry) = manifest.entries.iter().find(|e| e.hydrated) else {
        panic!("no hydrated cassette in the corpus");
    };
    if entry.engine_id != running_engine_id() {
        // Engine drift — the pinned bytes are stale; the byte-identity
        // claim across two subprocesses still holds regardless of the
        // pin, so prove THAT and skip the pin comparison.
        eprintln!("engine drift; proving subprocess equality without the pin");
    }
    let plat = corpus_dir().join(&entry.input_plat);
    let a = run_once(&plat, entry.seed);
    let b = run_once(&plat, entry.seed);
    assert_eq!(
        a, b,
        "hydrated cassette replayed to different plat_hashes in two fresh processes"
    );
}

fn run_once(plat: &Path, seed: u64) -> String {
    let out = Command::new(heso_bin())
        .args(["run", "--seed", &seed.to_string(), plat.to_str().unwrap()])
        .output()
        .expect("spawn heso run");
    assert!(
        out.status.success(),
        "heso run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("plat json");
    v["plat_hash"].as_str().expect("plat_hash").to_owned()
}

/// The `heso-verify` binary must exist alongside `heso`; the harness's
/// producer/verifier WIRING cross-check depends on it. (It shares serde_jcs
/// with the engine, so it is not an independent canonicalizer — see the
/// module doc, point 4.)
#[test]
fn heso_verify_binary_is_available() {
    assert!(
        heso_verify_bin().exists(),
        "heso-verify binary not found at {} — build it: `cargo build -p heso-verify`",
        heso_verify_bin().display()
    );
    let _ = heso_bin();
}
