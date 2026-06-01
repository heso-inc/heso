//! CROSS-ARCH DETERMINISM PROOF — arm64-native vs x86_64-via-Rosetta.
//!
//! The single-host K-process harness (`determinism_conformance.rs`) proves
//! byte-identical replay across HashMap `RandomState` + allocator entropy +
//! process boundaries on ONE (arch, OS, toolchain). It does NOT prove that
//! the SAME bytes come out on a DIFFERENT instruction-set architecture.
//!
//! This gate closes the x86_64-vs-aarch64 half of that gap WITHOUT a remote
//! runner: on an Apple-silicon host with Rosetta 2, it builds the `heso`
//! binary for `x86_64-apple-darwin`, runs every checked-in corpus cassette
//! through that x86_64 binary (Rosetta translates the x86_64 Mach-O
//! transparently — no `arch -x86_64` wrapper needed), and asserts each
//! replay's `plat_hash` is BYTE-IDENTICAL to the SAME pinned value the
//! native arm64 manifest carries. Same host, same pinned hash, foreign ISA:
//! that equality IS the cross-arch byte-identity proof for this arch pair.
//!
//! HONESTY — what this proves and what it does NOT:
//!   * PROVES: arm64-native and x86_64-via-Rosetta-EXECUTION agree on every
//!     pinned `plat_hash` on THIS macOS host. This is foreign-ISA EXECUTION,
//!     not cross-COMPILATION of the test result, and not a different OS.
//!   * DOES NOT prove macOS-vs-Linux, nor a NATIVE x86_64 host (Rosetta is a
//!     faithful-but-not-bit-for-bit-guaranteed translator — but since the
//!     determinism path is seeded ChaCha20 + JCS + BLAKE3 with no
//!     platform-pointer / HashMap-order bytes in the canonical plat, an arch
//!     divergence WOULD surface here). The {linux x2, native-x86_64-macos}
//!     legs remain the CI matrix's job (`determinism-matrix.yml`), still to
//!     be OBSERVED GREEN.
//!
//! GATING: this test is `#[ignore]` AND additionally requires
//! `HESO_CROSS_ARCH=1`, so a normal `cargo test` never pays the multi-minute
//! x86_64 cross-build (which includes the QuickJS-sys C build for x86_64).
//! Run it explicitly:
//!
//!   HESO_CROSS_ARCH=1 cargo test -p heso-cli --test determinism_cross_arch \
//!       -- --ignored --nocapture
//!
//! SKIP-CLEAN: when any precondition is absent — not an Apple-silicon macOS
//! host, Rosetta not installed, or the `x86_64-apple-darwin` target / build
//! unavailable (e.g. offline) — the test prints exactly WHY it skipped and
//! returns Ok. It NEVER panics on a missing precondition; the only panic is a
//! genuine cross-arch hash divergence.

#[path = "determinism_support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use support::{corpus_dir, heso_bin, running_engine_id, Manifest, ManifestEntry};

/// The foreign target whose bytes we compare against the native arm64 pin.
const CROSS_TARGET: &str = "x86_64-apple-darwin";

/// The opt-in env gate. The `#[ignore]` attribute already keeps this out of
/// a default `cargo test`; this second gate keeps it out even of a
/// `-- --ignored` sweep unless cross-arch was explicitly requested, so the
/// slow cross-build is never an accident.
fn cross_arch_requested() -> bool {
    std::env::var("HESO_CROSS_ARCH").as_deref() == Ok("1")
}

/// True only on an Apple-silicon (aarch64) macOS host — the one
/// configuration where Rosetta can execute an x86_64 Mach-O.
fn is_apple_silicon_macos() -> bool {
    cfg!(target_os = "macos") && cfg!(target_arch = "aarch64")
}

/// Rosetta 2 is present iff its runtime helper directory exists. This is the
/// same probe `softwareupdate --install-rosetta` populates; if it is absent,
/// the x86_64 Mach-O cannot be executed on this host.
fn rosetta_present() -> bool {
    Path::new("/Library/Apple/usr/libexec/oah").exists()
}

/// The profile segment (`debug` / `release` / a custom profile dir) the
/// native `heso` binary lives under. We derive it from the binary path
/// rather than guessing, so a `--release` run or a custom profile still
/// locates the matching x86_64 sibling.
fn native_profile_dir() -> Option<String> {
    // `heso_bin()` => `<…>/target[/<triple>]/<profile>/heso`. The profile is
    // the parent directory's file name.
    let bin = heso_bin();
    bin.parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
}

/// The workspace `target/` root, derived from the native binary path. The
/// native binary is at either `target/<profile>/heso` (host build) or
/// `target/<triple>/<profile>/heso` (already-targeted build); walk up from
/// the profile dir until the directory is literally named `target`.
fn target_root() -> Option<PathBuf> {
    let bin = heso_bin();
    // bin = …/<profile>/heso ; ancestors: <profile>, then either `target`
    // or `<triple>` then `target`.
    let mut dir = bin.parent()?.to_path_buf(); // <profile>
    for _ in 0..3 {
        dir = dir.parent()?.to_path_buf();
        if dir.file_name().and_then(|s| s.to_str()) == Some("target") {
            return Some(dir);
        }
    }
    None
}

/// Where the cross-built x86_64 `heso` binary should land:
/// `target/x86_64-apple-darwin/<profile>/heso`.
fn cross_heso_path(profile: &str) -> Option<PathBuf> {
    Some(
        target_root()?
            .join(CROSS_TARGET)
            .join(profile)
            .join("heso"),
    )
}

/// Ensure the `x86_64-apple-darwin` std component is installed for the
/// active toolchain (idempotent; a no-op when already present). Returns
/// false (with a printed reason) when the add fails, e.g. offline.
fn ensure_cross_target_installed() -> bool {
    // Already installed?
    if let Ok(out) = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        let listed = String::from_utf8_lossy(&out.stdout);
        if listed.lines().any(|l| l.trim() == CROSS_TARGET) {
            return true;
        }
    }
    // Try to add it (will hit the network; skips clean on failure).
    let status = Command::new("rustup")
        .args(["target", "add", CROSS_TARGET])
        .status();
    match status {
        Ok(s) if s.success() => true,
        Ok(_) => {
            eprintln!(
                "SKIP cross-arch: `rustup target add {CROSS_TARGET}` failed \
                 (offline or toolchain unavailable)"
            );
            false
        }
        Err(e) => {
            eprintln!("SKIP cross-arch: could not run rustup ({e})");
            false
        }
    }
}

/// Cross-build the x86_64 `heso` (and `heso-verify` for parity with the
/// native harness's wiring cross-check) for `x86_64-apple-darwin`. This is
/// the SLOW step — a cold build pulls the QuickJS-sys C build for x86_64.
/// Returns false (printed reason) on build failure so the caller skips clean.
fn cross_build() -> bool {
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "-p",
            "heso-cli",
            "--bin",
            "heso",
            "-p",
            "heso-verify",
            "--bin",
            "heso-verify",
            "--target",
            CROSS_TARGET,
        ])
        .status();
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("SKIP cross-arch: x86_64 cross-build exited {s}");
            false
        }
        Err(e) => {
            eprintln!("SKIP cross-arch: could not spawn cargo for the cross-build ({e})");
            false
        }
    }
}

/// Run `heso run --seed <seed> <plat>` through the x86_64 binary (Rosetta
/// executes it on the arm64 host) and return its `plat_hash`. Panics with
/// captured stderr on failure so a regression names the cassette.
fn cross_replay_hash(cross_heso: &Path, plat: &Path, seed: u64) -> String {
    let out = Command::new(cross_heso)
        .args(["run", "--seed", &seed.to_string(), plat.to_str().unwrap()])
        .output()
        .expect("spawn x86_64 heso run under Rosetta");
    assert!(
        out.status.success(),
        "x86_64 heso run failed for {}: {}",
        plat.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("x86_64 heso run stdout is a plat JSON");
    v["plat_hash"]
        .as_str()
        .expect("x86_64-replayed plat carries a plat_hash")
        .to_owned()
}

/// The cross-arch proof. For every corpus cassette, the x86_64-via-Rosetta
/// replay must reproduce the SAME pinned `plat_hash` the native arm64
/// manifest carries. Skips clean (never panics) when the host cannot run an
/// x86_64 binary.
#[test]
#[ignore = "slow x86_64 cross-build + Rosetta execution; opt in with HESO_CROSS_ARCH=1 and --ignored"]
fn determinism_cross_arch_x86_64_via_rosetta_matches_native_arm64_pins() {
    if !cross_arch_requested() {
        eprintln!(
            "SKIP cross-arch: set HESO_CROSS_ARCH=1 to run the x86_64-via-Rosetta proof \
             (it cross-builds heso for {CROSS_TARGET}, a multi-minute cold build)"
        );
        return;
    }
    if !is_apple_silicon_macos() {
        eprintln!(
            "SKIP cross-arch: not an Apple-silicon macOS host — Rosetta x86_64 execution \
             is unavailable here (this leg only proves the aarch64<->x86_64 macOS pair on \
             an arm64 Mac; the other legs are the CI matrix's job)"
        );
        return;
    }
    if !rosetta_present() {
        eprintln!(
            "SKIP cross-arch: Rosetta 2 not installed (/Library/Apple/usr/libexec/oah absent) — \
             install it with `softwareupdate --install-rosetta` to run this proof locally"
        );
        return;
    }
    if !ensure_cross_target_installed() {
        return; // reason already printed
    }
    if !cross_build() {
        return; // reason already printed
    }

    let Some(profile) = native_profile_dir() else {
        eprintln!("SKIP cross-arch: could not derive the build profile from the native heso path");
        return;
    };
    let Some(cross_heso) = cross_heso_path(&profile) else {
        eprintln!("SKIP cross-arch: could not derive the target/ root from the native heso path");
        return;
    };
    // The build claimed success; the binary MUST be where we expect. If it
    // is not, that is a real wiring bug (wrong profile/target layout), so
    // fail clean with the exact expected path rather than silently skip.
    assert!(
        cross_heso.exists(),
        "x86_64 cross-build reported success but the binary is missing at {} \
         (unexpected target/ layout — a custom CARGO_TARGET_DIR or profile mismatch?)",
        cross_heso.display()
    );

    let manifest = Manifest::load();
    assert!(
        !manifest.entries.is_empty(),
        "determinism corpus manifest is empty — nothing to cross-check"
    );

    // engine_id drift gate, exactly like the native harness: engine.version
    // lives in the hash region, so a bump moves every pinned hash BY DESIGN.
    // If the running (native) binary drifted from the manifest, the pins are
    // stale and the cross-arch comparison against them is meaningless — skip
    // clean with the regenerate instruction rather than redden on stale pins.
    let running_id = running_engine_id();
    if manifest.entries.iter().any(|e| e.engine_id != running_id) {
        eprintln!(
            "SKIP cross-arch: manifest engine_id != running {running_id} (EXPECTED DRIFT) — \
             regenerate the corpus before re-pinning the cross-arch proof"
        );
        return;
    }

    let mut proven = 0usize;
    for entry in &manifest.entries {
        cross_check_entry(&cross_heso, entry);
        proven += 1;
    }

    eprintln!(
        "CROSS-ARCH PROOF: {proven} cassettes replayed BYTE-IDENTICAL on \
         x86_64-via-Rosetta vs the pinned native aarch64 plat_hash (same host, foreign ISA). \
         macOS-vs-Linux and native-x86_64 remain the CI matrix's job."
    );
}

/// Cross-check one cassette: the x86_64-via-Rosetta `plat_hash` must equal
/// the pinned native arm64 value. A divergence here is THE cross-arch bug.
fn cross_check_entry(cross_heso: &Path, entry: &ManifestEntry) {
    let plat = corpus_dir().join(&entry.input_plat);
    assert!(
        plat.exists(),
        "corpus plat missing for `{}`: {}",
        entry.cassette,
        plat.display()
    );
    let got = cross_replay_hash(cross_heso, &plat, entry.seed);
    assert_eq!(
        got, entry.expected_plat_hash,
        "CROSS-ARCH DIVERGENCE: `{}` replayed to {} on x86_64-via-Rosetta but the manifest \
         pins {} (the native aarch64 value). The native arm64 leg is green for the same \
         cassette, so this is an ARCH-DEPENDENT byte in the canonical plat — a real \
         cross-architecture determinism bug (suspect a non-portable RNG, pointer-width / \
         HashMap-iteration bytes, or the QuickJS fork diverging across ISA).",
        entry.cassette, got, entry.expected_plat_hash
    );
}
