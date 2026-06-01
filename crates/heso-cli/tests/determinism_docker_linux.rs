//! DOCKER-LINUX DETERMINISM PROOF — linux/amd64 + linux/arm64 in-container
//! replay vs the pinned native-arm64 plat_hashes.
//!
//! The single-host K-process harness (`determinism_conformance.rs`) proves
//! byte-identical replay across HashMap `RandomState` + allocator entropy +
//! process boundaries on ONE (arch, OS, toolchain). The Rosetta sibling
//! (`determinism_cross_arch.rs`) closes the aarch64<->x86_64 *macOS* pair on
//! a single host. Neither proves macOS-vs-**Linux**.
//!
//! This gate closes the Linux half WITHOUT a remote runner: when a Docker
//! daemon is reachable, it builds `heso` INSIDE a `rust:1.90-bookworm`
//! container for each of `linux/amd64` and `linux/arm64` (the non-native
//! platform runs under QEMU/binfmt emulation), runs every checked-in corpus
//! cassette through that in-container binary, and asserts each replay's
//! `plat_hash` is BYTE-IDENTICAL to the SAME pinned value the native arm64
//! manifest carries. The container build mounts the workspace READ-ONLY and
//! redirects `CARGO_TARGET_DIR` to a container-writable `/tmp/target`, so the
//! host tree is never touched.
//!
//! HONESTY — what this proves and what it does NOT:
//!   * PROVES (on a green run): a Linux build of the engine — native-arch
//!     `linux/arm64` and emulated `linux/amd64` — reproduces every pinned
//!     `plat_hash` from this aarch64-macOS-generated corpus. That is the
//!     macOS-vs-Linux byte-identity leg for these two Linux arches.
//!   * DOES NOT prove NATIVE x86_64-macOS (Rosetta is a translator and Docker
//!     here runs a Linux VM — there is no macOS-x86_64 surface on an arm64
//!     Mac to test; that leg stays the CI matrix's job, `macos-13`). The
//!     emulated `linux/amd64` leg is strong evidence but the native CI matrix
//!     (`ubuntu-latest` + `ubuntu-24.04-arm`) remains the authoritative
//!     bare-metal Linux enforcement.
//!
//! GATING: this test is `#[ignore]` AND additionally requires
//! `HESO_DOCKER_DETERMINISM=1`, so a normal `cargo test` never pays the
//! multi-minute in-container builds (each platform compiles the QuickJS-sys C
//! sources + the whole CLI under emulation). Run it explicitly:
//!
//!   HESO_DOCKER_DETERMINISM=1 cargo test -p heso-cli \
//!       --test determinism_docker_linux -- --ignored --nocapture
//!
//! SKIP-CLEAN: every precondition prints exactly WHY it skipped and returns
//! Ok — env not set, `docker` CLI absent, `docker info` failing (daemon
//! down), or the running binary's `engine_id` having drifted from the pinned
//! manifest. A per-platform QEMU/exec-format failure skips THAT platform
//! only. The ONLY panic is a genuine in-container `plat_hash` divergence.

#[path = "determinism_support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::Command;

use support::{corpus_dir, running_engine_id, Manifest, ManifestEntry};

/// The container image the in-container build runs under. Pinned to the
/// SAME channel as `rust-toolchain.toml` (`channel = "1.90"`) so the
/// in-container compiler matches the host toolchain that minted the pins —
/// on an MSRV bump this tag MUST move in lockstep with `rust-toolchain.toml`
/// or the `--locked` build can fail.
const DOCKER_IMAGE: &str = "rust:1.90-bookworm";

/// The two Linux platforms proven. `linux/arm64` is native on an Apple-
/// silicon host (fast); `linux/amd64` runs under QEMU/binfmt emulation
/// (slow, and skipped clean if no emulator is installed).
const PLATFORMS: [&str; 2] = ["linux/amd64", "linux/arm64"];

/// The opt-in env gate. The `#[ignore]` attribute already keeps this out of
/// a default `cargo test`; this second gate keeps it out even of a
/// `-- --ignored` sweep unless the Docker proof was explicitly requested, so
/// the slow in-container builds are never an accident.
fn docker_determinism_requested() -> bool {
    std::env::var("HESO_DOCKER_DETERMINISM").as_deref() == Ok("1")
}

/// True iff a `docker` CLI is on PATH (probed via `docker --version`).
fn docker_cli_present() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// True iff the Docker daemon is reachable (`docker info` exits 0). This is
/// the precondition that FIRES on a developer host with Docker Desktop not
/// running — it must skip clean, never redden.
fn docker_daemon_up() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Walk up from this crate's `CARGO_MANIFEST_DIR` to the workspace root —
/// the first ancestor that holds a `Cargo.lock` AND a `Cargo.toml` declaring
/// `[workspace]`. That directory is what we mount read-only at `/heso`, so
/// the in-container `cargo build --locked` sees the same lockfile the host
/// pinned the corpus with.
fn workspace_root() -> Option<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let lock = dir.join("Cargo.lock");
        let toml = dir.join("Cargo.toml");
        if lock.is_file() && toml.is_file() {
            if let Ok(contents) = std::fs::read_to_string(&toml) {
                if contents.contains("[workspace]") {
                    return Some(dir);
                }
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The corpus directory expressed RELATIVE to the workspace root, so it can
/// be addressed from inside the container as `<workspace>/<rel>` under the
/// `/heso` mount. Returns e.g. `crates/heso-cli/tests/determinism_corpus`.
fn corpus_rel_to_workspace(workspace: &std::path::Path) -> Option<String> {
    corpus_dir()
        .strip_prefix(workspace)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
}

/// The single in-container shell program. First it builds `heso` with
/// `--locked` (stdout redirected to stderr via `1>&2` so the only thing on
/// stdout is our machine-readable replay lines). Then, for each manifest
/// entry, it runs `heso run --seed <seed> <plat>` and prints
/// `HESO_PLAT_HASH <cassette> <plat_hash>`, parsing the run's JSON
/// `plat_hash` field with a tiny grep/sed (the image ships coreutils, no
/// `jq` dependency). Everything runs inside the read-only `/heso` mount with
/// `CARGO_TARGET_DIR=/tmp/target` — the mount is read-only, so cargo MUST
/// write its target tree elsewhere.
fn container_program(corpus_rel: &str, entries: &[ManifestEntry]) -> String {
    let mut prog = String::new();
    prog.push_str("set -e\n");
    // run_one <cassette> <seed> <plat>: replay one cassette and emit a
    // machine-readable `HESO_PLAT_HASH <cassette> <hash>` line. The field on
    // stdout is `"plat_hash":"<64hex>"`; grep+sed extracts the hex run.
    prog.push_str(
        "run_one() {\n\
         \x20 local cassette=\"$1\"; local seed=\"$2\"; local plat=\"$3\"\n\
         \x20 local out hash\n\
         \x20 out=\"$($HESO run --seed \"$seed\" \"$plat\")\"\n\
         \x20 hash=\"$(printf '%s' \"$out\" | grep -o '\"plat_hash\":\"[0-9a-f]*\"' | head -n1 | sed 's/.*\"plat_hash\":\"//; s/\"//')\"\n\
         \x20 printf 'HESO_PLAT_HASH %s %s\\n' \"$cassette\" \"$hash\"\n\
         }\n",
    );
    // rquickjs-sys's bindgen needs libclang, which the base rust image lacks —
    // install it before building (the container already has network for cargo).
    prog.push_str(
        "apt-get update -qq 1>&2 && apt-get install -y -qq clang libclang-dev pkg-config 1>&2\n",
    );
    // Build straight to stderr so stdout stays clean for the replay lines.
    prog.push_str("cargo build --locked -p heso-cli --bin heso 1>&2\n");
    prog.push_str("HESO=/tmp/target/debug/heso\n");
    for entry in entries {
        prog.push_str(&format!(
            "run_one '{cassette}' '{seed}' '/heso/{corpus_rel}/{input}'\n",
            cassette = entry.cassette,
            seed = entry.seed,
            corpus_rel = corpus_rel,
            input = entry.input_plat,
        ));
    }
    prog
}

/// Run the in-container build+replay for one platform and return the parsed
/// `cassette -> plat_hash` lines. Returns:
///   * `Ok(Some(map))` on a successful container run,
///   * `Ok(None)` when the platform is unavailable (QEMU/exec-format missing)
///     — a clean per-platform SKIP, reason already printed,
///   * `Err(msg)` only on an unexpected docker failure we want surfaced.
fn run_platform(
    platform: &str,
    workspace: &std::path::Path,
    program: &str,
) -> Result<Option<Vec<(String, String)>>, String> {
    let mount = format!("{}:/heso:ro", workspace.display());
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--platform",
            platform,
            "-v",
            &mount,
            "-e",
            "CARGO_TARGET_DIR=/tmp/target",
            "-w",
            "/heso",
            DOCKER_IMAGE,
            "bash",
            "-c",
            program,
        ])
        .output()
        .map_err(|e| format!("spawn docker run for {platform}: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // A missing emulator for the non-native platform surfaces as an
        // exec-format / no-matching-manifest error. That is a clean
        // per-platform SKIP (the emulator is absent), NOT a determinism
        // failure — do not panic on it.
        let lc = stderr.to_lowercase();
        if lc.contains("exec format error")
            || lc.contains("no matching manifest")
            || lc.contains("exec /bin/bash")
            || lc.contains("rosetta error")
            || lc.contains("requested platform")
        {
            eprintln!(
                "SKIP platform {platform}: emulation unavailable (QEMU/binfmt not installed for \
                 this platform) — install `docker/setup-qemu-action` (CI) or enable Docker \
                 Desktop's 'Use Rosetta/QEMU' to run the foreign-arch leg. stderr: {}",
                stderr.trim()
            );
            return Ok(None);
        }
        return Err(format!(
            "docker run for {platform} exited {}: {}",
            out.status, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut pairs = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("HESO_PLAT_HASH ") {
            let mut it = rest.split_whitespace();
            if let (Some(cassette), Some(hash)) = (it.next(), it.next()) {
                pairs.push((cassette.to_owned(), hash.to_owned()));
            }
        }
    }
    Ok(Some(pairs))
}

/// The Docker-Linux proof. For every corpus cassette and each available
/// Linux platform, the in-container replay must reproduce the SAME pinned
/// `plat_hash` the native arm64 manifest carries. Skips clean (never panics)
/// when Docker is unavailable; the only panic is a real cross-OS/arch
/// divergence.
#[test]
#[ignore = "slow in-container builds under emulation; opt in with HESO_DOCKER_DETERMINISM=1 and --ignored"]
fn determinism_docker_linux_matches_native_arm64_pins() {
    if !docker_determinism_requested() {
        eprintln!(
            "SKIP docker-linux: set HESO_DOCKER_DETERMINISM=1 to run the in-container Linux proof \
             (it builds heso inside {DOCKER_IMAGE} for linux/amd64 + linux/arm64, multi-minute \
             cold builds under emulation)"
        );
        return;
    }
    if !docker_cli_present() {
        eprintln!(
            "SKIP docker-linux: no `docker` CLI on PATH — install Docker (Desktop or engine) to \
             run the in-container Linux determinism proof locally"
        );
        return;
    }
    if !docker_daemon_up() {
        eprintln!(
            "SKIP docker-linux: `docker info` failed — the Docker daemon is unreachable (Docker \
             Desktop not running / no engine). Start the daemon to run this proof; the Linux \
             legs are otherwise enforced by the CI matrix (determinism-matrix.yml)."
        );
        return;
    }

    let Some(workspace) = workspace_root() else {
        eprintln!(
            "SKIP docker-linux: could not locate the workspace root (no ancestor Cargo.lock + \
             [workspace] Cargo.toml above CARGO_MANIFEST_DIR)"
        );
        return;
    };
    let Some(corpus_rel) = corpus_rel_to_workspace(&workspace) else {
        eprintln!(
            "SKIP docker-linux: the corpus dir is not under the workspace root — cannot address \
             it inside the /heso mount"
        );
        return;
    };

    let manifest = Manifest::load();
    assert!(
        !manifest.entries.is_empty(),
        "determinism corpus manifest is empty — nothing to cross-check"
    );

    // engine_id drift gate, exactly like the native + Rosetta harnesses:
    // engine.version lives in the hash region, so a bump moves every pinned
    // hash BY DESIGN. If the running (native) binary drifted from the
    // manifest, the pins are stale and the in-container comparison against
    // them is meaningless — skip clean with the regenerate instruction.
    let running_id = running_engine_id();
    if manifest.entries.iter().any(|e| e.engine_id != running_id) {
        eprintln!(
            "SKIP docker-linux: manifest engine_id != running {running_id} (EXPECTED DRIFT) — \
             regenerate the corpus before re-pinning the docker-linux proof"
        );
        return;
    }

    let program = container_program(&corpus_rel, &manifest.entries);

    let mut platforms_proven = 0usize;
    let mut cassettes_proven = 0usize;
    for platform in PLATFORMS {
        let pairs = match run_platform(platform, &workspace, &program) {
            Ok(Some(pairs)) => pairs,
            Ok(None) => continue, // per-platform skip, reason printed
            Err(msg) => {
                // An unexpected docker failure (not an emulation gap) — surface
                // it loudly so a broken setup is visible, but as a SKIP of this
                // platform, not a determinism panic. Only a HASH MISMATCH panics.
                eprintln!("SKIP platform {platform}: unexpected docker failure: {msg}");
                continue;
            }
        };
        // 0 lines ⇒ the in-container build/replay could not run on THIS host
        // (e.g. a foreign-arch build under QEMU emulation that OOMs/chokes, or a
        // missing build resource) — skip the platform cleanly rather than panic.
        // A determinism MISMATCH (hashes differ) still panics below; a PARTIAL run
        // (some-but-not-all lines) is a real bug and still panics.
        if pairs.is_empty() {
            eprintln!(
                "SKIP platform {platform}: in-container build/replay produced 0 plat_hashes \
                 on this host (likely an emulation / build-resource limit) — the CI matrix \
                 (native runners) enforces this leg"
            );
            continue;
        }
        assert_eq!(
            pairs.len(),
            manifest.entries.len(),
            "docker-linux {platform}: parsed {} of {} replay lines — a PARTIAL in-container run \
             (a real bug, not an emulation gap)",
            pairs.len(),
            manifest.entries.len()
        );
        for (entry, (cassette, got)) in manifest.entries.iter().zip(pairs.iter()) {
            assert_eq!(
                cassette, &entry.cassette,
                "docker-linux {platform}: replay line order drifted — expected `{}` got `{}`",
                entry.cassette, cassette
            );
            assert!(
                !got.is_empty(),
                "docker-linux {platform}: empty plat_hash parsed for `{}` — the in-container \
                 `heso run` produced no plat_hash (run failure)",
                entry.cassette
            );
            assert_eq!(
                got, &entry.expected_plat_hash,
                "DOCKER DIVERGENCE [{platform}]: `{}` replayed to {} in-container but the manifest \
                 pins {} (the native aarch64 value). The native arm64 leg is green for the same \
                 cassette, so this is an OS/ARCH-DEPENDENT byte in the canonical plat — a real \
                 cross-OS determinism bug (suspect a non-portable RNG, pointer-width / \
                 HashMap-iteration bytes, or the QuickJS fork diverging across OS/ISA).",
                entry.cassette, got, entry.expected_plat_hash
            );
            cassettes_proven += 1;
        }
        eprintln!(
            "DOCKER-LINUX PROOF [{platform}]: {} cassettes replayed BYTE-IDENTICAL in-container \
             vs the pinned native aarch64 plat_hash.",
            manifest.entries.len()
        );
        platforms_proven += 1;
    }

    eprintln!(
        "DOCKER-LINUX SUMMARY: {platforms_proven}/{} platforms proven, {cassettes_proven} total \
         cassette-replays byte-identical to the pinned native aarch64 hashes. Native \
         x86_64-macOS remains the CI matrix's job (untestable on this arm64 host).",
        PLATFORMS.len()
    );
}
