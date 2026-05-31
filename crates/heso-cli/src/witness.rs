//! `heso witness` — the operator-side caller for the notary's v1.1
//! Witness Receipt flow (WS6).
//!
//! This is the producer half of the cross-repo operator-attestation
//! contract whose verifier half lives in the enterprise `heso-notary`
//! crate. The two repos share **no** crate, so the load-bearing wire
//! contract — the [`OPERATOR_ATTEST_DOMAIN`] domain tag, the JCS field
//! order, and the raw-`serde_jcs` (NOT `canonical_bytes`) preimage rule —
//! is duplicated here by hand and pinned byte-for-byte by the
//! [`tests::preimage_matches_golden_fixture`] vector. If the notary's WS2
//! test and this test ever disagree on the golden hex, the flow is broken
//! and one side fails fast.
//!
//! ## What it does
//!
//! Given a plat (a `heso open`/`stamp` artifact, or an explicit
//! `--input-url` + `--plat-hash`) and a notary base URL:
//!
//! 1. `GET <notary>/pubkey` to learn the target notary's own Ed25519
//!    public key (`notary_id`). Signing over the notary's *own* id is
//!    what closes cross-notary replay — a captured attestation cannot be
//!    POSTed to a different notary because its pubkey differs.
//! 2. Build the operator-signed preimage = [`OPERATOR_ATTEST_DOMAIN`] ++
//!    `serde_jcs::to_vec({input_url, notary_id, plat_hash, witness_scope})`
//!    (JCS sorts the keys, so the four fields land in that fixed order)
//!    and sign it with the operator's **plat-sealing** [`IdentityKey`] —
//!    the same key that seals the plat. No new crypto; the resulting
//!    [`heso_core::Signature`] already carries the base64 pubkey + sig the
//!    wire wants.
//! 3. `POST <notary>/witness` the v1.1 `WitnessRequest`
//!    `{input_url, plat_hash, operator_public_key, operator_signature,
//!    witness_scope}`.
//! 4. Print the returned signed Witness Receipt to stdout.
//!
//! ## Byte-pinning rule (load-bearing)
//!
//! The preimage MUST use `serde_jcs::to_vec` **directly**. It MUST NOT be
//! routed through `heso_verify::canonical_bytes`, which strips any
//! top-level `plat_hash` key (its hash region is `["plat_hash","sig"]`).
//! The attestation object's top-level key *is* named `plat_hash`, so
//! `canonical_bytes` would silently drop it and defeat the binding. The
//! [`tests::raw_jcs_preserves_plat_hash`] guard pins this.

use std::path::PathBuf;
use std::process::ExitCode;

use heso_core::IdentityKey;
use serde::Deserialize;

use crate::DEFAULT_IDENTITY_PATH;

/// Domain-separation tag for the operator attestation. Exact bytes: the
/// 23 ASCII bytes of `"heso-operator-attest/v1"` followed by one NUL
/// (`0x00`) = 24 bytes. The trailing NUL is the disjointness guard:
/// RFC-8785 (JCS) output is JSON text and never contains a raw `0x00`, so
/// the domain prefix and the JCS payload are provably non-overlapping
/// with no length prefix.
///
/// Style-matched to the notary's `domain.rs`
/// (`NOTARY_SIGNING_DOMAIN = b"heso-witness/v1\0"`,
/// `AUDIT_DOMAIN = b"heso-audit/v1\0"`) and disjoint from the plat
/// signing domains (`heso-plat/v1\0`, `heso-plat-sig:v1\0`).
pub const OPERATOR_ATTEST_DOMAIN: &[u8] = b"heso-operator-attest/v1\0";

/// Operator-declared provenance of how the plat bytes were produced.
/// Serialized as its lowercase wire value (`static`/`ssr`/`hydrated`/
/// `none`). It rides inside the operator-signed bytes so a lying operator
/// cannot re-declare it after the fact — the notary computes NO content
/// comparison, this is a pure declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessScope {
    Static,
    Ssr,
    Hydrated,
    None,
}

impl WitnessScope {
    /// The lowercase wire/JCS value. Must match the notary's
    /// `#[serde(rename_all = "lowercase")]` exactly.
    pub fn as_wire(self) -> &'static str {
        match self {
            WitnessScope::Static => "static",
            WitnessScope::Ssr => "ssr",
            WitnessScope::Hydrated => "hydrated",
            WitnessScope::None => "none",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "static" => Some(WitnessScope::Static),
            "ssr" => Some(WitnessScope::Ssr),
            "hydrated" => Some(WitnessScope::Hydrated),
            "none" => Some(WitnessScope::None),
            _ => None,
        }
    }
}

/// Build the operator-attestation preimage exactly as the notary
/// reconstructs it for verification.
///
/// `preimage = OPERATOR_ATTEST_DOMAIN (24 bytes) || JCS_BYTES`, where
/// `JCS_BYTES = serde_jcs::to_vec({input_url, notary_id, plat_hash,
/// witness_scope})`. All four values are UTF-8 JSON strings. JCS sorts
/// the keys lexicographically, fixing the order
/// `input_url, notary_id, plat_hash, witness_scope`.
///
/// CRITICAL: uses raw `serde_jcs::to_vec`, never `canonical_bytes`
/// (which would strip the top-level `plat_hash`). See module docs.
pub fn operator_attest_preimage(
    input_url: &str,
    notary_id: &str,
    plat_hash: &str,
    witness_scope: WitnessScope,
) -> Result<Vec<u8>, String> {
    let jcs = serde_jcs::to_vec(&serde_json::json!({
        "input_url": input_url,
        "notary_id": notary_id,
        "plat_hash": plat_hash,
        "witness_scope": witness_scope.as_wire(),
    }))
    .map_err(|e| format!("failed to JCS-canonicalize the operator attestation: {e}"))?;
    let mut preimage = Vec::with_capacity(OPERATOR_ATTEST_DOMAIN.len() + jcs.len());
    preimage.extend_from_slice(OPERATOR_ATTEST_DOMAIN);
    preimage.extend_from_slice(&jcs);
    Ok(preimage)
}

/// The notary's `GET /pubkey` response. Only `public_key` is required;
/// any sibling fields the notary adds are ignored.
#[derive(Debug, Deserialize)]
struct PubkeyResponse {
    public_key: String,
}

/// The v1.1 `WitnessRequest` body. The wire names are pinned to the
/// frozen contract — they MUST match the notary's `Deserialize` exactly:
/// `operator_public_key`, `operator_signature`, `witness_scope`.
#[derive(Debug, serde::Serialize)]
struct WitnessRequest<'a> {
    input_url: &'a str,
    plat_hash: &'a str,
    operator_public_key: &'a str,
    operator_signature: &'a str,
    witness_scope: &'a str,
}

struct WitnessArgs {
    notary: String,
    key_path: PathBuf,
    scope: WitnessScope,
    /// Either a plat file path, or `None` when `--input-url`/`--plat-hash`
    /// are supplied directly.
    file: Option<String>,
    input_url: Option<String>,
    plat_hash: Option<String>,
}

fn print_usage() {
    eprintln!("usage: heso witness <plat-file> --notary <url> [--scope SCOPE] [--key PATH]");
    eprintln!("   or: heso witness --notary <url> --input-url <url> --plat-hash <hex> [--scope SCOPE] [--key PATH]");
    eprintln!();
    eprintln!("Request a v1.1 Witness Receipt from a notary, binding the plat to");
    eprintln!("an operator attestation signed with your local identity key.");
    eprintln!();
    eprintln!("  --notary <url>     Base URL of the target notary (required).");
    eprintln!("  --input-url <url>  The plat's input_url (when no <plat-file> is given).");
    eprintln!("  --plat-hash <hex>  The plat's plat_hash (when no <plat-file> is given).");
    eprintln!("  --scope SCOPE      Operator-declared provenance: static (default), ssr, hydrated, none.");
    eprintln!("  --key PATH         Identity key to sign with (default: {DEFAULT_IDENTITY_PATH}).");
}

fn parse_args(args: &[String]) -> Result<WitnessArgs, ExitCode> {
    let mut notary: Option<String> = None;
    let mut key_path: Option<PathBuf> = None;
    let mut scope = WitnessScope::Static;
    let mut file: Option<String> = None;
    let mut input_url: Option<String> = None;
    let mut plat_hash: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                return Err(ExitCode::SUCCESS);
            }
            "--notary" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--notary needs a value (the notary base URL)");
                    return Err(ExitCode::from(2));
                };
                notary = Some(v.clone());
                i += 2;
            }
            "--key" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--key needs a value");
                    return Err(ExitCode::from(2));
                };
                key_path = Some(PathBuf::from(v));
                i += 2;
            }
            "--scope" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--scope needs a value (static|ssr|hydrated|none)");
                    return Err(ExitCode::from(2));
                };
                let Some(parsed) = WitnessScope::parse(v) else {
                    eprintln!("unknown --scope `{v}`; expected static|ssr|hydrated|none");
                    return Err(ExitCode::from(2));
                };
                scope = parsed;
                i += 2;
            }
            "--input-url" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--input-url needs a value");
                    return Err(ExitCode::from(2));
                };
                input_url = Some(v.clone());
                i += 2;
            }
            "--plat-hash" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--plat-hash needs a value");
                    return Err(ExitCode::from(2));
                };
                plat_hash = Some(v.clone());
                i += 2;
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag `{other}`");
                print_usage();
                return Err(ExitCode::from(2));
            }
            _ => {
                if file.is_some() {
                    eprintln!("unexpected extra argument `{}`; pass a single <plat-file>", args[i]);
                    return Err(ExitCode::from(2));
                }
                file = Some(args[i].clone());
                i += 1;
            }
        }
    }

    let Some(notary) = notary else {
        eprintln!("witness: --notary <url> is required");
        print_usage();
        return Err(ExitCode::from(2));
    };
    if file.is_some() && (input_url.is_some() || plat_hash.is_some()) {
        eprintln!("witness: pass EITHER a <plat-file> OR --input-url + --plat-hash, not both");
        return Err(ExitCode::from(2));
    }
    if file.is_none() && (input_url.is_none() || plat_hash.is_none()) {
        eprintln!("witness: need a <plat-file>, or both --input-url and --plat-hash");
        print_usage();
        return Err(ExitCode::from(2));
    }

    Ok(WitnessArgs {
        notary,
        key_path: key_path.unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_PATH)),
        scope,
        file,
        input_url,
        plat_hash,
    })
}

/// Pull `input_url` and `plat_hash` out of a plat artifact. `input_url`
/// must be byte-exact — it is the literal string the operator signs, the
/// notary echoes into the receipt, and re-fetches, with no normalization.
fn extract_from_plat(value: &serde_json::Value) -> Result<(String, String), String> {
    let input_url = value
        .get("input_url")
        .and_then(|v| v.as_str())
        .ok_or("plat is missing a string `input_url` field")?
        .to_owned();
    let plat_hash = value
        .get("plat_hash")
        .and_then(|v| v.as_str())
        .ok_or("plat is missing a string `plat_hash` field; seal/stamp it first")?
        .to_owned();
    Ok((input_url, plat_hash))
}

/// `heso witness` — sign an operator attestation over a plat and POST it
/// to a notary for a v1.1 Witness Receipt.
pub async fn cmd_witness(args: &[String]) -> ExitCode {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(code) => return code,
    };

    // Resolve {input_url, plat_hash} either from a plat file or directly
    // from the flags.
    let (input_url, plat_hash) = if let Some(ref file) = parsed.file {
        let contents = match tokio::fs::read_to_string(file).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to read `{file}`: {e}");
                return ExitCode::from(2);
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("`{file}` is not valid JSON: {e}");
                return ExitCode::from(2);
            }
        };
        // A sealed envelope wraps the body under `content`; unwrap it so
        // the operator signs the same plat_hash the notary echoes.
        let body = value.get("content").unwrap_or(&value);
        match extract_from_plat(body) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("witness: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        // Validated in parse_args: both present when no file.
        (parsed.input_url.unwrap(), parsed.plat_hash.unwrap())
    };

    // Load the operator's plat-sealing identity.
    let key = match IdentityKey::load(&parsed.key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("failed to load identity at `{}`: {e}", parsed.key_path.display());
            eprintln!("run `heso identity init` first, or pass --key <PATH>.");
            return ExitCode::FAILURE;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("witness: failed to build HTTP client: {e}");
            return ExitCode::FAILURE;
        }
    };

    let base = parsed.notary.trim_end_matches('/');

    // (1) Learn the target notary's own pubkey (notary_id). Signing over
    //     it is what closes cross-notary replay.
    let pubkey_url = format!("{base}/pubkey");
    let notary_id = match fetch_notary_id(&client, &pubkey_url).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("witness: {e}");
            return ExitCode::FAILURE;
        }
    };

    // (2) Build + sign the operator-attestation preimage.
    let preimage = match operator_attest_preimage(&input_url, &notary_id, &plat_hash, parsed.scope) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("witness: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sig = key.sign(&preimage);

    // (3) POST the v1.1 WitnessRequest. `sig.public_key`/`sig.signature`
    //     are already standard-base64 — the exact wire shape.
    let request = WitnessRequest {
        input_url: &input_url,
        plat_hash: &plat_hash,
        operator_public_key: &sig.public_key,
        operator_signature: &sig.signature,
        witness_scope: parsed.scope.as_wire(),
    };
    let witness_url = format!("{base}/witness");
    let receipt = match post_witness(&client, &witness_url, &request).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("witness: {e}");
            return ExitCode::FAILURE;
        }
    };

    // (4) Surface the returned receipt verbatim on stdout.
    match serde_json::to_string(&receipt) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("witness: failed to serialize the notary's receipt: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn fetch_notary_id(client: &reqwest::Client, url: &str) -> Result<String, String> {
    // `reqwest`'s `json` helpers are gated behind a feature this
    // workspace does not enable, so we drive the body bytes directly via
    // `serde_json` — same crate the rest of the CLI uses.
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url} returned HTTP {}", resp.status()));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| format!("GET {url} returned an unreadable body: {e}"))?;
    let body: PubkeyResponse = serde_json::from_str(&text)
        .map_err(|e| format!("GET {url} returned an unexpected body (no `public_key`): {e}"))?;
    Ok(body.public_key)
}

async fn post_witness(
    client: &reqwest::Client,
    url: &str,
    request: &WitnessRequest<'_>,
) -> Result<serde_json::Value, String> {
    let payload = serde_json::to_string(request)
        .map_err(|e| format!("failed to serialize the witness request: {e}"))?;
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|e| format!("POST {url} failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("POST {url} returned an unreadable body: {e}"))?;
    if !status.is_success() {
        // Surface the notary's rejection (e.g. 401 attestation did not
        // verify, 400 malformed/legacy) so the operator can act on it.
        let detail = text.trim();
        return Err(format!(
            "notary rejected the witness request: HTTP {status}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            }
        ));
    }
    serde_json::from_str(&text)
        .map_err(|e| format!("POST {url} returned a non-JSON receipt: {e}"))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The frozen cross-repo golden fixture (witness_scope = static).
    /// These values are byte-identical to the notary's WS2 conformance
    /// test; the whole point of the duplicated contract is that both
    /// sides assert the SAME `expected_preimage_hex`.
    const GOLDEN_INPUT_URL: &str = "https://example.com/";
    const GOLDEN_NOTARY_ID: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
    const GOLDEN_PLAT_HASH: &str =
        "bc272895d75d0d780e6304e2cbd15a7a67819a3909c1aa5c51f7b5bbb28abccf";
    const GOLDEN_PREIMAGE_HEX: &str = "6865736f2d6f70657261746f722d6174746573742f7631007b22696e7075745f75726c223a2268747470733a2f2f6578616d706c652e636f6d2f222c226e6f746172795f6964223a224f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b3d222c22706c61745f68617368223a2262633237323839356437356430643738306536333034653263626431356137613637383139613339303963316161356335316637623562626232386162636366222c227769746e6573735f73636f7065223a22737461746963227d";
    /// The re-seeded golden operator seed's public key (base64 std). Same
    /// key the notary's fixture uses; decoupled from the scaffold key.
    const GOLDEN_OPERATOR_PUBKEY: &str = "RaHGEZnpJn1PdahrTaRj3XSWQLKHOMHTWumslFuziqQ=";
    /// Deterministic Ed25519 signature over the golden preimage with the
    /// re-seeded golden operator seed — pinned in the notary's fixture too.
    const GOLDEN_OPERATOR_SIG: &str =
        "DMSca4IB1ffTF6jgy2uvBfHbsBLpXN/sT4bizT5bukqhiDsH6CXGDPJVqUOd43GdTiBGar8LlTyjPCetPaEbBQ==";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn domain_is_24_bytes_with_trailing_nul() {
        assert_eq!(OPERATOR_ATTEST_DOMAIN, b"heso-operator-attest/v1\0");
        assert_eq!(OPERATOR_ATTEST_DOMAIN.len(), 24);
        assert_eq!(*OPERATOR_ATTEST_DOMAIN.last().unwrap(), 0x00);
        assert_eq!(hex(OPERATOR_ATTEST_DOMAIN), "6865736f2d6f70657261746f722d6174746573742f763100");
    }

    #[test]
    fn domain_is_disjoint_from_plat_domains() {
        // Mirror the notary's domain.rs disjointness test against the
        // plat signing domains this repo actually ships.
        assert_ne!(OPERATOR_ATTEST_DOMAIN, heso_engine_fetch::plat::SIGNING_DOMAIN);
        assert_ne!(
            OPERATOR_ATTEST_DOMAIN,
            heso_engine_fetch::plat::SIGNING_DOMAIN_INLINE
        );
    }

    /// THE lockstep guarantee: the preimage this caller builds for the
    /// frozen fixture is byte-identical to the notary's WS2 vector. If
    /// this fails, the runtime caller and the notary verifier disagree on
    /// the signed bytes and the flow is broken — fail loud.
    #[test]
    fn preimage_matches_golden_fixture() {
        let preimage = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .expect("preimage builds");
        assert_eq!(hex(&preimage), GOLDEN_PREIMAGE_HEX);
        // 24 domain bytes + 199 JCS bytes = 223.
        assert_eq!(preimage.len(), 223);
    }

    /// Signing the golden preimage with the re-seeded golden operator seed
    /// must reproduce the pinned deterministic Ed25519 signature (RFC 8032)
    /// AND verify via `verify_strict` — proving this caller's signature is
    /// interoperable with the notary, byte-for-byte.
    #[test]
    fn signing_golden_preimage_reproduces_pinned_signature() {
        let key = IdentityKey::from_bytes(&[
            0xa1, 0x7e, 0x6f, 0x0c, 0x93, 0xb2, 0x48, 0xd5, 0xe1, 0xc4, 0x07, 0x9a, 0xb3, 0x5d,
            0x62, 0xf8, 0x08, 0x4c, 0x1a, 0xef, 0x27, 0x90, 0x5b, 0x3d, 0xc6, 0xe8, 0x14, 0x3f,
            0xa9, 0x0b, 0x75, 0xd2,
        ]);
        assert_eq!(key.public_key_b64(), GOLDEN_OPERATOR_PUBKEY);
        let preimage = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        let sig = key.sign(&preimage);
        assert_eq!(sig.public_key, GOLDEN_OPERATOR_PUBKEY);
        assert_eq!(sig.signature, GOLDEN_OPERATOR_SIG);
        // Round-trips through the house verify_strict path.
        sig.verify(&preimage).expect("golden signature verifies");
    }

    /// The re-seed DE-COUPLES the golden operator from the shipped
    /// scaffold/zero-seed keys. Pin that the all-0x07 seed still derives
    /// the well-known scaffold pubkey, and that the golden operator key is
    /// DISJOINT from both that scaffold key and the zero-seed notary id —
    /// so a future accidental re-collision fails loud here.
    #[test]
    fn golden_operator_key_is_not_a_scaffold_key() {
        const SCAFFOLD_PUBKEY: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";
        assert_eq!(
            IdentityKey::from_bytes(&[7u8; 32]).public_key_b64(),
            SCAFFOLD_PUBKEY,
            "the all-0x07 seed must still derive the well-known scaffold key"
        );
        assert_ne!(
            GOLDEN_OPERATOR_PUBKEY, SCAFFOLD_PUBKEY,
            "golden operator collides with the scaffold key — re-seed it"
        );
        assert_ne!(
            GOLDEN_OPERATOR_PUBKEY, GOLDEN_NOTARY_ID,
            "golden operator collides with the zero-seed notary id — re-seed it"
        );
    }

    /// Guard the byte-pinning rule: the JCS the caller signs MUST contain
    /// `plat_hash`. Routing through `canonical_bytes` (which strips the
    /// top-level `plat_hash`) would silently drop it and defeat the
    /// binding. We assert the raw JCS string carries the key.
    #[test]
    fn raw_jcs_preserves_plat_hash() {
        let preimage = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        let jcs = &preimage[OPERATOR_ATTEST_DOMAIN.len()..];
        let jcs_str = std::str::from_utf8(jcs).unwrap();
        assert!(
            jcs_str.contains("\"plat_hash\":\"bc272895"),
            "raw serde_jcs must preserve plat_hash; got {jcs_str}"
        );
        // And the JCS key order is the fixed lexicographic one.
        assert!(jcs_str.starts_with(
            "{\"input_url\":\"https://example.com/\",\"notary_id\":"
        ));
        assert!(jcs_str.ends_with("\"witness_scope\":\"static\"}"));
    }

    /// `witness_scope` rides inside the signed bytes, so changing it
    /// changes the preimage (a lying operator cannot re-declare scope).
    #[test]
    fn scope_is_bound_into_the_preimage() {
        let p_static = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        for other in [WitnessScope::Ssr, WitnessScope::Hydrated, WitnessScope::None] {
            let p = operator_attest_preimage(
                GOLDEN_INPUT_URL,
                GOLDEN_NOTARY_ID,
                GOLDEN_PLAT_HASH,
                other,
            )
            .unwrap();
            assert_ne!(p_static, p, "scope {} must change the preimage", other.as_wire());
        }
    }

    /// `notary_id` is bound in, closing cross-notary replay: a different
    /// notary's pubkey yields a different preimage, so the signature won't
    /// verify against the wrong notary.
    #[test]
    fn notary_id_is_bound_into_the_preimage() {
        let a = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        let b = operator_attest_preimage(
            GOLDEN_INPUT_URL,
            "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    /// `input_url` is byte-exact: a trailing-slash variant changes the
    /// preimage, so an attestation over one URL won't verify for another.
    #[test]
    fn input_url_is_byte_exact() {
        let with_slash = operator_attest_preimage(
            "https://example.com/",
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        let without_slash = operator_attest_preimage(
            "https://example.com",
            GOLDEN_NOTARY_ID,
            GOLDEN_PLAT_HASH,
            WitnessScope::Static,
        )
        .unwrap();
        assert_ne!(with_slash, without_slash);
    }

    #[test]
    fn scope_wire_values_match_lowercase_serde() {
        assert_eq!(WitnessScope::Static.as_wire(), "static");
        assert_eq!(WitnessScope::Ssr.as_wire(), "ssr");
        assert_eq!(WitnessScope::Hydrated.as_wire(), "hydrated");
        assert_eq!(WitnessScope::None.as_wire(), "none");
    }

    #[test]
    fn witness_request_serializes_with_pinned_wire_names() {
        let req = WitnessRequest {
            input_url: GOLDEN_INPUT_URL,
            plat_hash: GOLDEN_PLAT_HASH,
            operator_public_key: GOLDEN_OPERATOR_PUBKEY,
            operator_signature: GOLDEN_OPERATOR_SIG,
            witness_scope: "static",
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(v.get("input_url").is_some());
        assert!(v.get("plat_hash").is_some());
        assert!(v.get("operator_public_key").is_some());
        assert!(v.get("operator_signature").is_some());
        assert_eq!(v.get("witness_scope").unwrap(), "static");
        // Exactly the five v1.1 fields, nothing extra (e.g. no notary_id).
        assert_eq!(v.as_object().unwrap().len(), 5);
        assert!(v.get("notary_id").is_none());
    }
}
