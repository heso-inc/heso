//! The verdict engine of the standalone verifier — pure, process-free, so the
//! crate's own `cargo test` can assert every exit code and pinpoint string
//! without spawning a binary.
//!
//! It is a thin re-expression of [`heso_action`]'s offline verify path:
//! [`heso_action::verify::open_receipt`] (alg → version → content hash →
//! signatures → redaction → RFC-3161 anchor → trust level) per receipt, and
//! [`heso_action::chain::verify_action_receipt_chain`] for the inter-link
//! ordering. The standalone binary adds NO crypto and NO second verify rule — it
//! only maps the library's typed verdict to the published CONTRACT
//! ([`ExitCode`]) and a stable `--json` shape, and PINPOINTS the failing link
//! ("chain broken at receipt K of N", a diverged field) from the same typed
//! outcome the engine returns.

use heso_action::chain::{verify_action_receipt_chain, ChainOutcome};
use heso_action::receipt::{ActionReceipt, TransparencyRequirement};
use heso_action::verify::{open_receipt_with_time, open_receipt_with_transparency, ActionOutcome};

/// The pinned transparency-log inputs the relying party supplies on the command
/// line (`--checkpoint`, `--log-key`, `--witness-keys`, `--require-transparency`).
///
/// The log + witness keys are TOFU pins the bundle ships; they are NEVER resolved
/// from a `KeyRegistry`. When this is `Some`, every receipt's `transparency[]`
/// block is verified two-stage against the pinned log key (and, with witnesses
/// pinned, its cosignatures); `--require-transparency` additionally fails closed
/// on a receipt that carries no proof.
#[derive(Debug, Clone)]
pub struct TransparencyOpts {
    /// The pinned log public key (raw 32-byte Ed25519).
    pub log_pubkey: [u8; 32],
    /// The pinned witness public keys (raw 32-byte Ed25519), possibly empty.
    pub witness_pubkeys: Vec<[u8; 32]>,
    /// `Some(Required)` ⇒ a receipt with no `transparency[]` fails closed.
    pub require: Option<TransparencyRequirement>,
    /// Optional checkpoint-note cross-check: when set, every receipt's embedded
    /// checkpoint MUST equal this exact note text (a swapped checkpoint is a
    /// usage-class mismatch). The embedded note is still what gets verified
    /// against the log key.
    pub checkpoint: Option<String>,
}

/// The published exit-code contract a relying party scripts against. Stable: a
/// caller may branch on the integer without parsing any text.
///
/// - `0` VALID — every receipt verifies and (for >1) the chain is intact.
/// - `1` INVALID — well-formed receipts, but tampered content, a bad signature,
///   a malformed redaction, an unverifiable time anchor, a trust-level lie, or a
///   broken chain link (drop / reorder / insert / re-point).
/// - `2` WRONG-ALGORITHM-OR-HASH-MISMATCH — not acceptable as a receipt this
///   verifier can validate: a foreign/older `alg`, an unsupported
///   `action_version`, a structurally malformed receipt, OR a content
///   `action_hash` that does not match the recomputed BLAKE3.
/// - `64` USAGE — bad command line / unreadable inputs (mirrors `EX_USAGE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// 0 — the bundle verifies end to end.
    Valid = 0,
    /// 1 — a forgery the verifier could fully parse: tamper, bad signature, or a
    /// broken chain link.
    Invalid = 1,
    /// 2 — not a receipt this verifier accepts: wrong algorithm, unsupported
    /// version, structurally malformed, or a self-hash mismatch.
    WrongAlgorithmOrHash = 2,
    /// 64 — usage error (bad args / unreadable files). `EX_USAGE`.
    Usage = 64,
}

impl ExitCode {
    /// The stable lowercase token emitted in the `--json` `status` field.
    pub fn token(self) -> &'static str {
        match self {
            ExitCode::Valid => "valid",
            ExitCode::Invalid => "invalid",
            ExitCode::WrongAlgorithmOrHash => "wrong_algorithm_or_hash",
            ExitCode::Usage => "usage",
        }
    }
}

/// The full verdict: the contract exit code, a one-line human reason, and — when
/// a specific link failed — the PINPOINT (`failed_at` 1-based receipt index and
/// `total` chain length, plus an optional `diverged_field`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The published [`ExitCode`] a script branches on.
    pub code: ExitCode,
    /// A short, human-readable reason naming the failure class (or "ok").
    pub reason: String,
    /// The number of receipts read from the input (the chain length, `N`).
    pub total: usize,
    /// The 1-based position of the receipt that failed (`K` in "receipt K of N"),
    /// when the failure is attributable to a specific link. `None` for a global
    /// failure (empty input, usage) or success.
    pub failed_at: Option<usize>,
    /// The class of failure as a stable token (e.g. `"hash_mismatch"`,
    /// `"invalid_signature"`, `"link_broken"`), for machine consumers that want
    /// more than the exit code without parsing `reason`. `None` on success.
    pub failure_kind: Option<&'static str>,
    /// The diverged field / invariant detail when the library named one (e.g. a
    /// `LinkBroken` detail naming `prev_receipt_hash` or `session_id`). `None`
    /// when the failure is not field-attributable.
    pub diverged_field: Option<String>,
}

impl Verdict {
    fn ok(total: usize) -> Self {
        Verdict {
            code: ExitCode::Valid,
            reason: "ok".to_string(),
            total,
            failed_at: None,
            failure_kind: None,
            diverged_field: None,
        }
    }

    /// Render the verdict as the stable `--json` line (a single compact object,
    /// no trailing newline). Hand-built so the output has zero dependency-version
    /// churn and a fixed key order a relying party can rely on.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(160);
        s.push('{');
        s.push_str(&format!("\"status\":\"{}\"", self.code.token()));
        s.push_str(&format!(",\"exit_code\":{}", self.code as u8));
        s.push_str(&format!(",\"total\":{}", self.total));
        s.push_str(&format!(",\"reason\":{}", json_str(&self.reason)));
        match self.failed_at {
            Some(k) => s.push_str(&format!(",\"failed_at\":{k}")),
            None => s.push_str(",\"failed_at\":null"),
        }
        match self.failure_kind {
            Some(k) => s.push_str(&format!(",\"failure_kind\":{}", json_str(k))),
            None => s.push_str(",\"failure_kind\":null"),
        }
        match &self.diverged_field {
            Some(f) => s.push_str(&format!(",\"diverged_field\":{}", json_str(f))),
            None => s.push_str(",\"diverged_field\":null"),
        }
        s.push('}');
        s
    }

    /// The human-readable (non-JSON) one-liner the binary prints to stderr on
    /// failure / stdout on success, including the PINPOINT when present.
    pub fn human(&self) -> String {
        match self.code {
            ExitCode::Valid => {
                if self.total == 1 {
                    "VALID: 1 receipt verified".to_string()
                } else {
                    format!("VALID: chain of {} receipts verified", self.total)
                }
            }
            _ => {
                let mut line = format!("{}: {}", self.code.token().to_uppercase(), self.reason);
                if let Some(k) = self.failed_at {
                    line.push_str(&format!(" (at receipt {k} of {})", self.total));
                }
                if let Some(f) = &self.diverged_field {
                    line.push_str(&format!(" [diverged field: {f}]"));
                }
                line
            }
        }
    }
}

/// Parse a JSONL receipts file (one [`ActionReceipt`] per non-empty line) into a
/// `Vec`. A blank line is skipped; a malformed line is a usage-class failure
/// (the input is not a well-formed bundle) reported with its 1-based line number.
pub fn parse_receipts_jsonl(bytes: &[u8]) -> Result<Vec<ActionReceipt>, Verdict> {
    let text = std::str::from_utf8(bytes).map_err(|_| Verdict {
        code: ExitCode::Usage,
        reason: "receipts file is not valid UTF-8".to_string(),
        total: 0,
        failed_at: None,
        failure_kind: Some("bad_input"),
        diverged_field: None,
    })?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ActionReceipt>(line) {
            Ok(r) => out.push(r),
            Err(e) => {
                return Err(Verdict {
                    code: ExitCode::Usage,
                    reason: format!("receipts line {} is not a well-formed receipt: {e}", i + 1),
                    total: out.len(),
                    failed_at: Some(i + 1),
                    failure_kind: Some("bad_input"),
                    diverged_field: None,
                })
            }
        }
    }
    Ok(out)
}

/// Verify a parsed chain and produce the contract [`Verdict`].
///
/// One receipt is verified in isolation (no chain invariants apply); two or more
/// are verified as a chain. Either way the verdict is derived from the SAME typed
/// library outcome the engine uses, so the standalone binary can never diverge
/// from `heso-engine verify`.
///
/// `expected_pubkey`, when `Some`, additionally requires the verified operator
/// key of EVERY receipt to equal it — the bundle's pinned `public_key` is the
/// relying party's trust anchor, so a receipt validly signed by a *different*
/// operator must not pass against this bundle.
pub fn verify_chain_verdict(
    chain: &[ActionReceipt],
    expected_pubkey: Option<&str>,
    transparency: Option<&TransparencyOpts>,
) -> Verdict {
    if chain.is_empty() {
        return Verdict {
            code: ExitCode::Usage,
            reason: "no receipts to verify (empty bundle)".to_string(),
            total: 0,
            failed_at: None,
            failure_kind: Some("empty"),
            diverged_field: None,
        };
    }

    // Pin check FIRST on each receipt's declared operator key — a cheap,
    // fail-closed gate before the crypto. The cryptographic binding of that key
    // to the content is then proven by open_receipt below; matching the pin here
    // ensures a (validly signed) foreign-operator receipt cannot ride the bundle.
    if let Some(pin) = expected_pubkey {
        for (i, receipt) in chain.iter().enumerate() {
            let op = receipt
                .signatures
                .iter()
                .find(|e| e.key_id == heso_action::domain::OPERATOR_KEY_ID);
            match op {
                Some(entry) if entry.public_key == pin => {}
                Some(entry) => {
                    return Verdict {
                        code: ExitCode::Invalid,
                        reason: format!(
                            "operator key {} does not match the bundle's pinned public_key {pin}",
                            entry.public_key
                        ),
                        total: chain.len(),
                        failed_at: Some(i + 1),
                        failure_kind: Some("wrong_operator_key"),
                        diverged_field: Some("public_key".to_string()),
                    }
                }
                None => {
                    return Verdict {
                        code: ExitCode::WrongAlgorithmOrHash,
                        reason: "receipt has no operator signature entry".to_string(),
                        total: chain.len(),
                        failed_at: Some(i + 1),
                        failure_kind: Some("malformed"),
                        diverged_field: None,
                    }
                }
            }
        }
    }

    let total = chain.len();

    // The base integrity verdict (per-receipt crypto + chain links). A non-Valid
    // base short-circuits — transparency is only judged for an otherwise-sound
    // bundle.
    let base = base_chain_verdict(chain, total);
    if base.code != ExitCode::Valid {
        return base;
    }

    // Transparency-log enforcement (optional). Run AFTER the base passes so a
    // tamper/forgery surfaces for its clearer reason first; then every receipt's
    // `transparency[]` is checked against the pinned log + witness keys.
    if let Some(opts) = transparency {
        if let Some(v) = transparency_pass(chain, total, opts) {
            return v;
        }
    }

    base
}

/// The base integrity verdict: the standalone-receipt path for a single receipt,
/// the chain integrity path for two or more. Transparency is NOT judged here.
fn base_chain_verdict(chain: &[ActionReceipt], total: usize) -> Verdict {
    if total == 1 {
        // A standalone receipt: the chain machinery would still accept it as a
        // 1-link "chain", but a single receipt may legitimately carry NO chain
        // block. Verify it directly so a non-chained receipt is not rejected for
        // lacking a session_id.
        let (outcome, _time) = open_receipt_with_time(&chain[0]);
        return match outcome {
            ActionOutcome::Valid(_) => Verdict::ok(total),
            other => receipt_failure(other, 1, total),
        };
    }

    match verify_action_receipt_chain(chain) {
        ChainOutcome::Valid { length } => Verdict::ok(length),
        ChainOutcome::Empty => Verdict {
            code: ExitCode::Usage,
            reason: "no receipts to verify (empty bundle)".to_string(),
            total,
            failed_at: None,
            failure_kind: Some("empty"),
            diverged_field: None,
        },
        ChainOutcome::ContentTamper { seq, reason } => {
            // `seq` is the receipt's own position field; the 1-based index in the
            // file is seq + 1 for a well-formed genesis-at-0 chain. Report the
            // pinpoint against the position field the library named.
            receipt_failure(reason, seq_to_index(seq, chain), total)
        }
        ChainOutcome::LinkBroken { seq, detail } => {
            let diverged = diverged_field_from_detail(&detail);
            Verdict {
                code: ExitCode::Invalid,
                reason: format!("chain broken: {detail}"),
                total,
                failed_at: Some(seq_to_index(seq, chain)),
                failure_kind: Some("link_broken"),
                diverged_field: diverged,
            }
        }
        // The suspend/resume LIFECYCLE verdicts are produced only by
        // `verify_session_chain` (the lifecycle verifier), which this standalone
        // bundle verifier does not invoke — it walks the plain integrity chain via
        // `verify_action_receipt_chain`. They are mapped here so the match stays
        // exhaustive and a future wiring of the session verifier surfaces them as
        // a clean Invalid rather than a panic.
        ChainOutcome::RoleViolation { seq, detail, .. } => Verdict {
            code: ExitCode::Invalid,
            reason: format!("lifecycle role violation: {detail}"),
            total,
            failed_at: Some(seq_to_index(seq, chain)),
            failure_kind: Some("role_violation"),
            diverged_field: None,
        },
        ChainOutcome::IllegalTransition { seq, detail } => Verdict {
            code: ExitCode::Invalid,
            reason: format!("illegal lifecycle transition: {detail}"),
            total,
            failed_at: Some(seq_to_index(seq, chain)),
            failure_kind: Some("illegal_transition"),
            diverged_field: None,
        },
        ChainOutcome::DoubleTerminal { seq, first, second } => Verdict {
            code: ExitCode::Invalid,
            reason: format!(
                "double terminal for one action spec: {second:?} after {first:?} (first wins)"
            ),
            total,
            failed_at: Some(seq_to_index(seq, chain)),
            failure_kind: Some("double_terminal"),
            diverged_field: None,
        },
        ChainOutcome::KeyNotValidAtPosition { seq, role, detail } => Verdict {
            code: ExitCode::Invalid,
            reason: format!("{role:?} key not valid at chain position: {detail}"),
            total,
            failed_at: Some(seq_to_index(seq, chain)),
            failure_kind: Some("key_not_valid_at_position"),
            diverged_field: None,
        },
    }
}

/// Run the transparency-log pass over an already-integrity-valid chain. Returns
/// `Some(failing_verdict)` on the FIRST receipt whose transparency does not hold,
/// `None` when every receipt passes (so the caller keeps the base Valid verdict).
fn transparency_pass(
    chain: &[ActionReceipt],
    total: usize,
    opts: &TransparencyOpts,
) -> Option<Verdict> {
    for (i, receipt) in chain.iter().enumerate() {
        // Optional cross-check: a `--checkpoint` file must match every receipt's
        // embedded note byte-for-byte (a swapped checkpoint is a forgery).
        if let Some(pinned) = &opts.checkpoint {
            for proof in &receipt.transparency {
                if &proof.checkpoint != pinned {
                    return Some(Verdict {
                        code: ExitCode::Invalid,
                        reason: "receipt's embedded checkpoint does not match the --checkpoint file"
                            .to_string(),
                        total,
                        failed_at: Some(i + 1),
                        failure_kind: Some("transparency_unverifiable"),
                        diverged_field: Some("transparency.checkpoint".to_string()),
                    });
                }
            }
        }

        let outcome = open_receipt_with_transparency(
            receipt,
            &opts.log_pubkey,
            &opts.witness_pubkeys,
            opts.require,
        );
        match outcome {
            ActionOutcome::Valid(_) => {}
            other => return Some(receipt_failure(other, i + 1, total)),
        }
    }
    None
}

/// Map a single-receipt [`ActionOutcome`] failure to a [`Verdict`] with the
/// contract exit code and the pinpoint at receipt `index` of `total`.
fn receipt_failure(outcome: ActionOutcome, index: usize, total: usize) -> Verdict {
    let (code, kind, reason, field): (ExitCode, &'static str, String, Option<String>) = match outcome
    {
        // Unreachable in practice (caller only routes failures here), kept total.
        ActionOutcome::Valid(_) => {
            return Verdict::ok(total);
        }
        // --- Exit 2: not an acceptable receipt / self-hash mismatch ----------
        ActionOutcome::WrongAlgorithm(a) => (
            ExitCode::WrongAlgorithmOrHash,
            "wrong_algorithm",
            format!("envelope alg `{a}` is not an ActionReceipt this verifier accepts"),
            Some("alg".to_string()),
        ),
        ActionOutcome::Unsupported(m) => (
            ExitCode::WrongAlgorithmOrHash,
            "unsupported_version",
            format!("unsupported receipt: {m}"),
            Some("action_version".to_string()),
        ),
        ActionOutcome::HashMismatch => (
            ExitCode::WrongAlgorithmOrHash,
            "hash_mismatch",
            "content action_hash does not match the recomputed BLAKE3".to_string(),
            Some("action_hash".to_string()),
        ),
        ActionOutcome::Malformed(m) => (
            ExitCode::WrongAlgorithmOrHash,
            "malformed",
            format!("malformed receipt: {m}"),
            None,
        ),
        // --- Exit 1: a forgery in a well-formed receipt ----------------------
        ActionOutcome::InvalidSignature(e) => (
            ExitCode::Invalid,
            "invalid_signature",
            format!("signature did not verify: {e}"),
            Some("signature".to_string()),
        ),
        ActionOutcome::MalformedRedaction(m) => (
            ExitCode::Invalid,
            "malformed_redaction",
            format!("malformed redaction record: {m}"),
            Some("redaction".to_string()),
        ),
        ActionOutcome::TrustLevelMismatch { embedded, derived } => (
            ExitCode::Invalid,
            "trust_level_mismatch",
            format!("trust level claims {embedded:?} but signatures imply {derived:?}"),
            Some("trust_level".to_string()),
        ),
        ActionOutcome::TimeAnchorUnverifiable(m) => (
            ExitCode::Invalid,
            "time_anchor_unverifiable",
            format!("trusted-time anchor present but unverifiable: {m}"),
            Some("time_anchor".to_string()),
        ),
        // A signed resource class whose facts do not re-derive it — a forgery in a
        // well-formed receipt (exit 1).
        ActionOutcome::ClassificationMismatch(m) => (
            ExitCode::Invalid,
            "classification_mismatch",
            format!("signed classification does not re-derive from the facts: {m}"),
            Some("ert".to_string()),
        ),
        // The receipt pins a taxonomy this verifier does not embed: NOT acceptable
        // to validate here (exit 2) — re-run with a verifier embedding it; never a
        // silent pass.
        ActionOutcome::TaxonomyUnavailable(h) => (
            ExitCode::WrongAlgorithmOrHash,
            "taxonomy_unavailable",
            format!("cannot re-derive: receipt pins taxonomy_hash `{h}` this verifier does not embed"),
            Some("ert.taxonomy_hash".to_string()),
        ),
        // A payment whose signed mandate verdict is Invalid/Absent — a payment that
        // fired without a verified user authorization, attested in the signed
        // content (exit 1: well-formed but unauthorized).
        ActionOutcome::MandateRejected(m) => (
            ExitCode::Invalid,
            "mandate_rejected",
            format!("payment lacked a valid user authorization: {m}"),
            Some("action.mandate".to_string()),
        ),
        // An L1 receipt whose approver co-signature was made by the operator's own
        // key — a cryptographic forgery of the human gate (operator signed both
        // roles), so no separation of duty (exit 1: well-formed but unauthorized).
        ActionOutcome::SelfApproval => (
            ExitCode::Invalid,
            "self_approval",
            "L1 receipt co-signed by the operator key itself — no separation of duty"
                .to_string(),
            Some("trust_level".to_string()),
        ),
        // A quorum receipt with fewer distinct, verified, approved approver legs than
        // its signed threshold — a well-formed receipt that does not meet quorum
        // (exit 1).
        ActionOutcome::ThresholdNotMet { have, need } => (
            ExitCode::Invalid,
            "threshold_not_met",
            format!("multi-approval has {have} distinct approval(s) but needs {need}"),
            Some("multi_approval".to_string()),
        ),
        // A receipt whose signed anchor_policy is Required but which carries no
        // trusted-time anchor — the producer signed a mandatory-time requirement and
        // minted anchorless (exit 1: well-formed but missing the required anchor).
        ActionOutcome::AnchorRequired => (
            ExitCode::Invalid,
            "anchor_required",
            "receipt signed anchor_policy=Required but carries no trusted-time anchor"
                .to_string(),
            Some("time_anchor".to_string()),
        ),
        // A present transparency proof that does not verify against the pinned
        // log key (bad checkpoint note, wrong log key, broken stage-1/stage-2
        // inclusion, or a bad cosignature). Per A-m2 this reuses Invalid (=1) and
        // carries the distinct kind in the JSON reason field, NOT a new exit code.
        ActionOutcome::TransparencyUnverifiable(m) => (
            ExitCode::Invalid,
            "transparency_unverifiable",
            format!("transparency-log inclusion proof did not verify: {m}"),
            Some("transparency".to_string()),
        ),
        // `--require-transparency` was set but the receipt carries no proof.
        ActionOutcome::TransparencyRequired => (
            ExitCode::Invalid,
            "transparency_required",
            "--require-transparency set but receipt carries no transparency-log inclusion proof"
                .to_string(),
            Some("transparency".to_string()),
        ),
    };
    Verdict {
        code,
        reason,
        total,
        failed_at: Some(index),
        failure_kind: Some(kind),
        diverged_field: field,
    }
}

/// Translate a `seq` (a receipt's position field, genesis = 0) to a 1-based file
/// index. For a well-formed chain seq+1 is the index; if the chain has slid
/// (drop/reorder) the seq is still the most meaningful pinpoint, clamped into
/// range so "receipt K of N" never points past the end.
fn seq_to_index(seq: u64, chain: &[ActionReceipt]) -> usize {
    let by_seq = (seq as usize).saturating_add(1);
    by_seq.min(chain.len()).max(1)
}

/// Extract a diverged field name from a `LinkBroken` detail string, so the JSON
/// verdict can name the specific invariant that broke without the caller parsing
/// the prose. Recognizes the field names the chain verifier embeds.
fn diverged_field_from_detail(detail: &str) -> Option<String> {
    for field in ["prev_receipt_hash", "session_id", "seq"] {
        if detail.contains(field) {
            return Some(field.to_string());
        }
    }
    if detail.contains("genesis") {
        return Some("seq".to_string());
    }
    None
}

/// Minimal JSON string escaper for the hand-built `--json` output (quotes,
/// backslash, and control characters — enough for receipt diagnostics).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Validate the pinned `public_key` argument is a base64 32-byte Ed25519 key.
/// A bad pin is a usage error (the bundle's trust anchor is unreadable), not an
/// invalid-receipt verdict.
pub fn validate_pubkey(pubkey: &str) -> Result<(), Verdict> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let pin = pubkey.trim();
    match B64.decode(pin.as_bytes()) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(bytes) => Err(Verdict {
            code: ExitCode::Usage,
            reason: format!("public_key decodes to {} bytes, expected 32", bytes.len()),
            total: 0,
            failed_at: None,
            failure_kind: Some("bad_input"),
            diverged_field: None,
        }),
        Err(_) => Err(Verdict {
            code: ExitCode::Usage,
            reason: "public_key is not valid base64".to_string(),
            total: 0,
            failed_at: None,
            failure_kind: Some("bad_input"),
            diverged_field: None,
        }),
    }
}

/// Read the transparency-log CLI inputs into a [`TransparencyOpts`], or `Ok(None)`
/// when no transparency flag was given.
///
/// A pinned log key is MANDATORY the moment any transparency flag is in play — a
/// checkpoint, cosignatures, or a `--require-transparency` mandate cannot be
/// judged without it. Missing/garbled files are usage-class errors (exit 64), so
/// a relying party never silently "passes" a transparency check it could not run.
pub fn load_transparency_opts(
    checkpoint_path: Option<&str>,
    log_key_path: Option<&str>,
    witness_keys_path: Option<&str>,
    require: bool,
) -> Result<Option<TransparencyOpts>, Verdict> {
    let any = checkpoint_path.is_some()
        || log_key_path.is_some()
        || witness_keys_path.is_some()
        || require;
    if !any {
        return Ok(None);
    }

    let log_key_path = log_key_path.ok_or_else(|| {
        usage_err("--log-key <file> is required when verifying transparency (checkpoint/witness/require)")
    })?;
    let log_raw = std::fs::read_to_string(log_key_path)
        .map_err(|e| usage_err(&format!("reading --log-key {log_key_path}: {e}")))?;
    let log_pubkey = decode_ed25519_pubkey(log_raw.trim())
        .map_err(|why| usage_err(&format!("--log-key: {why}")))?;

    let mut witness_pubkeys = Vec::new();
    if let Some(p) = witness_keys_path {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| usage_err(&format!("reading --witness-keys {p}: {e}")))?;
        for (n, line) in raw.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let key = decode_ed25519_pubkey(t)
                .map_err(|why| usage_err(&format!("--witness-keys line {}: {why}", n + 1)))?;
            witness_pubkeys.push(key);
        }
    }

    let checkpoint = match checkpoint_path {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .map_err(|e| usage_err(&format!("reading --checkpoint {p}: {e}")))?,
        ),
        None => None,
    };

    Ok(Some(TransparencyOpts {
        log_pubkey,
        witness_pubkeys,
        require: require.then_some(TransparencyRequirement::Required),
        checkpoint,
    }))
}

/// Decode a base64 32-byte Ed25519 public key into raw bytes.
fn decode_ed25519_pubkey(b64: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|_| "key is not valid base64".to_string())?;
    if bytes.len() != 32 {
        return Err(format!("key decodes to {} bytes, expected 32", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// A usage-class [`Verdict`] (exit 64) for a bad transparency CLI input.
fn usage_err(msg: &str) -> Verdict {
    Verdict {
        code: ExitCode::Usage,
        reason: msg.to_string(),
        total: 0,
        failed_at: None,
        failure_kind: Some("usage"),
        diverged_field: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use heso_action::chain::bind_into_chain;
    use heso_action::domain::{ACTION_ENVELOPE_ALG, ACTION_SIGNING_DOMAIN, OPERATOR_KEY_ID};
    use heso_action::receipt::{
        action_canonical_bytes, action_content_hash, ActionContent, ActionDetail, ActionReceipt,
        GateDecision, MatchedCondition, PolicyOutcome, SignatureEntry, TrustLevel, Verb,
    };
    use serde_json::{Map, Value};

    const OPERATOR_SEED: [u8; 32] = [0u8; 32];
    const ZERO_SEED_PUBKEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

    /// A fully-populated v2 standalone content (the same shape the engine's
    /// golden vector pins), built inline so this crate's tests do not reach into
    /// another crate's private test fixtures.
    fn fixed_content() -> ActionContent {
        let mut fields = Map::new();
        fields.insert("prompt".into(), Value::String("summarize the filing".into()));
        fields.insert("model".into(), Value::String("gpt-4o".into()));
        ActionContent {
            action_version: heso_action::domain::ACTION_VERSION.into(),
            captured_at: "2026-05-29T12:00:00Z".into(),
            agent_identity: ZERO_SEED_PUBKEY.into(),
            action: ActionDetail {
                verb: Verb::LlmCall,
                domain: None,
                action: None,
                ert: None,
                mandate: None,
                tool_name: "openai.chat.completions".into(),
                target_host: Some("api.openai.com".into()),
                workflow: "research-run-7".into(),
                account: "acct_acme".into(),
                fields,
                result_hash: Some("a".repeat(64)),
                error: None,
            },
            policy: PolicyOutcome {
                rule_id: "allow-llm".into(),
                rule_display: "allow llm_call to api.openai.com".into(),
                matched_conditions: vec![MatchedCondition {
                    field: "verb".into(),
                    op: "eq".into(),
                    value: Value::String("llm_call".into()),
                }],
                decision_path: GateDecision::Allow,
            },
            approver_decision: None,
            multi_approval: None,
            redaction: None,
            guardrail: None,
            trust_level: TrustLevel::L0,
            action_hash: String::new(),
            session_id: None,
            seq: None,
            prev_receipt_hash: None,
            kind: None,
            suspension: None,
            key_rotation: None,
            nonce: None,
            time_anchor: None,
            anchor_policy: None,
            attestation: None,
        }
    }

    fn sign_entry(seed: &[u8; 32], role: &str, domain: &[u8], content: &ActionContent) -> SignatureEntry {
        let key = heso_core::IdentityKey::from_bytes(seed);
        let canonical = action_canonical_bytes(content);
        let mut payload = Vec::with_capacity(domain.len() + canonical.len());
        payload.extend_from_slice(domain);
        payload.extend_from_slice(&canonical);
        let s = key.sign(&payload);
        SignatureEntry {
            algorithm: s.algorithm,
            key_id: role.to_string(),
            public_key: s.public_key,
            signature: s.signature,
            valid_from: None,
            valid_until: None,
        }
    }

    fn chained(session: &str, seq: u64, prev: Option<&ActionContent>) -> ActionReceipt {
        let mut content = fixed_content();
        content.action.workflow = format!("s-{session}-step-{seq}");
        content.trust_level = TrustLevel::L0;
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        }
    }

    fn good_chain(session: &str, len: usize) -> Vec<ActionReceipt> {
        let mut out = Vec::with_capacity(len);
        out.push(chained(session, 0, None));
        for i in 1..len {
            let prev = out[i - 1].content.clone();
            out.push(chained(session, i as u64, Some(&prev)));
        }
        out
    }

    fn standalone() -> ActionReceipt {
        let mut content = fixed_content();
        content.trust_level = TrustLevel::L0;
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        }
    }

    #[test]
    fn valid_chain_exits_zero() {
        let chain = good_chain("s1", 4);
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Valid, "{}", v.human());
        assert_eq!(v.total, 4);
        assert!(v.to_json().contains("\"status\":\"valid\""));
    }

    #[test]
    fn valid_standalone_receipt_exits_zero() {
        let v = verify_chain_verdict(&[standalone()], Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Valid, "{}", v.human());
    }

    #[test]
    fn tampered_content_is_exit_two_hash_mismatch_with_pinpoint() {
        let mut chain = good_chain("s1", 4);
        chain[2].content.action.account = "acct_evil".into(); // no re-stamp ⇒ self-hash fails
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::WrongAlgorithmOrHash);
        assert_eq!(v.failure_kind, Some("hash_mismatch"));
        assert_eq!(v.failed_at, Some(3), "1-based pinpoint at receipt 3 of 4");
        assert!(v.human().contains("at receipt 3 of 4"), "{}", v.human());
    }

    #[test]
    fn forged_signature_is_exit_one() {
        let mut chain = good_chain("s1", 3);
        let mut raw = B64.decode(chain[1].signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        chain[1].signatures[0].signature = B64.encode(&raw);
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("invalid_signature"));
        assert_eq!(v.failed_at, Some(2));
    }

    #[test]
    fn dropped_receipt_is_link_broken_exit_one() {
        let full = good_chain("s1", 4);
        let chain = vec![full[0].clone(), full[1].clone(), full[3].clone()];
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("link_broken"));
        assert!(v.reason.contains("chain broken"), "{}", v.reason);
        // The drop surfaces as the seq-3 receipt out of order.
        assert!(v.human().contains("of 3"), "{}", v.human());
    }

    #[test]
    fn reordered_receipts_are_link_broken_exit_one() {
        let full = good_chain("s1", 4);
        let chain = vec![full[0].clone(), full[2].clone(), full[1].clone(), full[3].clone()];
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("link_broken"));
    }

    #[test]
    fn repointed_prev_hash_names_diverged_field() {
        let mut chain = good_chain("s1", 3);
        let mut c = chain[2].content.clone();
        c.prev_receipt_hash = Some("f".repeat(64));
        c.action_hash = action_content_hash(&c);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &c);
        chain[2] = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: c,
            signatures: vec![operator],
            transparency: vec![],
        };
        let v = verify_chain_verdict(&chain, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("link_broken"));
        assert_eq!(v.diverged_field.as_deref(), Some("prev_receipt_hash"));
        assert!(v.to_json().contains("\"diverged_field\":\"prev_receipt_hash\""));
    }

    #[test]
    fn wrong_envelope_alg_is_exit_two() {
        let mut r = standalone();
        r.alg = heso_action::domain::ACTION_ENVELOPE_ALG_V1.into();
        let v = verify_chain_verdict(&[r], None, None);
        assert_eq!(v.code, ExitCode::WrongAlgorithmOrHash);
        assert_eq!(v.failure_kind, Some("wrong_algorithm"));
    }

    #[test]
    fn empty_chain_is_usage() {
        let v = verify_chain_verdict(&[], None, None);
        assert_eq!(v.code, ExitCode::Usage);
    }

    #[test]
    fn wrong_pinned_key_is_invalid() {
        // Genesis signed by the zero seed, but the bundle pins a different key.
        let chain = good_chain("s1", 2);
        let other = heso_core::IdentityKey::from_bytes(&[9u8; 32]).public_key_b64();
        let v = verify_chain_verdict(&chain, Some(&other), None);
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("wrong_operator_key"));
        assert_eq!(v.diverged_field.as_deref(), Some("public_key"));
    }

    #[test]
    fn jsonl_round_trips_and_skips_blank_lines() {
        let chain = good_chain("s1", 3);
        let mut buf = String::new();
        for r in &chain {
            buf.push_str(&serde_json::to_string(r).unwrap());
            buf.push('\n');
        }
        buf.push('\n'); // trailing blank line tolerated
        let parsed = parse_receipts_jsonl(buf.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 3);
        let v = verify_chain_verdict(&parsed, Some(ZERO_SEED_PUBKEY), None);
        assert_eq!(v.code, ExitCode::Valid, "{}", v.human());
    }

    #[test]
    fn malformed_jsonl_line_is_usage() {
        let bad = b"{ not json }\n";
        let err = parse_receipts_jsonl(bad).unwrap_err();
        assert_eq!(err.code, ExitCode::Usage);
        assert_eq!(err.failed_at, Some(1));
    }

    #[test]
    fn validate_pubkey_accepts_32_bytes_rejects_others() {
        assert!(validate_pubkey(ZERO_SEED_PUBKEY).is_ok());
        assert!(validate_pubkey("not base64!!").is_err());
        assert!(validate_pubkey(&B64.encode([0u8; 16])).is_err());
    }

    // --- RT-2: transparency-log CLI flags + exit codes ---------------------

    const LOG_SEED: [u8; 32] = [7u8; 32];

    fn log_pubkey() -> [u8; 32] {
        heso_core::IdentityKey::from_bytes(&LOG_SEED).public_key_bytes()
    }

    /// Attach a real single-leaf two-stage proof to a standalone receipt.
    fn standalone_with_proof() -> ActionReceipt {
        use heso_action::transparency::{
            leaf_value_from_action_hash, merkle_tree_hash, note_key_hash, top_leaf_value,
        };
        let mut r = standalone();
        let ah = r.content.action_hash.clone();
        let leaf = leaf_value_from_action_hash(&ah).unwrap();
        let org_root = merkle_tree_hash(&[leaf]);
        let org_id = [3u8; 16];
        let epoch = 5u64;
        let top_leaf = top_leaf_value(&org_id, epoch, &org_root);
        let top_root = merkle_tree_hash(&[top_leaf]);
        let body = format!("log.heso.ca\n1\n{}\n", B64.encode(top_root));
        let key = heso_core::IdentityKey::from_bytes(&LOG_SEED);
        let sig = key.sign(body.as_bytes());
        let sig_raw = B64.decode(sig.signature.as_bytes()).unwrap();
        let kh = note_key_hash("log.heso.ca", &key.public_key_bytes());
        let mut blob = Vec::new();
        blob.extend_from_slice(&kh);
        blob.extend_from_slice(&sig_raw);
        let checkpoint = format!("{body}\n— log.heso.ca {}", B64.encode(&blob));
        r.transparency = vec![heso_action::receipt::TransparencyProof {
            log_id: "log.heso.ca".into(),
            leaf_index: 0,
            inclusion_proof: vec![],
            org_root: Some(B64.encode(org_root)),
            org_tree_size: Some(1),
            epoch: Some(epoch),
            org_id: Some("03030303-0303-0303-0303-030303030303".into()),
            top_leaf_index: Some(0),
            top_inclusion_proof: vec![],
            checkpoint,
            cosignatures: vec![],
        }];
        r
    }

    fn opts(require: bool, log_key: [u8; 32]) -> TransparencyOpts {
        TransparencyOpts {
            log_pubkey: log_key,
            witness_pubkeys: vec![],
            require: require.then_some(TransparencyRequirement::Required),
            checkpoint: None,
        }
    }

    #[test]
    fn valid_transparency_proof_exits_zero() {
        let r = standalone_with_proof();
        let v = verify_chain_verdict(&[r], Some(ZERO_SEED_PUBKEY), Some(&opts(true, log_pubkey())));
        assert_eq!(v.code, ExitCode::Valid, "{}", v.human());
    }

    #[test]
    fn missing_proof_with_require_exits_one() {
        let r = standalone(); // no transparency[]
        let v = verify_chain_verdict(&[r], Some(ZERO_SEED_PUBKEY), Some(&opts(true, log_pubkey())));
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("transparency_required"));
        assert!(v.to_json().contains("\"exit_code\":1"));
    }

    #[test]
    fn missing_proof_without_require_exits_zero() {
        let r = standalone();
        let v = verify_chain_verdict(&[r], Some(ZERO_SEED_PUBKEY), Some(&opts(false, log_pubkey())));
        assert_eq!(v.code, ExitCode::Valid, "{}", v.human());
    }

    #[test]
    fn proof_under_wrong_log_key_exits_one_unverifiable() {
        let r = standalone_with_proof();
        let wrong = heso_core::IdentityKey::from_bytes(&[8u8; 32]).public_key_bytes();
        let v = verify_chain_verdict(&[r], Some(ZERO_SEED_PUBKEY), Some(&opts(true, wrong)));
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("transparency_unverifiable"));
    }

    #[test]
    fn checkpoint_cross_check_mismatch_exits_one() {
        let r = standalone_with_proof();
        let mut o = opts(false, log_pubkey());
        o.checkpoint = Some("a totally different note\n".to_string());
        let v = verify_chain_verdict(&[r], Some(ZERO_SEED_PUBKEY), Some(&o));
        assert_eq!(v.code, ExitCode::Invalid);
        assert_eq!(v.failure_kind, Some("transparency_unverifiable"));
    }

    #[test]
    fn load_transparency_opts_requires_log_key_when_any_flag_set() {
        // No flags at all ⇒ None (transparency off).
        assert!(load_transparency_opts(None, None, None, false).unwrap().is_none());
        // --require-transparency with no --log-key ⇒ usage error.
        let err = load_transparency_opts(None, None, None, true).unwrap_err();
        assert_eq!(err.code, ExitCode::Usage);
    }
}
