//! Chain *verify* — the read-side verifiers that prove a chain is intact.
//!
//! [`verify_action_receipt_chain`] is the pre-lifecycle integrity check (genesis
//! + monotonic seq + stable session + link integrity, with per-receipt crypto
//! delegated to [`crate::verify::open_receipt`]). [`verify_session_chain`] and
//! [`verify_session_chain_with_rotation`] layer the suspend/resume lifecycle and
//! as-of-position key-rotation rules on top. The producer-side link primitives
//! these verify against live in [`super::lifecycle`]; both halves are re-exported
//! from [`super`] so callers use the flat `chain::` path unchanged.
//!
//! ## The verdict
//!
//! Every verifier returns a [`ChainOutcome`] that NAMES the failure mode and the
//! `seq` it occurred at; `Valid` is only returned when every link verifies in
//! isolation AND the inter-link invariants hold. Fail-closed: an empty slice is
//! [`ChainOutcome::Empty`], never `Valid`.

use crate::domain::{
    ACTION_SIGNING_DOMAIN, SIGNING_DOMAIN_DECISION, SIGNING_DOMAIN_SUSPEND,
};
use crate::receipt::{
    action_canonical_bytes, action_content_hash, ActionContent, ActionReceipt, ReceiptKind,
    RotatedRole, SignatureEntry, SignerRole,
};
use crate::verify::{open_receipt, ActionOutcome};

use super::lifecycle::{action_spec_hash, link_hash};

/// The result of verifying a chain of [`ActionReceipt`]s.
///
/// `Valid` is only returned when every link verifies in isolation AND the
/// inter-link invariants hold; otherwise the verdict NAMES the failure mode and
/// the `seq` it occurred at, so a caller maps it to a precise diagnostic / exit
/// code.
#[derive(Debug)]
pub enum ChainOutcome {
    /// Every receipt verified on its own and every link is intact. Carries the
    /// number of receipts in the verified chain.
    Valid {
        /// The count of receipts verified (the chain length).
        length: usize,
    },
    /// A receipt's OWN cryptography failed — its content hash or a signature did
    /// not verify, or it was structurally unacceptable. The chain cannot be
    /// trusted because a link is itself forged/tampered. Carries the offending
    /// `seq` and the per-receipt [`ActionOutcome`].
    ContentTamper {
        /// The `seq` of the offending receipt (its position field, as carried).
        seq: u64,
        /// The per-receipt verdict that failed.
        reason: ActionOutcome,
    },
    /// Every receipt is internally valid, but the ORDER is wrong: a malformed
    /// genesis, a `seq` gap/repeat/regression (drop/reorder/insert), a
    /// `session_id` that changes mid-chain, or a `prev_receipt_hash` that does
    /// not equal the recomputed link of the actual predecessor.
    LinkBroken {
        /// The `seq` of the receipt whose link failed (the successor side of the
        /// broken link).
        seq: u64,
        /// A human-readable description of which invariant broke.
        detail: String,
    },
    /// The chain was empty — there is nothing to verify. Fail closed (never
    /// `Valid`).
    Empty,
    /// SESSION-CHAIN ONLY (suspend/resume layer, [`verify_session_chain`]). A
    /// receipt's lifecycle [`ReceiptKind`] is signed by the WRONG cryptographic
    /// authority — a `Decision`-role kind (`approved`/`denied`/`expired`/
    /// `escalated`) that carries only a producer signature (the customer trying to
    /// approve their own pause), or a `Producer`-role kind
    /// (`action`/`suspended`/`completed`/`key_rotation`) signed under a decision
    /// domain. This is design §8.A(f): a producer-signed `approved` MUST verify
    /// invalid. Distinct from [`ContentTamper`](Self::ContentTamper), which is a
    /// self-hash/signature failure under the *expected* role; here the crypto is
    /// well-formed but the SIGNER ROLE is wrong for the kind.
    RoleViolation {
        /// The `seq` of the offending receipt.
        seq: u64,
        /// The lifecycle kind whose role binding was violated.
        kind: ReceiptKind,
        /// Which authority the kind required ([`SignerRole`]).
        required: SignerRole,
        /// A human-readable description of how the binding broke.
        detail: String,
    },
    /// SESSION-CHAIN ONLY. The sequence of lifecycle [`ReceiptKind`]s for an
    /// `action_hash` is not a legal transition. The verifier accepts exactly two
    /// shapes per `action_hash`: the gated 3-step `suspended → approved →
    /// completed` (and its terminal-deny variants) and the fast 1–2-step
    /// `action` / `action → completed` (no `suspended`). Anything else — a
    /// `completed` with no preceding `suspended`/`action`, an `approved` with no
    /// `suspended`, a decision after a terminal — lands here. The idempotency unit
    /// is `action_hash`, never `seq` (design §6.2).
    IllegalTransition {
        /// The `seq` of the receipt whose kind made the transition illegal.
        seq: u64,
        /// A human-readable description of the illegal transition.
        detail: String,
    },
    /// SESSION-CHAIN ONLY. More than one TERMINAL receipt
    /// (`completed`/`denied`/`expired`) was appended for a single suspended
    /// `action_hash`. The single-terminal rule (design §5/§6) is first-terminal-
    /// wins: the second terminal — an approval racing a deadline, a double-fire, a
    /// replay — is rejected. Carries the `seq` of the offending SECOND terminal.
    DoubleTerminal {
        /// The `seq` of the second (rejected) terminal receipt.
        seq: u64,
        /// The kind of the first terminal that already won.
        first: ReceiptKind,
        /// The kind of the second terminal that is rejected.
        second: ReceiptKind,
    },
    /// SESSION-CHAIN ONLY (PHASE 6 — key rotation,
    /// [`verify_session_chain_with_rotation`]). A receipt's verifying signature is
    /// by a key that is NOT the one valid for that receipt's signer ROLE AS OF its
    /// chain position. Either the signer's key was never registered / already
    /// retired at this `seq` (a foreign or stale key), or a `key_rotation` was
    /// authorized by something other than the OUTGOING key it names (a forged
    /// rotation). This is the design §8.A / security-B3 invariant: TOFU pins the
    /// registry ROOT, and every signer is checked against the as-of-position
    /// registry state — so a key rotated mid-pause still lets the earlier receipt
    /// verify under the key valid at its position, while a key outside its validity
    /// window is rejected here even though its bytes verify under the right domain.
    KeyNotValidAtPosition {
        /// The `seq` of the offending receipt.
        seq: u64,
        /// The signer role whose key was checked ([`SignerRole`]).
        role: SignerRole,
        /// A human-readable description of how the as-of-position key check broke.
        detail: String,
    },
}

/// The binding-neutral projection of a [`ChainOutcome`] — plain fields the node
/// and wasm surfaces map into their own `#[napi]` / `#[wasm_bindgen]` result
/// types. The single owner of the chain error tags + detail formats so the two
/// bindings cannot drift. (The Python surface reports its own dict shape and does
/// NOT use this.)
pub struct ChainSummary {
    /// Whether the chain verified end to end.
    pub ok: bool,
    /// The verified chain length (only when `ok`).
    pub length: Option<usize>,
    /// The stable error tag (`"empty"`, `"link_broken"`, …) when not `ok`.
    pub error: Option<&'static str>,
    /// The offending `seq`, when one applies.
    pub seq: Option<u64>,
    /// A human-readable detail, when one applies.
    pub detail: Option<String>,
}

impl ChainOutcome {
    /// Project into the binding-neutral [`ChainSummary`] (see its docs). The node
    /// and wasm surfaces both build their result type from this, so the error tags
    /// and detail formats live in exactly one place.
    pub fn summarize(&self) -> ChainSummary {
        match self {
            ChainOutcome::Valid { length } => ChainSummary {
                ok: true,
                length: Some(*length),
                error: None,
                seq: None,
                detail: None,
            },
            ChainOutcome::Empty => ChainSummary {
                ok: false,
                length: None,
                error: Some("empty"),
                seq: None,
                detail: None,
            },
            ChainOutcome::ContentTamper { seq, reason } => ChainSummary {
                ok: false,
                length: None,
                error: Some("content_tamper"),
                seq: Some(*seq),
                detail: Some(reason.verdict_tag()),
            },
            ChainOutcome::LinkBroken { seq, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("link_broken"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
            ChainOutcome::RoleViolation { seq, kind, required: _, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("role_violation"),
                seq: Some(*seq),
                detail: Some(format!("{kind:?}: {detail}")),
            },
            ChainOutcome::IllegalTransition { seq, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("illegal_transition"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
            ChainOutcome::DoubleTerminal { seq, first, second } => ChainSummary {
                ok: false,
                length: None,
                error: Some("double_terminal"),
                seq: Some(*seq),
                detail: Some(format!("first={first:?},second={second:?}")),
            },
            ChainOutcome::KeyNotValidAtPosition { seq, role: _, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("key_not_valid_at_position"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
        }
    }
}

#[cfg(test)]
mod chain_summary_golden {
    use super::ChainOutcome;

    #[test]
    fn summarize_locks_the_binding_error_tags() {
        let v = ChainOutcome::Valid { length: 4 }.summarize();
        assert!(v.ok);
        assert_eq!(v.length, Some(4));
        assert!(v.error.is_none());

        assert_eq!(ChainOutcome::Empty.summarize().error, Some("empty"));

        let lb = ChainOutcome::LinkBroken { seq: 3, detail: "boom".into() }.summarize();
        assert!(!lb.ok);
        assert_eq!(lb.error, Some("link_broken"));
        assert_eq!(lb.seq, Some(3));
        assert_eq!(lb.detail.as_deref(), Some("boom"));
    }
}

/// Verify an ordered slice of [`ActionReceipt`]s as a chain.
///
/// Each receipt is first verified in isolation via [`open_receipt`]; any failure
/// short-circuits to [`ChainOutcome::ContentTamper`] naming that receipt's `seq`.
/// Then the inter-link invariants are checked in order:
///
/// 1. **Chain block present.** Every receipt in a chain MUST carry
///    `session_id` + `seq` (a chain is not a bag of standalone receipts).
/// 2. **Genesis.** `chain[0].seq == 0` and it carries no `prev_receipt_hash`.
/// 3. **Monotonic seq.** `chain[i].seq == chain[i-1].seq + 1` — a gap is a
///    **drop**, a repeat/regression is a **reorder/insert**.
/// 4. **Stable session.** `chain[i].session_id == chain[0].session_id`.
/// 5. **Link integrity.** `chain[i].prev_receipt_hash == link_hash(chain[i-1])`.
///
/// Any inter-link failure is [`ChainOutcome::LinkBroken`] naming the successor's
/// `seq` and the invariant that broke. An empty slice is [`ChainOutcome::Empty`].
pub fn verify_action_receipt_chain(chain: &[ActionReceipt]) -> ChainOutcome {
    if chain.is_empty() {
        return ChainOutcome::Empty;
    }

    // Pass 1: every receipt must verify on its own. A forged/tampered link is
    // reported as ContentTamper before any ordering claim is trusted.
    for receipt in chain {
        let seq = receipt.content.seq.unwrap_or(0);
        match open_receipt(receipt) {
            ActionOutcome::Valid(_) => {}
            reason => return ChainOutcome::ContentTamper { seq, reason },
        }
    }

    // Pass 2: the inter-link invariants. Every receipt is now known-authentic,
    // so a failure here is purely an ordering/linking forgery.

    // Genesis must declare a chain block and sit at seq 0 with no predecessor.
    let genesis = &chain[0].content;
    let session = match (&genesis.session_id, genesis.seq) {
        (Some(s), Some(0)) => s.clone(),
        (Some(_), Some(n)) => {
            return ChainOutcome::LinkBroken {
                seq: n,
                detail: format!("genesis receipt has seq {n}, expected 0"),
            }
        }
        _ => {
            return ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt carries no chain block (session_id + seq required)"
                    .to_string(),
            }
        }
    };
    if let Some(prev) = &genesis.prev_receipt_hash {
        if !prev.is_empty() {
            return ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt must carry no prev_receipt_hash".to_string(),
            };
        }
    }

    let mut expected_seq: u64 = 1;
    for window in chain.windows(2) {
        let prev = &window[0].content;
        let cur = &window[1].content;

        // Successor must declare its chain block.
        let cur_seq = match (&cur.session_id, cur.seq) {
            (Some(s), Some(n)) if *s == session => n,
            (Some(other), Some(n)) if *other != session => {
                return ChainOutcome::LinkBroken {
                    seq: n,
                    detail: format!(
                        "session_id changed mid-chain: `{other}` != genesis `{session}`"
                    ),
                }
            }
            _ => {
                // Missing chain block on a non-genesis receipt: report against
                // the position it should have held.
                return ChainOutcome::LinkBroken {
                    seq: expected_seq,
                    detail: "non-genesis receipt carries no chain block".to_string(),
                };
            }
        };

        // Monotonic, gapless seq. A gap (drop), repeat, or regression
        // (reorder/insert) is named with the seq we actually saw.
        if cur_seq != expected_seq {
            return ChainOutcome::LinkBroken {
                seq: cur_seq,
                detail: format!(
                    "seq {cur_seq} out of order (expected {expected_seq}); a drop, reorder, \
                     or insert breaks the chain"
                ),
            };
        }

        // Link integrity: the successor must commit to the recomputed link of
        // the ACTUAL predecessor, not whatever it claims.
        let want = link_hash(prev);
        match &cur.prev_receipt_hash {
            Some(got) if *got == want => {}
            Some(got) => {
                return ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: format!(
                        "prev_receipt_hash {got} != recomputed link {want} of seq {}",
                        prev.seq.unwrap_or(0)
                    ),
                }
            }
            None => {
                return ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: "non-genesis receipt carries no prev_receipt_hash".to_string(),
                }
            }
        }

        expected_seq += 1;
    }

    ChainOutcome::Valid { length: chain.len() }
}

// ============================================================================
// Suspend/resume session chain (the lifecycle verifier, design §6 + §8.A)
// ============================================================================
//
// `verify_action_receipt_chain` above is the PRE-LIFECYCLE integrity check: it
// delegates per-receipt crypto to `open_receipt` (which only knows the operator/
// approver roles under ACTION/APPROVAL domains) and enforces seq contiguity +
// link integrity. It stays untouched — its goldens are pinned.
//
// `verify_session_chain` is the suspend/resume LAYER on top. It re-uses the SAME
// seq+link+session integrity rules (a multi-day pause can never read as a drop —
// §6.5), then adds the four lifecycle rules:
//   (a) per-kind ROLE binding   — producer vs decision authority (§8.A(f))
//   (b) legal TRANSITION graph  — gated 3-step OR fast 1–2-step, per action_hash
//   (c) SINGLE-TERMINAL rule    — first terminal wins, per suspended action_hash
//   (d) TIME-AGNOSTIC integrity — no wall-clock predicate anywhere
//
// CLOUD BOUNDARY: this is the LOCAL verifier. The approver/ledger PRIVATE keys it
// role-checks against are hosted-cloud custody; here we verify that a decision
// kind carries a valid signature under the DECISION domain by a key DISTINCT from
// the producer (operator) key — the local, offline half of "a customer cannot
// self-approve". Binding a decision to a specific allow-listed approver pubkey set
// (`approval.approver_pubkeys`) and the hosted key custody are out of scope.

/// The signing domain a receipt of `kind` MUST have been signed under.
///
/// Producer kinds split by construction: a plain `action`/`completed`/
/// `key_rotation` is an ordinary producer authorization
/// ([`ACTION_SIGNING_DOMAIN`]); a `suspended` park-record is producer-signed but
/// under the DISTINCT [`SIGNING_DOMAIN_SUSPEND`] (so a plain action authorization
/// can never be replayed as a suspend record). Decision kinds
/// (`approved`/`denied`/`expired`/`escalated`) are signed under
/// [`SIGNING_DOMAIN_DECISION`] by an approver/ledger key. The pairwise-
/// disjointness of all three is pinned in `domain::tests::dump_signing_domains`,
/// so a signature minted for one kind can never verify for another.
fn signing_domain_for_kind(kind: ReceiptKind) -> &'static [u8] {
    match kind {
        ReceiptKind::Action | ReceiptKind::Completed | ReceiptKind::KeyRotation => {
            ACTION_SIGNING_DOMAIN
        }
        ReceiptKind::Suspended => SIGNING_DOMAIN_SUSPEND,
        ReceiptKind::Approved
        | ReceiptKind::Denied
        | ReceiptKind::Expired
        | ReceiptKind::Escalated => SIGNING_DOMAIN_DECISION,
    }
}

/// The EFFECTIVE signer role for a receipt's content (PHASE 6).
///
/// Identical to [`ReceiptKind::signer_role`] for every kind EXCEPT a
/// `key_rotation` that rotates the DECISION role: the retiring key signs off on
/// its own replacement, so a decision-key rotation is DECISION-signed (not
/// producer-signed). A producer-key rotation — and a `key_rotation` with no
/// payload (which the rotation pass rejects) — stays producer-role, preserving the
/// existing `key_rotation_is_lifecycle_neutral` behavior.
fn effective_signer_role(content: &ActionContent) -> SignerRole {
    match (content.effective_kind(), &content.key_rotation) {
        (ReceiptKind::KeyRotation, Some(r)) => rotation_signer_role(r.role),
        (kind, _) => kind.signer_role(),
    }
}

/// The EFFECTIVE signing domain for a receipt's content (PHASE 6) — the domain its
/// authorizing signature was minted under. Defers to [`signing_domain_for_kind`]
/// for every kind except a DECISION-role `key_rotation`, which is signed under
/// [`SIGNING_DOMAIN_DECISION`] by the outgoing decision key.
fn effective_signing_domain(content: &ActionContent) -> &'static [u8] {
    match (content.effective_kind(), &content.key_rotation) {
        (ReceiptKind::KeyRotation, Some(r)) if r.role == RotatedRole::Decision => {
            SIGNING_DOMAIN_DECISION
        }
        (kind, _) => signing_domain_for_kind(kind),
    }
}

/// Is this lifecycle kind a TERMINAL of a suspended action — the single-terminal
/// rule's unit (design §5/§6)? `completed` (the side effect fired), `denied` (a
/// human refused), and `expired` (the deadline passed) end the lifecycle; at most
/// one may exist per suspended action spec ([`action_spec_hash`]).
/// `approved`/`escalated` are NON-terminal transitions (`approved` is followed by
/// `completed`), and `suspended`/`action`/`key_rotation` are not terminals of a
/// pause.
fn is_terminal(kind: ReceiptKind) -> bool {
    matches!(
        kind,
        ReceiptKind::Completed | ReceiptKind::Denied | ReceiptKind::Expired
    )
}

/// Verify ONE lifecycle receipt's own crypto with ROLE binding (design §8.A(f)).
///
/// This is the kind-aware analog of [`open_receipt`]: it re-runs the full per-
/// receipt gate (alg, version, content hash, signatures, redaction, trust) AND
/// then enforces that the verifying signature was minted under the domain the
/// receipt's [`ActionContent::effective_kind`] REQUIRES.
///
/// The mechanism is domain separation, not a name check: `open_receipt` verifies
/// the operator entry under [`ACTION_SIGNING_DOMAIN`]. For a `suspended`/decision
/// kind that body was signed under [`SIGNING_DOMAIN_SUSPEND`] /
/// [`SIGNING_DOMAIN_DECISION`], so the operator-entry check would FAIL — we
/// therefore verify the entry under the kind's required domain ourselves. A
/// `Decision`-role kind additionally MUST be signed by a key that is NOT the
/// producer (operator) key on the same receipt: a customer re-using their
/// operator key to sign their own `approved` is a [`ChainOutcome::RoleViolation`]
/// even if the bytes verify under the decision domain.
///
/// Public because a single pushed receipt must be verifiable OUTSIDE a full
/// session chain: the control plane's receipt-push gate receives lifecycle links
/// one at a time (a `suspended` link arrives before its `approved`/`completed`
/// successors exist), and running `open_receipt` on it would reject every
/// legitimate non-`Action` kind with `InvalidSignature` for the domain reason
/// above. This is THE per-receipt verifier for a receipt of ANY kind.
pub fn open_lifecycle_receipt(receipt: &ActionReceipt) -> Result<(), ChainOutcome> {
    let seq = receipt.content.seq.unwrap_or(0);
    let kind = receipt.content.effective_kind();

    match kind {
        // A plain action (or its absent default) is exactly what `open_receipt`
        // already validates end-to-end under ACTION_SIGNING_DOMAIN.
        ReceiptKind::Action => match open_receipt(receipt) {
            ActionOutcome::Valid(_) => Ok(()),
            reason => Err(ChainOutcome::ContentTamper { seq, reason }),
        },
        // Every other kind signs under a non-ACTION domain, so `open_receipt`'s
        // operator-entry check cannot validate it. We run the same integrity
        // sub-checks (alg/version/hash) then verify the single signature under the
        // kind's REQUIRED domain, and enforce the role.
        _ => verify_kind_bound_receipt(receipt, kind, seq),
    }
}

/// Integrity + role check for a non-`Action` lifecycle receipt.
///
/// Re-derives `action_hash` (a content mutation is [`ChainOutcome::ContentTamper`]
/// with [`ActionOutcome::HashMismatch`], the same diagnostic `open_receipt`
/// gives), then requires exactly one signature entry that verifies under
/// [`signing_domain_for_kind`]. For a `Decision`-role kind the verifying key MUST
/// differ from any producer (operator) key also present — the offline half of "no
/// self-approval".
fn verify_kind_bound_receipt(
    receipt: &ActionReceipt,
    kind: ReceiptKind,
    seq: u64,
) -> Result<(), ChainOutcome> {
    // Content self-hash — identical rule to open_receipt step 3.
    if receipt.content.action_hash != action_content_hash(&receipt.content) {
        return Err(ChainOutcome::ContentTamper {
            seq,
            reason: ActionOutcome::HashMismatch,
        });
    }

    let canonical = action_canonical_bytes(&receipt.content);
    // PHASE 6: use the CONTENT-effective domain/role so a decision-role
    // `key_rotation` (the outgoing decision key signing off its own replacement)
    // verifies under SIGNING_DOMAIN_DECISION as a Decision signer, while every
    // other kind — and a producer-role rotation — keeps its kind-default.
    let domain = effective_signing_domain(&receipt.content);
    let required = effective_signer_role(&receipt.content);

    // Exactly one entry must verify under the kind's required domain. We accept
    // the FIRST entry that verifies; a kind-bound receipt carries one authoritative
    // signature (producer-suspend or approver/ledger-decision).
    let verifying: Option<&SignatureEntry> = receipt
        .signatures
        .iter()
        .find(|e| verify_entry_under(e, domain, &canonical).is_ok());

    let signer = match verifying {
        Some(e) => e,
        None => {
            // No entry verifies under the required domain. If an entry verifies
            // under the PRODUCER (action) domain for a Decision kind, name it a
            // role violation (the self-approval shape); otherwise it's tamper.
            if required == SignerRole::Decision {
                let producer_signed = receipt
                    .signatures
                    .iter()
                    .any(|e| verify_entry_under(e, ACTION_SIGNING_DOMAIN, &canonical).is_ok());
                if producer_signed {
                    return Err(ChainOutcome::RoleViolation {
                        seq,
                        kind,
                        required,
                        detail: format!(
                            "{kind:?} is decision-signed, but only a producer (operator) \
                             signature is present — a customer cannot approve their own pause"
                        ),
                    });
                }
            }
            return Err(ChainOutcome::ContentTamper {
                seq,
                reason: ActionOutcome::Malformed(format!(
                    "no signature verifies under the {kind:?} kind's required domain"
                )),
            });
        }
    };

    // Role binding: a Decision kind must be signed by a key DISTINCT from any
    // producer key on the receipt. If the SAME key both produced and "decided",
    // that is a self-approval — reject it even though the decision bytes verify.
    if required == SignerRole::Decision {
        let producer_key_reused = receipt.signatures.iter().any(|e| {
            e.public_key == signer.public_key
                && verify_entry_under(e, ACTION_SIGNING_DOMAIN, &canonical).is_ok()
        });
        if producer_key_reused {
            return Err(ChainOutcome::RoleViolation {
                seq,
                kind,
                required,
                detail: format!(
                    "{kind:?} decision is signed by the same key that produced an action \
                     authorization on this receipt — no self-approval"
                ),
            });
        }
    }

    Ok(())
}

/// Verify one [`SignatureEntry`] over `domain ++ canonical` via the house
/// `verify_strict` path. A thin local mirror of `verify::verify_entry` (kept
/// private to that module) so the session-chain verifier can probe an entry under
/// an arbitrary lifecycle domain.
fn verify_entry_under(
    entry: &SignatureEntry,
    domain: &[u8],
    canonical: &[u8],
) -> Result<(), heso_verify::SignatureError> {
    let mut payload = Vec::with_capacity(domain.len() + canonical.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(canonical);
    let sig = heso_verify::Signature {
        algorithm: entry.algorithm.clone(),
        public_key: entry.public_key.clone(),
        signature: entry.signature.clone(),
    };
    sig.verify(&payload)
}

/// Verify a suspend/resume SESSION chain — the lifecycle verifier (design §6 +
/// §8.A).
///
/// A superset of [`verify_action_receipt_chain`] for chains whose receipts carry
/// a lifecycle [`ReceiptKind`]. It runs in three passes, each fail-closed:
///
/// 1. **Per-receipt crypto with ROLE binding** ([`open_lifecycle_receipt`]):
///    every link verifies its own alg/version/hash/signature, AND the verifying
///    signature was minted under the domain the receipt's kind requires —
///    `action`/`suspended`/`completed`/`key_rotation` PRODUCER-signed,
///    `approved`/`denied`/`expired`/`escalated` DECISION-signed by a key the
///    producer does not control. A producer-signed `approved` is
///    [`ChainOutcome::RoleViolation`], NOT `Valid` (§8.A(f), rule (a)).
/// 2. **Structural integrity** — the SAME genesis + monotonic-seq + stable-
///    session + link-hash rules as [`verify_action_receipt_chain`]. Integrity is
///    `seq contiguity + hash linkage + signature + role` ONLY; there is NO wall-
///    clock predicate, so a multi-day pause between `suspended@N` and `approved@
///    N+1` can never read as a drop (rule (d), §6.5).
/// 3. **Lifecycle transition graph + single-terminal**, grouped by `action_hash`
///    (the idempotency unit, NEVER `seq` — §6.2):
///    - **Legal shapes (rule b):** the gated `suspended → {approved → completed |
///      denied | expired | escalated…}` and the fast `action` / `action →
///      completed` (1–2 seq, no `suspended`). `escalated` is a non-terminal that
///      may repeat before a terminal. A `completed`/`approved` with no preceding
///      `suspended` (when the group ever suspended) or an out-of-nowhere decision
///      is [`ChainOutcome::IllegalTransition`].
///    - **Single terminal (rule c):** at most one of `completed`/`denied`/
///      `expired` per suspended `action_hash`; a second terminal is
///      [`ChainOutcome::DoubleTerminal`] (first-terminal-wins, §5).
///
/// An empty slice is [`ChainOutcome::Empty`] (fail closed).
pub fn verify_session_chain(chain: &[ActionReceipt]) -> ChainOutcome {
    if chain.is_empty() {
        return ChainOutcome::Empty;
    }

    // Pass 1: per-receipt crypto WITH role binding. A self-hash/signature failure
    // is ContentTamper; a wrong-authority signer is RoleViolation.
    for receipt in chain {
        if let Err(outcome) = open_lifecycle_receipt(receipt) {
            return outcome;
        }
    }

    // Pass 2: structural integrity (seq + session + link). Identical invariants to
    // verify_action_receipt_chain — and deliberately TIME-AGNOSTIC.
    if let Err(outcome) = verify_chain_structure(chain) {
        return outcome;
    }

    // Pass 3: the lifecycle transition graph + single-terminal, per action_hash.
    if let Err(outcome) = verify_lifecycle_transitions(chain) {
        return outcome;
    }

    ChainOutcome::Valid { length: chain.len() }
}

// ============================================================================
// Key rotation across a multi-day pause (PHASE 6 — design §8.A, security B3)
// ============================================================================
//
// `verify_session_chain` above proves each signer is the RIGHT ROLE (a decision
// is decision-domain-signed by a key distinct from the producer) — but it does
// NOT pin WHICH key. Phase 6 adds the as-of-position check: a signing key can be
// rotated WHILE a session is parked (a pause may span days), so the key valid
// when a receipt was minted may be retired by verify time.
//
// The mechanism: TOFU pins the registry ROOT (the genesis-time producer +
// decision keys). The verifier walks the chain in seq order maintaining a
// `KeyRegistry`; each `key_rotation` receipt — signed by the OUTGOING key —
// installs an INCOMING key for its role from the NEXT position onward. Every
// signer is then validated against the registry state AS OF its OWN position. A
// receipt minted before a rotation still verifies under the key valid at its
// position; a key outside its validity window is rejected even though its bytes
// verify under the right domain. Integrity stays POSITION-based (seq), never
// wall-clock — the multi-day gap is invisible to the check (§6.5).
//
// CLOUD BOUNDARY: the registry ROOT passed in is a TOFU pin the caller supplies;
// the hosted distribution of that root + the DECISION (approver/ledger) key
// custody (outgoing and incoming) are CLOUD primitives and OUT OF SCOPE. This is
// the offline, local as-of-position verifier only.

/// One key's validity WINDOW for a role, expressed in chain POSITIONS (`seq`),
/// never wall-clock. A key is valid for receipts whose `seq` lies in
/// `[from_seq, until_seq]` inclusive; `until_seq == None` is an open-ended
/// (current) key. A `key_rotation` at position N closes the outgoing key at
/// `until_seq = N` (it must still be valid to sign the rotation itself) and opens
/// the incoming key at `from_seq = N + 1`.
#[derive(Debug, Clone)]
struct KeyValidity {
    /// Base64 (standard alphabet) 32-byte public key.
    public_key: String,
    /// First `seq` (inclusive) this key is valid for its role.
    from_seq: u64,
    /// Last `seq` (inclusive) this key is valid; `None` = open-ended/current.
    until_seq: Option<u64>,
}

/// The per-role key registry the as-of-position verifier walks. Seeded from the
/// TOFU-pinned genesis keys (the ROOT) and advanced by each in-chain
/// `key_rotation`. Look-up is by chain POSITION: [`key_at`](Self::key_at) returns
/// the key whose validity window contains a given `seq`.
///
/// The registry ROOT is the TOFU pin — design §8.A: TOFU pins the registry root,
/// NOT the per-receipt signer, so a since-rotated key still verifies under the
/// key valid at its position.
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    producer: Vec<KeyValidity>,
    decision: Vec<KeyValidity>,
}

impl KeyRegistry {
    /// A registry whose ROOT is the genesis-time keys: `producer_root` signs
    /// `action`/`suspended`/`completed`/`key_rotation` from `seq 0`, and
    /// `decision_root` signs `approved`/`denied`/`expired`/`escalated` from
    /// `seq 0`. Both are open-ended until a `key_rotation` retires them. This is
    /// the TOFU pin the caller commits to once; `None` for `decision_root` means a
    /// session that never expects a decision signer (a pure fast-allow chain) —
    /// a decision receipt then has no valid key and is rejected as
    /// [`ChainOutcome::KeyNotValidAtPosition`] (fail closed, never fail-open).
    pub fn from_roots(producer_root: &str, decision_root: Option<&str>) -> Self {
        let mut decision = Vec::new();
        if let Some(d) = decision_root {
            decision.push(KeyValidity {
                public_key: d.to_string(),
                from_seq: 0,
                until_seq: None,
            });
        }
        KeyRegistry {
            producer: vec![KeyValidity {
                public_key: producer_root.to_string(),
                from_seq: 0,
                until_seq: None,
            }],
            decision,
        }
    }

    /// The public key valid for `role` AS OF chain position `seq`, if any. A key is
    /// valid when `from_seq <= seq` and (`until_seq` is `None` or `seq <=
    /// until_seq`). Returns `None` when no registered key covers this position —
    /// the fail-closed case.
    fn key_at(&self, role: SignerRole, seq: u64) -> Option<&str> {
        let windows = match role {
            SignerRole::Producer => &self.producer,
            SignerRole::Decision => &self.decision,
        };
        windows
            .iter()
            .find(|w| w.from_seq <= seq && w.until_seq.map(|u| seq <= u).unwrap_or(true))
            .map(|w| w.public_key.as_str())
    }

    /// Apply a `key_rotation` at position `seq`: close the role's currently-open
    /// key at `until_seq = seq` and open `incoming` at `from_seq = seq + 1`. The
    /// caller has already verified the rotation was authorized by the outgoing key.
    fn apply_rotation(&mut self, role: RotatedRole, incoming: &str, seq: u64) {
        let windows = match role {
            RotatedRole::Producer => &mut self.producer,
            RotatedRole::Decision => &mut self.decision,
        };
        // Close every still-open window for this role at `seq` (there is exactly
        // one open key per role at any position, but close defensively).
        for w in windows.iter_mut() {
            if w.until_seq.is_none() {
                w.until_seq = Some(seq);
            }
        }
        windows.push(KeyValidity {
            public_key: incoming.to_string(),
            from_seq: seq + 1,
            until_seq: None,
        });
    }
}

/// The public key of the signature entry that VERIFIES this receipt under its
/// kind's required domain — the authoritative signer whose validity-window the
/// as-of-position check pins. Returns `None` if no entry verifies (which
/// `verify_session_chain` would already have rejected as tamper/role).
fn verifying_signer_key(receipt: &ActionReceipt) -> Option<String> {
    // The content-effective domain so a decision-role key_rotation is probed under
    // SIGNING_DOMAIN_DECISION, matching pass 1.
    let domain = effective_signing_domain(&receipt.content);
    let canonical = action_canonical_bytes(&receipt.content);
    receipt
        .signatures
        .iter()
        .find(|e| verify_entry_under(e, domain, &canonical).is_ok())
        .map(|e| e.public_key.clone())
}

/// Verify a suspend/resume SESSION chain WITH key-rotation as-of-position binding
/// (PHASE 6 — design §8.A, security B3).
///
/// A strict superset of [`verify_session_chain`]: it first runs that verifier in
/// full (per-receipt crypto + role binding, structural integrity, lifecycle
/// transitions, single-terminal) and short-circuits on any failure. It then runs
/// a fourth, position-based pass against a TOFU-pinned [`KeyRegistry`] root:
///
/// - Walking the chain in `seq` order, each receipt's verifying signer
///   ([`verifying_signer_key`]) MUST be the key valid for the receipt's signer
///   ROLE ([`ReceiptKind::signer_role`]) AS OF its `seq`
///   ([`KeyRegistry::key_at`]). A key outside its validity window — never
///   registered, or already retired by a prior rotation — is
///   [`ChainOutcome::KeyNotValidAtPosition`], even though its bytes verified under
///   the right domain in the earlier pass.
/// - A `key_rotation` receipt additionally must be authorized by the OUTGOING key
///   it names: its `key_rotation.outgoing_public_key` MUST equal both the
///   receipt's verifying signer AND the role's current registry key. The retiring
///   key signs off on its own replacement; a rotation signed by anything else (or
///   naming an outgoing key that is not the current one) is rejected. The incoming
///   key is then installed for positions after this one.
///
/// The result: a key rotated DURING a multi-day pause still lets the earlier
/// `suspended`/`approved` receipt verify under the key that was valid at its
/// position, while a forged or stale signer is caught. The check is purely
/// positional — no wall-clock predicate — so the length of the pause is invisible
/// to it (§6.5). An empty slice is [`ChainOutcome::Empty`] (fail closed).
pub fn verify_session_chain_with_rotation(
    chain: &[ActionReceipt],
    mut registry: KeyRegistry,
) -> ChainOutcome {
    // Passes 1–3 (crypto+role, structure, transitions) are exactly the existing
    // session verifier. Reuse it verbatim so its semantics never drift; only on
    // its `Valid` do we run the rotation pass.
    match verify_session_chain(chain) {
        ChainOutcome::Valid { .. } => {}
        other => return other,
    }

    // Pass 4: as-of-position key binding. The chain is already known structurally
    // sound (contiguous seq from a genesis), so walking it in slice order walks it
    // in seq order.
    for receipt in chain {
        let seq = receipt.content.seq.unwrap_or(0);
        let kind = receipt.content.effective_kind();
        // PHASE 6: the role whose registry window this signer must fall in — the
        // content-effective role, so a decision-key rotation is checked against the
        // DECISION window (its outgoing decision key), not the producer window.
        let role = effective_signer_role(&receipt.content);

        // The signer that actually verified this receipt (pass 1 guaranteed one
        // exists; treat an absence defensively as a closed failure).
        let signer = match verifying_signer_key(receipt) {
            Some(k) => k,
            None => {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: "no signature verifies under the receipt's required domain at \
                             rotation-check time"
                        .to_string(),
                }
            }
        };

        // The key the registry says is valid for this role at this position.
        let expected = match registry.key_at(role, seq) {
            Some(k) => k.to_string(),
            None => {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: format!(
                        "no {role:?} key is valid at seq {seq} (the registry root has no \
                         key for this role, or every key for it was already retired)"
                    ),
                }
            }
        };

        if signer != expected {
            return ChainOutcome::KeyNotValidAtPosition {
                seq,
                role,
                detail: format!(
                    "{role:?} receipt at seq {seq} is signed by a key that is not the one \
                     valid for its role at this position (signed by `{signer}`, expected \
                     `{expected}`) — a foreign or since-rotated key"
                ),
            };
        }

        // A key_rotation must be authorized by the OUTGOING key it names, and that
        // outgoing key must be the role's current registry key. Then install the
        // incoming key from the next position.
        if kind == ReceiptKind::KeyRotation {
            let rotation = match &receipt.content.key_rotation {
                Some(r) => r,
                None => {
                    return ChainOutcome::KeyNotValidAtPosition {
                        seq,
                        role,
                        detail: "key_rotation receipt carries no key_rotation payload".to_string(),
                    }
                }
            };
            // The rotation's named outgoing key must equal the verifying signer
            // (which we already proved is the role's current registry key) — the
            // retiring key signs off on its own replacement.
            if rotation.outgoing_public_key != signer {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: format!(
                        "key_rotation at seq {seq} names outgoing key `{}` but is signed by \
                         `{signer}` — the retiring key must authorize its own replacement",
                        rotation.outgoing_public_key
                    ),
                };
            }
            registry.apply_rotation(rotation.role, &rotation.incoming_public_key, seq);
        }
    }

    ChainOutcome::Valid { length: chain.len() }
}

/// Map a [`RotatedRole`] to the [`SignerRole`] whose registry window it advances.
fn rotation_signer_role(role: RotatedRole) -> SignerRole {
    match role {
        RotatedRole::Producer => SignerRole::Producer,
        RotatedRole::Decision => SignerRole::Decision,
    }
}

/// The structural integrity invariants shared by both chain verifiers: a chain
/// block on every link, a seq-0 genesis with no predecessor, contiguous seq, a
/// stable session_id, and each `prev_receipt_hash == link_hash(predecessor)`.
///
/// Returns the same [`ChainOutcome::LinkBroken`] verdicts
/// [`verify_action_receipt_chain`] does (the existing function keeps its own copy
/// so its goldens never move; this is the lifecycle verifier's structural pass).
/// Contains NO wall-clock check — integrity is position + linkage only (§6.5).
fn verify_chain_structure(chain: &[ActionReceipt]) -> Result<(), ChainOutcome> {
    let genesis = &chain[0].content;
    let session = match (&genesis.session_id, genesis.seq) {
        (Some(s), Some(0)) => s.clone(),
        (Some(_), Some(n)) => {
            return Err(ChainOutcome::LinkBroken {
                seq: n,
                detail: format!("genesis receipt has seq {n}, expected 0"),
            })
        }
        _ => {
            return Err(ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt carries no chain block (session_id + seq required)"
                    .to_string(),
            })
        }
    };
    if let Some(prev) = &genesis.prev_receipt_hash {
        if !prev.is_empty() {
            return Err(ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt must carry no prev_receipt_hash".to_string(),
            });
        }
    }

    let mut expected_seq: u64 = 1;
    for window in chain.windows(2) {
        let prev = &window[0].content;
        let cur = &window[1].content;

        let cur_seq = match (&cur.session_id, cur.seq) {
            (Some(s), Some(n)) if *s == session => n,
            (Some(other), Some(n)) if *other != session => {
                return Err(ChainOutcome::LinkBroken {
                    seq: n,
                    detail: format!(
                        "session_id changed mid-chain: `{other}` != genesis `{session}`"
                    ),
                })
            }
            _ => {
                return Err(ChainOutcome::LinkBroken {
                    seq: expected_seq,
                    detail: "non-genesis receipt carries no chain block".to_string(),
                })
            }
        };

        if cur_seq != expected_seq {
            return Err(ChainOutcome::LinkBroken {
                seq: cur_seq,
                detail: format!(
                    "seq {cur_seq} out of order (expected {expected_seq}); a drop, reorder, \
                     or insert breaks the chain"
                ),
            });
        }

        let want = link_hash(prev);
        match &cur.prev_receipt_hash {
            Some(got) if *got == want => {}
            Some(got) => {
                return Err(ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: format!(
                        "prev_receipt_hash {got} != recomputed link {want} of seq {}",
                        prev.seq.unwrap_or(0)
                    ),
                })
            }
            None => {
                return Err(ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: "non-genesis receipt carries no prev_receipt_hash".to_string(),
                })
            }
        }

        expected_seq += 1;
    }

    Ok(())
}

/// The lifecycle transition graph + single-terminal rule, evaluated per
/// `action_hash` (design §6.2: the idempotency unit is `action_hash`, never
/// `seq`).
///
/// Walks the chain IN ORDER, maintaining per-`action_hash` lifecycle state, and
/// asserts each receipt's kind is a legal next step for its action:
///
/// - First sighting of an `action_hash`:
///   - `suspended` opens a gated lifecycle (awaiting a decision).
///   - `action` / `completed` opens (and, for `action→completed`, can close) a
///     FAST lifecycle — no `suspended` required.
///   - any other kind first (a bare `approved`/`denied`/`completed` with nothing
///     to decide on) is an [`ChainOutcome::IllegalTransition`].
/// - After `suspended`: `approved` / `escalated` (non-terminal) or `denied` /
///   `expired` (terminal). `completed` is illegal here — a gated action must be
///   `approved` before it fires.
/// - After `approved`: `completed` (the fire). A second decision is illegal.
/// - After `escalated`: another `escalated`, or any decision/terminal.
/// - Single-terminal: once a terminal (`completed`/`denied`/`expired`) is
///   recorded for an action, ANY later terminal for the same action is
///   [`ChainOutcome::DoubleTerminal`]; a non-terminal after a terminal is an
///   [`ChainOutcome::IllegalTransition`].
///
/// `key_rotation` is lifecycle-neutral: it carries no action lifecycle and is
/// skipped here (its role binding is still enforced in pass 1).
fn verify_lifecycle_transitions(chain: &[ActionReceipt]) -> Result<(), ChainOutcome> {
    use std::collections::HashMap;

    /// Per-action-spec lifecycle position.
    enum State {
        /// A `suspended` was seen; awaiting a decision.
        Suspended,
        /// An `approved` was seen; awaiting the `completed` fire.
        Approved,
        /// An `escalated` was seen; awaiting a decision/terminal (may re-escalate).
        Escalated,
        /// A terminal (`completed`/`denied`/`expired`) closed this action.
        Terminal(ReceiptKind),
        /// A fast `action` opened (and, alone, closed) this action — but it may be
        /// followed by exactly one `completed` (the `action→completed` shape).
        FastAction,
    }

    let mut states: HashMap<String, State> = HashMap::new();

    for receipt in chain {
        let kind = receipt.content.effective_kind();
        let seq = receipt.content.seq.unwrap_or(0);
        // Group by the STABLE action-spec identity, not the per-receipt content
        // self-hash (which differs across links). This is the §6.2 idempotency
        // unit: suspended/approved/completed of ONE gated action share it.
        let spec = action_spec_hash(&receipt.content);

        // key_rotation carries no action lifecycle.
        if kind == ReceiptKind::KeyRotation {
            continue;
        }

        match states.get(&spec) {
            // First time we see this action spec.
            None => match kind {
                ReceiptKind::Suspended => {
                    states.insert(spec, State::Suspended);
                }
                ReceiptKind::Action => {
                    states.insert(spec, State::FastAction);
                }
                ReceiptKind::Completed => {
                    // A bare `completed` with no prior `suspended`/`action` is the
                    // fast allow path collapsed to one terminal receipt — legal.
                    states.insert(spec, State::Terminal(kind));
                }
                _ => {
                    return Err(ChainOutcome::IllegalTransition {
                        seq,
                        detail: format!(
                            "{kind:?} is the first receipt for its action spec, but a \
                             decision/terminal must follow a `suspended` (or be a fast \
                             `action`/`completed`)"
                        ),
                    })
                }
            },
            // We have prior state for this action spec. Compute the next state
            // (or an error), then write it after the match to avoid borrowing
            // `states` mutably while it is read.
            Some(state) => {
                let next: State = match (state, kind) {
                    // --- Single-terminal: a terminal already won. ---------------
                    (State::Terminal(first), k) if is_terminal(k) => {
                        return Err(ChainOutcome::DoubleTerminal {
                            seq,
                            first: *first,
                            second: k,
                        })
                    }
                    (State::Terminal(_), k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows a terminal for the same action spec — the \
                                 lifecycle is closed"
                            ),
                        })
                    }
                    // --- After suspended: a decision (terminal or not). ---------
                    (State::Suspended, ReceiptKind::Approved) => State::Approved,
                    (State::Suspended, ReceiptKind::Escalated) => State::Escalated,
                    (State::Suspended, k) if is_terminal(k) && k != ReceiptKind::Completed => {
                        // denied / expired terminate a suspended action directly.
                        State::Terminal(k)
                    }
                    (State::Suspended, ReceiptKind::Completed) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: "`completed` follows `suspended` with no `approved` — a \
                                     gated action must be approved before it fires"
                                .to_string(),
                        })
                    }
                    // --- After approved: only the completed fire. ---------------
                    (State::Approved, ReceiptKind::Completed) => {
                        State::Terminal(ReceiptKind::Completed)
                    }
                    (State::Approved, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows `approved`; only `completed` (the fire) is legal"
                            ),
                        })
                    }
                    // --- After escalated: re-escalate, decide, or terminate. ----
                    (State::Escalated, ReceiptKind::Escalated) => State::Escalated,
                    (State::Escalated, ReceiptKind::Approved) => State::Approved,
                    (State::Escalated, k) if is_terminal(k) && k != ReceiptKind::Completed => {
                        State::Terminal(k)
                    }
                    (State::Escalated, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows `escalated`; expected another escalation, an \
                                 approval, or a deny/expire terminal"
                            ),
                        })
                    }
                    // --- After a fast action: at most one completed. ------------
                    (State::FastAction, ReceiptKind::Completed) => {
                        State::Terminal(ReceiptKind::Completed)
                    }
                    (State::FastAction, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows a fast `action`; only a single `completed` may \
                                 follow the fast allow path"
                            ),
                        })
                    }
                    // --- A second `suspended` for the same spec. ----------------
                    (_, ReceiptKind::Suspended) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: "a second `suspended` for an action spec already in flight"
                                .to_string(),
                        })
                    }
                    // --- Anything else is illegal. ------------------------------
                    (_, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!("{k:?} is not a legal next step for this action spec"),
                        })
                    }
                };
                states.insert(spec, next);
            }
        }
    }

    Ok(())
}
