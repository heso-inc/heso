//! Cross-receipt chaining — tamper-evident ordering over a session of
//! [`ActionReceipt`]s.
//!
//! A single [`ActionReceipt`] proves *one* action happened under policy. A
//! chain proves a *sequence* happened in a specific order with nothing dropped,
//! reordered, or inserted between links. The chain block lives in the SIGNED
//! content ([`ActionContent::session_id`] / [`ActionContent::seq`] /
//! [`ActionContent::prev_receipt_hash`]), so an operator cannot re-point a
//! receipt at a different predecessor without breaking its own operator
//! signature.
//!
//! ## Layout
//!
//! The module splits along the build-vs-verify seam (ADR-0014: deterministic
//! orchestration in the kernel, behaviour unchanged):
//!
//! - [`lifecycle`] — the producer-side link primitives that BUILD a chain:
//!   [`link_input`] / [`link_hash`] (the domain-separated, length-prefixed link
//!   digest), [`bind_into_chain`] (stamp the chain block before signing), and
//!   [`action_spec_hash`] (the §6.2 idempotency grouping key).
//! - [`verify`] — the read-side verifiers: [`verify_action_receipt_chain`] (the
//!   pre-lifecycle integrity check that NAMES the failure —
//!   [`ChainOutcome::ContentTamper`] vs [`ChainOutcome::LinkBroken`]),
//!   [`verify_session_chain`] (the suspend/resume lifecycle layer), and
//!   [`verify_session_chain_with_rotation`] (the as-of-position key-rotation
//!   layer) plus [`KeyRegistry`].
//!
//! Every public item is re-exported here, so callers continue to use the flat
//! `chain::` path (`chain::verify_action_receipt_chain`, `chain::link_hash`, …)
//! with no change after the split.
//!
//! ## The link
//!
//! Each non-genesis receipt carries `prev_receipt_hash = link_hash(prev)`, the
//! BLAKE3 of the previous receipt's domain-separated, **length-prefixed**
//! [`link_input`]. Genesis (`seq == 0`) carries no `prev_receipt_hash`
//! (`None`/empty). The collision-resistance argument for the length prefixing
//! lives in [`lifecycle`].
//!
//! ## The verdict
//!
//! [`verify_action_receipt_chain`] runs the full per-receipt offline check
//! ([`crate::verify::open_receipt`]: alg, version, content hash, signatures,
//! redaction, trust level) on every link AND the inter-link invariants, and
//! NAMES the failure via [`ChainOutcome`]. Fail-closed: an empty slice is
//! [`ChainOutcome::Empty`], not `Valid`.

pub mod lifecycle;
pub mod verify;

pub use lifecycle::{action_spec_hash, bind_into_chain, link_hash, link_input};
pub use verify::{
    open_lifecycle_receipt, verify_action_receipt_chain, verify_session_chain,
    verify_session_chain_with_rotation, ChainOutcome, ChainSummary, KeyRegistry,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        ACTION_ENVELOPE_ALG, ACTION_SIGNING_DOMAIN, APPROVAL_SIGNING_DOMAIN, APPROVER_KEY_ID,
        OPERATOR_KEY_ID, SIGNING_DOMAIN_DECISION, SIGNING_DOMAIN_SUSPEND,
    };
    use crate::receipt::fixtures::fixed_content;
    use crate::receipt::{
        action_canonical_bytes, action_content_hash, ActionContent, ActionReceipt, RotatedRole,
        SignatureEntry, TrustLevel,
    };
    use crate::verify::ActionOutcome;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    const OPERATOR_SEED: [u8; 32] = [0u8; 32];

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

    /// Build a chained, operator-signed L0 receipt at `seq` whose content is
    /// derived from the fixture but made unique per position (so distinct links
    /// have distinct action_hashes).
    fn chained_receipt(session: &str, seq: u64, prev: Option<&ActionContent>) -> ActionReceipt {
        let mut content = fixed_content();
        content.action.workflow = format!("session-{session}-step-{seq}");
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

    /// A genesis + N successors, correctly linked.
    fn good_chain(session: &str, len: usize) -> Vec<ActionReceipt> {
        let mut out = Vec::with_capacity(len);
        let genesis = chained_receipt(session, 0, None);
        out.push(genesis);
        for i in 1..len {
            let prev = out[i - 1].content.clone();
            out.push(chained_receipt(session, i as u64, Some(&prev)));
        }
        out
    }

    #[test]
    fn empty_chain_is_empty_not_valid() {
        assert!(matches!(verify_action_receipt_chain(&[]), ChainOutcome::Empty));
    }

    #[test]
    fn single_genesis_is_valid() {
        let chain = good_chain("s1", 1);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_chain_verifies() {
        let chain = good_chain("s1", 5);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 5),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn link_input_is_length_prefixed_no_boundary_slide() {
        // Two receipts where (session_id, action_hash) differ only by where the
        // boundary sits must NOT produce the same link. session "ab" + hash "cd"
        // vs session "a" + hash "bcd": raw concat would collide; length-prefix
        // keeps them distinct.
        let mut a = fixed_content();
        a.session_id = Some("ab".into());
        a.seq = Some(0);
        a.action_hash = "cd".into();
        let mut b = fixed_content();
        b.session_id = Some("a".into());
        b.seq = Some(0);
        b.action_hash = "bcd".into();
        assert_ne!(link_input(&a), link_input(&b));
        assert_ne!(link_hash(&a), link_hash(&b));
    }

    #[test]
    fn tampered_content_in_a_link_is_content_tamper() {
        let mut chain = good_chain("s1", 4);
        // Mutate a content field of receipt #2 WITHOUT re-stamping action_hash:
        // its own self-hash now fails (the per-receipt crypto), so it's tamper,
        // not a broken link.
        chain[2].content.action.account = "acct_evil".into();
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(matches!(reason, ActionOutcome::HashMismatch));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    #[test]
    fn forged_signature_in_a_link_is_content_tamper() {
        let mut chain = good_chain("s1", 3);
        let mut raw = B64.decode(chain[1].signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        chain[1].signatures[0].signature = B64.encode(&raw);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 1);
                assert!(matches!(reason, ActionOutcome::InvalidSignature(_)));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    #[test]
    fn dropped_receipt_is_link_broken() {
        // Build 0..4, then drop #2. Each remaining receipt is internally valid,
        // but seq jumps 1 -> 3 (a gap = drop), and #3's prev_receipt_hash points
        // at the now-missing #2.
        let full = good_chain("s1", 4);
        let chain = vec![full[0].clone(), full[1].clone(), full[3].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 3);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn reordered_receipts_are_link_broken() {
        let full = good_chain("s1", 4);
        // Swap #1 and #2: seq goes 0, 2, 1, 3 — the first out-of-order is seq 2.
        let chain = vec![full[0].clone(), full[2].clone(), full[1].clone(), full[3].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn inserted_foreign_receipt_is_link_broken() {
        // Insert a valid receipt from ANOTHER session between #0 and #1. It is
        // internally valid, so the failure is a broken link: its session_id
        // differs from genesis (caught before the hash compare).
        let mut chain = good_chain("s1", 3);
        let foreign = chained_receipt("s2", 0, None);
        chain.insert(1, foreign);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { detail, .. } => {
                assert!(
                    detail.contains("session_id changed") || detail.contains("out of order"),
                    "got: {detail}"
                );
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn repointed_prev_hash_is_link_broken() {
        // Every receipt is internally valid, but #2's prev_receipt_hash is
        // re-stamped to a wrong value and re-signed — so the per-receipt check
        // passes yet the link to the real predecessor is broken.
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
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("prev_receipt_hash"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn genesis_with_nonzero_seq_is_link_broken() {
        // A "chain" that starts at seq 1 (the real genesis was dropped).
        let full = good_chain("s1", 3);
        let chain = vec![full[1].clone(), full[2].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("genesis"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn genesis_carrying_prev_hash_is_link_broken() {
        let mut chain = good_chain("s1", 2);
        let mut c = chain[0].content.clone();
        c.prev_receipt_hash = Some("a".repeat(64));
        c.action_hash = action_content_hash(&c);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &c);
        chain[0] = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: c,
            signatures: vec![operator],
            transparency: vec![],
        };
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 0);
                assert!(detail.contains("prev_receipt_hash"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    /// GOLDEN: a fixed two-receipt zero-seed chain produces a byte-stable
    /// genesis link hash. Pinned so any drift in the chain-link rule (domain tag,
    /// length-prefix layout, field order) is a loud, deliberate change.
    #[test]
    fn golden_genesis_link_hash_is_byte_stable() {
        let genesis = chained_receipt("sess-golden", 0, None);
        let link = link_hash(&genesis.content);
        assert_eq!(link.len(), 64);
        assert_eq!(
            link,
            "8dfc58fd55076aeeffea330e3c8259e98d7cf8fa09e6e85150358edc2122eda9",
            "genesis link hash drifted (regenerate the golden vector intentionally)"
        );
    }

    /// L1 (approver-cosigned) receipts chain exactly like L0 ones — the chain
    /// check delegates the per-receipt crypto to open_receipt, which handles both.
    #[test]
    fn l1_receipts_chain() {
        const APPROVER_SEED: [u8; 32] = [5u8; 32];
        let session = "s-l1";
        let mut g = fixed_content();
        g.policy.decision_path = crate::receipt::GateDecision::RequireApproval;
        g.approver_decision = Some(crate::receipt::ApproverRecord {
            decision: crate::receipt::ApproverDecision::Approved,
            approver_identity: heso_core::IdentityKey::from_bytes(&APPROVER_SEED).public_key_b64(),
            reason: "ok".into(),
            decided_at: "2026-05-29T12:05:00Z".into(),
            sla_minutes: Some(30),
        });
        g.trust_level = TrustLevel::L1;
        bind_into_chain(&mut g, session, None);
        g.action_hash = action_content_hash(&g);
        let g_op = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &g);
        let g_ap = sign_entry(&APPROVER_SEED, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, &g);
        let genesis = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: g,
            signatures: vec![g_op, g_ap],
            transparency: vec![],
        };
        let chain = vec![genesis];
        assert!(matches!(
            verify_action_receipt_chain(&chain),
            ChainOutcome::Valid { length: 1 }
        ));
    }

    // ========================================================================
    // PHASE 2 — suspend/resume session chain (verify_session_chain)
    // ========================================================================

    use crate::receipt::{
        ApprovalTerms, ContextRef, ContextScheme, GateDecision, OnTimeout, ReceiptKind, SignerRole,
        Suspension, SuspensionPolicy,
    };

    /// A distinct approver seed — its pubkey differs from the operator's, so a
    /// decision it signs is by a DIFFERENT cryptographic authority (the local half
    /// of "the customer cannot self-approve"; the hosted key custody is cloud).
    const APPROVER_SEED: [u8; 32] = [7u8; 32];
    /// A distinct ledger seed (the sweeper/ledger key that signs `expired` /
    /// timeout-`approved`). LOCAL PLACEHOLDER for the cloud ledger key custody.
    const LEDGER_SEED: [u8; 32] = [9u8; 32];

    /// The ONE action descriptor a gated lifecycle shares across its links. Keeping
    /// `verb`/`tool_name`/`workflow`/`account`/`fields` identical across
    /// suspended→approved→completed is what makes their `action_spec_hash` match —
    /// the §6.2 idempotency unit. Only `kind`/`seq`/`prev`/envelope/decision fields
    /// differ per link. A `nonce` carries the per-spec identity so two different
    /// lifecycles in one session get DIFFERENT specs without touching the
    /// descriptor shape.
    fn lifecycle_base(spec_tag: &str) -> ActionContent {
        let mut c = fixed_content();
        c.policy.decision_path = GateDecision::RequireApproval;
        // The action descriptor is the spec identity; tag it via the workflow so
        // distinct lifecycles are distinct specs, but keep it STABLE across one
        // lifecycle's links.
        c.action.workflow = format!("wf-{spec_tag}");
        c.trust_level = TrustLevel::L0;
        c
    }

    /// Stamp the chain block (`seq`/`prev`/`action_hash` derived from `prev` via
    /// [`bind_into_chain`]) and producer-sign `content` under `domain` with the
    /// operator key (the producer role).
    fn producer_link(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        domain: &[u8],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let producer = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, domain, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![producer],
            transparency: vec![],
        }
    }

    /// Stamp + DECISION-sign `content` under `SIGNING_DOMAIN_DECISION` with
    /// `decision_seed` (an approver/ledger key, NOT the operator key). The role tag
    /// is `"approver"` so it is structurally distinguishable; the verifier keys on
    /// the verifying DOMAIN + key, not the tag.
    fn decision_link(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        decision_seed: &[u8; 32],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let decider = sign_entry(
            decision_seed,
            APPROVER_KEY_ID,
            SIGNING_DOMAIN_DECISION,
            &content,
        );
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![decider],
            transparency: vec![],
        }
    }

    /// A representative suspension envelope for a `suspended` link.
    fn envelope() -> Suspension {
        Suspension {
            resume_token_hash: "a".repeat(64),
            context_ref: ContextRef {
                scheme: ContextScheme::Customer,
                key: "sess".into(),
                hash: "b".repeat(64),
            },
            tool_binding_hash: Some("c".repeat(64)),
            policy: SuspensionPolicy {
                policy_id: "pol".into(),
                policy_hash: "d".repeat(64),
                rule: "amount_usd > 100000".into(),
            },
            approval: ApprovalTerms {
                sla: "2d".into(),
                expires_at: "2026-06-04T18:00:00Z".into(),
                on_timeout: OnTimeout::Deny,
                approver_pubkeys: vec!["ed25519:appr".into()],
                escalation: None,
            },
        }
    }

    /// Build the gated 3-step happy path for ONE spec, linked from `prev` (its
    /// seqs follow `prev` via [`bind_into_chain`]). Returns the three receipts so
    /// callers can splice them into a longer session chain.
    fn gated_lifecycle(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
    ) -> Vec<ActionReceipt> {
        // suspended@N (producer, SUSPEND domain)
        let mut s = lifecycle_base(spec_tag);
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, session, prev, SIGNING_DOMAIN_SUSPEND);

        // approved@N+1 (decision, DECISION domain, approver key)
        let mut a = lifecycle_base(spec_tag);
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, session, Some(&suspended.content), &APPROVER_SEED);

        // completed@N+2 (producer, ACTION domain)
        let mut c = lifecycle_base(spec_tag);
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link(c, session, Some(&approved.content), ACTION_SIGNING_DOMAIN);

        vec![suspended, approved, completed]
    }

    // ---- (a) ROLE BINDING --------------------------------------------------

    #[test]
    fn gated_three_seq_happy_path_verifies() {
        let chain = gated_lifecycle("sess", "pay", None);
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// THE adversarial role test (§8.A(f)): a `approved` receipt that is
    /// PRODUCER-signed (operator key, under the producer/action path) MUST verify
    /// INVALID — a customer cannot approve their own pause.
    #[test]
    fn producer_signed_approved_is_role_violation() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Rebuild the approved link as a PRODUCER signature (operator key) instead
        // of a decision signature. Sign it under the ACTION domain with the
        // operator key — the self-approval shape.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved_forged = producer_link(
            a,
            "sess",
            Some(&chain[0].content),
            ACTION_SIGNING_DOMAIN,
        );
        // Re-link completed onto the forged approved so structure stays intact and
        // the failure is purely the role.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(
            c,
            "sess",
            Some(&approved_forged.content),
            ACTION_SIGNING_DOMAIN,
        );
        let forged = vec![chain[0].clone(), approved_forged, completed];
        match verify_session_chain(&forged) {
            ChainOutcome::RoleViolation { seq, kind, required, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(kind, ReceiptKind::Approved);
                assert_eq!(required, SignerRole::Decision);
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    /// A decision receipt signed by the SAME key that also carries a producer
    /// (operator) action signature on the same receipt is a self-approval — even
    /// though the decision bytes verify under the decision domain.
    #[test]
    fn decision_signed_by_reused_operator_key_is_role_violation() {
        let chain = gated_lifecycle("sess", "pay", None);
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        bind_into_chain(&mut a, "sess", Some(&chain[0].content));
        a.action_hash = action_content_hash(&a);
        // Two entries by the SAME (operator) key: one decision-domain, one
        // action-domain. The decision verifies, but the same key also produced an
        // action authorization → self-approval.
        let decision = sign_entry(&OPERATOR_SEED, APPROVER_KEY_ID, SIGNING_DOMAIN_DECISION, &a);
        let producer = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &a);
        let approved = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: a,
            signatures: vec![decision, producer],
            transparency: vec![],
        };
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);
        let forged = vec![chain[0].clone(), approved, completed];
        match verify_session_chain(&forged) {
            ChainOutcome::RoleViolation { seq, kind, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(kind, ReceiptKind::Approved);
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    /// A correctly SUSPEND-domain-signed `suspended` link verifies STANDALONE via
    /// the public [`open_lifecycle_receipt`] — but FAILS `open_receipt` with
    /// `InvalidSignature` (which only accepts ACTION-domain operator entries).
    /// Pins why the kind-aware verifier is the public per-receipt entry point for
    /// a single pushed lifecycle link (the cloud receipt-push gate).
    #[test]
    fn suspended_link_verifies_standalone_via_open_lifecycle_receipt() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        assert!(open_lifecycle_receipt(&suspended).is_ok());
        assert!(matches!(
            crate::verify::open_receipt(&suspended),
            ActionOutcome::InvalidSignature(_)
        ));
    }

    /// A `suspended` signed under the plain ACTION domain (not SUSPEND) does not
    /// verify under its required domain → ContentTamper (the producer-suspend
    /// binding is enforced).
    #[test]
    fn suspended_signed_under_action_domain_fails() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        // Wrong domain: ACTION instead of SUSPEND.
        let suspended = producer_link(s, "sess", None, ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended]) {
            ChainOutcome::ContentTamper { seq, .. } => assert_eq!(seq, 0),
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    /// A tampered content byte on a lifecycle receipt is ContentTamper
    /// (HashMismatch), exactly like the standalone verifier.
    #[test]
    fn tampered_lifecycle_content_is_content_tamper() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        chain[0].content.action.account = "acct_evil".into();
        match verify_session_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 0);
                assert!(matches!(reason, ActionOutcome::HashMismatch));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    /// A forged decision signature (bit-flipped) verifies under NO domain → the
    /// decision link is rejected.
    #[test]
    fn forged_decision_signature_is_rejected() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        let mut raw = B64.decode(chain[1].signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        chain[1].signatures[0].signature = B64.encode(&raw);
        match verify_session_chain(&chain) {
            ChainOutcome::ContentTamper { seq, .. } | ChainOutcome::RoleViolation { seq, .. } => {
                assert_eq!(seq, 1)
            }
            other => panic!("expected a rejection at seq 1, got {other:?}"),
        }
    }

    /// REPLAY SAFETY (design §8.A / security M5): a decision signature minted in
    /// session A cannot be transplanted into session B. The decision signs over
    /// [`action_canonical_bytes`], which includes `session_id` / `seq` /
    /// `prev_receipt_hash` (the chain block is signed content), so the same
    /// approver signature presented over a session-B body — which carries a
    /// DIFFERENT `session_id` and `prev_receipt_hash` — no longer verifies under
    /// [`SIGNING_DOMAIN_DECISION`]. The link then has no valid decision signature,
    /// so the session verifier rejects it (a Decision-role kind with only a
    /// non-verifying signature is fail-closed, never `Valid`). This is the
    /// cross-session transplant the design forbids: "approver decided in A" cannot
    /// be replayed as "approver decided in B".
    #[test]
    fn decision_signature_from_session_a_is_rejected_in_session_b() {
        // Session A: a legitimate gated lifecycle. chain_a[1] is an `approved`
        // decision the approver really signed over A's {session_id:"sess_a", seq:1,
        // prev=H(suspended_a)} canonical body.
        let chain_a = gated_lifecycle("sess_a", "pay", None);
        let stolen_sig = chain_a[1].signatures[0].clone();
        assert!(
            matches!(verify_session_chain(&chain_a), ChainOutcome::Valid { .. }),
            "session A must verify on its own first"
        );

        // Session B: its own genesis suspended@0 (producer, SUSPEND domain).
        let mut s_b = lifecycle_base("pay");
        s_b.kind = Some(ReceiptKind::Suspended);
        s_b.suspension = Some(envelope());
        let suspended_b = producer_link(s_b, "sess_b", None, SIGNING_DOMAIN_SUSPEND);

        // Build B's approved@1 body (session_id:"sess_b", prev=H(suspended_b)) but
        // staple session A's stolen decision SIGNATURE onto it instead of decision-
        // signing it in B. The signature is byte-for-byte the one the approver
        // produced in A.
        let mut a_b = lifecycle_base("pay");
        a_b.kind = Some(ReceiptKind::Approved);
        bind_into_chain(&mut a_b, "sess_b", Some(&suspended_b.content));
        a_b.action_hash = action_content_hash(&a_b);
        let approved_b_replayed = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: a_b,
            signatures: vec![stolen_sig],
            transparency: vec![],
        };

        let forged = vec![suspended_b, approved_b_replayed];
        // The stolen signature does NOT verify over B's body (different session_id +
        // prev_receipt_hash), so the decision link is rejected fail-closed.
        match verify_session_chain(&forged) {
            ChainOutcome::ContentTamper { seq, .. } | ChainOutcome::RoleViolation { seq, .. } => {
                assert_eq!(seq, 1, "the replayed decision at seq 1 must be rejected");
            }
            other => panic!("a cross-session replayed decision must be rejected, got {other:?}"),
        }
    }

    /// The dual of the replay test: transplanting the WHOLE session-A `approved`
    /// receipt (its original `session_id:"sess_a"` body AND signature, unmodified)
    /// into session B is caught by the structural pass — `session_id` changed
    /// mid-chain — even though A's decision signature is itself perfectly valid.
    /// Neither transplant shape can smuggle an A decision into B.
    #[test]
    fn whole_decision_receipt_from_session_a_is_rejected_in_session_b() {
        let chain_a = gated_lifecycle("sess_a", "pay", None);
        let approved_a = chain_a[1].clone(); // intact A body+sig, session_id:"sess_a", seq 1

        let mut s_b = lifecycle_base("pay");
        s_b.kind = Some(ReceiptKind::Suspended);
        s_b.suspension = Some(envelope());
        let suspended_b = producer_link(s_b, "sess_b", None, SIGNING_DOMAIN_SUSPEND);

        // Splice A's approved@1 (still says session_id "sess_a") after B's genesis.
        let forged = vec![suspended_b, approved_a];
        match verify_session_chain(&forged) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(
                    detail.contains("session_id changed mid-chain"),
                    "expected a session-change link break, got: {detail}"
                );
            }
            other => panic!("a foreign-session decision must break the chain, got {other:?}"),
        }
    }

    /// The E2E shape proof: a real gated 3-seq lifecycle
    /// (`suspended → approved → completed`) is `Valid` under the LIFECYCLE verifier
    /// [`verify_session_chain`], and the PRE-LIFECYCLE
    /// [`verify_action_receipt_chain`] correctly REJECTS it — because that verifier
    /// only knows the operator/approver roles under ACTION/APPROVAL domains, so the
    /// SUSPEND-domain `suspended` link fails its per-receipt `open_receipt` gate
    /// (`ContentTamper`). This pins WHICH verifier is the source of truth for the
    /// gated shape: a suspend/resume chain MUST be validated with
    /// `verify_session_chain`, not the standalone integrity verifier. (The fast
    /// `action`/`action→completed` shape — all ACTION-domain — is the only gated-
    /// adjacent shape the pre-lifecycle verifier accepts; see
    /// `fast_*_verifies`.)
    #[test]
    fn gated_three_seq_is_session_valid_and_pre_lifecycle_rejects_suspend_domain() {
        let chain = gated_lifecycle("sess", "pay", None);
        assert!(
            matches!(verify_session_chain(&chain), ChainOutcome::Valid { length: 3 }),
            "the lifecycle verifier accepts the gated 3-seq shape"
        );
        // The pre-lifecycle verifier runs open_receipt per link; the SUSPEND-domain
        // genesis is not an operator-ACTION authorization, so it is ContentTamper at
        // seq 0 — fail closed, never a false Valid.
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, .. } => assert_eq!(seq, 0),
            other => panic!(
                "verify_action_receipt_chain must NOT validate a suspend/decision \
                 chain; got {other:?}"
            ),
        }
    }

    // ---- (b) LEGAL TRANSITION GRAPH ----------------------------------------

    /// Fast allow path, single `completed` receipt (1 seq, no suspended).
    #[test]
    fn fast_single_completed_verifies() {
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", None, ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// Fast allow path, `action → completed` (2 seq, no suspended). A plain
    /// `action` carries kind=None (byte-stable default).
    #[test]
    fn fast_action_then_completed_verifies() {
        let mut a = lifecycle_base("pay");
        a.kind = None; // the byte-stable Action default
        let action = producer_link(a, "sess", None, ACTION_SIGNING_DOMAIN);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&action.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[action, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A `completed` directly after `suspended` with NO `approved` is illegal — a
    /// gated action must be approved before it fires.
    #[test]
    fn completed_after_suspended_without_approval_is_illegal() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&suspended.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended, completed]) {
            ChainOutcome::IllegalTransition { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("no `approved`"), "got: {detail}");
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    /// An `approved` with no preceding `suspended` (first receipt for its spec) is
    /// illegal — there is nothing to decide on.
    #[test]
    fn approved_with_no_suspended_is_illegal() {
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", None, &APPROVER_SEED);
        // genesis with a decision kind — but genesis structure is fine; the
        // transition graph rejects it.
        match verify_session_chain(&[approved]) {
            ChainOutcome::IllegalTransition { seq, .. } => assert_eq!(seq, 0),
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    /// A gated `suspended → denied` (terminal deny) verifies.
    #[test]
    fn suspended_then_denied_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut d = lifecycle_base("pay");
        d.kind = Some(ReceiptKind::Denied);
        let denied = decision_link(d, "sess", Some(&suspended.content), &APPROVER_SEED);
        match verify_session_chain(&[suspended, denied]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A gated `suspended → expired` (ledger-signed timeout terminal) verifies.
    #[test]
    fn suspended_then_expired_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Expired);
        let expired = decision_link(e, "sess", Some(&suspended.content), &LEDGER_SEED);
        match verify_session_chain(&[suspended, expired]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A gated `suspended → escalated → approved → completed` verifies — escalated
    /// is a non-terminal transition.
    #[test]
    fn suspended_escalated_approved_completed_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Escalated);
        let escalated = decision_link(e, "sess", Some(&suspended.content), &APPROVER_SEED);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&escalated.content), &LEDGER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        match verify_session_chain(&[suspended, escalated, approved, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// Two DISTINCT gated lifecycles (different specs) interleaved in one session
    /// chain verify — the idempotency unit is the spec, not seq.
    #[test]
    fn two_distinct_specs_in_one_session_verify() {
        let first = gated_lifecycle("sess", "pay", None);
        let second = gated_lifecycle("sess", "wire", Some(&first[2].content));
        let chain: Vec<ActionReceipt> = first.into_iter().chain(second).collect();
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 6),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    // ---- (c) SINGLE-TERMINAL RULE ------------------------------------------

    /// A second terminal for one suspended spec is rejected — first terminal wins.
    /// Here: `suspended → approved → completed`, then a second `completed` for the
    /// SAME spec.
    #[test]
    fn double_terminal_completed_is_rejected() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        // Append a SECOND completed for the same spec, linked correctly.
        let mut c2 = lifecycle_base("pay");
        c2.kind = Some(ReceiptKind::Completed);
        let completed2 = producer_link(c2, "sess", Some(&chain[2].content), ACTION_SIGNING_DOMAIN);
        chain.push(completed2);
        match verify_session_chain(&chain) {
            ChainOutcome::DoubleTerminal { seq, first, second } => {
                assert_eq!(seq, 3);
                assert_eq!(first, ReceiptKind::Completed);
                assert_eq!(second, ReceiptKind::Completed);
            }
            other => panic!("expected DoubleTerminal, got {other:?}"),
        }
    }

    /// An approval RACING a deadline: `suspended → expired` (terminal), then a late
    /// `approved`/`completed` for the same spec. The late terminal (`completed`) is
    /// a DoubleTerminal; a late non-terminal `approved` is an IllegalTransition
    /// after a terminal. Test the terminal-after-terminal (expired then completed).
    #[test]
    fn approval_racing_expired_deadline_is_rejected() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Expired);
        let expired = decision_link(e, "sess", Some(&suspended.content), &LEDGER_SEED);

        // A late approval lands AFTER the expired terminal.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&expired.content), &APPROVER_SEED);

        match verify_session_chain(&[suspended, expired, approved]) {
            ChainOutcome::IllegalTransition { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("terminal"), "got: {detail}");
            }
            other => panic!("expected IllegalTransition after terminal, got {other:?}"),
        }
    }

    /// `denied` then a late `completed` for the same spec → DoubleTerminal (two
    /// terminals).
    #[test]
    fn denied_then_completed_is_double_terminal() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut d = lifecycle_base("pay");
        d.kind = Some(ReceiptKind::Denied);
        let denied = decision_link(d, "sess", Some(&suspended.content), &APPROVER_SEED);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&denied.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended, denied, completed]) {
            ChainOutcome::DoubleTerminal { seq, first, second } => {
                assert_eq!(seq, 2);
                assert_eq!(first, ReceiptKind::Denied);
                assert_eq!(second, ReceiptKind::Completed);
            }
            other => panic!("expected DoubleTerminal, got {other:?}"),
        }
    }

    // ---- (d) TIME-AGNOSTIC --------------------------------------------------

    /// A long WALL-CLOCK gap between suspend and approval MUST NOT read as a drop:
    /// integrity is seq contiguity + linkage + signature + role only. We set the
    /// approval's informational `captured_at` years after the suspend and confirm
    /// the chain still verifies Valid (no time predicate anywhere).
    #[test]
    fn long_wall_clock_gap_is_not_a_drop() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        s.captured_at = "2026-06-01T00:00:00Z".into();
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        // Decided 5 years later — still just data, never an integrity input.
        a.captured_at = "2031-06-01T00:00:00Z".into();
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        c.captured_at = "2031-06-01T00:05:00Z".into();
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        match verify_session_chain(&[suspended, approved, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid despite the multi-year gap, got {other:?}"),
        }
    }

    /// An expired `expires_at` in the PAST does NOT make a still-non-terminal chain
    /// fail — timeouts are a policy eval over content, never an integrity predicate.
    /// A `suspended` whose envelope `expires_at` is long past, with no terminal,
    /// still verifies as a valid (open) chain.
    #[test]
    fn past_expires_at_with_no_terminal_still_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        let mut env = envelope();
        env.approval.expires_at = "2000-01-01T00:00:00Z".into(); // long past
        s.suspension = Some(env);
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        match verify_session_chain(&[suspended]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid (a past deadline is not an integrity failure), got {other:?}"),
        }
    }

    // ---- structural integrity still applies in the session verifier --------

    /// A dropped link in a session chain is still LinkBroken (the structural pass
    /// is shared, and time-agnostic).
    #[test]
    fn dropped_link_in_session_chain_is_link_broken() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Drop the middle (approved@1): seq jumps 0 -> 2.
        let pruned = vec![chain[0].clone(), chain[2].clone()];
        match verify_session_chain(&pruned) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    /// An empty session chain is Empty, not Valid (fail closed).
    #[test]
    fn empty_session_chain_is_empty() {
        assert!(matches!(verify_session_chain(&[]), ChainOutcome::Empty));
    }

    /// The action-spec hash is STABLE across a gated lifecycle's links (so they
    /// group together) yet DIFFERS between distinct specs — the property the
    /// transition graph relies on.
    #[test]
    fn action_spec_hash_is_stable_within_a_lifecycle_and_distinct_across() {
        let chain = gated_lifecycle("sess", "pay", None);
        let h0 = action_spec_hash(&chain[0].content);
        let h1 = action_spec_hash(&chain[1].content);
        let h2 = action_spec_hash(&chain[2].content);
        assert_eq!(h0, h1, "suspended and approved share one spec");
        assert_eq!(h1, h2, "approved and completed share one spec");
        let other = gated_lifecycle("sess", "wire", None);
        assert_ne!(
            h0,
            action_spec_hash(&other[0].content),
            "distinct specs must hash differently"
        );
        // It is NOT the per-receipt self-hash (those differ across links).
        assert_ne!(chain[0].content.action_hash, chain[1].content.action_hash);
    }

    /// A `key_rotation` receipt is lifecycle-neutral: it role-binds as a producer
    /// and does not disturb a co-located gated lifecycle.
    #[test]
    fn key_rotation_is_lifecycle_neutral() {
        // genesis: a key_rotation (producer, ACTION domain), then a fresh gated
        // lifecycle for a spec.
        let mut k = lifecycle_base("rotate");
        k.kind = Some(ReceiptKind::KeyRotation);
        let rotation = producer_link(k, "sess", None, ACTION_SIGNING_DOMAIN);
        let life = gated_lifecycle("sess", "pay", Some(&rotation.content));
        let chain: Vec<ActionReceipt> = std::iter::once(rotation).chain(life).collect();
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    // ========================================================================
    // PHASE 6 — key rotation across a multi-day pause
    // (verify_session_chain_with_rotation, design §8.A, security B3)
    // ========================================================================

    use crate::receipt::KeyRotation;

    /// A second operator seed — the INCOMING producer key after a producer
    /// rotation. Its pubkey differs from `OPERATOR_SEED`'s.
    const OPERATOR_SEED_2: [u8; 32] = [1u8; 32];

    /// A second approver seed — the INCOMING decision key after a decision
    /// rotation. LOCAL PLACEHOLDER for the cloud approver key custody.
    const APPROVER_SEED_2: [u8; 32] = [8u8; 32];

    fn pubkey_of(seed: &[u8; 32]) -> String {
        heso_core::IdentityKey::from_bytes(seed).public_key_b64()
    }

    /// Stamp the chain block and PRODUCER-sign `content` under `domain` with an
    /// arbitrary `seed` (so a producer link can be signed by the old OR the new
    /// operator key — the rotation case the fixed-seed `producer_link` cannot
    /// express).
    fn producer_link_seed(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        domain: &[u8],
        seed: &[u8; 32],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let producer = sign_entry(seed, OPERATOR_KEY_ID, domain, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![producer],
            transparency: vec![],
        }
    }

    /// Build a producer-role `key_rotation` link signed by `outgoing_seed` (the
    /// retiring operator key) that installs `incoming_seed`'s pubkey.
    fn producer_rotation(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
        outgoing_seed: &[u8; 32],
        incoming_seed: &[u8; 32],
    ) -> ActionReceipt {
        let mut k = lifecycle_base(spec_tag);
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Producer,
            outgoing_public_key: pubkey_of(outgoing_seed),
            incoming_public_key: pubkey_of(incoming_seed),
        });
        producer_link_seed(k, session, prev, ACTION_SIGNING_DOMAIN, outgoing_seed)
    }

    /// Build a decision-role `key_rotation` link signed by `outgoing_seed` (the
    /// retiring approver/ledger key) that installs `incoming_seed`'s pubkey. A
    /// decision rotation is DECISION-domain signed (the outgoing decision key
    /// authorizes its own replacement).
    fn decision_rotation(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
        outgoing_seed: &[u8; 32],
        incoming_seed: &[u8; 32],
    ) -> ActionReceipt {
        let mut k = lifecycle_base(spec_tag);
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Decision,
            outgoing_public_key: pubkey_of(outgoing_seed),
            incoming_public_key: pubkey_of(incoming_seed),
        });
        decision_link(k, session, prev, outgoing_seed)
    }

    /// The TOFU registry root for the standard operator + approver seeds.
    fn root_registry() -> KeyRegistry {
        KeyRegistry::from_roots(&pubkey_of(&OPERATOR_SEED), Some(&pubkey_of(&APPROVER_SEED)))
    }

    /// Baseline: the gated happy path verifies with rotation enabled when the
    /// registry root names the keys that actually signed and there is NO rotation.
    #[test]
    fn rotation_verifier_accepts_unrotated_gated_chain() {
        let chain = gated_lifecycle("sess", "pay", None);
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// THE headline scenario (security B3): the PRODUCER key is rotated DURING a
    /// pause. `suspended@0` is signed by the OLD operator; `key_rotation@1` (signed
    /// by the old operator) installs the new operator; `approved@2` is the
    /// approver's decision; `completed@3` is signed by the NEW operator. The
    /// earlier `suspended` still verifies under the key valid at its position, and
    /// the `completed` verifies under the rotated-in key. TOFU pinned only the
    /// ROOT.
    #[test]
    fn producer_key_rotated_mid_pause_still_verifies() {
        // suspended@0 — old operator, SUSPEND domain.
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link_seed(s, "sess", None, SIGNING_DOMAIN_SUSPEND, &OPERATOR_SEED);

        // key_rotation@1 — signed by the OUTGOING (old) operator, installs new.
        let rotation =
            producer_rotation("sess", "rotate", Some(&suspended.content), &OPERATOR_SEED, &OPERATOR_SEED_2);

        // approved@2 — the approver decision (unaffected by the producer rotation).
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED);

        // completed@3 — signed by the NEW operator key.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid across a producer rotation, got {other:?}"),
        }
    }

    /// The APPROVER (decision) key is rotated mid-pause: the EARLIER `approved`
    /// receipt was signed by the OLD approver and MUST still verify under the key
    /// valid at its position, even though a later `key_rotation` retired it. Shape:
    /// `suspended@0` → `approved@1` (OLD approver) → `key_rotation@2` (decision
    /// role, signed by old approver) → `completed@3` (producer). The completed is
    /// the terminal; the rotation just advances the decision registry for any
    /// FUTURE decision.
    #[test]
    fn approver_key_rotated_after_approval_still_verifies_earlier_approval() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        // approved@1 — OLD approver key (the registry root decision key).
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        // key_rotation@2 — decision-role, signed by the OUTGOING (old) approver,
        // installs the new approver. Lifecycle-neutral (does not touch the spec).
        let rotation =
            decision_rotation("sess", "rotate", Some(&approved.content), &APPROVER_SEED, &APPROVER_SEED_2);

        // completed@3 — producer fires after approval.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&rotation.content), ACTION_SIGNING_DOMAIN);

        let chain = vec![suspended, approved, rotation, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid: earlier approval under the old key, got {other:?}"),
        }
    }

    /// A DECISION key rotated BEFORE the approval: `suspended@0` →
    /// `key_rotation@1` (decision role, old approver signs) → `approved@2` (the NEW
    /// approver) → `completed@3`. The approval is by the rotated-IN decision key.
    #[test]
    fn decision_rotation_then_approval_by_new_key_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let rotation =
            decision_rotation("sess", "rotate", Some(&suspended.content), &APPROVER_SEED, &APPROVER_SEED_2);

        // approved@2 — by the NEW approver key.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED_2);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid: approval by the rotated-in key, got {other:?}"),
        }
    }

    /// A completed signed by the NEW operator key WITHOUT a preceding
    /// `key_rotation` is rejected: the new key was never installed, so it is not
    /// valid at its position even though its bytes verify under the ACTION domain.
    #[test]
    fn unrotated_new_key_signer_is_rejected() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        // completed@2 — signed by OPERATOR_SEED_2, but no rotation ever installed it.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, detail } => {
                assert_eq!(seq, 2);
                assert_eq!(role, SignerRole::Producer);
                assert!(detail.contains("not the one valid"), "got: {detail}");
            }
            other => panic!("expected KeyNotValidAtPosition for the foreign key, got {other:?}"),
        }
    }

    /// After a producer rotation, a receipt signed by the OLD (now-retired)
    /// operator key is rejected at its position — the key's validity window closed
    /// at the rotation seq.
    #[test]
    fn retired_key_signing_after_its_rotation_is_rejected() {
        // suspended@0 (old op) → key_rotation@1 (old op installs new) →
        // completed@2 signed AGAIN by the OLD op (illegal: retired at seq 1).
        let mut s = lifecycle_base("pay");
        s.kind = None; // a fast action genesis (no suspension envelope needed)
        let action = producer_link_seed(s, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let rotation =
            producer_rotation("sess", "rotate", Some(&action.content), &OPERATOR_SEED, &OPERATOR_SEED_2);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&rotation.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let chain = vec![action, rotation, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 2);
                assert_eq!(role, SignerRole::Producer);
            }
            other => panic!("expected the retired key to be rejected at seq 2, got {other:?}"),
        }
    }

    /// A FORGED rotation: a `key_rotation` signed by a key that is NOT the role's
    /// current registry key (here the NEW operator tries to rotate itself in before
    /// being installed) is rejected — the signer is not valid at its position.
    #[test]
    fn rotation_signed_by_non_current_key_is_rejected() {
        // genesis fast action by the real operator, then a rotation that CLAIMS to
        // retire the new key but is signed by the new key — which is not current.
        let mut g = lifecycle_base("pay");
        g.kind = None;
        let action = producer_link_seed(g, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        // Rotation names outgoing = OPERATOR_SEED_2 and is signed by OPERATOR_SEED_2,
        // but the current producer key is OPERATOR_SEED — so the signer is not valid
        // at this position.
        let rotation = producer_rotation(
            "sess",
            "rotate",
            Some(&action.content),
            &OPERATOR_SEED_2,
            &OPERATOR_SEED_2,
        );

        let chain = vec![action, rotation];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(role, SignerRole::Producer);
            }
            other => panic!("expected the forged rotation to be rejected, got {other:?}"),
        }
    }

    /// A rotation whose named `outgoing_public_key` does NOT match its actual
    /// signer is rejected even though the signer IS the current key — the receipt
    /// must honestly name the key it retires (the signed payload and the signature
    /// must agree).
    #[test]
    fn rotation_naming_wrong_outgoing_key_is_rejected() {
        let mut g = lifecycle_base("pay");
        g.kind = None;
        let action = producer_link_seed(g, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        // Build a rotation signed by the current operator (OPERATOR_SEED) but whose
        // payload claims to retire a DIFFERENT key.
        let mut k = lifecycle_base("rotate");
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Producer,
            outgoing_public_key: pubkey_of(&APPROVER_SEED), // wrong: not the signer
            incoming_public_key: pubkey_of(&OPERATOR_SEED_2),
        });
        let rotation =
            producer_link_seed(k, "sess", Some(&action.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let chain = vec![action, rotation];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, detail, .. } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("names outgoing key"), "got: {detail}");
            }
            other => panic!("expected the mismatched outgoing key to be rejected, got {other:?}"),
        }
    }

    /// A decision receipt on a session whose registry root has NO decision key
    /// fails closed (KeyNotValidAtPosition), never fail-open — the empty-allowlist
    /// discipline (design Minor-7) at the LOCAL layer.
    #[test]
    fn decision_with_no_registered_decision_key_fails_closed() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Root with a producer key but NO decision key.
        let registry = KeyRegistry::from_roots(&pubkey_of(&OPERATOR_SEED), None);
        match verify_session_chain_with_rotation(&chain, registry) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 1); // the approved@1 decision
                assert_eq!(role, SignerRole::Decision);
            }
            other => panic!("expected fail-closed with no decision key, got {other:?}"),
        }
    }

    /// The rotation pass is POSITION-based, never wall-clock: a producer rotation
    /// across a multi-YEAR `captured_at` gap still verifies. The pause length is
    /// invisible to the as-of-position check (§6.5).
    #[test]
    fn rotation_across_multi_year_gap_is_time_agnostic() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        s.captured_at = "2026-06-01T00:00:00Z".into();
        let suspended = producer_link_seed(s, "sess", None, SIGNING_DOMAIN_SUSPEND, &OPERATOR_SEED);

        let mut rotation = producer_rotation(
            "sess",
            "rotate",
            Some(&suspended.content),
            &OPERATOR_SEED,
            &OPERATOR_SEED_2,
        );
        // (re-stamp captured_at far in the future and re-sign so the link stays
        // intact)
        rotation.content.captured_at = "2030-01-01T00:00:00Z".into();
        rotation.content.action_hash = action_content_hash(&rotation.content);
        rotation.signatures =
            vec![sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &rotation.content)];

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        a.captured_at = "2031-06-01T00:00:00Z".into();
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        c.captured_at = "2031-06-01T00:05:00Z".into();
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid despite the multi-year gap, got {other:?}"),
        }
    }

    /// `valid_from`/`valid_until` on a SignatureEntry are byte-free when absent: a
    /// receipt whose entries omit them serializes identically to the pre-Phase-6
    /// shape, and adding them never touches `action_hash` (signatures are outside
    /// the signed content). Proves the byte-stability requirement.
    #[test]
    fn signature_entry_windows_are_byte_free_when_absent() {
        let chain = gated_lifecycle("sess", "pay", None);
        let entry = &chain[0].signatures[0];
        let json = serde_json::to_value(entry).unwrap();
        assert!(json.get("valid_from").is_none(), "valid_from leaked into the wire");
        assert!(json.get("valid_until").is_none(), "valid_until leaked into the wire");
        // The signed content hash is unchanged by the (absent) window fields.
        assert_eq!(
            chain[0].content.action_hash,
            action_content_hash(&chain[0].content)
        );
    }

    /// A populated `valid_from`/`valid_until` round-trips and STILL does not change
    /// `action_hash` — the windows live outside `action_canonical_bytes`, so they
    /// are audit metadata only, never an integrity input (design §6.5).
    #[test]
    fn signature_entry_windows_round_trip_without_touching_action_hash() {
        let chain = gated_lifecycle("sess", "pay", None);
        let before = chain[0].content.action_hash.clone();
        let mut receipt = chain[0].clone();
        receipt.signatures[0].valid_from = Some("2026-06-01T00:00:00Z".into());
        receipt.signatures[0].valid_until = Some("2026-12-31T23:59:59Z".into());
        // action_hash is over content only; signature metadata cannot move it.
        assert_eq!(receipt.content.action_hash, before);
        let round: ActionReceipt =
            serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap();
        assert_eq!(round.signatures[0].valid_from.as_deref(), Some("2026-06-01T00:00:00Z"));
        assert_eq!(round.signatures[0].valid_until.as_deref(), Some("2026-12-31T23:59:59Z"));
        // And it still verifies (the entry's bytes that the signature covers are
        // unchanged; the windows are not signed).
        match verify_session_chain_with_rotation(
            &[round, chain[1].clone(), chain[2].clone()],
            root_registry(),
        ) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid with windows populated, got {other:?}"),
        }
    }

    /// `key_rotation: None` is byte-free on the standalone path: a plain action
    /// receipt with no rotation payload omits the key entirely, so adding the field
    /// costs zero canonical bytes (the standalone-path byte-stability requirement).
    #[test]
    fn key_rotation_none_is_byte_free_on_the_wire() {
        let c = fixed_content();
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("key_rotation").is_none(), "key_rotation leaked into the standalone wire");
    }
}

// ============================================================================
// RT-5 (BLOCKER): a POPULATED two-stage `transparency[]` rides through
// open_receipt, the chain verifiers, and the JCS export round-trip WITHOUT
// touching `action_hash` / signatures. The merge-at-export safety claim rests on
// this — zero prior tests exercised a non-empty `transparency[]`.
// ============================================================================

#[cfg(test)]
mod transparency_blocker_tests {
    use super::*;
    use crate::domain::{ACTION_ENVELOPE_ALG, ACTION_SIGNING_DOMAIN, OPERATOR_KEY_ID};
    use crate::receipt::fixtures::fixed_content;
    use crate::receipt::{
        action_canonical_bytes, action_content_hash, ActionContent, ActionReceipt, SignatureEntry,
        TransparencyProof, TrustLevel,
    };
    use crate::transparency::{leaf_value_from_action_hash, merkle_tree_hash, top_leaf_value, HASH_LEN};
    use crate::verify::{open_receipt, ActionOutcome};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    const OPERATOR_SEED: [u8; 32] = [0u8; 32];
    const LOG_SEED: [u8; 32] = [7u8; 32];

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

    /// A real single-leaf two-stage proof over a receipt's `action_hash`.
    fn proof_for(action_hash: &str) -> TransparencyProof {
        let leaf = leaf_value_from_action_hash(action_hash).unwrap();
        let org_root = merkle_tree_hash(&[leaf]);
        let org_id = [3u8; 16];
        let epoch = 5u64;
        let top_leaf = top_leaf_value(&org_id, epoch, &org_root);
        let top_root = merkle_tree_hash(&[top_leaf]);
        let body = format!("log.heso.ca\n1\n{}\n", B64.encode(top_root));
        let key = heso_core::IdentityKey::from_bytes(&LOG_SEED);
        let sig = key.sign(body.as_bytes());
        let sig_raw = B64.decode(sig.signature.as_bytes()).unwrap();
        let kh = crate::transparency::note_key_hash("log.heso.ca", &key.public_key_bytes());
        let mut blob = Vec::new();
        blob.extend_from_slice(&kh);
        blob.extend_from_slice(&sig_raw);
        let checkpoint = format!("{body}\n— log.heso.ca {}", B64.encode(&blob));
        TransparencyProof {
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
        }
    }

    fn chained_with_transparency(session: &str, seq: u64, prev: Option<&ActionContent>) -> ActionReceipt {
        let mut content = fixed_content();
        content.action.workflow = format!("session-{session}-step-{seq}");
        content.trust_level = TrustLevel::L0;
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        let ah = content.action_hash.clone();
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![proof_for(&ah)],
        }
    }

    /// (a) A populated `transparency[]` does NOT change the action_hash or break
    /// the operator signature: open_receipt is still Valid.
    #[test]
    fn populated_transparency_does_not_break_open_receipt() {
        let r = chained_with_transparency("s1", 0, None);
        // Stamping transparency must not have touched the self-hash.
        assert_eq!(r.content.action_hash, action_content_hash(&r.content));
        assert!(matches!(open_receipt(&r), ActionOutcome::Valid(TrustLevel::L0)));
        assert!(!r.transparency.is_empty(), "fixture must populate transparency[]");
    }

    /// (b) A chain whose every receipt carries a populated `transparency[]` still
    /// verifies — transparency is outside the linked content.
    #[test]
    fn chain_with_populated_transparency_verifies() {
        let g = chained_with_transparency("s1", 0, None);
        let r1 = chained_with_transparency("s1", 1, Some(&g.content));
        let r2 = chained_with_transparency("s1", 2, Some(&r1.content));
        let chain = vec![g, r1, r2];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid, got {other:?}"),
        }
        // And the rotation-aware lifecycle verifier accepts it too (a pure
        // ACTION-domain fast chain needs no decision root).
        let producer = heso_core::IdentityKey::from_bytes(&OPERATOR_SEED).public_key_b64();
        let roots = KeyRegistry::from_roots(&producer, None);
        match verify_session_chain_with_rotation(&chain, roots) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected rotation-aware Valid, got {other:?}"),
        }
    }

    /// (c) The JCS export round-trip (serialize → bytes → deserialize) PRESERVES
    /// `transparency[]` exactly and leaves `action_hash` + signatures untouched.
    #[test]
    fn jcs_round_trip_preserves_transparency_and_hash() {
        let r = chained_with_transparency("s1", 0, None);
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: ActionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.transparency, r.transparency, "transparency[] must survive round-trip");
        assert_eq!(back.content.action_hash, r.content.action_hash);
        assert_eq!(back.signatures, r.signatures);
        // The canonical signed bytes are identical with or without transparency:
        // it lives OUTSIDE content.
        let mut stripped = r.clone();
        stripped.transparency.clear();
        assert_eq!(
            action_canonical_bytes(&back.content),
            action_canonical_bytes(&stripped.content),
            "transparency must not enter the canonical signed body"
        );
    }

    /// Sanity: a top-leaf value is stable across two equal calls (the frozen
    /// commitment) — guards the RT-5 proof builder against silent drift.
    #[test]
    fn top_leaf_value_is_deterministic() {
        let org_id = [3u8; 16];
        let root = [0xABu8; HASH_LEN];
        assert_eq!(top_leaf_value(&org_id, 5, &root), top_leaf_value(&org_id, 5, &root));
    }
}
