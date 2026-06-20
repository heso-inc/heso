//! Chain *lifecycle* — the producer-side link primitives that BUILD a chain.
//!
//! This is the write half of cross-receipt chaining: the domain-separated,
//! length-prefixed link digest a successor records, and the helper that stamps a
//! receipt's chain block (`session_id` / `seq` / `prev_receipt_hash`) into place
//! before it is signed. The read half — verifying a chain end-to-end — lives in
//! [`super::verify`]. Both are re-exported from [`super`] so callers use the flat
//! `chain::` path unchanged.
//!
//! ### Why length-prefixed
//!
//! The link input commits to three byte strings: `session_id`, `seq` (LE u64),
//! and `action_hash`. If they were concatenated raw, an attacker could move
//! bytes across the `session_id` / `action_hash` boundary
//! (`"sess" ++ "abc…"` vs `"se" ++ "ssabc…"`) and forge a colliding link to
//! splice a different receipt into the order. Each field is therefore prefixed
//! with its byte length as a LE u64 ([`push_field`]), under the
//! [`RECEIPT_CHAIN_DOMAIN`] separator — so the link digest is an unambiguous,
//! collision-resistant commitment to *(session, position, content)* and the
//! order it implies cannot be forged by field-boundary sliding.

use crate::domain::RECEIPT_CHAIN_DOMAIN;
use crate::receipt::{action_canonical_bytes, ActionContent};

/// Append one length-prefixed field to a link-input buffer: an 8-byte LE length
/// followed by the raw bytes. The length prefix is what makes the concatenation
/// unambiguous (no field-boundary sliding).
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The domain-separated, length-prefixed byte string a receipt's link digest is
/// computed over.
///
/// Layout: `RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le) ++
/// LP(action_hash)`, where `LP(x) = len(x) as u64-le ++ x`. `seq` is encoded as
/// its 8-byte LE value; `session_id` defaults to empty bytes when absent (a
/// standalone receipt has no session). `action_hash` is included as its UTF-8
/// hex bytes — it transitively commits to the entire signed content (it is the
/// BLAKE3 of [`action_canonical_bytes`]), so the link binds *content*, not just
/// position.
pub fn link_input(content: &ActionContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RECEIPT_CHAIN_DOMAIN.len() + 64 + 64);
    buf.extend_from_slice(RECEIPT_CHAIN_DOMAIN);
    let session = content.session_id.as_deref().unwrap_or("");
    push_field(&mut buf, session.as_bytes());
    let seq = content.seq.unwrap_or(0);
    push_field(&mut buf, &seq.to_le_bytes());
    push_field(&mut buf, content.action_hash.as_bytes());
    buf
}

/// The link digest a *successor* receipt records in its `prev_receipt_hash`:
/// lowercase-hex BLAKE3 (64 chars) of [`link_input`].
pub fn link_hash(content: &ActionContent) -> String {
    blake3::hash(&link_input(content)).to_hex().to_string()
}

/// Bind `content` into a chain at the given position by stamping its chain block
/// from its predecessor — a producer helper so the signer does not re-derive the
/// link rule. Sets `session_id`, `seq`, and `prev_receipt_hash` IN PLACE; the
/// caller then (re)computes `action_hash` and signs (the chain block is signed
/// content). For genesis, pass `prev = None` and it stamps `seq = 0` with no
/// `prev_receipt_hash`.
///
/// Note: `action_canonical_bytes` is re-exported here only so producers in
/// sibling crates can locate the exact bytes the link commits to; the binding
/// itself uses [`link_hash`].
pub fn bind_into_chain(content: &mut ActionContent, session_id: &str, prev: Option<&ActionContent>) {
    content.session_id = Some(session_id.to_string());
    match prev {
        None => {
            content.seq = Some(0);
            content.prev_receipt_hash = None;
        }
        Some(prev) => {
            content.seq = Some(prev.seq.unwrap_or(0) + 1);
            content.prev_receipt_hash = Some(link_hash(prev));
        }
    }
    // Touch the re-export so the doc reference is real and the import is used by
    // producers linking against this module.
    let _ = action_canonical_bytes;
}

/// The lifecycle GROUPING key — the action-spec identity that is STABLE across a
/// `suspended → approved → completed` lifecycle (design §6.2's `action_hash =
/// BLAKE3(canonical_json({tool, args, intent} minus volatile))`, the idempotency
/// unit).
///
/// The receipt's own `content.action_hash` field is the per-receipt CONTENT
/// self-hash — it differs across links (each carries a different `kind`/`seq`/
/// `prev_receipt_hash`), so it cannot group a lifecycle. This helper instead
/// hashes only the action DESCRIPTOR — `verb`, fine `domain`/`action` labels,
/// `tool_name`, `target_host`, `workflow`, `account`, and the post-redaction
/// `fields` — which the producer keeps identical across the lifecycle of one
/// gated action. It is COMPUTED, never serialized, so it adds zero wire bytes and
/// does not perturb any golden vector. Domain-separated under
/// [`RECEIPT_CHAIN_DOMAIN`] so the value can never collide with a content hash or
/// a chain-link digest.
///
/// LOCAL note: a hosted ledger enforces `UNIQUE(session_id, action_hash, ...)` on
/// the producer-declared spec hash; here we re-derive it from the signed
/// descriptor so the local verifier needs no extra trusted field.
pub fn action_spec_hash(content: &ActionContent) -> String {
    let a = &content.action;
    let descriptor = serde_json::json!({
        "verb": a.verb,
        "domain": a.domain,
        "action": a.action,
        "tool_name": a.tool_name,
        "target_host": a.target_host,
        "workflow": a.workflow,
        "account": a.account,
        "fields": a.fields,
    });
    let mut buf = Vec::new();
    buf.extend_from_slice(RECEIPT_CHAIN_DOMAIN);
    buf.extend_from_slice(&heso_verify::canonical_bytes(&descriptor));
    blake3::hash(&buf).to_hex().to_string()
}
