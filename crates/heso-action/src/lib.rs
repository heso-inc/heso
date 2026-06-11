//! Zero-dependency wire types + offline verifier for HESO agent
//! **ActionReceipts**.
//!
//! An ActionReceipt is the signed, offline-verifiable record of a single agent
//! action (an LLM call, tool call, payment, …): what the agent did, which
//! policy gate fired, whether a human approved it, and which fields were
//! redacted before signing. This crate carries the wire format and the
//! verifier; signing and the runtime pipeline live in `heso-engine`.
//!
//! It mirrors [`heso_verify`]'s discipline — RFC-8785 canonicalization, a
//! BLAKE3 content hash, Ed25519 `verify_strict`, and frozen
//! domain-separation tags ([`domain`]) — and depends DOWN on the open `heso`
//! crates, never up.
//!
//! ## v2 capabilities
//!
//! - [`chain`] — cross-receipt chaining: a session of receipts linked by a
//!   domain-separated, length-prefixed BLAKE3 over each predecessor, verified by
//!   [`chain::verify_action_receipt_chain`] which NAMES the failure
//!   ([`chain::ChainOutcome::ContentTamper`] vs [`chain::ChainOutcome::LinkBroken`]).
//! - [`tsa`] — RFC-3161 trusted-time anchoring: the always-on, fail-closed
//!   VERIFY path ([`tsa::verify_time_anchor`], surfaced through
//!   [`verify::open_receipt_with_time`] / [`verify::TimeStatus`]); the real
//!   CMS/TSTInfo crypto and the producer-side requesting are behind the `tsa`
//!   cargo feature.
//!
//! Both are signed-content additions behind a bumped
//! [`domain::ACTION_VERSION`] / [`domain::ACTION_ENVELOPE_ALG`] (v2), so a
//! pre-change v1 receipt fails closed rather than being reinterpreted.

pub mod chain;
pub mod delegation;
pub mod domain;
pub mod ert;
pub mod mandate;
pub mod receipt;
pub mod step;
pub mod tsa;
pub mod verify;

// ── Promoted crypto-core modules ─────────────────────────────────────────────

/// Pure audit-chain primitives (compute_entry_hash + verify_chain_bytes).
/// Always available; heso-engine::audit re-uses these and adds file I/O.
pub mod audit_core;

/// Pure RFC-6962 Merkle tree verification (verify_inclusion + verify_consistency).
/// Always available; heso-engine::log re-exports these and adds the stateful
/// producer (MerkleLog).
pub mod transparency;
