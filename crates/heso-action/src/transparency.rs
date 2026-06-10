//! Pure RFC-6962 SHA-256 Merkle tree verification primitives.
//!
//! This module is the **verify-only** half of HESO's transparency layer. The
//! stateful producer ([`MerkleLog`] with `append` / `inclusion_proof` /
//! `consistency_proof`) lives in `heso-engine::log`; the pure offline
//! verifiers here have no tree state and are callable from any crate that
//! holds only `heso-action`.
//!
//! ## Two hashes, never mixed
//!
//! - **BLAKE3 = WHAT.** Every receipt/audit *content* hash is BLAKE3. A leaf
//!   VALUE here is the raw 32 BLAKE3 bytes of a receipt's `action_hash`.
//! - **SHA-256 = ORDER.** The Merkle *tree* over those leaf values uses RFC 6962
//!   hashing (SHA-256 with domain-separating prefixes). The whole point is
//!   interop: an off-the-shelf RFC-6962 / C2SP / Sigsum witness can verify
//!   inclusion and consistency with NO HESO-specific code.
//!
//! ## RFC 6962 hashing rule (§2.1)
//!
//! ```text
//! leaf_hash(value) = SHA-256(0x00 || value)
//! node_hash(l, r)  = SHA-256(0x01 || l || r)
//! empty tree root  = SHA-256("")
//! ```

use sha2::{Digest, Sha256};

/// The width of a leaf value and of every internal hash: 32 bytes.
pub const HASH_LEN: usize = 32;

/// Decode a receipt's `action_hash` (64 lowercase-hex characters) into the raw
/// 32-byte leaf VALUE the transparency tree commits to.
///
/// # Errors
///
/// Returns [`TransparencyError::BadActionHash`] unless the input is exactly 64
/// characters of lowercase hex.
pub fn leaf_value_from_action_hash(action_hash: &str) -> Result<[u8; HASH_LEN], TransparencyError> {
    let bytes = action_hash.as_bytes();
    if bytes.len() != 64 {
        return Err(TransparencyError::BadActionHash);
    }
    let mut out = [0u8; HASH_LEN];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, TransparencyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(TransparencyError::BadActionHash),
    }
}

// ============================================================================
// RFC 6962 hashing primitives — also used by heso-engine::log (MerkleLog)
// ============================================================================

/// RFC 6962 leaf hash: `SHA-256(0x00 || value)`.
pub fn leaf_hash(value: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(value);
    h.finalize().into()
}

/// RFC 6962 internal-node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// RFC 6962 empty-tree root: `SHA-256("")`.
pub fn empty_root() -> [u8; HASH_LEN] {
    Sha256::new().finalize().into()
}

/// `k` = the largest power of two **strictly less than** `n`. Requires `n >= 2`.
pub fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash (§2.1) over `leaves` (already-computed leaf VALUES,
/// i.e. the 32-byte BLAKE3 contents — leaf hashing happens here).
/// Used by `heso-engine::log::MerkleLog` to compute subtree roots.
pub fn merkle_tree_hash(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = split_point(n);
            node_hash(&merkle_tree_hash(&leaves[..k]), &merkle_tree_hash(&leaves[k..]))
        }
    }
}

// ============================================================================
// Pure offline verification (public API)
// ============================================================================

/// Offline RFC-6962 inclusion verification (§2.1.1): recompute the root from
/// `leaf_value` at `index` in a tree of `size` leaves using `proof`, and compare
/// to `root`. No tree state.
///
/// Returns `true` iff the proof is well-formed and yields exactly `root`.
pub fn verify_inclusion(
    leaf_value: &[u8; HASH_LEN],
    index: usize,
    size: usize,
    root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if index >= size {
        return false;
    }
    let mut fne = index;
    let mut sne = size - 1;
    let mut hash = leaf_hash(leaf_value);
    let mut iter = proof.iter();

    while sne > 0 {
        let Some(sibling) = iter.next() else {
            return false;
        };
        if fne % 2 == 1 || fne == sne {
            hash = node_hash(sibling, &hash);
            if fne.is_multiple_of(2) {
                while fne != 0 && fne.is_multiple_of(2) {
                    fne /= 2;
                    sne /= 2;
                }
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fne /= 2;
        sne /= 2;
    }

    iter.next().is_none() && &hash == root
}

/// Offline RFC-6962 consistency verification (§2.1.2): given the old root over
/// `old_size` leaves and the new root over `new_size` leaves, check that `proof`
/// proves the new tree is an append-only extension of the old one. No tree state.
///
/// Returns `true` iff the proof is well-formed and reproduces BOTH the supplied
/// `old_root` and `new_root`.
pub fn verify_consistency(
    old_size: usize,
    old_root: &[u8; HASH_LEN],
    new_size: usize,
    new_root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut seed: Vec<[u8; HASH_LEN]> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        seed.push(*old_root);
    }
    seed.extend_from_slice(proof);
    if seed.is_empty() {
        return false;
    }

    let mut fr = seed[0];
    let mut sr = seed[0];
    let mut fne = old_size - 1;
    let mut sne = new_size - 1;
    while fne % 2 == 1 {
        fne /= 2;
        sne /= 2;
    }

    for step in &seed[1..] {
        if sne == 0 {
            return false;
        }
        if fne % 2 == 1 || fne == sne {
            fr = node_hash(step, &fr);
            sr = node_hash(step, &sr);
            while fne != 0 && fne.is_multiple_of(2) {
                fne /= 2;
                sne /= 2;
            }
        } else {
            sr = node_hash(&sr, step);
        }
        fne /= 2;
        sne /= 2;
    }

    sne == 0 && &fr == old_root && &sr == new_root
}

// ============================================================================
// Top-tree leaf commitment (HESO transparency D2 — two-stage proof, stage 2)
// ============================================================================

/// The domain-separation tag for a top-tree leaf value. FROZEN FOREVER: this
/// string is part of the cross-language conformance surface (the Python
/// checkpoint job hashes the byte-identical preimage) and a published top-leaf
/// commitment can never be recomputed under a different tag. Do NOT change it.
pub const TOP_LEAF_DOMAIN: &[u8] = b"heso-transparency-top-leaf-v1";

/// The frozen top-tree leaf VALUE committing one org's epoch snapshot.
///
/// HESO's transparency log is a per-org append-only leaf log under a single
/// append-only "epoch" top tree (design D2). Each epoch, the top tree gains one
/// immutable leaf per org-with-new-leaves: a commitment to that org's current
/// root at that epoch. This is that commitment.
///
/// ## Frozen preimage (never change)
///
/// ```text
/// top_leaf_value = SHA-256(
///       "heso-transparency-top-leaf-v1"   // TOP_LEAF_DOMAIN
///    || org_id        // 16 raw uuid bytes (network/big-endian, as in the uuid)
///    || epoch         // u64, big-endian
///    || org_root      // 32 bytes, the org's RFC-6962 root for this epoch
/// )
/// ```
///
/// The result is itself a 32-byte LEAF VALUE — pass it to [`leaf_hash`] (via
/// [`verify_inclusion`]) for the stage-2 top-tree inclusion check. It is
/// deliberately NOT pre-hashed with the `0x00` leaf prefix here, so it composes
/// with the same RFC-6962 verifiers stage 1 uses.
///
/// This is a heso-defined commitment (not RFC-6962-constrained) and MUST stay
/// byte-identical to the Python checkpoint job's `top_leaf` (the shared
/// conformance fixture pins it).
pub fn top_leaf_value(org_id: &[u8; 16], epoch: u64, org_root: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(TOP_LEAF_DOMAIN);
    h.update(org_id);
    h.update(epoch.to_be_bytes());
    h.update(org_root);
    h.finalize().into()
}

// ============================================================================
// C2SP signed-note parsing + verification (transparency checkpoints)
// ============================================================================

/// A parsed C2SP signed note (the checkpoint form a `TransparencyProof` carries).
///
/// Wire shape (see <https://c2sp.org/signed-note>): a UTF-8 text body of
/// `origin\n<size>\n<base64 root>\n`, then a blank line, then one or more
/// signature lines `— <name> <base64(4-byte keyhash || 64-byte ed25519 sig)>`.
/// HESO checkpoints carry exactly the log signature; witness cosignatures ride
/// in `TransparencyProof.cosignatures`, not in the note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNote {
    /// The note origin (HESO: the log domain, e.g. `log.heso.ca`). First body line.
    pub origin: String,
    /// The tree SIZE the note commits to (second body line).
    pub size: u64,
    /// The 32-byte tree ROOT the note commits to (decoded from the third body line).
    pub root: [u8; HASH_LEN],
    /// The exact NOTE TEXT (the body, signatures stripped) the signatures are over
    /// — `origin\n<size>\n<base64 root>\n`. This is the byte string a verifier
    /// re-hashes for the keyhash and runs ed25519 `verify_strict` against.
    pub text: String,
    /// Every parsed signature line.
    pub signatures: Vec<NoteSignature>,
}

/// One signature line of a [`SignedNote`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// The signer name (the key name, between `— ` and the space).
    pub name: String,
    /// The first 4 bytes of `SHA-256(name || "\n" || 0x01 || pubkey)` (C2SP
    /// signed-note key hash) — a fast filter so a verifier knows which signature
    /// line a given key produced before running ed25519.
    pub key_hash: [u8; 4],
    /// The raw 64-byte Ed25519 signature over the note `text`.
    pub signature: [u8; 64],
}

/// Errors from parsing or verifying a C2SP signed note.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoteError {
    /// The note body is not `origin\n<size>\n<base64 root>\n` + blank + sig lines.
    #[error("malformed signed note: {0}")]
    Malformed(&'static str),
    /// The base64 root (body line 3) did not decode to 32 bytes.
    #[error("signed-note root is not a base64 32-byte hash")]
    BadRoot,
    /// A signature line was not `— <name> <base64 blob>` with a 68-byte blob.
    #[error("malformed signature line: {0}")]
    BadSignatureLine(&'static str),
    /// No signature line matched the pinned log key, or the matching one failed
    /// ed25519 `verify_strict`.
    #[error("no valid signature from the pinned log key")]
    NoTrustedSignature,
}

/// Parse a C2SP signed note. Does NO signature verification — call
/// [`verify_note_against_key`] (or [`SignedNote::verify_with_key`]) for that.
pub fn parse_signed_note(note: &str) -> Result<SignedNote, NoteError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    // Split body from signature block on the first blank line. The body keeps
    // its trailing newline (the note text the signatures cover ends in `\n`).
    let (body, sig_block) = note
        .split_once("\n\n")
        .ok_or(NoteError::Malformed("missing blank line before signatures"))?;
    let text = format!("{body}\n");

    let mut body_lines = text.lines();
    let origin = body_lines
        .next()
        .ok_or(NoteError::Malformed("missing origin line"))?
        .to_string();
    let size: u64 = body_lines
        .next()
        .ok_or(NoteError::Malformed("missing size line"))?
        .parse()
        .map_err(|_| NoteError::Malformed("size line is not a u64"))?;
    let root_b64 = body_lines.next().ok_or(NoteError::Malformed("missing root line"))?;
    if body_lines.next().is_some() {
        return Err(NoteError::Malformed("unexpected extra body lines"));
    }
    let root_bytes = B64.decode(root_b64.as_bytes()).map_err(|_| NoteError::BadRoot)?;
    if root_bytes.len() != HASH_LEN {
        return Err(NoteError::BadRoot);
    }
    let mut root = [0u8; HASH_LEN];
    root.copy_from_slice(&root_bytes);

    let mut signatures = Vec::new();
    for line in sig_block.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let rest = line
            .strip_prefix("— ")
            .ok_or(NoteError::BadSignatureLine("line does not start with `— `"))?;
        let (name, blob_b64) = rest
            .split_once(' ')
            .ok_or(NoteError::BadSignatureLine("missing name/blob separator"))?;
        let blob = B64
            .decode(blob_b64.as_bytes())
            .map_err(|_| NoteError::BadSignatureLine("blob is not base64"))?;
        if blob.len() != 4 + 64 {
            return Err(NoteError::BadSignatureLine("blob is not 4-byte keyhash + 64-byte sig"));
        }
        let mut key_hash = [0u8; 4];
        key_hash.copy_from_slice(&blob[..4]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&blob[4..]);
        signatures.push(NoteSignature {
            name: name.to_string(),
            key_hash,
            signature,
        });
    }
    if signatures.is_empty() {
        return Err(NoteError::Malformed("no signature lines"));
    }

    Ok(SignedNote { origin, size, root, text, signatures })
}

/// The C2SP signed-note key hash: the first 4 bytes of
/// `SHA-256(name || "\n" || 0x01 || pubkey)`. The `0x01` is the C2SP Ed25519
/// algorithm identifier.
pub fn note_key_hash(name: &str, pubkey: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([0x01]);
    h.update(pubkey);
    let full: [u8; HASH_LEN] = h.finalize().into();
    [full[0], full[1], full[2], full[3]]
}

/// Verify a parsed [`SignedNote`] against a pinned Ed25519 log public key (raw
/// 32 bytes). Requires at least one signature line whose `key_hash` matches the
/// pinned key AND whose ed25519 signature `verify_strict`s over the note text.
///
/// The pinned key is supplied by the caller (library param / CLI flag), never a
/// `KeyRegistry` — the relying party trusts the log key it was given out of band.
pub fn verify_note_against_key(note: &SignedNote, log_pubkey: &[u8; 32]) -> Result<(), NoteError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    for sig in &note.signatures {
        if note_key_hash(&sig.name, log_pubkey) != sig.key_hash {
            continue;
        }
        // Reuse the house Ed25519 verify_strict path (heso_verify owns dalek);
        // it expects base64 fields and the `"Ed25519"` algorithm tag.
        let candidate = heso_verify::Signature {
            algorithm: "Ed25519".to_string(),
            public_key: B64.encode(log_pubkey),
            signature: B64.encode(sig.signature),
        };
        if candidate.verify(note.text.as_bytes()).is_ok() {
            return Ok(());
        }
    }
    Err(NoteError::NoTrustedSignature)
}

impl SignedNote {
    /// Convenience: [`verify_note_against_key`] against this note.
    pub fn verify_with_key(&self, log_pubkey: &[u8; 32]) -> Result<(), NoteError> {
        verify_note_against_key(self, log_pubkey)
    }
}

/// Errors from building proofs or decoding a leaf value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransparencyError {
    /// An `action_hash` was not exactly 64 lowercase-hex characters.
    #[error("action_hash must be 64 lowercase-hex characters")]
    BadActionHash,
    /// An inclusion proof was requested for a leaf index at or beyond the tree size.
    #[error("leaf index {index} out of range for a tree of {size} leaves")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The tree size at the time of the request.
        size: usize,
    },
    /// A consistency proof range was invalid (`old_size == 0`, or `old_size > new_size`).
    #[error("invalid consistency range: old_size {old_size}, new_size {new_size}")]
    BadConsistencyRange {
        /// The requested earlier size.
        old_size: usize,
        /// The current tree size.
        new_size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8; HASH_LEN]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn empty_root_is_sha256_of_empty_string() {
        assert_eq!(
            hx(&empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn leaf_value_from_action_hash_decodes_64_lowercase_hex() {
        let wh = "d29d0238e8cf7890a26cb89607e28263e875efc6a5502c7b65e74d2aaf99d337";
        let v = leaf_value_from_action_hash(wh).unwrap();
        assert_eq!(hx(&v), wh);
    }

    #[test]
    fn leaf_value_rejects_bad_action_hash() {
        assert_eq!(leaf_value_from_action_hash("dead"), Err(TransparencyError::BadActionHash));
        let upper = "D29D0238E8CF7890A26CB89607E28263E875EFC6A5502C7B65E74D2AAF99D337";
        assert_eq!(leaf_value_from_action_hash(upper), Err(TransparencyError::BadActionHash));
        let nonhex = "z29d0238e8cf7890a26cb89607e28263e875efc6a5502c7b65e74d2aaf99d337";
        assert_eq!(leaf_value_from_action_hash(nonhex), Err(TransparencyError::BadActionHash));
    }

    // --- C2SP signed-note parse + verify -----------------------------------

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// Build + sign a C2SP note with `seed` over body `origin\n<size>\n<b64 root>\n`.
    fn make_note(seed: &[u8; 32], origin: &str, size: u64, root: &[u8; HASH_LEN]) -> String {
        let body = format!("{origin}\n{size}\n{}\n", B64.encode(root));
        let key = heso_core::IdentityKey::from_bytes(seed);
        let sig = key.sign(body.as_bytes());
        let sig_raw = B64.decode(sig.signature.as_bytes()).unwrap();
        let kh = note_key_hash(origin, &key.public_key_bytes());
        let mut blob = Vec::new();
        blob.extend_from_slice(&kh);
        blob.extend_from_slice(&sig_raw);
        format!("{body}\n— {origin} {}", B64.encode(&blob))
    }

    #[test]
    fn signed_note_parses_and_verifies_against_pinned_key() {
        let root = [0x11u8; HASH_LEN];
        let note_text = make_note(&[7u8; 32], "log.heso.ca", 42, &root);
        let note = parse_signed_note(&note_text).unwrap();
        assert_eq!(note.origin, "log.heso.ca");
        assert_eq!(note.size, 42);
        assert_eq!(note.root, root);
        let pk = heso_core::IdentityKey::from_bytes(&[7u8; 32]).public_key_bytes();
        assert!(note.verify_with_key(&pk).is_ok());
        // A different pinned key is rejected.
        let wrong = heso_core::IdentityKey::from_bytes(&[8u8; 32]).public_key_bytes();
        assert_eq!(note.verify_with_key(&wrong), Err(NoteError::NoTrustedSignature));
    }

    #[test]
    fn signed_note_rejects_tampered_body() {
        let note_text = make_note(&[7u8; 32], "log.heso.ca", 42, &[0x11u8; HASH_LEN]);
        // Flip the size in the body without re-signing.
        let tampered = note_text.replacen("\n42\n", "\n43\n", 1);
        let note = parse_signed_note(&tampered).unwrap();
        let pk = heso_core::IdentityKey::from_bytes(&[7u8; 32]).public_key_bytes();
        assert_eq!(note.verify_with_key(&pk), Err(NoteError::NoTrustedSignature));
    }

    #[test]
    fn malformed_notes_are_rejected() {
        assert!(matches!(parse_signed_note("no blank line"), Err(NoteError::Malformed(_))));
        assert!(matches!(parse_signed_note("a\n1\nnotb64\n\n— a AAA"), Err(NoteError::BadRoot)));
    }

    // --- RT-6: inclusion/consistency across a key_rotation leaf -------------

    fn inclusion_path(index: usize, leaves: &[[u8; HASH_LEN]]) -> Vec<[u8; HASH_LEN]> {
        let n = leaves.len();
        if n == 1 {
            return Vec::new();
        }
        let k = split_point(n);
        if index < k {
            let mut p = inclusion_path(index, &leaves[..k]);
            p.push(merkle_tree_hash(&leaves[k..]));
            p
        } else {
            let mut p = inclusion_path(index - k, &leaves[k..]);
            p.push(merkle_tree_hash(&leaves[..k]));
            p
        }
    }

    fn consistency_path(m: usize, leaves: &[[u8; HASH_LEN]]) -> Vec<[u8; HASH_LEN]> {
        if m == leaves.len() {
            return Vec::new();
        }
        consistency_subproof(m, leaves, true)
    }

    fn consistency_subproof(m: usize, leaves: &[[u8; HASH_LEN]], b: bool) -> Vec<[u8; HASH_LEN]> {
        let n = leaves.len();
        if m == n {
            if b {
                return Vec::new();
            }
            return vec![merkle_tree_hash(leaves)];
        }
        let k = split_point(n);
        if m <= k {
            let mut proof = consistency_subproof(m, &leaves[..k], b);
            proof.push(merkle_tree_hash(&leaves[k..]));
            proof
        } else {
            let mut proof = consistency_subproof(m - k, &leaves[k..], false);
            proof.push(merkle_tree_hash(&leaves[..k]));
            proof
        }
    }

    /// The `action_hash` of a `key_rotation` receipt's content — an ordinary
    /// producer authorization, so it is an ordinary leaf VALUE.
    fn key_rotation_action_hash() -> String {
        use crate::receipt::{KeyRotation, ReceiptKind, RotatedRole};
        let mut content = crate::receipt::fixtures::fixed_content();
        content.kind = Some(ReceiptKind::KeyRotation);
        content.key_rotation = Some(KeyRotation {
            role: RotatedRole::Producer,
            outgoing_public_key: heso_core::IdentityKey::from_bytes(&[0u8; 32]).public_key_b64(),
            incoming_public_key: heso_core::IdentityKey::from_bytes(&[1u8; 32]).public_key_b64(),
        });
        crate::receipt::action_content_hash(&content)
    }

    /// A tree whose leaves include a `key_rotation` receipt's action_hash proves
    /// inclusion + consistency exactly like any other leaf — the tree layer is
    /// agnostic to the signer role of the leaf.
    #[test]
    fn inclusion_and_consistency_across_key_rotation_leaf() {
        let rot = key_rotation_action_hash();
        let leaves: Vec<[u8; HASH_LEN]> = vec![
            leaf_value_from_action_hash(&"a".repeat(64)).unwrap(),
            leaf_value_from_action_hash(&rot).unwrap(), // the rotation leaf at index 1
            leaf_value_from_action_hash(&"c".repeat(64)).unwrap(),
            leaf_value_from_action_hash(&"d".repeat(64)).unwrap(),
            leaf_value_from_action_hash(&"e".repeat(64)).unwrap(),
        ];

        // Inclusion of the rotation leaf against the full-tree root.
        let root = merkle_tree_hash(&leaves);
        let proof = inclusion_path(1, &leaves);
        assert!(
            verify_inclusion(&leaves[1], 1, leaves.len(), &root, &proof),
            "the key_rotation leaf must prove inclusion"
        );

        // Consistency from a 3-leaf prefix (which already contains the rotation
        // leaf) to the 5-leaf tree.
        let old_root = merkle_tree_hash(&leaves[..3]);
        let cproof = consistency_path(3, &leaves);
        assert!(
            verify_consistency(3, &old_root, leaves.len(), &root, &cproof),
            "the tree extension over the rotation leaf must be consistency-provable"
        );
    }

    // --- Two-stage inclusion round-trip (leaf→org_root, top_leaf→top_root) --

    fn hx_short(b: &[u8; HASH_LEN]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A full two-stage proof round-trips: a receipt leaf proves into its org
    /// root (stage 1), and the frozen top-leaf commitment over that org root
    /// proves into the top root (stage 2).
    #[test]
    fn two_stage_inclusion_round_trip() {
        // Stage 1: an org tree of 4 leaves; prove leaf 2 → org_root.
        let org_leaves: Vec<[u8; HASH_LEN]> = (0..4u8)
            .map(|i| leaf_value_from_action_hash(&format!("{i:02x}").repeat(32)).unwrap())
            .collect();
        let org_root = merkle_tree_hash(&org_leaves);
        let s1 = inclusion_path(2, &org_leaves);
        assert!(verify_inclusion(&org_leaves[2], 2, org_leaves.len(), &org_root, &s1));

        // Stage 2: a top tree of 3 leaves; this org's epoch commitment sits at
        // top index 1 and must prove into the top root.
        let org_id: [u8; 16] = [9u8; 16];
        let epoch: u64 = 5;
        let top_leaf = top_leaf_value(&org_id, epoch, &org_root);
        let other = top_leaf_value(&[1u8; 16], epoch, &[0u8; HASH_LEN]);
        let third = top_leaf_value(&[2u8; 16], epoch, &[1u8; HASH_LEN]);
        let top_leaves = vec![other, top_leaf, third];
        let top_root = merkle_tree_hash(&top_leaves);
        let s2 = inclusion_path(1, &top_leaves);
        assert!(verify_inclusion(&top_leaves[1], 1, top_leaves.len(), &top_root, &s2));

        // A wrong org_root yields a different top-leaf that does NOT prove in.
        let bad = top_leaf_value(&org_id, epoch, &[0xFFu8; HASH_LEN]);
        assert!(!verify_inclusion(&bad, 1, top_leaves.len(), &top_root, &s2));
    }

    /// The frozen top-leaf commitment fixture — the cross-language conformance
    /// surface the Python checkpoint job's `top_leaf` must reproduce. A FIXED
    /// `(org_id, epoch, org_root)` triple yields a pinned 32-byte value forever.
    #[test]
    fn frozen_top_leaf_value_vector() {
        assert_eq!(TOP_LEAF_DOMAIN, b"heso-transparency-top-leaf-v1");
        let org_id: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let epoch: u64 = 7;
        let org_root: [u8; HASH_LEN] = [0xABu8; HASH_LEN];
        // Recompute the expected value independently (the exact frozen preimage).
        let mut h = Sha256::new();
        h.update(b"heso-transparency-top-leaf-v1");
        h.update(org_id);
        h.update(epoch.to_be_bytes());
        h.update(org_root);
        let expected: [u8; HASH_LEN] = h.finalize().into();
        assert_eq!(top_leaf_value(&org_id, epoch, &org_root), expected);
        // Pin the hex so a drift (or a Python mismatch) is caught loudly.
        assert_eq!(
            hx_short(&top_leaf_value(&org_id, epoch, &org_root)),
            "d735c0307fff8b8450df1ca9ac279975fc27a8c937502225d74c421c6533ea51"
        );
    }
}
