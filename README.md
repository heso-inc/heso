# heso — verify AI-agent action receipts

**Don't trust the vendor. Run the verifier.**

Every action a heso-governed AI agent takes is sealed into a signed
**ActionReceipt**: Ed25519 (`verify_strict`) over RFC 8785 (JCS) canonical
bytes, BLAKE3-chained to its predecessors, optionally anchored to RFC 3161
trusted time and an RFC 6962 transparency log. This repository is the
**complete, offline verifier** for those receipts — everything a relying party
(an auditor, a counterparty, a court) needs to check one with **zero heso
account, zero network, zero trust in us**.

```sh
cargo build --release -p heso-verify-cli
./target/release/heso-verify-cli --help

# verify a receipt (or a JSONL chain) against the operator's public key
./target/release/heso-verify-cli receipt.json
./target/release/heso-verify-cli --json chain.jsonl

# with RFC 3161 trusted-time verification compiled in (pinned TSA roots):
cargo build --release -p heso-verify-cli --features tsa
```

Exit codes are graded and stable: `0` valid / `1` invalid / `2` wrong
algorithm or hash / `64` usage.

## What's in here

| Crate | What it does |
| --- | --- |
| `heso-verify` | The primitives: RFC 8785 canonicalization, BLAKE3, Ed25519 `verify_strict`. |
| `heso-core` | `IdentityKey` — the Ed25519 key format receipts are signed with. |
| `heso-action` | ActionReceipt wire types + the offline verifier: signature, chain, quorum, delegation, RFC 3161 anchor (under `tsa`), RFC 6962 two-stage transparency proofs. |
| `heso-verify-cli` | The standalone CLI a relying party runs; vendored into evidence bundles as `VERIFY.sh`'s engine. |
| `specs/` | The wire-format specifications the verifier implements. |

Verification is **fail-closed** throughout: a receipt carrying an anchor or
proof the build cannot check verifies as invalid/unchecked, never silently as
valid.

## What's deliberately NOT here

The producer side — minting, signing seams, pre-sign redaction, policy
gating, evidence-bundle packaging — is the commercial
[HESO Enterprise](https://heso.ca) layer. The security model does not depend
on its secrecy (keys, not code, are the secret); it's simply not what this
repository is for. **A receipt's validity is decided entirely by the code you
are reading here.**

## This repository is a generated mirror

Source of truth lives in the private enterprise workspace; each release is
exported here by a sync script as one commit (`chore: regenerate mirror …`).
Issues and discussions are welcome — code contributions can't be merged here
directly, but we'll port accepted changes upstream with attribution.

## License

MIT OR Apache-2.0, at your option.
