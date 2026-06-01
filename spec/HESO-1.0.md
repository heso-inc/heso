# HESO/1.0

HESO/1.0 is an open protocol for **agent-driven web observation**. It
defines four interlocking data structures — the **plat** (a
content-addressed JSON observation of one web resource), the **cassette**
(the embedded record of every HTTP exchange the observation touched), the
**receipt** (a signed attestation of an executed action trace), and the
**verb namespace** (the canonical names agents use to act on the web) —
plus the **determinism rules** that let any conformant implementation
re-execute a plan and produce a byte-identical hash.

This file is a stub. **The canonical spec lives at <https://heso.ca/spec>.**

## Trust model — what a plat proves

HESO/1.0 does **not** prove that a web resource told the truth. No protocol
can: a server may serve different bytes to different callers and lie in its
own response, and a transport proof (zkTLS, a TEE attestation) only binds the
bytes the server chose to emit, not their honesty. HESO/1.0 deliberately makes
a narrower, durable claim — **accountability + replay** — on three legs.

**LEG 1 (the hero) — the record.** A plat embeds a **cassette** of every HTTP
exchange the run touched, plus the plan and the observation. Any party re-runs
those recorded bytes through a conformant engine and MUST obtain a
**byte-identical** plat (the same `plat_hash`). This is the verifiable core: it
requires no notary, no network, no clock, and no trust in the implementation,
and it catches a lying summarizer — an engine that claims an observation the
recorded bytes do not support. Its load-bearing claim is **determinism**,
specified in [§ Determinism](#determinism--the-load-bearing-claim-of-leg-1-the-record--replay-leg)
and enforced by the conformance harness.

**LEG 2 — operator binding.** A plat is signed by an operator identity key,
producing non-repudiable **attribution**: "operator key `K` made this claim, at
time `T`." This closes repudiation, cross-notary replay, downgrade-to-unsigned,
and forging-under-another-identity. It is **attribution, not authorization**,
and it is **not** a claim that the `plat_hash` is the authentic capture of the
URL — a different operator may honestly record a different version of the same
page. Attribution assigns liability; it does not certify content. Receivers pin
trusted signers via `verify --trusted-keys` (§3.9, §4.6).

**LEG 3 — the notary (secondary): the liveness / time anchor.** An optional,
independent party MAY attest that a URL was **live and served something at time
T**. A HESO/1.0 notary performs **zero content comparison**: it fetches its own
byte stream — which differs from the operator's cassette by design (`Date`,
`Set-Cookie`, CDN request-IDs) — and attests only liveness and time, never that
the operator's plat is the truth of the URL. It is a time anchor, not a hero.

**"We do not prove truth" is a feature, not a gap.** Every durable
accountability primitive on the internet — a notary public, Certificate
Transparency, C2PA content credentials, signed audit logs, signed git commits —
is load-bearing *precisely because* it binds attribution + time +
tamper-evidence and refuses to certify truth. HESO/1.0 is the same shape for
agent web runs: the record (Leg 1) is the verifiable hero, attribution (Leg 2)
assigns the liability, and the notary (Leg 3) anchors liveness in time.

## Core verbs (HESO/1.0)

A conformant implementation MUST dispatch the following verbs. Detailed
wire format, JSON output shapes, exit-code semantics, and the four
plan-resident action verbs (`open`, `click`, `fill`, `submit`) are
specified on the canonical spec page.

| Verb | Role |
|---|---|
| `read` | Fetch + execute JS + return rich content (text, forms, cookies, console, framework, deltas). |
| `open` | Page summary (title, headings, action graph). |
| `click` | Dispatch a click on an element matched by ref / text / selector / aria. |
| `fill` | Set the value of an input and fire `input` + `change`. |
| `submit` | Serialize a form, POST per `enctype`, observe the response. |
| `stamp` | Execute a plan against the live web; mint a plat with embedded cassette. |
| `run` | Re-execute a plan against the embedded cassette — no network. |
| `replay` | Emit the recorded step log from a plat. With `--plan`, emit the standalone plan JSON. |
| `refresh` | Re-stamp a plat against the live web and report whether it has drifted. |
| `verify` | Polymorphic content-identity check across plats, sealed envelopes, and signed receipts. |
| `info` | Human summary of a plat (with two args, a structural diff). |
| `seal` | Wrap a plat in an Ed25519 envelope. |
| `unseal` | Verify a sealed envelope; with `--extract`, emit the inner plat body. |
| `eval-js` | Evaluate JS in a sandboxed QuickJS context with seeded entropy and a virtual clock. |
| `eval-dom` | Fetch a URL, run its scripts, then evaluate JS against the post-hydration DOM. |
| `wait` | Block until a page condition is satisfied. |
| `batch` | Run many URLs in parallel under one cookie jar. |
| `search` | Multi-backend web search across Mojeek, Brave, Marginalia, and Wikipedia (optional SearXNG; DuckDuckGo opt-in via --engines ddg,ddg-lite); no API key. |
| `serve` | Long-running JSON-RPC 2.0 server over stdin/stdout. |
| `identity` | Generate or inspect an Ed25519 signing identity. |

## Determinism — the load-bearing claim of LEG 1 (the record / replay leg)

The hero of the Heso trust model is **LEG 1: the record and its
deterministic replay.** A plat carries the cassette of every HTTP exchange
the run touched; anyone can re-run those recorded bytes through the engine
and get a **byte-identical** plat — the same `plat_hash`. This leg catches
a lying summarizer and needs **no notary**: the artifact either re-hashes
to the recorded value or it does not.

The determinism guarantee is concrete, not aspirational:

- **Canonicalization** is RFC 8785 (JCS) — object keys are sorted, numbers
  use ECMA-262 `ToString`, so the hash never depends on map iteration
  order. `plat_hash` is lowercase-hex **BLAKE3** over the JCS bytes of the
  plat body with `plat_hash` and `sig` stripped.
- **The JS runtime is fenced** so a hydrated page is reproducible given
  `(seed, cassette)`: `Math.random` / `crypto.*` draw from a seeded
  **ChaCha20** stream (chosen over the non-portable `StdRng` for cross-host
  portability); `Date.now` / `performance.now` read a **virtual clock**
  that starts at 0 and never reads wall time; the timezone is pinned to
  **UTC**. The seed is recorded in the plat (`seed`), so a verifier replays
  under the same stream.
- **Async hydration settles on a virtual-clock fixed point**, never on
  `Instant::now()` — so an async-mutating page captures the same DOM every
  run.

**The proof** is a K = 16-fresh-process conformance harness
(`crates/heso-cli/tests/determinism_conformance.rs`) plus a pinned
per-cassette `expected_plat_hash` manifest
(`crates/heso-cli/tests/determinism_corpus/manifest.json`), including one
JS-hydrated cassette that drives the QuickJS fences through `plat_hash`.
Fresh processes are mandatory: they vary the HashMap `RandomState` seed and
allocator layout that an in-process loop would hide. The aarch64<->x86_64
**macOS** pair is additionally **proven locally**: a gated test
(`crates/heso-cli/tests/determinism_cross_arch.rs`) cross-builds `heso` for
`x86_64-apple-darwin` and executes it under Rosetta on the arm64 host,
asserting every cassette reproduces the SAME pinned native-arm64
`plat_hash` (foreign-ISA execution, not cross-compilation, not cross-OS).
The **linux** legs and the **native** x86_64-macOS leg are **not** claimed
from one machine — they are enforced by a CI matrix over
`{x86_64,aarch64} × {linux,macos}` plus the Rosetta cross-arch leg
(`.github/workflows/determinism-matrix.yml`); any matrix divergence is a
release blocker.

**Version-pinning honesty.** Offline VERIFY of a plat's signature survives
engine bumps. Offline REPLAY to regenerate `plat_hash` is **`engine_id`
pinned**: `engine{name,version}` (`version` = `CARGO_PKG_VERSION`) is in the
signed body, so a version bump changes `plat_hash` by design. The manifest's
`engine_id` gate makes a cross-version mismatch attributable
("regenerate"), distinct from a real determinism bug (same `engine_id`,
different hash).

## Reference implementation

The reference implementation is the `heso` binary in this repository.
Dispatch behavior, flag surface, and JSON output shapes are defined by
[`crates/heso-cli/src/main.rs`](../crates/heso-cli/src/main.rs); plat,
cassette, and receipt construction live in the `heso-engine-*` crates
alongside it.

A second implementation in any language is sufficient to validate the
spec. The canonical spec at <https://heso.ca/spec> is the binding text;
this file exists so external references that resolve to
`spec/HESO-1.0.md` in the source tree continue to work.

## License

CC0 1.0 (spec text) · MIT or Apache-2.0 (reference implementation).
