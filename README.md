# Followee for Rust

> A relay protocol for following people, not platforms.

`followee-rs` is the first non-normative implementation of the [Followee DID method and relay protocol](https://github.com/followee-protocol/followee). It is intended to turn the protocol into independently testable code, produce reusable conformance fixtures, and demonstrate a small network of relays exchanging partial current identity state without a shared blockchain or global registry.

Followee gives a person a durable cryptographic identifier whose current contact document can point to feeds, websites, social profiles, handles, and other services. Applications follow the identifier rather than a platform account. Independent relays help clients find the latest signed record, but clients verify records themselves and do not trust relay assurances.

No relay network is required for the first useful deployment. A domain can map a WebFinger handle to a Followee DID and expose the current signed record; a client verifies it locally. Relays later add replication, DID-only lookup, and independence from that original domain.

## Status

**Milestone 4 (resolver and relay network) is delivered and awaiting review; Milestone 3 remains reviewed at `milestone-3-v0.9-reviewed`.** Milestone 4 adds, against the same pinned v0.9 specification: the strict bounded production HTTP/CBOR relay client (`relay::client`) — one client path shared by synchronization, the direct relay commands, and the resolver, with exact paths/methods/media types, deterministic-CBOR-first outer-response validation, byte-string opacity, injected clocks, explicit shared operation budgets, an injectable transport, and a default-public network policy (HTTPS-only, credential-free, no private/loopback/link-local or otherwise sensitive destinations, validated redirects, resolution-pinned connections) with an explicit loopback development policy for tests and the demonstration; the current-state synchronization receiver (`relay::sync`) that consumes a peer's `v1/changes` feed through the ordinary two-phase ingress (no second verifier, ordering, or update-number path — `commit_current` remains the sole assigner), persists peer identity and the exact opaque cursor in both storage backends keyed by the peer's stable relay instance identifier, handles `ResetRequired` by discarding only the cursor, rejects over-`itemLimit` responses completely, and persists the cursor only after the response's accepted entries are durably processed; the section 14 multi-relay resolver (`resolver`) with one aggregate budget (deadline, bytes, requests, visited relays, reference depth) shared across the entire traversal, deterministic FIFO scheduling, local verification of every Full candidate for the explicit requested DID, continuation past Absent/Error/rejected outer responses, cycle detection, sticky RootRevoked retention, per-DID state isolation, and lazy path compression that stores only routing state after a verified traversal; the minimal non-interactive `followee relay publish`, `relay resolve`, `relay changes`, `relay sync`, and multi-relay `followee resolve` commands (JSON output, stable symbols, protocol-versus-infrastructure failure distinction, no protocol decisions in handlers); the Appendix B.11.2/B.11.3/B.11.5/B.11.7 behavioural gates executed through the production client and receiver paths on both backends (all existing B.11 server-side byte-exact tests retained); and the deterministic three-relay shell demonstration (`demo/three_relay_demo.sh`, run by `tests/three_relay_demo.rs`) driving three real `followee relay serve` processes on isolated SQLite databases through the production binary surfaces. Everything the previous milestones delivered is unchanged: the complete v0.9 protocol core, the Milestone 2 authoring CLI, the Milestone 3 relay with its v0.9 concurrent-ingress visibility evidence, the byte-exact Appendix B.2–B.12 conformance suite, and the Milestone 1.5 clean-room differential evidence (218/218; 53 confirmed fixtures) all remain applicable. All recorded specification questions in [`SPEC-QUESTIONS.md`](SPEC-QUESTIONS.md) are resolved (SQ-17–SQ-19 record Milestone 4's non-blocking derived readings). WebFinger, handle discovery, and migration presentation are Milestone 5 scope and have not begun.

[`tools/spec_vector_check.py`](tools/spec_vector_check.py) independently re-derives every computable Appendix B test-vector value from the specification text (82/82 reproduce byte-for-byte against v0.9, whose Appendix B is byte-identical to v0.8.1). It is a spec-review aid, not the Milestone 1.5 clean-room model, and is excluded from that model's authoring context.

Do not use `did:flw` for production identities. The DID method is not registered, the implementation has not passed conformance or interoperability testing, and the public keys in the protocol test vectors are deliberately backed by published private seeds.

## Repository role

This repository will provide:

- a strict Rust implementation of Followee v1 identifier, CBOR, COSE, signature, verification, authority, and ordering rules;
- command-line tools for creating, signing, inspecting, selecting, publishing, and resolving Followee records;
- a bounded HTTP/CBOR relay backed by SQLite;
- relay synchronization, reference traversal, and client-side verification;
- WebFinger handle discovery and inverse verification;
- machine-readable conformance fixtures suitable for unrelated implementations; and
- a reproducible local demonstration with at least three relays.

It will not define the protocol. If this code or its tests disagree with the normative specification, the specification governs unless it is deliberately amended in the protocol repository.

## Documents

- [Followee specification](https://github.com/followee-protocol/followee/blob/main/Followee-Specification.md) — normative protocol definition
- [Followee whitepaper](https://github.com/followee-protocol/followee/blob/main/Followee-Whitepaper.md) — motivation, design rationale, and security model
- [Rust implementation brief](IMPLEMENTATION.md) — repository scope, architecture, test strategy, and milestone gates

The Rust brief currently targets protocol repository commit `13777db64e1eca63796a8f485cf721307d2c3869` (specification v0.9). When a normative ambiguity is resolved, the brief must be re-pinned and the complete conformance suite rerun.

## Design commitments

The implementation is being built around several non-negotiable properties:

- received CBOR and COSE bytes remain intact through verification;
- clients and relays verify full records locally rather than trusting a transmitted `verified` flag;
- descriptor binding is checked independently of the signed body's claimed DID;
- root revocation has sticky, absolute precedence while that state is retained;
- deterministic ordering converges without a shared event chain;
- one audited strict-Ed25519 path enforces every Followee verification rule;
- parsing, traversal, storage, time, and response costs are explicitly bounded; and
- fixtures distinguish normative values, provisional implementation output, and independently confirmed results.

## Planned milestones

| Milestone | Deliverable |
| --- | --- |
| 0 | Rust scaffold, lockfile, CI, safety gates, injected clock/randomness, and `SPEC-QUESTIONS.md` |
| 1 | Protocol core and complete Appendix B conformance tests |
| 1.5 | Separately authored Python core model and differential testing |
| 2 | Identity authoring, signing, verification, inspection, and selection CLI |
| 3 | Single bounded SQLite relay with the mandatory HTTP/CBOR API |
| 4 | Resolver, synchronization, references, and a deterministic three-relay demonstration |
| 5 | WebFinger handles and a minimal public demonstration |
| 6 | Neutral fixture publication and external interoperability evidence |

Milestones are gates, not labels. Relay work does not begin until both the Rust protocol core and the independently authored Python model pass their acceptance criteria.

## Development

The toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml); with [rustup](https://rustup.rs) installed, every `cargo` invocation resolves it automatically. All commands work from a clean clone. The CI floor, run on every push and pull request, is:

```text
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo audit
cargo deny check
```

`cargo-audit` and `cargo-deny` are installed separately (`cargo install cargo-audit cargo-deny` or prebuilt release binaries); their policies live in [`deny.toml`](deny.toml).

The deterministic three-relay demonstration runs from a clean clone (it builds the binary and the `relay_housekeeping` example on demand, or reuses `FOLLOWEE_BIN`/`HOUSEKEEPING_BIN`):

```text
bash demo/three_relay_demo.sh
```

It is also executed as a test (`tests/three_relay_demo.rs`) by `cargo test --all-targets`. The network commands default to the public HTTPS-only policy; the demonstration and tests pass `--policy development` explicitly for loopback HTTP.

The crate root carries `#![forbid(unsafe_code)]`, and `clippy::arithmetic_side_effects` is denied crate-wide so unchecked arithmetic fails the lint gate. Security-sensitive protocol branches require direct tests, requirement traceability, fuzzing, and mutation-testing review; line coverage alone is not treated as evidence of correctness.

## Contributing

Read the complete pinned specification and [implementation brief](IMPLEMENTATION.md) before changing protocol-facing code. Do not silently resolve protocol ambiguities in this repository: record them in `SPEC-QUESTIONS.md` and resolve them in `followee-protocol/followee` before implementation depends on an interpretation.

Work proceeds one milestone at a time; each milestone stops at its acceptance criteria for review before the next begins. The Milestone 1.5 Python model must be authored in a clean session without access to this repository's Rust source or provisional fixtures (IMPLEMENTATION.md sections 11.4 and 14).

## Security

This project is experimental and has not been audited. Please do not publish suspected vulnerabilities as public issues once security-sensitive code exists; a private reporting route will be added before the first executable release.

## Licence

The implementation is licensed under the [MIT License](LICENSE). The protocol documents in `followee-protocol/followee` are licensed separately under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
