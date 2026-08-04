# Followee for Rust

> A relay protocol for following people, not platforms.

`followee-rs` is the first non-normative implementation of the [Followee DID method and relay protocol](https://github.com/followee-protocol/followee). It is intended to turn the protocol into independently testable code, produce reusable conformance fixtures, and demonstrate a small network of relays exchanging partial current identity state without a shared blockchain or global registry.

Followee gives a person a durable cryptographic identifier whose current contact document can point to feeds, websites, social profiles, handles, and other services. Applications follow the identifier rather than a platform account. Independent relays help clients find the latest signed record, but clients verify records themselves and do not trust relay assurances.

## Status

**Pre-implementation.** The protocol specification and Rust implementation brief are complete enough to begin Milestone 0. No usable library, CLI, relay, resolver, or production identity system exists in this repository yet.

The first implementation session is deliberately limited to scaffolding: package structure, lockfile, CI, safety policy, injected clock and randomness traits, and the initial specification questions. Cryptography and CBOR begin only after that scaffold has been reviewed.

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

The Rust brief currently targets protocol repository commit `663c948`. When a normative ambiguity is resolved, the brief must be re-pinned and the complete conformance suite rerun.

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

Development commands will be added during Milestone 0 and must work from a clean clone. The expected CI floor is:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo audit
cargo deny check
```

The crate will use `#![forbid(unsafe_code)]`. Security-sensitive protocol branches require direct tests, requirement traceability, fuzzing, and mutation-testing review; line coverage alone is not treated as evidence of correctness.

## Contributing

Read the complete pinned specification and [implementation brief](IMPLEMENTATION.md) before changing protocol-facing code. Do not silently resolve protocol ambiguities in this repository: record them in `SPEC-QUESTIONS.md` and resolve them in `followee-protocol/followee` before implementation depends on an interpretation.

The first coding contribution should implement **Milestone 0 only**. Please stop at its acceptance criteria and present the scaffold and CI for review before beginning cryptography or CBOR.

## Security

This project is experimental and has not been audited. Please do not publish suspected vulnerabilities as public issues once security-sensitive code exists; a private reporting route will be added before the first executable release.

## Licence

The implementation is licensed under the [MIT License](LICENSE). The protocol documents in `followee-protocol/followee` are licensed separately under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
