# Followee Rust Implementation Brief

## 1. Purpose

This document specifies the first non-normative implementation of the Followee DID method and relay protocol. The implementation exists to:

1. turn the written protocol into executable, independently testable behaviour;
2. expose ambiguities or errors in the protocol before production registration;
3. publish machine-readable conformance material reusable by unrelated implementations;
4. demonstrate multiple relays exchanging partial current state without a shared chain; and
5. provide useful command-line tools for creating, publishing and resolving Followee identities.

The implementation is not the protocol. Where this document, the code or a test disagrees with the normative Followee specification, the specification governs unless it is deliberately amended in the protocol repository.

## 2. Normative target

Implementation work targets:

- repository: <https://github.com/followee-protocol/followee>
- specification: `Followee-Specification.md`
- pinned commit: `41f82fa272b96468363f2106f7923ad168f5bf82`
- specification draft: `v0.4`
- protocol version: `1`
- DID method: `did:flw`

The whitepaper is design rationale, not a wire-format authority.

The implementation MUST NOT silently invent behaviour when the specification is ambiguous. Record the ambiguity in `SPEC-QUESTIONS.md`, write the smallest failing or pending test that demonstrates it, and resolve it in the protocol repository before depending on an interpretation.

No milestone may pass while `SPEC-QUESTIONS.md` contains an unresolved question that affects code in that milestone. If resolving a question amends the normative specification, update the pinned commit in this section, record the change in the implementation repository, and rerun the complete conformance and differential suite. A previous green result against another commit is not inherited automatically.

## 3. Implementation status and naming

The repository is `followee-protocol/followee-rs`.

It is the first implementation but is not a privileged “reference truth.” Public documentation should describe it as:

> A non-normative Rust implementation of the Followee DID method and relay protocol.

The later `followee-icp` implementation is expected to be independently written in Motoko and to consume the same external conformance fixtures without sharing protocol implementation code.

## 4. Scope

### 4.1 Required eventual capabilities

The completed v0.1 implementation will provide:

- exact Followee DID creation and parsing;
- root and revocation key generation;
- Authority Descriptor construction and DID derivation;
- complete Contact Document authoring;
- root Identity Record signing;
- root-revoked Identity Record signing;
- strict full-record verification;
- deterministic candidate ordering;
- sticky root-revocation state;
- a command-line client;
- a bounded SQLite-backed relay;
- all mandatory HTTP/CBOR relay operations for the claimed roles;
- client-side multi-relay resolution and reference traversal;
- relay-to-relay current-state synchronization;
- WebFinger handle discovery and inverse verification;
- machine-readable conformance fixtures;
- a local multi-relay demonstration; and
- an optional minimal public WebFinger demonstration.

### 4.2 Explicit non-goals

Version 0.1 will not provide:

- blogging, feeds, ranking, advertising or a social application;
- an ICP canister or any ICP dependency;
- a graphical interface;
- a global registry, shared blockchain or consensus mechanism;
- a production hardware-wallet, HSM, enclave or remote-signer integration;
- a relay-history protocol;
- automatic DID migration;
- additional signature suites, hash functions or DID versions;
- embedded binary avatars or content;
- production admission payments, sponsorship or accounting; or
- a claim that the unregistered `did:flw` method is production-standardised.

The optional remote-signer interface in Section 18 and relay history in Section 19 of the protocol specification are deferred.

## 5. Delivery strategy

Build the implementation in ordered milestones. Do not construct the public deployment, synchronization scheduler or WebFinger example before the core passes all byte-level conformance tests.

Keep the first codebase as one Rust package with one library and one binary. Split it into crates only after actual dependency or release boundaries appear.

Suggested initial layout:

```text
followee-rs/
├── Cargo.toml
├── Cargo.lock
├── IMPLEMENTATION.md
├── README.md
├── LICENSE
├── SPEC-QUESTIONS.md
├── src/
│   ├── lib.rs
│   ├── cbor.rs
│   ├── cose.rs
│   ├── crypto.rs
│   ├── did.rs
│   ├── contact.rs
│   ├── record.rs
│   ├── verify.rs
│   ├── ordering.rs
│   ├── store.rs
│   ├── relay.rs
│   ├── resolver.rs
│   ├── webfinger.rs
│   └── bin/
│       └── followee.rs
├── tests/
│   ├── conformance.rs
│   ├── state_machine.rs
│   ├── relay_http.rs
│   ├── synchronization.rs
│   └── resolution.rs
├── fixtures/
├── fuzz/
├── tools/
│   └── python-model/
└── demo/
```

This is a logical layout, not a demand for empty placeholder modules. Add files when their milestone begins.

## 6. Technology choices

Use stable Rust with the current stable edition supported by the toolchain at project creation. Commit `Cargo.lock`.

Preferred components are:

| Concern | Choice |
| --- | --- |
| Async runtime | Tokio |
| HTTP server | Axum |
| HTTP client | Reqwest |
| CLI | Clap |
| Durable state | SQLite |
| SQLite access | A maintained Rust SQLite library with explicit transaction control |
| Hashing | SHA-256 from a maintained RustCrypto implementation |
| Ed25519 | `ed25519-dalek`, supplemented where necessary to meet every Section 3.3 check |
| Base58btc | `bs58` or an equivalently narrow maintained implementation |
| URI handling | `url` |
| IDNA | A maintained IDNA2008-capable library |
| JSON/JRD | Serde JSON, confined to WebFinger and authoring formats |
| Property tests | Proptest |
| Fuzzing | `cargo-fuzz`/libFuzzer |
| Errors | Typed errors, preferably using `thiserror` internally |

Do not choose dependencies merely because their API names resemble the protocol. Confirm their encoded output and rejection behaviour using the normative vectors.

### 6.1 CBOR and COSE rule

Do not deserialize untrusted Identity Records directly into Serde domain structs and then re-encode them for verification.

Implement a small protocol-specific deterministic CBOR reader/writer, or a strict validation layer over a low-level CBOR library, that can:

- retain exact received byte slices;
- reject indefinite lengths;
- reject non-minimal integers and lengths;
- reject duplicate or incorrectly ordered map keys;
- reject forbidden tags, floats and simple values;
- enforce nesting, member and byte limits before allocation;
- reject trailing bytes;
- expose the exact record-body bytes used for signature verification and digesting; and
- deterministically encode every Followee v1 structure byte-for-byte.

Implement the narrow Followee COSE Sign1 profile directly over this codec. Do not depend on a general COSE library accepting or emitting the required fully specified algorithm value `-19` correctly.

### 6.2 Ed25519 rule

Use pure Ed25519, never Ed25519ph or Ed25519ctx.

The verifier MUST satisfy every explicit requirement in Section 3.3 of the protocol specification. Calling a function named `verify_strict` is not by itself evidence that every Followee subgroup and encoding rule is enforced. Add explicit point/subgroup checks where the selected library does not prove them, and retain negative tests for:

- non-canonical public keys;
- non-canonical `R`;
- `S >= L`;
- identity and small-order points;
- points outside the prime-order subgroup; and
- signatures that pass a broader or cofactored verification equation but fail Followee’s required equation.

Implement exactly one production cryptographic verification entry point, conceptually:

```rust
crypto::verify_followee_ed25519(public_key, message, signature)
```

This function owns every Section 3.3 check and is the exact function exercised by the primitive edge-case vectors. The complete record verifier MUST reach Ed25519 verification only through this entry point. It MUST NOT call an underlying dependency's ordinary, permissive, batch or alternate verification routine directly.

Keep any signature-verifier abstraction private to the crate. A private internal `verify_record_with_verifier` path MAY accept a verifier interface for tests, while the public production `verify_record` wrapper MUST always supply the Followee-strict implementation.

Two wiring tests must substitute a spy verifier and exercise authority-dependent key selection through complete positive envelopes:

- the Appendix B.4 Root case delegates exactly once with the descriptor's root public key, `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`; and
- the Appendix B.5 RootRevoked case delegates exactly once with label `5`'s revealed revocation public key, `29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7`.

Each test must assert the exact 32 key bytes, exact reconstructed COSE `Sig_structure` bytes and exact received 64-byte signature passed to the spy; observing merely that some key was supplied is insufficient. The end-to-end B.4 `S + L` envelope case must pass through the public production wrapper, not the injectable test path.

After selecting the Ed25519 dependency, configure Clippy's disallowed-method mechanism, or an equivalently mechanical repository check, to reject direct calls to every underlying verification entry point outside the narrowly audited implementation of `crypto::verify_followee_ed25519`. Any scoped lint allowance must be confined to that wrapper. Code review alone is not the enforcement mechanism, and adding a correctly tested strict helper while leaving another record-path call in place is a conformance failure.

The crate root MUST contain:

```rust
#![forbid(unsafe_code)]
```

No `unsafe` code may be introduced by this repository. This attribute does not govern dependencies; dependency use of `unsafe` must be minimised and reviewed rather than assumed absent. Dependency advisory, source and licence policy are enforced separately through `cargo-audit` and `cargo-deny`.

## 7. Core library design

### 7.1 Public model

Expose typed representations for authoring and verified results, but keep untrusted parsed values distinct from verified values. In particular:

- `FolloweeDid` represents a canonical, fully validated v1 DID;
- `AuthorityDescriptor` represents a validated deterministic descriptor;
- `ContactDocument` represents a schema-valid complete document;
- `UnverifiedRecord` retains received envelope and body bytes;
- `VerifiedRecord` can only be created by the complete verification algorithm;
- `BodyDigest` is computed locally and is never treated as transmitted authority;
- `AuthorityState` is `Unknown`, `Root` or `RootRevoked`; and
- result and error types preserve the protocol error classification.

Do not expose constructors that let callers fabricate `VerifiedRecord` or sticky `RootRevoked` state without verification.

### 7.2 Determinism

Given identical structured input, every platform and run MUST produce identical:

- public-key CBOR;
- revocation commitment;
- Authority Descriptor CBOR;
- descriptor digest and DID;
- Contact Document CBOR;
- record-body CBOR;
- COSE protected header and `Sig_structure`;
- complete Identity Record envelope; and
- body digest.

Map iteration order from a language container MUST NOT determine wire order.

### 7.3 Time and randomness

Inject `Clock` and `RandomSource` abstractions into code that uses time or randomness.

Production implementations use the operating system clock and CSPRNG. Tests use deterministic implementations. Arithmetic around timestamps, skew bounds and update counters MUST be checked and MUST NOT wrap.

### 7.4 Key handling

For the proof of concept, the CLI may store 32-byte Ed25519 seeds in local files. This is an application format, not part of the Followee protocol.

Requirements:

- root and revocation secrets are written to separately named files;
- new secret files use owner-only permissions where the operating system supports them;
- existing files are never overwritten without an explicit flag;
- secrets never appear in normal logs, error messages, shell examples or JSON diagnostics;
- production commands reject exact matches for all published Appendix B secret seeds: both B.2 root and revocation seeds and both B.8 attacker root and revocation seeds;
- secret buffers are zeroised where practical; and
- the CLI prominently warns that local files are demonstration custody, not a production vault.

The creation command should permit the revocation key to be written directly to a different path or removable medium.

### 7.5 Authoring format

The CLI may accept a friendly JSON Contact Document using field names rather than CBOR labels. This JSON is an implementation convenience and is not a Followee wire format.

It MUST map unambiguously to the normative Contact Document, reject unknown fields by default, enforce all limits before signing, and always create a complete document rather than a delta.

## 8. CLI surface

The eventual single `followee` binary should support at least:

```text
followee identity create
followee record sign-root
followee record revoke-root
followee record verify
followee record inspect
followee record select
followee relay serve
followee relay publish
followee relay resolve
followee relay changes
followee resolve
followee handle resolve
followee handle verify
```

Exact flag names may evolve, but commands MUST support non-interactive use and machine-readable output for tests.

`record inspect` must clearly distinguish raw parsed claims from locally verified facts. It must not display a Contact Document as verified when verification was skipped or failed.

`record select` accepts candidates in arbitrary order and returns the same winner and metadata for every permutation.

The CLI should return nonzero exit status on failure and provide stable symbolic error names. Raw secret material must never be emitted by a general `--verbose` or diagnostic mode.

## 9. Relay implementation

### 9.1 Role

The relay will eventually claim the Ingress Relay role and therefore also conform as a Relay, Relay Resolver and Record Verifier.

It must expose the mandatory HTTP/CBOR operations in Section 12:

```text
GET  v1/info
POST v1/resolve
GET  v1/directory
POST v1/publish
POST v1/changes
```

It must use the exact media types, schemas, result alignment, status values, error codes, bounds and CORS behaviour in the specification.

Before returning a stored Full result, the relay repeats the future-bound check against its current injected clock. A stored record that has become premature is not returned as Full or conflated with Absent: the relay returns a usable Ref or the per-DID `premature` Error result. This serving-time decision must not mutate the stored entry, change `lastUpdated`, or increment the relay-local update number.

### 9.2 Storage

Use SQLite transactions to make current-state replacement, sticky authority-state changes and relay-local update-number assignment atomic.

The conceptual persistent state includes:

- stable relay instance identifier;
- cursor generation;
- directory generation;
- next relay-local update number;
- partial DID map;
- exact full envelope bytes or local reference;
- sticky authority state;
- retained ordering metadata;
- per-entry `lastUpdated`;
- relay directory entries; and
- peer synchronization cursors.

The database schema is an implementation detail and must not leak into the wire protocol.

A received invalid, duplicate, losing or post-revocation Root record MUST NOT increment the update counter. A winning record and a newly learned RootRevoked transition MUST be persisted before an admission acknowledgement is returned.

### 9.3 Cursors

Use an opaque bounded cursor encoding that commits to the relay’s cursor generation and a relay-local scan position. The decoder must reject malformed or foreign-generation cursors with the specified result.

Pagination tests must prove that:

- no eligible current tuple is skipped;
- a DID updated several times appears only as its current tuple;
- `nextCursor` never advances beyond an omitted eligible entry;
- an entry too large for the requested byte limit returns `responseTooLarge` rather than looping; and
- reset causes bounded re-enumeration without deleting independently verified local identity state.

For `v1/changes`, status `1` alone encodes `ResetRequired`. Its deterministic-CBOR response contains exactly labels `0: 1` and `1: 1`; entries, `nextCursor`, `hasMore`, `directoryGeneration` and `errorCode` are all forbidden. Status `2` requires an error code. Tests must reject every status/field combination forbidden by Section 12.6 rather than accepting it merely because the Appendix A CDDL marks the union fields optional.

### 9.4 Synchronization

Synchronization consumes another relay’s `v1/changes` feed. Full entries are untrusted candidates and pass through the ordinary ingress algorithm. References remain unverified routing hints.

Peer polling schedule, scope and retry policy are configuration, not protocol consensus. Tests use explicit deterministic synchronization calls rather than sleeping for timers.

### 9.5 Networking modes

Conforming public mode requires an advertised HTTPS base URI. The Rust process may run behind a TLS reverse proxy.

A development mode may permit plain HTTP only for loopback addresses and integration tests. It must be visibly marked non-conforming and must not permit accidental public binding without an explicit unsafe-development flag.

Reference traversal and WebFinger fetching must apply an explicit network policy. Default public operation rejects unsupported schemes, embedded credentials and unsafe redirect transitions. Private, loopback, link-local and otherwise sensitive destinations require an explicit local-development or operator policy; discovered endpoints are untrusted input and must not become unrestricted SSRF primitives.

## 10. Resolver and WebFinger

The resolver stores canonical Followee DIDs as durable keys. Cached names, handles, records and services are replaceable presentation state.

Implement the aggregate defaults in Section 14.1 with one shared operation budget. A relay or migration hop must never reset the deadline, byte, concurrency or visited-relay budget.

The resolver must:

- query multiple configured relays;
- locally verify every Full candidate;
- discard invalid candidates without treating them as valid `Absent` results;
- treat Absent and per-DID Error results as supplying neither a candidate nor a reference target;
- charge Absent and Error responses to the same shared operation budgets as other responses and continue while an unqueried relay selected for the operation remains reachable within those budgets;
- treat Error(`premature`) solely as the reporting relay's clock-dependent diagnostic and never transfer that classification to a Full candidate from that or another relay;
- leave cached identity and sticky authority state unchanged by Absent and Error results;
- traverse references through matching directory generations;
- perform cycle detection using the specified tuple;
- retain and apply sticky RootRevoked state;
- distinguish `notFound` from `temporarilyUnavailable`;
- expose freshness and staleness; and
- implement all three migration-check states without automatic re-following.

WebFinger support must verify the exact requested canonical `acct:` subject and require exactly one Followee DID relation. Handle claims in `alsoKnownAs` remain unverified until inverse lookup maps the exact handle back to the same DID. The demonstration handle authority must not assign ASCII-case variants under one domain to different DIDs; accepted variants are rejected or mapped as aliases to the same DID while exact-subject verification remains unchanged.

The public WebFinger demonstration is deferred until the local resolver and relay tests pass. It may then use a tiny independently deployed HTTPS function with a provider-assigned domain; no purchased custom domain is required for the proof of concept.

## 11. Test strategy

Testing is a primary deliverable, not cleanup after implementation.

### 11.1 Normative conformance tests

The implementation MUST reproduce Appendix B byte-for-byte, including:

- both public keys from the published seeds;
- revocation public-key CBOR and commitment;
- Authority Descriptor bytes, digest, multihash and DID;
- root and RootRevoked body bytes and digests;
- exact protected headers;
- exact `Sig_structure` bytes;
- exact signatures and complete envelopes;
- equal-time ordering; and
- the validly signed descriptor-substitution rejection.

Every mutation in Appendix B.7 must be represented as an executable negative test. The test should assert the intended symbolic error where the verification algorithm defines one, not merely assert generic failure.

The B.8 candidate must verify cryptographically under the attacker key but fail with `identityBindingMismatch` before it can be admitted or displayed.

#### Appendix B.7 fault isolation

Appendix B.7 describes logical rejection conditions, but a literal byte edit to signed material also invalidates the existing signature. Such an input is multi-fault and usually cannot constrain which symbolic error a conforming implementation reports. The executable bundle must therefore isolate the intended condition wherever possible.

When a case mutates the protected header or payload, regenerate the COSE signature with the applicable published private seed unless signature failure is itself the condition under test. Changing a signed field while retaining the old signature is not a single-fault test. Mutations confined to the COSE tag, unprotected headers, detached-payload representation or signature bytes do not require re-signing. Every case must declare the `faultProfile` and `errorAssertion` fields defined in Section 12 honestly.

Use the following construction plan:

| Appendix B.7 item | Required treatment |
| ---: | --- |
| 1 | Implement all three v0.4 identity-binding cases: (a) an unchanged internally consistent envelope verified against a different syntactically valid target DID; (b) a body `id` changed to another valid DID, re-signed with the applicable legitimate key and verified against the original target; and (c) that same re-signed mutation verified against the mutated target. Every case has exact error `identityBindingMismatch`. Case (a) may be classified as `multiple` because both body-to-target and descriptor-to-target comparisons fail, but the exact assertion remains portable because Section 8.1 normatively assigns the same error to both checks. Cases (b) and (c) isolate the two relations separately. |
| 2 | Use target-only cases without mutating the signed envelope. A structurally well-formed multihash using a code other than `0x12`, with declared length matching bytes present, has exact error `unsupportedHash`. Code `0x12` with a structurally well-formed digest length other than `0x20`, again matching the bytes present, also has exact error `unsupportedHash`. Add separate malformed cases for a missing or non-minimal varint, declared/actual length disagreement and trailing bytes, each with exact error `invalidDid`. The specification explicitly assigns these errors despite any additional body-to-target inequality created by changing the target. |
| 3 | Encode protected `alg = -8`, then re-sign the resulting `Sig_structure` with the legitimate applicable key so the unsupported suite is the only fault. |
| 4–6 | Mutate only the missing tag, non-empty unprotected map or detached-payload representation. Preserve the otherwise valid signed material and signature. |
| 7–10 | Make the intended deterministic-CBOR or schema mutation and re-sign the exact mutated payload with the legitimate applicable key. |
| 11 | Remove the RootRevoked record's label `5` and re-sign the mutated body with the published revocation private key; the fixture must fail for the missing required field rather than for a stale signature. |
| 12 | Put the published B.8 attacker revocation public key in Alice's RootRevoked body, retain Alice's original revocation commitment, and sign with the corresponding attacker revocation seed. Signature verification under the revealed key would succeed, leaving the commitment mismatch as the single fault and `invalidRevocationKey` as the exact error. A one-bit public-key mutation without its private key does not isolate this condition. |
| 13 | Change only one signature bit. Do not re-sign. |
| 14 | Use the exact `S + L` Followee-envelope fixture below for scalar canonicality. Test the harder point, subgroup and verification-equation cases with vetted external strict-Ed25519 primitive vectors unless a Followee-envelope construction is independently established. Do not hand-roll or casually re-sign these vectors. |
| 15 | Set `validUntil_ms < timestamp_ms` and re-sign the mutated payload with the legitimate applicable key. |
| 16 | Expand into boundary fixtures for each relevant aggregate hard limit. Re-sign whenever signed material changes, and construct each case so an earlier unrelated cap—especially the 16 KiB envelope limit—does not mask the intended failure. |

##### Item 14 strict-Ed25519 cases

The `S >= L` case is derived directly from Appendix B.4. Keep the B.4 body, target DID, descriptor, protected header, `Sig_structure` and signature `R` bytes unchanged. Interpret the original scalar as a little-endian integer, add the Ed25519 group order `L`, and replace only the 32 scalar bytes. Because `[S + L]B = [S]B`, a verifier that omits Section 3.3 rule 4 may accept it even though the encoding is non-canonical.

The exact mutated 64-byte signature is:

```text
4db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94
aa69aeecb156fa78fa072ff9a4e54a9e67103f9346dbef51c053cac381a50214
```

The complete case has `faultProfile: single`, `accepted: false`, `errorAssertion: exact`, and `error: invalidSignature`. It requires no new key, descriptor, payload or signature-generation operation. The fixture builder must independently recompute the scalar addition rather than merely copying these bytes.

Non-canonical point encodings, small-order points, subgroup failures and cofactored-versus-uncofactored verification divergence require carefully constructed material. A generic signing operation over a Followee `Sig_structure` normally destroys the property being tested. Cover these Section 3.3 rules first at the strict-verifier primitive boundary using well-understood published cross-implementation Ed25519 edge-case vectors with their original public key, message and signature bytes unchanged.

For every external cryptographic vector, record its stable source, vector identifier, retrieved artifact digest, licence, original expected result and the exact Section 3.3 rule exercised. Verify it independently before adoption. It is a primitive conformance fixture, not a complete Followee-envelope fixture. It may be promoted to a Followee-envelope fixture only if an equivalent construction over an actual Followee `Sig_structure` is mathematically justified and independently reproduced. Re-signing an external edge-case vector does not perform that adaptation.

Primitive fixtures must invoke the same production `crypto::verify_followee_ed25519` entry point used by record verification. They must not call a test-only strict helper or bypass wrapper. In addition, both record-path wiring tests from Section 6.2 must capture and compare the authority-specific public key, full message bytes and signature passed by their complete parsed envelopes. Together with the public-path B.4 `S + L` case and the mechanical direct-call restriction, this establishes that primitive conformance is connected to both record-verification authority branches rather than merely present somewhere in the codebase.

Before Milestone 1 begins, the protocol repository must replace or supplement Appendix B.7 with unambiguous construction recipes and expected errors. Until that amendment is committed and Section 2 is re-pinned, items 1 and 2 remain unresolved specification questions and the affected conformance cases remain `implementation` rather than `specification` fixtures.

Appendix B does not by itself cover every security-bearing branch in Sections 5 and 8. Milestone 1 therefore also requires locally authored, explicitly provisional tests for:

- the Section 5.4 future boundary immediately below, exactly at and immediately above `now_ms + MAX_FUTURE_SKEW_MS`;
- overflow-safe future-bound comparison;
- Section 5.5 `validUntil_ms` schema validity, freshness and staleness;
- stale RootRevoked records still activating revocation;
- Section 8.2 absolute RootRevoked precedence over a later-timestamp Root record;
- exclusion of every Root record after sticky revocation;
- absence of any “last good Root” fallback; and
- Section 8.5 behaviour after sticky state is deliberately discarded, distinguished from behaviour while it is retained.

These tests must not be represented as specification-published byte vectors until their expected results have the fixture provenance described in Section 12.

### 11.2 Requirement traceability

Tests for normative behaviour should include the specification section in their name or nearby documentation, for example:

```text
sec_8_1_rejects_valid_signature_with_substituted_descriptor
sec_13_2_losing_record_does_not_increment_update_number
```

Maintain a lightweight `tests/REQUIREMENTS.md` mapping every testable MUST/MUST NOT in implemented sections to one or more tests. Coverage percentages do not replace this map.

### 11.3 Unit and property tests

Property and state-machine tests must cover at least:

- canonical encoding determinism;
- accepted-value decode/encode stability;
- candidate winner independence from arrival order;
- duplicate admission idempotence;
- monotonic sticky revocation;
- inability of Root to displace RootRevoked;
- update-number changes if and only if admitted current identity state changes;
- cursor pagination without gaps;
- reset and restore behaviour;
- shared traversal budgets;
- reference and migration cycle detection; and
- checked arithmetic at timestamp and counter boundaries.

Randomized state-machine tests should generate sequences of valid, invalid, duplicate, losing, premature, RootRevoked and post-revocation Root candidates and compare the implementation against a deliberately simple Rust model.

That model is useful for catching state-machine implementation mistakes but is not independent evidence: it may share the production code’s author, language and interpretation of the specification. It must not be described as an interoperability check or substitute for the separately authored Python model below.

### 11.4 Independent Python core model

Create a small, deliberately direct Python implementation of Sections 3 through 8 under `tools/python-model/`. Its purpose is to detect comprehension errors shared by the Rust production code and its same-language test model.

Independence requirements:

- it is written in a separate clean session using only the pinned normative specification, Appendix B and fixture cases whose derivation status is `specification`;
- its authoring workspace and context exclude the Rust source, Rust tests, Rust implementation notes, all `implementation`-status fixtures, Rust-derived expected outputs and prior differential reports;
- it shares no protocol code, generated parser, fixture-producing code or algorithmic helper with Rust;
- its provenance records the specification commit and the independent authoring constraint; and
- the resulting code remains intentionally small and readable by a human reviewer.

Before any provisional case is revealed, the Python model and its authoring record must be reviewed and frozen at a recorded source commit or content digest. Only then may `implementation`-status inputs be supplied to the differential harness. Their Rust-derived expected outputs remain outside the Python authoring context: the frozen model computes its own results before the harness compares them. Agreement may promote an unchanged case to `confirmed`; disagreement opens a specification or implementation review issue. Running provisional fixtures through a model that saw their expected outputs while it was being written is not independent confirmation.

The Python model must independently implement enough of Sections 3 through 8 to derive DIDs, preserve and validate deterministic CBOR bytes, reconstruct the COSE `Sig_structure`, perform Followee-strict Ed25519 verification, classify verification results and select candidates. A library’s ordinary Ed25519 verifier is insufficient unless its behaviour is demonstrated to satisfy every Section 3.3 requirement or supplemented with explicit checks. Library documentation or successful rejection of one malformed signature is not evidence for the remaining rules: run the B.4 `S + L` envelope case and the adopted primitive edge-case vectors explicitly against the Python verifier.

Differential testing rules are:

- every shared fixture must produce the expected accept/reject result, and cases with `errorAssertion: exact` must also produce the specified symbolic error;
- valid randomized structured inputs must produce identical deterministic bytes, DIDs, digests, signatures, verification results and winners for the operations both models implement;
- arbitrary malformed fuzz inputs must produce identical accept/reject results; and
- exact error equality for an input violating several independent rules is required only where the specification defines precedence, because Section 8.1 permits cheap independent checks to be reordered.

Any disagreement is resolved from the normative specification, not by majority vote between implementations. The Python model is independent core evidence but does not alone satisfy Section 20.4, which also requires the broader authoring, selection and HTTP/CBOR exchange behaviours stated there.

### 11.5 Fuzzing

Fuzz at least:

- DID parsing;
- deterministic CBOR validation;
- complete COSE envelope parsing;
- record verification;
- relay API CBOR parsing;
- cursor decoding; and
- WebFinger response parsing.

For arbitrary input, the implementation must not panic, hang, perform unbounded allocation, read beyond input, or accept a value only after silently normalising forbidden encoding.

Keep a short bounded fuzz smoke run in CI and document commands for longer local campaigns.

### 11.6 Integration tests

Black-box tests should start real server instances with isolated temporary SQLite databases and exercise actual HTTP bytes.

The eventual integration suite must demonstrate:

- publication and exact-byte resolution;
- multiple DIDs in aligned batches;
- response-size splitting behaviour;
- two relays learning updates through `v1/changes`;
- three updates coalescing into one current tuple;
- differing relay views converging when information is exchanged;
- references, directory generations and lazy path compression;
- reference cycles and unreachable endpoints;
- cursor reset, including the exact two-field `ResetRequired` response followed by bounded null-cursor enumeration;
- all `changes` status-dependent required and forbidden field combinations, including rejection of every label `2` through `6` on status `1`;
- a stored Full record becoming premature after an injected backwards clock correction, producing Error(`premature`) without a state or update-number change;
- one relay returning Absent and another Error(`premature`) before a further selected relay returns a valid Full candidate, with resolution continuing and the candidate classified only by the client's injected clock;
- Absent and Error results leaving cached identity and sticky authority state unchanged;
- sticky revocation surviving Full-to-Ref conversion;
- withheld and stale records;
- handle discovery and inverse verification; and
- reciprocal and non-reciprocal migration claims.

Tests must use injected clocks or explicit operations. Do not make correctness depend on arbitrary sleeps.

### 11.7 CI quality gates

CI must run, at minimum:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo audit
cargo deny check
```

CI should also run fixture verification, a bounded fuzz smoke suite and coverage reporting. Target at least 90% line coverage for the protocol core, while requiring direct tests for every implemented normative branch regardless of aggregate coverage.

CI must enforce the Section 6.2 direct-verification-call restriction. If the selected enforcement uses Clippy's disallowed-method configuration, the configuration and its narrowly scoped wrapper allowance are committed and covered by a small guard test or CI check that would fail if an alternate call site were introduced.

At every protocol-core milestone review, run targeted mutation testing with `cargo-mutants` and retain its report as review evidence. Every surviving mutant in security-sensitive or normative core code must be killed by an added test or individually explained; line coverage alone does not show that executed behaviour is constrained. Mutation testing may run at milestone gates rather than burdening every ordinary push.

No test may depend on the public Internet unless it is clearly separated as an opt-in deployment smoke test.

## 12. Machine-readable conformance fixtures

The shared fixture bundle ultimately belongs in the platform-neutral `followee` protocol repository, not solely in this implementation repository.

This implementation should propose a bundle containing:

- a versioned manifest;
- structured authoring input where applicable;
- exact binary CBOR/COSE files;
- target DID;
- recipient time where relevant;
- expected accept/reject result;
- a machine-readable fault profile;
- an error-assertion mode and expected symbolic error where applicable;
- expected body digest, authority, timestamp and freshness where relevant; and
- provenance containing relevant specification references, derivation status and independent confirmations.

Each case must classify its fault shape as `none`, `single`, `multiple` or `unknown`. Fault shape and error assertion are separate properties. A rejecting case uses `errorAssertion: exact` only when the fixture is intended to constrain a particular symbolic error; it then must include `error`. It uses `errorAssertion: unspecified` when only rejection is portable and must then omit `error`. An accepting case omits both fields.

For example:

```json
{
  "faultProfile": "single",
  "expected": {
    "accepted": false,
    "errorAssertion": "exact",
    "error": "identityBindingMismatch"
  }
}
```

```json
{
  "faultProfile": "multiple",
  "expected": {
    "accepted": false,
    "errorAssertion": "unspecified"
  }
}
```

Multi-fault cases normally assert only acceptance or rejection because Section 8.1 permits independent cheap checks to be reordered. They may assert an exact error when the normative specification itself defines precedence. The manifest schema must reject inconsistent combinations, such as `exact` without `error`, `unspecified` with `error`, or an accepted result carrying either error field.

Each case has one derivation status:

| Status | Meaning |
| --- | --- |
| `specification` | The exact expected value or result is published normatively in the pinned specification, such as Appendix B bytes. A section citation alone does not qualify. |
| `implementation` | The expected value is provisional and has so far been derived or reproduced by only one implementation, even if it is believed to follow normative prose. |
| `confirmed` | The expected value has been independently reproduced by at least two implementations sharing no protocol core. |

The manifest should record the producing implementation and confirmations without treating either as an authority. A case may advance from `implementation` to `confirmed`; its bytes and expected result must not change during that promotion. A mismatch creates a review issue rather than silently replacing the fixture.

For a derived negative vector, provenance must additionally identify its positive base vector, the logical mutation, whether protected or payload bytes changed, whether the envelope was re-signed, and which published test key was used. For an externally sourced cryptographic primitive vector, record the source and artifact details required by Section 11.1 instead. This makes accidental stale-signature faults and decorative edge cases detectable during review without treating the fixture generator as authoritative.

The Python clean-room authoring session receives only `specification`-status fixtures. All provisional cases and their expected values are withheld until the model is frozen as required by Section 11.4. Afterward, the harness may expose their input bytes to the frozen model and compare independently computed outcomes. Confirmation records must identify the frozen model revision. Merely replaying an expected value that influenced the model’s construction cannot promote a fixture.

JSON may be used for the manifest, with binary artifacts stored as files rather than enormous embedded hexadecimal strings. The manifest format is a testing interchange format, not a Followee wire protocol.

The Rust implementation must consume the published fixture files as external inputs. It must not generate the expected value using the same function under test and then compare the function with itself.

Interoperability and conformance reports must state which fixture subset they exercised. Agreement on `implementation` cases demonstrates reproduction of provisional expectations; only the `confirmed` subset has independent cross-implementation confirmation. This status does not replace the full Section 20.4 interoperability criterion.

## 13. Milestones and acceptance criteria

The following gate applies to every milestone: no unresolved `SPEC-QUESTIONS.md` entry may affect code delivered by that milestone. If the normative specification changes, re-pin Section 2 and rerun the complete suite before accepting new work.

### Milestone 0: scaffold

Deliver:

- Rust package and committed lockfile;
- module skeleton only where immediately needed;
- formatting, linting and test CI;
- `#![forbid(unsafe_code)]` at the crate root;
- `cargo-audit` and `cargo-deny` configuration;
- `SPEC-QUESTIONS.md`, recording identified protocol questions and their resolution status; entries through the code-`7` symbolic rename and non-authoritative Absent/Error client rules must cite their resolution in specification v0.4 at the pinned commit rather than remain open;
- injected clock and randomness traits; and
- documented developer commands.

Acceptance:

- clean format and lint;
- tests run on a fresh clone; and
- no protocol behaviour is claimed yet.

### Milestone 1: protocol core and Appendix B

Deliver:

- strict CBOR subset;
- exact COSE Sign1 profile;
- key and descriptor handling;
- DID parsing and derivation;
- Contact Document and record schemas;
- signing, verification, digesting and ordering;
- the sole production strict-Ed25519 entry point and mechanical direct-call restriction; and
- complete Appendix B tests.

Acceptance:

- every published positive byte sequence reproduces exactly;
- every required negative mutation is rejected;
- every Appendix B.7 case follows the fault-isolation plan in Section 11.1 and records its construction provenance;
- no case asserts an exact non-signature error while also retaining a signature invalidated by its mutation;
- the B.4 `S + L` signature is independently recomputed, rejected as `invalidSignature`, and remains otherwise byte-identical to the positive case;
- adopted point, subgroup and verification-equation vectors retain their published primitive inputs, pass provenance review, and are not mislabelled as complete Followee envelopes;
- every primitive Ed25519 vector executes through the production strict-verification entry point used by record verification;
- the B.4 Root wiring test delegates exactly once with the descriptor's exact root public key, COSE `Sig_structure` and received signature;
- the B.5 RootRevoked wiring test delegates exactly once with label `5`'s exact revealed revocation public key, COSE `Sig_structure` and received signature;
- the public B.4 `S + L` test uses the non-injectable production record-verification wrapper;
- CI rejects direct underlying-library verification calls outside the audited strict wrapper;
- the Appendix B.7 item 1 and item 2 fixtures exactly implement the binding and hash-error classifications fixed by specification v0.4 at the pinned commit;
- B.8 fails specifically with `identityBindingMismatch` despite a valid attacker signature;
- future-bound, stale-record, absolute RootRevoked-precedence, no-fallback and sticky-state-loss tests described in Section 11.1 pass;
- no untrusted parser panic under the initial fuzz corpus;
- all implemented MUST/MUST NOT requirements are mapped to tests; and
- targeted `cargo-mutants` output has no unexplained surviving mutant in normative or security-sensitive core code.

Do not begin relay code before this milestone passes.

### Milestone 1.5: independent Python core model

Deliver:

- the small Python model described in Section 11.4;
- an authoring record showing it was produced in a separate session using only the pinned specification and `specification`-status fixtures, without access to Rust source or Rust-derived material;
- a recorded commit or content digest freezing the reviewed model before provisional fixtures are revealed;
- independent Appendix B reproduction;
- a differential harness that supplies provisional inputs only after the freeze and does not feed their expected outputs into model authoring; and
- curated and randomized differential cases with the comparison rules in Section 11.4.

Acceptance:

- the allowed authoring inputs and excluded Rust-derived inputs are recorded and auditable;
- Appendix B positive values are independently reproduced rather than imported from Rust output;
- the model’s frozen revision predates its first access to any `implementation`-status fixture;
- shared fixtures agree on acceptance or rejection, and every case marked `errorAssertion: exact` agrees on the specified symbolic error;
- valid randomized shared operations agree on bytes and semantic results;
- arbitrary malformed inputs agree on acceptance versus rejection;
- fixture promotion follows Section 12 without changing the original bytes or expected result;
- every disagreement is resolved against the specification and retained as a regression test; and
- the model is small enough for direct human review and makes no claim to full Section 20.4 interoperability.

The Python model may be commissioned before or after Rust Milestone 1, but its clean authoring session must not inspect Rust or provisional fixture material. Do not begin relay code until both Milestone 1 and Milestone 1.5 pass.

### Milestone 2: authoring and inspection CLI

Deliver:

- identity creation;
- root record signing;
- RootRevoked record signing;
- verification and inspection;
- deterministic candidate selection;
- friendly complete-document JSON input; and
- safe local test-key storage.

Acceptance:

- a shell-level test creates a new DID, signs a record and verifies it;
- a separately stored revocation key creates a winning RootRevoked record;
- a later Root record cannot be selected after sticky revocation; and
- no ordinary output or failure path reveals a secret key.

### Milestone 3: single relay

Deliver:

- SQLite state;
- atomic ingress algorithm;
- `v1/info`, `v1/resolve`, `v1/directory`, `v1/publish` and `v1/changes`;
- opaque cursors and reset behaviour; and
- black-box HTTP/CBOR tests.

Acceptance:

- the relay passes Sections 20.1 and 20.2 tests applicable without peers;
- update numbers change exactly when specified;
- resolve distinguishes Absent from a retained but presently premature record;
- `changes` uses the exact two-field status-`1` response as the sole ResetRequired signal, forbids labels `2` through `6` in that response, and enforces every other status-dependent field rule;
- restart preserves identity, generation and sticky authority state; and
- malformed and oversized input is bounded before expensive processing.

### Milestone 4: resolver and relay network

Deliver:

- client traversal budgets;
- reference traversal and cycle detection;
- current-state synchronization;
- peer cursor persistence;
- lazy path compression; and
- a deterministic three-relay local demonstration.

Acceptance:

- relays can begin with different partial views;
- one relay can synchronize a newer record without historical events;
- a client follows references but verifies the final Full locally;
- a client continues past Absent and Error results while another relay selected for the operation remains unqueried within the shared budgets;
- Error(`premature`) from one relay cannot classify or suppress a Full candidate obtained from that or another relay, and the candidate is checked using the client's injected clock;
- Absent and Error results cannot alter cached identity or sticky RootRevoked state;
- cycles and unavailable peers terminate within shared budgets; and
- synchronized invalid or losing input does not alter current state.

### Milestone 5: handles and public demonstration

Deliver:

- WebFinger lookup;
- inverse handle verification;
- optional current-record bootstrap;
- migration presentation states; and
- a minimal HTTPS handle authority deployed on a provider-assigned domain.

Acceptance:

- exact-subject and exactly-one-link requirements are tested;
- ASCII-case variants cannot be assigned to different DIDs by the demonstration authority;
- a signed `alsoKnownAs` claim is not called verified without inverse mapping;
- disappearance or reassignment of a handle does not change the followed DID;
- invalid bootstrap records are discarded locally; and
- the demonstration works without an ICP dependency or purchased domain.

### Milestone 6: external interoperability

Deliver:

- published neutral fixture bundle;
- documented HTTP transcript examples;
- release binaries or reproducible build instructions; and
- an interoperability run against the independent Motoko implementation when available.

Acceptance follows Section 20.4 of the protocol specification. No implementation may be described as interoperable merely because it communicates with another process built from the same core library.

## 14. Agent working rules

An AI coding agent working from this brief should:

1. read the complete pinned Followee specification before designing protocol types;
2. implement one milestone at a time;
3. begin each milestone with tests and a short plan;
4. prefer simple explicit protocol code over abstraction-heavy frameworks;
5. preserve raw wire bytes through verification;
6. avoid speculative extensibility beyond protocol v1;
7. run formatting, linting and the relevant tests after every material change;
8. report exact commands and results;
9. identify specification ambiguity rather than silently resolving it;
10. avoid changing protocol documents from the implementation repository;
11. avoid committing, pushing, publishing or deploying unless explicitly asked; and
12. stop at the current milestone’s acceptance criteria for review.

For the first coding session, the agent should perform Milestone 0 only, then present the scaffold and CI for review. It should not begin cryptographic or CBOR implementation in the same unreviewed pass.

The Python model must be assigned through a separate clean session whose context contains the pinned protocol specification and `specification`-status fixtures only. It must not receive Rust source, tests, implementation notes, provisional fixtures, Rust-derived expected outputs or differential reports until the reviewed model is frozen at a recorded revision. Do not ask the Rust implementation agent to produce its own “independent” model after reading the production code; independence cannot be added as a comment after the fact.

## 15. Definition of v0.1 completion

The Rust implementation reaches v0.1 when:

- Milestones 0 through 5, including Milestone 1.5, pass locally and in CI;
- all claimed protocol roles satisfy their conformance requirements;
- the shared fixture bundle is published in the protocol repository;
- no known specification ambiguity is hidden in implementation behaviour;
- security-sensitive dependencies and strict-verification assumptions are documented;
- a clean checkout can reproduce tests and binaries from documented commands;
- the three-relay demonstration is repeatable without privileged infrastructure; and
- the repository clearly states that the specification, not this code, is normative.

External interoperability with the Motoko implementation is the next release gate, not something the Rust implementation can prove alone.
