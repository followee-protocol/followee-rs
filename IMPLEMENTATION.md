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
- pinned repository commit: `ac5a794f2fdadc13cddf5367fa3e047617e3e950`
- reviewed protocol-document tag: `v0.9.2-reviewed`
- specification revision commit: `f1d19fec0dba455d90d473bfad625d1c288e0c15`
- specification SHA-256: `47af5fbf0c4505386b4e04d948ef89d013f878ea820fb02522817661d633633a`
- specification draft: `v0.9.2`
- whitepaper: `Followee-Whitepaper.md`
- whitepaper revision commit: `ac5a794f2fdadc13cddf5367fa3e047617e3e950`
- whitepaper SHA-256: `dc106ee10741d5a8b157447b0f256eb61435ea036a4616e862387658e60c8387`
- whitepaper draft: `v0.10.1`
- protocol version: `1`
- DID method: `did:flw`

The whitepaper is design rationale, not a wire-format authority.

The implementation MUST NOT silently invent behaviour when the specification is ambiguous. Record the ambiguity in `SPEC-QUESTIONS.md`, write the smallest failing or pending test that demonstrates it, and resolve it in the protocol repository before depending on an interpretation.

`SPEC-QUESTIONS.md` must begin with a compact resolution index covering every named question category in the file. For each category, the index records the relevant SQ entries, affected surface, resolving specification revision and commit, present status, and the regression or conformance evidence that pins the resolution. The index is an audit aid rather than a substitute for the full question history, and must be updated whenever a category or resolution is added.

No milestone may pass while `SPEC-QUESTIONS.md` contains an unresolved question that affects code in that milestone. If resolving a question amends the normative specification, update the pinned commit in this section, record the change in the implementation repository, and rerun the complete applicable conformance and differential suite. A previous green result against another commit is not inherited automatically. Evidence for a demonstrably unchanged, out-of-scope surface may be retained only when the amendment explicitly leaves that surface unchanged and this brief records the scope argument and immutable evidence revisions.

The v0.8 amendment preserves the earlier Alice positive vectors but changes normative CBOR error classification, adds Bob and fault-isolated basic-validity vectors, and fixes relay batch-isolation and synchronization-progress rules. A previous green result against v0.7 remains useful evidence but is not a v0.8 result. Rust and the independently maintained Python model must be updated from the pinned specification in separate maintenance passes; the Python pass must be reviewed and frozen before it receives Rust changes, outputs, fixtures or differential results. The neutral harness must then rerun the complete corpus rather than only new cases. Its report must preserve the v0.7 fixture-bundle digest and baseline metrics and separately count acceptance/rejection disagreements, permitted symbolic differences on unspecified multi-fault inputs, and genuine specification ambiguities.

The v0.8.1 amendment is deliberately narrow. It clarifies that a well-formed, basically valid, deterministically encoded CBOR simple value not admitted by a v1 schema is a schema fault, not a deterministic-profile fault, and adds the two signed Appendix B.12 vectors. A previous green result against v0.8 remains useful evidence but is not a v0.8.1 result. Rust and Python must again be maintained independently from the pinned text before the neutral harness is re-pinned. The complete v0.8.1 suite must be rerun; no prior result, fixture promotion or disagreement count is inherited automatically.

The v0.9 amendment is relay-only. It closes the concurrent-ingress cursor-overtaking hazard by requiring update-number assignment, state commitment and changes-feed visibility to form one observable order. Sections 3 through 8, every record and envelope byte, and Appendix B.2 through B.12 are unchanged. The reviewed v0.8.1 Rust core, clean-room model, 218-of-218 differential result and 53 confirmed fixtures therefore remain applicable evidence for that unchanged core; they are not rewritten or relabelled as newly derived v0.9 evidence. The bounded Rust relay maintenance pass is reviewed at `497d57c1b1fce53b1e4c89747ef454d6b3f9a7b5` (`milestone-3-v0.9-reviewed`): it audits the invariant against both production backends, moves expensive state-independent verification outside the relay write-critical section, and adds deterministic concurrency and controlled-fault evidence while preserving all prior Milestone 2 and 3 behaviour. The resolver and relay-network milestone is reviewed at `c74d59d20945e103e9b208413156922cd5be8a49` (`milestone-4-v0.9-reviewed`): it adds the bounded production HTTP/CBOR client, peer synchronization receiver with durable cursors, shared-budget multi-relay resolution, direct network CLI surfaces and the deterministic three-relay demonstration. A new clean-room core-model maintenance pass was not required solely for that amendment because the model's Sections 3-through-8 scope did not change. The reviewed relay work remains evidence at its v0.9 pin; subsequent work pins the current specification revision stated above.

The v0.9.1 amendment resolves the Milestone 5 migration-state ambiguity recorded as SQ-20 without changing wire bytes, cryptography, record verification, ordering, relay ingress, cursor semantics or the Appendix B vectors. A reciprocal check that obtains both winning admissible records but finds either one stale is complete and therefore **Checked but unverified**; diagnostics may distinguish `claimantStale` from `counterpartStale`. **Not checked** is reserved for checks that did not complete because they were deferred, exhausted their shared budget, timed out, encountered unavailability or found no admissible counterpart. Neither state permits migration-oriented presentation or changes durable identity state. The existing core and v0.9 relay evidence remained applicable, and the reviewed Milestone 5 resolver implements this classification through its production path.

The v0.9.2 amendment resolves the publish-response field-presence ambiguity exposed by the first Rust–Motoko interoperability campaign. Status `0` forbids `errorCode`; status `1` permits it only as an accurate `losingRecord` or `duplicate` diagnostic; status `2` requires it and forbids those two no-change codes. Any other combination is malformed and the complete response is rejected. A conforming status-`2` publication rejection remains successful HTTP-layer protocol processing and SHOULD use HTTP `200`. Both status-`1` encodings observed in Campaign 1—with and without the permitted diagnostic—remain conforming and must remain visibly distinct in reports rather than being normalized. This is a normative relay-wrapper change, so specification Section 20.4 requires the complete conformance and interoperability campaign to be rerun against one pinned v0.9.2 bundle and participant set; a publish-only rerun is insufficient. Cryptography, record bytes, ordering, cursor visibility and every Appendix B vector remain unchanged, so the frozen v0.8.1 Python core-model evidence remains applicable to its unchanged Sections 3-through-8 scope and is not rewritten as v0.9.2 evidence.

## 3. Implementation status and naming

The repository is `followee-protocol/followee-rs`.

It is the first implementation but is not a privileged “reference truth.” Public documentation should describe it as:

> A non-normative Rust implementation of the Followee DID method and relay protocol.

The independent Motoko implementation is maintained at <https://github.com/followee-protocol/followee-motoko>. Its first implementation was authored from the sealed v0.9.1 authoring subset and frozen at `3840d9adf07755d326d920f4711dafc4e08bcb40` (`motoko-v0.9.1-independent-freeze`) before coordinator expectations, Rust source or campaign results were revealed. That tag and its recorded challenge output remain immutable independence evidence; later corrections and transport work descend from it and do not rewrite or retag it.

Reviewed Rust milestones 0 through 5 are complete through tag `milestone-5-v0.9.1-reviewed` at `8606a102bfb4f2bbfbc81e364bdf548c437bf123`; Milestone 4 remains preserved at `c74d59d20945e103e9b208413156922cd5be8a49` (`milestone-4-v0.9-reviewed`). The neutral v0.9.1 bundle is reviewed at `c90742eb763cda5bd3c6e7d20ab1799590da489b` (`v0.9.1-interop-bundle-reviewed`). Campaign 1 is preserved at `515f37d86a35937b3539bfafdd671291d6abb443` (`v0.9.1-interop-campaign-1`): its 76 expected-vector cases and 36 blind challenges had zero unexplained protocol disagreements, and its Rust-serving live exchange completed, but its Motoko-serving direction lacked the full HTTP/CBOR role surface. It therefore made no complete Section 20.4 interoperability claim. Milestone 6 is the active release gate and must complete the v0.9.2 work specified below without altering any of those historical tags or reports.

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

Candidate selection MUST take the expected target DID explicitly. It MUST NOT infer the selected identity from candidate arrival order. Verified records for other DIDs may be ignored or reported diagnostically, but they cannot choose the subject, winner, or sticky authority state for the target operation.

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
- production commands reject exact matches for all published Appendix B secret seeds: both B.2 root and revocation seeds, both B.8 attacker root and revocation seeds, and both B.9 Bob root and revocation seeds;
- secret buffers are zeroised where practical; and
- the CLI prominently warns that local files are demonstration custody, not a production vault.

The creation command should permit the revocation key to be written directly to a different path or removable medium.

### 7.5 Authoring format

The CLI may accept a friendly JSON Contact Document using field names rather than CBOR labels. This JSON is an implementation convenience and is not a Followee wire format.

It MUST map unambiguously to the normative Contact Document, reject unknown fields by default, enforce all limits before signing, and always create a complete document rather than a delta. Service `mediaType`, `language`, and `rel` values MUST use the fixed, registry-independent grammars introduced in specification v0.6 Section 7.3 and retained by v0.9.2; authoring and verification paths must apply the same grammar. Every URI-valued field MUST use the pinned v0.9.2 Section 7.2 `URI` production, including optional query and fragment components, rather than the fragment-excluding RFC 3986 `absolute-URI` production.

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
followee handle serve
```

Exact flag names may evolve, but commands MUST support non-interactive use and machine-readable output for tests.

`record inspect` must clearly distinguish raw parsed claims from locally verified facts. It must not display a Contact Document as verified when verification was skipped or failed.

`record select` requires an explicit target DID, accepts candidates in arbitrary order, and returns the same winner and metadata for every permutation. Adding or reordering valid records for unrelated DIDs MUST NOT change the target, winner, or sticky authority state.

Milestone 5 owns the three handle commands. `handle resolve` performs production WebFinger discovery and reports the exact-subject and link-cardinality result. `handle verify` combines a locally verified Followee record with inverse WebFinger discovery and reports the handle claim as verified only when both directions bind to the same DID. `handle serve` is the minimal demonstration-authority process: it serves the JRD documents used by local black-box tests and may run behind provider HTTPS termination for the public demonstration. These commands must call the production WebFinger, verification and authority components rather than reproducing their decisions in CLI code.

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

Publish-response encoding and decoding must enforce specification v0.9.2 as a status-dependent union, not merely accept the Appendix A CDDL shape. Status `0` forbids `errorCode`. Status `1` accepts either no code or exactly the accurate `losingRecord`/`duplicate` diagnostic; the Rust server may retain its deterministic no-code encoding. Status `2` requires a registered rejection code other than those two. The receiver rejects the complete response for every other combination, including every registered status-`1` code outside `losingRecord` and `duplicate`. A conforming status-`2` protocol rejection is carried in the normal HTTP `200` response body; it is not converted into a transport error.

Before returning a stored Full result, the relay repeats the future-bound check against its current injected clock. A stored record that has become premature is not returned as Full or conflated with Absent: the relay returns a usable Ref or the per-DID `premature` Error result. This serving-time decision must not mutate the stored entry, change `lastUpdated`, or increment the relay-local update number.

### 9.2 Storage

Use SQLite transactions to make current-state replacement, sticky authority-state changes and relay-local update-number assignment atomic.

The write-critical section must include the final current-state comparison, sticky-authority enforcement, update-number assignment and state commit. Update numbers are assigned only inside the transaction that commits the winning state; `commit_current` is the sole assigner. The relay MUST NOT reserve or expose a sequence number and then commit its corresponding entry later, because a concurrent `changes` reader could return a cursor beyond an undecided lower number and permanently hide that later commit.

Perform bounded size checks, deterministic-CBOR validation, signature verification, descriptor work and other expensive candidate preparation before entering the write-critical section. Recheck every state-dependent admission condition inside it. SQLite's serialized writer transaction is the preferred v1 mechanism: readers may remain concurrent, but accepted writers pass through one allocation-through-commit order. Another mechanism is conforming only if it provides the same observable guarantee, for example by retaining a contiguous visibility watermark that cannot cross an unresolved lower update number.

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

Under concurrent ingress, a successful response's `nextCursor` MUST NOT advance beyond an update whose admission or commit remains undecided and that may later become visible. A cursor may expose only a contiguous committed prefix of the relay-local update order. Cancellation, rollback, duplicate or losing admission, and process failure must not leave a permanently blocking hole.

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

Migration classification follows specification v0.9.2 exactly, retaining the v0.9.1 clarification unchanged. **Verified** requires both winning admissible records, both fresh, and reciprocal. A completed check with either winning record stale or with failed reciprocity is **Checked but unverified**. **Not checked** means the reciprocal check did not complete. Tests must exercise stale claimant and stale counterpart cases separately, preserve the reason for diagnostics, suppress migration presentation in both cases, and prove that neither classification mutates the followed DID, cached identity record or sticky authority state.

WebFinger support must verify the exact requested canonical `acct:` subject and require exactly one Followee DID relation. Handle claims in `alsoKnownAs` remain unverified until inverse lookup maps the exact handle back to the same DID. The demonstration handle authority must not assign ASCII-case variants under one domain to different DIDs; accepted variants are rejected or mapped as aliases to the same DID while exact-subject verification remains unchanged.

The public WebFinger demonstration is deferred until the local resolver and relay tests pass. Its canonical reproducible deployment target is a container on Railway using the provider-assigned HTTPS domain, the platform-supplied `PORT`, and an explicitly configured public base URI. The image and start command must contain no private key or deployment credential; the demonstration authority publishes only reviewed public configuration and signed public record bytes. A purchased custom domain is not required.

Retain a provider-neutral VPS deployment beside the Railway path: the tested authority binary behind Caddy or nginx for HTTPS termination, with a hardened systemd unit and exact operator probes. This alternative is useful for an operator who already controls a server, but it is not required for the vanilla reproducible acceptance path. The Milestone 5 authority is immutable and needs no database. For later relay deployment tests, the Railway documentation may additionally describe mounting a persistent volume at `/data` and placing the SQLite database there; that optional profile must not be conflated with the stateless handle authority.

The reviewed Railway authority, the retained VPS profile and any ICP apex-canister deployment spike are alternative deployment targets, not cumulative release gates. Milestone 6 requires the complete reproducible build and loopback interoperability evidence in Section 13; it does not require a second public authority deployment or an ICP deployment unless one is separately chosen as a participant-hosting experiment. Such an experiment must be labelled optional and must not be used to paper over missing participant-owned HTTP/CBOR behaviour.

## 11. Test strategy

Testing is a primary deliverable, not cleanup after implementation.

### 11.1 Normative conformance tests

The implementation and neutral fixture tooling MUST reproduce every computable Appendix B value byte-for-byte. Sections B.2 through B.10 and B.12 are protocol-core obligations for Milestone 1; B.11 request and response bytes and digests are reproduced immediately, while their HTTP, client and synchronization behaviours become acceptance gates in Milestones 3 and 4. Reproduction includes:

- all public keys from the published seeds;
- revocation public-key CBOR and commitments;
- Authority Descriptor bytes, digests, multihashes and DIDs;
- root and RootRevoked body bytes and digests;
- Bob's complete positive body and envelope;
- exact protected headers;
- exact `Sig_structure` bytes;
- exact signatures and complete envelopes;
- equal-time ordering;
- the validly signed descriptor-substitution rejection; and
- every B.10, B.11 and B.12 stated length and SHA-256 digest.

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
| 17 | Replace unsigned-integer label `0` or `1` with the CBOR simple value `false` or `true` in the Authority Descriptor and nested public-key object. Cover both Boolean values at both schema levels. At least one complete case must derive its target DID from the Boolean-labelled descriptor and carry a valid signature from that descriptor's applicable key, isolating exact `schemaViolation` rather than signature or identity-binding failure. |
| 18 | Use the four exact Appendix B.10 invalid-UTF-8 bodies, each re-signed by Alice's legitimate root key. Preserve the invalid received text bytes without decoding, replacement or normalization. Each is a single-fault case with exact error `invalidCbor`; a stale signature would turn it into a different test. |
| 19 | Use both exact Appendix B.12 bodies and signatures. The deterministic-CBOR layer must admit simple value 16 (`f0`) and simple value 32 (`f8 20`); the extension-value schema must then reject each complete, correctly signed record with exact `schemaViolation`. Keep `undefined` (`f7`) separately rejected as `nonDeterministicCbor` by the profile. |

Appendix B.9 is a second complete positive identity, not merely seed material. Reproduce Bob's keys, commitment, descriptor, DID, body, `Sig_structure`, digest, signature and envelope exactly, and use Alice and Bob together to test cross-DID state isolation. Appendix B.10's adjacent-duplicate map vector and four invalid-UTF-8 vectors are normative `invalidCbor` cases. The duplicate must remain weakly key-sorted so duplication is its only fault; all five exact raw bodies and signatures must be consumed from specification-derived fixtures rather than recreated as implementation expectations.

Appendix B.12's two records are normative `schemaViolation` cases. Their simple values are not basic-validity or deterministic-profile faults. Test the boundary twice: the public deterministic-CBOR validation entry point accepts each value under sufficient limits, while complete record verification rejects the exact signed envelope at the applicable extension-value schema. This proves that the classification did not merely change names while remaining in the wrong layer.

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

Specification v0.4 resolved the former Appendix B.7 item 1 and item 2 ambiguities with unambiguous constructions and expected errors. Specification v0.7 added item 17, v0.8 added item 18 and the fault-isolated B.10 basic-validity vectors, and v0.8.1 adds item 19 and the fault-isolated B.12 schema vectors. A fixture is `specification`-status only when it follows the applicable normative construction exactly; merely citing the appendix does not promote independently chosen bytes or a multi-fault mutation.

Appendix B does not by itself cover every security-bearing branch in Sections 5 and 8. Milestone 1 therefore also requires locally authored, explicitly provisional tests for:

- the Section 5.4 future boundary immediately below, exactly at and immediately above `now_ms + MAX_FUTURE_SKEW_MS`;
- overflow-safe future-bound comparison;
- Section 5.5 `validUntil_ms` schema validity, freshness and staleness;
- stale RootRevoked records still activating revocation;
- Section 8.2 absolute RootRevoked precedence over a later-timestamp Root record;
- exclusion of every Root record after sticky revocation;
- absence of any “last good Root” fallback; and
- Section 8.5 behaviour after sticky state is deliberately discarded, distinguished from behaviour while it is retained.

Specification v0.9.2 Section 20.1 retains the URI-profile cases introduced in v0.7, which:

- accept scheme-bearing URIs with optional queries and fragments, including `https://example.com/profile?view=full#about` and `did:web:example.com#key-1`;
- reject network-path, absolute-path, relative-path, query-only and fragment-only references;
- accept otherwise valid RFC 3986 `IPvFuture` hosts introduced by either lowercase `v` or uppercase `V`; and
- exercise the same URI parser through every Contact Document position that admits a URI, rather than testing a helper that the record path does not call.

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
- deterministic concurrent-ingress interleavings in which a later writer attempts to commit while an earlier writer is paused, proving that no successful `changes` response can overtake an entry that later becomes visible;
- reset and restore behaviour;
- shared traversal budgets;
- reference and migration cycle detection; and
- checked arithmetic at timestamp and counter boundaries.

Randomized state-machine tests should generate sequences of valid, invalid, duplicate, losing, premature, RootRevoked and post-revocation Root candidates and compare the implementation against a deliberately simple Rust model.

That model is useful for catching state-machine implementation mistakes but is not independent evidence: it may share the production code’s author, language and interpretation of the specification. It must not be described as an interoperability check or substitute for the separately authored Python model below.

### 11.4 Independent Python core model

Maintain the small, deliberately direct Python implementation of Sections 3 through 8 in the separate public repository <https://github.com/followee-protocol/followee-python-cleanroom>, under that repository's `tools/python-model/` path. Its purpose is to detect comprehension errors shared by the Rust production code and its same-language test model. It MUST NOT be copied into this repository or made dependent on the Rust crate.

The independently authored baseline and reviewed maintenance lineage are preserved as follows:

| Artefact | Revision |
| --- | --- |
| Approved-input commit | `70b393fa15d7fa550b1864ff28a86a8a20726561` |
| Original independently authored freeze | `7ca1f623453065deefd1e6cfdf15e135d523dd7e` (`cleanroom-v0.6-freeze`) |
| Post-freeze reviewed correction | `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57` (`cleanroom-v0.6-review1`) |
| v0.7 approved-input maintenance commit | `6b944b952d1daec6840deae7e07f304f5349637d` |
| Reviewed v0.7 maintenance freeze | `a39138dae8072c7b89dc922bcfe6f5717312c6e6` (`cleanroom-v0.7-maintenance-freeze`) |
| v0.8 approved-input maintenance commit | `5d00c792a8d61f7080ad3f0ccf04642b2b491017` |
| v0.8 maintenance implementation | `8a681abe854feea2a20e42b8f0980237fb27296a` |
| Reviewed v0.8 maintenance freeze | `7be1b3c5f3000cadcd45637e3a96d7bb17ec2023` (`cleanroom-v0.8-maintenance-freeze`) |
| v0.8.1 approved-input maintenance commit | `984e3bbb425a857306d5d39353057493b8c33984` |
| Reviewed v0.8.1 maintenance freeze | `2a27565107d7b383e15ccb3972a11bdf5eb55aa2` (`cleanroom-v0.8.1-maintenance-freeze`) |
| Reviewed v0.8.1 conformance correction | `a94e9a8a7bd2f9c2e0947715ec387b6c3967e4e6` (`cleanroom-v0.8.1-conformance-correction-reviewed`) |

The reviewed correction rejects Boolean CBOR keys masquerading as integer labels and accepts uppercase as well as lowercase `IPvFuture` introducers. Its parent is the original freeze, its authoring record states that no excluded Rust or provisional material was revealed, and its public tag passes the complete 160-test clean-room suite. The original freeze tag remains immutable evidence of the model as first authored; the reviewed tag does not replace or rewrite it.

The v0.7 maintenance freeze independently applied the RFC 3986 `URI` production and exact CBOR label typing from the v0.7 specification, preserved the unchanged Appendix B positive bytes, and passed its complete 173-test suite before differential material was exposed. The reviewed v0.8 maintenance freeze independently derived the v0.7-to-v0.8 delta, reproduced Appendix B.9 and B.10, passed its complete 193-test suite, and includes a documentation-only post-maintenance correction whose parent is the implementation commit. Its tag peels to the reviewed correction commit and is the starting implementation revision for the v0.8.1 clean-room maintenance pass.

The reviewed v0.8.1 maintenance freeze independently reproduced Appendix B.12 and preserved the model's independently derived record-level `schemaViolation` classification. The immutable freeze also preserved a narrower structural-validator interpretation that the first differential run exposed. The separate reviewed conformance correction at `a94e9a8a7bd2f9c2e0947715ec387b6c3967e4e6` moved schema admission out of deterministic-CBOR decoding without rewriting that evidence. The corrected run at `beb89f656e1ca8398fd09b0be4799339a4fc1d98` (`v0.8.1-differential-final`) produced 218 agreed comparisons out of 218. The 53 implementation-status fixtures were subsequently promoted at `9493e39bd738372fe1e2fc1b2e96f6a41983c1be` (`v0.8.1-fixtures-confirmed`) without changing their substantive bytes or expected results. These revisions remain the frozen core evidence for v0.9, v0.9.1 and v0.9.2 because none of those amendments changes a core-model requirement.

Independence requirements:

- its original v0.6 version was written in a separate clean session using only that pinned normative specification, Appendix B and fixture cases whose derivation status was `specification`;
- its authoring workspace and context exclude the Rust source, Rust tests, Rust implementation notes, all `implementation`-status fixtures, Rust-derived expected outputs and prior differential reports;
- it shares no protocol code, generated parser, fixture-producing code or algorithmic helper with Rust;
- its provenance records the specification commit and the independent authoring constraint; and
- the resulting code remains intentionally small and readable by a human reviewer.

Before any provisional case is revealed, the Python model and its authoring record must be reviewed and frozen at a recorded source commit or content digest. Only then may `implementation`-status inputs be supplied to the differential harness. Their Rust-derived expected outputs remain outside the Python authoring context: the frozen model computes its own results before the harness compares them. Agreement may promote an unchanged case to `confirmed`; disagreement opens a specification or implementation review issue. Running provisional fixtures through a model that saw their expected outputs while it was being written is not independent confirmation.

The reviewed v0.8 maintenance lineage above is evidence of a versioned maintenance pass, not a claim that v0.8 was independently authored from a blank workspace. It remains immutable historical evidence and was not amended, squashed or retagged during v0.8.1 maintenance.

The v0.8.1 maintenance pass began at approved-input commit `984e3bbb425a857306d5d39353057493b8c33984`, whose parent was the reviewed v0.8 freeze. Its authoring context was limited to the clean-room repository's own frozen source, records and Git history; the exact v0.8 specification at commit `610f9a1e78d860e8bd685ef1435a53a16f1221ec` and SHA-256 `474f0b3880e838a5232890c3e2edc183c341fd25e28d7db0066ad109aa43113b`; the exact v0.8.1 specification at commit `2d5292e95af022af7beee2d154e7217e29907960` and SHA-256 `ad9895d1672e3f4f68dac9e2a92c1d04fb63229c406e67dc1041a5971a361b7d`; and v0.8.1 `specification`-status inputs derived solely from the v0.8.1 document. The maintenance session derived the semantic delta by comparing those two pinned specifications itself. It did not receive a prose summary of the changes, a list of affected sections, the amendment rationale, this implementation brief, the whitepaper, protocol-review discussion, Rust source or changes, Rust tests, Rust-derived fixtures or outputs, implementation reports, conformance-harness reports, baseline metrics, or differential results. Its authoring record identifies both specification pins and digests, independently explains the semantic change, and confirms that excluded material remained unavailable before the reviewed freeze.

The Python decoder MUST NOT materialize an untrusted CBOR map directly into a native `dict` before duplicate-key, key-type and deterministic-encoding validation. It must preserve every map entry and distinguish keys by CBOR generic-data-model type as well as value: unsigned integer `0` and simple value `false` are distinct even though Python compares and hashes them equally. Comparing received encoded key bytes is equivalent only after deterministic encoding has been established; before then, `00` and non-minimal `18 00` are different encodings of the same unsigned-integer key. Tests must cover a map containing both integer `0` and Boolean `false`, identical duplicate keys, and differently encoded equivalent keys. Appendix B.7 item 17's eventual schema rejection does not by itself prove that the decoder preserved every entry or classified duplicate keys correctly.

The Python model must independently implement enough of Sections 3 through 8 to derive DIDs, preserve and validate deterministic CBOR bytes, reconstruct the COSE `Sig_structure`, perform Followee-strict Ed25519 verification, classify verification results and select candidates. A library’s ordinary Ed25519 verifier is insufficient unless its behaviour is demonstrated to satisfy every Section 3.3 requirement or supplemented with explicit checks. Library documentation or successful rejection of one malformed signature is not evidence for the remaining rules: run the B.4 `S + L` envelope case and the adopted primitive edge-case vectors explicitly against the Python verifier.

Differential testing rules are:

- every shared fixture must produce the expected accept/reject result, and cases with `errorAssertion: exact` must also produce the specified symbolic error;
- valid randomized structured inputs must produce identical deterministic bytes, DIDs, digests, signatures, verification results and winners for the operations both models implement;
- arbitrary malformed fuzz inputs must produce identical accept/reject results; and
- exact error equality for an input violating several independent rules is required only where the specification defines precedence, because Section 8.1 permits cheap independent checks to be reordered.

Implementations used by the neutral differential harness must expose narrow public entry points to the same production primitives used by complete record processing, including strict Ed25519 verification, deterministic-CBOR validation with explicit bounded limits, timestamp generation, and candidate selection. Harness adapters must not call hidden fuzzing interfaces, test-only helpers, or recreate missing protocol behaviour. If a required production entry point is absent, the implementation must add and review that entry point before the differential operation is claimed.

Harness adapters are framing and transport glue, not protocol interpreters. An adapter MUST report exactly the success value or symbolic error classification returned by the implementation's reviewed production entry point. It MUST NOT map, normalize, infer or default a protocol error symbol, and MUST NOT catch a broad exception type in order to synthesize one. A missing classification or unexpected implementation exception is an adapter or harness infrastructure failure, never a Followee protocol result. If an implementation cannot expose the exact classification through a production entry point, that entry point must be added and reviewed before comparison. Adapter source and tests are part of every applicable milestone review; their tests must demonstrate transparent propagation of every exercised classification and distinguish unexpected exceptions from protocol rejections.

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
- malformed outer request versus malformed per-DID item HTTP classification;
- duplicate requested DIDs and exact request/response cardinality;
- opaque Full candidate isolation within otherwise valid resolve and `changes` wrappers;
- response-size splitting behaviour;
- two relays learning updates through `v1/changes`;
- three updates coalescing into one current tuple;
- differing relay views converging when information is exchanged;
- references, directory generations and lazy path compression;
- reference cycles and unreachable endpoints;
- cursor reset, including the exact two-field `ResetRequired` response followed by bounded null-cursor enumeration;
- deterministic concurrent publication showing that a successful `changes` cursor never overtakes an earlier update that is paused before commit and later becomes visible;
- all `changes` status-dependent required and forbidden field combinations, including rejection of every label `2` through `6` on status `1`;
- all publish-response status-dependent combinations required by specification v0.9.2: status `0` without a code, status `1` without a code and with each permitted code, status `2` with a permitted rejection code, rejection of status `0` with a code, exhaustive rejection of every other registered code on status `1`, and rejection of status `2` without a code or with `losingRecord`/`duplicate`; the status-`2` success-path test must arrive in HTTP `200`;
- rejection of an over-`itemLimit` `changes` response without entry processing or cursor advancement;
- cursor advancement past individually rejected or locally premature candidates in an accepted response;
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

### 11.8 Independent Motoko participant and interoperability campaigns

The first external participant and campaign are immutable evidence:

| Artefact | Revision |
| --- | --- |
| Motoko sealed-authoring-input commit | `7f2243ef729aa21e95e047becef12319ee50d765` |
| Motoko independent implementation freeze | `3840d9adf07755d326d920f4711dafc4e08bcb40` (`motoko-v0.9.1-independent-freeze`) |
| Neutral v0.9.1 interoperability bundle | `c90742eb763cda5bd3c6e7d20ab1799590da489b` (`v0.9.1-interop-bundle-reviewed`) |
| Rust Milestone 5 participant | `8606a102bfb4f2bbfbc81e364bdf548c437bf123` (`milestone-5-v0.9.1-reviewed`) |
| First Rust–Motoko campaign | `515f37d86a35937b3539bfafdd671291d6abb443` (`v0.9.1-interop-campaign-1`) |

Campaign 1 recorded four findings without normalizing or correcting them inside the archive:

- **W1:** status-`1` publish responses differed by the presence of `duplicate`; specification v0.9.2 resolves this as permitted diagnostic variation, so both byte encodings remain visible and conforming.
- **W2:** the frozen Motoko serving path re-verifies a retained opaque Full value and substitutes `internalError` where specification Section 12.3 and Appendix B.11.3 require the retained candidate bytes to be served verbatim. Correct this only in a descendant of the frozen tag, with a regression test whose seeded state cannot be produced by ordinary verified ingress.
- **I1:** Rust derives and validates the DID multihash internally but exposes no narrow production accessor for the exact multihash bytes. Add and review that accessor rather than reconstructing the value in an interoperability adapter.
- **I2:** the neutral interface does not define the language-independent JSON projection of the Authority Descriptor carried inside a record result. Define one exact projection in the v0.9.2 interface and test both participants against it; an adapter must not invent or normalize the missing shape.

The W2 correction must preserve the byte-string opacity boundary: wrapper parsing and serving may validate the outer response schema and bounds, but a retained Full byte string is opaque at that layer. Ordinary Motoko ingress continues to verify a candidate before it becomes current; the seeded-state regression exists solely to prove that serving does not add a second, contradictory admission decision. Its impossible-state seeding facility is test-only: it must live outside the production actor dependency graph, expose no production or Candid method, and be mechanically absent from the release canister/Wasm build. A gate must fail if the seeding entry point or its state-installation capability becomes reachable from production source, declared service surface or release artefact.

The Motoko transport milestone must implement the complete claimed relay HTTP/CBOR surface—`info`, `directory`, `publish`, `resolve` and `changes`—plus publish-response decoding and client behaviour under v0.9.2. Motoko production modules own protocol parsing, response encoding, cursor and state decisions. A loopback host shim may provide sockets and process plumbing only if it passes method, path, headers and body into the Motoko handler and returns the handler's status, headers and body verbatim. It MUST NOT parse CBOR, choose a status, maintain protocol state, repair output or implement a missing operation. Tamper tests must demonstrate that changed Motoko output reaches the comparison as a disagreement.

Campaign 2 follows this fixed order:

1. derive and review a new neutral bundle from `v0.9.2-reviewed`, retaining the authoring/coordinator directory boundary and preserving the v0.9.1 bundle unchanged;
2. update Rust and the Motoko descendant from the pinned v0.9.2 specification, add the W2/I1/I2 corrections and complete Motoko transport, then commit and tag both participant revisions before exposing newly derived coordinator expectations;
3. rerun every participant's complete local conformance, property, fuzz and applicable mutation gates against those exact revisions;
4. rerun the complete expected-vector phase, including every unchanged case rather than only publication cases;
5. preserve and digest-check the original pre-exposure Motoko challenge output, rerun both updated participants over the same challenge inputs, and require exact agreement without describing the maintenance rerun itself as newly blind;
6. rerun the complete live HTTP/CBOR phase in both directions, covering all five operations, publication outcomes `0`/`1`/`2`, Appendix B.11 hostile-peer cases, pagination, cursor reset, update visibility, final selected state and every v0.9.2 publish-response combination; and
7. archive requests, raw responses, participant pins, manifests, allowed opaque variations and every disagreement before making an interoperability claim.

Campaign 2 is a maintenance interoperability campaign between two reviewed implementations, one of which has an independently authored and immutably preserved ancestor. It is not a second independent-authoring exercise: its Motoko descendant is maintained with knowledge of the public Campaign 1 findings and may therefore know facts about the Rust participant that those findings disclose. Every Campaign 2 report and summary must state this qualification next to its agreement totals and must point to the original frozen tag for the narrower independence claim.

The campaign report counts acceptance/rejection disagreements, symbolic differences explicitly permitted by the specification, implementation defects, interface gaps and unresolved specification ambiguities separately. Permitted status-`1` diagnostic variation is recorded byte-for-byte and is not a disagreement. Any unexplained difference blocks acceptance; it is resolved against the pinned specification, never by participant majority. Campaign 1 remains historically accurate and MUST NOT be amended, regenerated or relabelled after the v0.9.2 resolution.

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
- `SPEC-QUESTIONS.md`, recording identified protocol questions and their resolution status, with the resolution-index table required by Section 2; entries through the CBOR basic-validity taxonomy, byte-string opacity, relay batch isolation, cursor-progress rules, schema-disallowed-simple-value classification and concurrent cursor-visibility invariant must cite their resolution at the applicable pinned specification revision rather than remain open;
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
- Contact Document and record schemas, including the registry-independent service-metadata grammars fixed by specification v0.6, the URI and exact CBOR-label rules fixed by specification v0.7, the basic-validity classifications fixed by specification v0.8, and the simple-value schema boundary fixed by specification v0.8.1;
- signing, verification, digesting and ordering;
- the sole production strict-Ed25519 entry point and mechanical direct-call restriction; and
- complete Appendix B.2–B.10 and B.12 core tests and byte-level reproduction of the B.11 relay fixtures.

Acceptance:

- every published positive byte sequence reproduces exactly;
- every required B.7, B.10 and B.12 core negative mutation is rejected;
- every Appendix B.7 case follows the fault-isolation plan in Section 11.1 and records its construction provenance;
- no case asserts an exact non-signature error while also retaining a signature invalidated by its mutation;
- the B.4 `S + L` signature is independently recomputed, rejected as `invalidSignature`, and remains otherwise byte-identical to the positive case;
- adopted point, subgroup and verification-equation vectors retain their published primitive inputs, pass provenance review, and are not mislabelled as complete Followee envelopes;
- every primitive Ed25519 vector executes through the production strict-verification entry point used by record verification;
- the B.4 Root wiring test delegates exactly once with the descriptor's exact root public key, COSE `Sig_structure` and received signature;
- the B.5 RootRevoked wiring test delegates exactly once with label `5`'s exact revealed revocation public key, COSE `Sig_structure` and received signature;
- the public B.4 `S + L` test uses the non-injectable production record-verification wrapper;
- CI rejects direct underlying-library verification calls outside the audited strict wrapper;
- the Appendix B.7 item 1 and item 2 fixtures exactly implement the binding and hash-error classifications introduced in specification v0.4 and retained at the pinned v0.9.2 commit;
- B.8 fails specifically with `identityBindingMismatch` despite a valid attacker signature;
- B.9 Bob keys, commitment, descriptor, DID, body, `Sig_structure`, digest, signature and envelope reproduce exactly, and Alice/Bob tests prove sticky authority and update state are keyed independently per DID;
- all five B.10 raw bodies reproduce their stated digests and `Sig_structure` lengths, their signatures verify under Alice's legitimate root key, and every case fails exactly with `invalidCbor` rather than `nonDeterministicCbor`, `schemaViolation` or `invalidSignature`;
- both B.12 raw bodies reproduce their stated digests and `Sig_structure` lengths, their signatures verify under Alice's legitimate root key, the public deterministic-CBOR validation entry point admits their simple values, and complete record verification fails each exact signed envelope with `schemaViolation` rather than `invalidCbor`, `nonDeterministicCbor` or `invalidSignature`;
- CBOR tests distinguish not-well-formed/basic-invalid input from basically valid non-deterministic input and from later Followee schema failures, recursively including ignored extension values while stopping at byte-string boundaries;
- duplicate-map validation compares CBOR data-model key identity rather than bare host-language equality or raw bytes before deterministic validation;
- service `mediaType` accepts exactly an RFC 6838 `type-name/subtype-name` without parameters, `language` accepts the complete well-formed RFC 5646 grammar including fixed grandfathered tags, and `rel` accepts exactly an RFC 8288 `reg-rel-type` or a URI satisfying specification v0.9.2 Section 7.2, with no mutable registry lookup or normalization;
- every numeric core label is accepted only from the corresponding CBOR unsigned-integer key; Boolean `false` and `true` substitutions in Authority Descriptors and public-key objects fail with `schemaViolation`, including the correctly signed, descriptor-bound Appendix B.7 item 17 construction;
- URI conformance tests accept scheme-bearing queries and fragments, reject every relative-reference form, and accept both lowercase and uppercase `IPvFuture` introducers through the production Contact Document path;
- service collection tests derive the effective Root and RootRevoked service maxima from the normative aggregate-member counting rule and current record schemas, assert that the computed results are respectively 61 and 60, and prove admission at each computed `N` with aggregate-limit rejection at `N + 1`; the independent 64-entry cap is tested separately, and 61/60 are expected computed results rather than fixture inputs;
- candidate selection takes an explicit target DID and remains permutation-independent over a mixed-identity candidate set, with every winner belonging to the target;
- future-bound, stale-record, absolute RootRevoked-precedence, no-fallback and sticky-state-loss tests described in Section 11.1 pass;
- no untrusted parser panic under the initial fuzz corpus;
- all implemented MUST/MUST NOT requirements are mapped to tests; and
- targeted `cargo-mutants` output has no unexplained surviving mutant in normative or security-sensitive core code.

Do not begin relay code before this milestone passes.

### Milestone 1.5: independent Python core model

Deliver:

- the separately maintained Python model and preserved v0.6 freeze/review tags described in Section 11.4;
- an authoring record showing the original model was produced in a separate session using only its pinned v0.6 specification and `specification`-status fixtures, without access to Rust source or Rust-derived material;
- a recorded commit or content digest freezing the reviewed model before provisional fixtures are revealed;
- the preserved reviewed v0.7 maintenance freeze identified in Section 11.4;
- a reviewed v0.8 maintenance revision produced from the v0.7 clean-room repository and pinned v0.8 specification only, without access to Rust, harness reports or differential material, and frozen before v0.8 differential comparison;
- a reviewed v0.8.1 maintenance revision produced from the reviewed v0.8 freeze and the pinned v0.8/v0.8.1 specifications only, without access to Rust, harness reports or differential material, and frozen before v0.8.1 differential comparison;
- the preserved v0.8.1 maintenance freeze, separately reviewed conformance correction, final 218-of-218 differential result and 53-fixture promotion evidence identified in Section 11.4;
- independent Appendix B reproduction;
- a differential harness that supplies provisional inputs only after the freeze and does not feed their expected outputs into model authoring; and
- curated and randomized differential cases with the comparison rules in Section 11.4.

Acceptance:

- the allowed authoring inputs and excluded Rust-derived inputs are recorded and auditable;
- Appendix B positive values are independently reproduced rather than imported from Rust output;
- the model’s frozen revision predates its first access to any `implementation`-status fixture;
- the v0.8 maintenance record identifies the v0.7 and v0.8 specification pins and digests, the reviewed v0.7 model revision, and the reviewed v0.8 maintenance revision;
- the v0.8.1 maintenance record identifies the v0.8 and v0.8.1 specification pins and digests, the reviewed v0.8 model revision, and the reviewed v0.8.1 maintenance revision;
- the Python CBOR decoder preserves every map entry until type-aware duplicate and deterministic checks complete, including integer/Boolean host-language collisions and differently encoded equivalent keys;
- Appendix B.9 and B.10 reproduce independently from the v0.8 specification before Rust-derived inputs are exposed;
- Appendix B.12 reproduces independently from the v0.8.1 specification before Rust-derived inputs are exposed;
- shared fixtures agree on acceptance or rejection, and every case marked `errorAssertion: exact` agrees on the specified symbolic error;
- valid randomized shared operations agree on bytes and semantic results;
- arbitrary malformed inputs agree on acceptance versus rejection;
- the full v0.8.1 differential corpus is rerun and its report preserves the archived v0.7 fixture-bundle digest and separately records the v0.8.1 fixture-bundle digest, acceptance/rejection disagreements, permitted unspecified symbolic differences and genuine ambiguities;
- the original v0.8.1 maintenance freeze remains immutable after the correction, the final differential tag records 218 agreed comparisons out of 218, and promotion to `confirmed` changes no substantive fixture input or expected result;
- fixture promotion follows Section 12 without changing the original bytes or expected result;
- every disagreement is resolved against the specification and retained as a regression test; and
- the model is small enough for direct human review and makes no claim to full Section 20.4 interoperability.

The existing Python model was commissioned after Rust Milestone 1 but independently, under the restrictions above. Any future independently authored model must likewise avoid Rust and provisional fixture material during its clean authoring session. Do not begin relay code until both Milestone 1 and Milestone 1.5 pass against the same pinned specification.

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
- opaque cursors and reset behaviour;
- the minimal `followee relay serve` operator command; and
- black-box HTTP/CBOR tests.

Acceptance:

- the relay passes Sections 20.1 and 20.2 tests applicable without peers;
- Appendix B.11.1's basically invalid outer request receives HTTP `400` with no per-item processing, while B.11.6's valid three-item request receives HTTP `200` with the exact aligned `[Full(Alice), Error(invalidDid), Full(Bob)]` results;
- duplicate requested DIDs are neither deduplicated nor reordered, every occurrence counts against the limit, and the resolve response count always equals the request count;
- update numbers change exactly when specified;
- update-number assignment, accepted-state commitment and changes-feed visibility form one observable order, and a deterministic concurrent-ingress test proves that no successful `nextCursor` can overtake an earlier entry that later becomes visible;
- resolve distinguishes Absent from a retained but presently premature record;
- successful `changes` responses never exceed the request's `itemLimit` and never advance past an omitted eligible entry;
- `changes` uses the exact two-field status-`1` response as the sole ResetRequired signal, forbids labels `2` through `6` in that response, and enforces every other status-dependent field rule;
- publish responses enforce the v0.9.2 status-dependent `errorCode` rules, and a conforming status-`2` rejection is returned in an HTTP `200` protocol response;
- `followee relay serve` accepts a SQLite path, uses the operating-system clock and CSPRNG, defaults to loopback with port-`0` reporting, emits one machine-readable startup object, refuses non-loopback development binding, shuts down cleanly on signals, and preserves relay identity and generations across restart; client-side `relay publish`, `relay resolve` and `relay changes` commands are assigned to Milestone 4;
- restart preserves identity, generation and sticky authority state; and
- malformed and oversized input is bounded before expensive processing.

### Milestone 4: resolver and relay network

Deliver:

- client traversal budgets;
- reference traversal and cycle detection;
- current-state synchronization;
- peer cursor persistence;
- lazy path compression;
- minimal non-interactive `followee relay publish`, `followee relay resolve`, `followee relay changes` and multi-relay `followee resolve` commands with machine-readable output; and
- a deterministic three-relay local demonstration.

Acceptance:

- relays can begin with different partial views;
- one relay can synchronize a newer record without historical events;
- a client follows references but verifies the final Full locally;
- an invalid or non-deterministic outer relay response is rejected without producing Absent, changing identity state, or terminating resolution while another already-selected relay remains reachable within the shared budgets;
- Appendix B.11.3's accepted resolve wrapper discards only the invalid Alice candidate at index `0` and retains Bob at index `1`, without shifting results or recursively validating Full byte strings as part of wrapper parsing;
- a client continues past Absent and Error results while another relay selected for the operation remains unqueried within the shared budgets;
- Error(`premature`) from one relay cannot classify or suppress a Full candidate obtained from that or another relay, and the candidate is checked using the client's injected clock;
- Absent and Error results cannot alter cached identity or sticky RootRevoked state;
- Appendix B.11.5 advances the peer cursor to the exact returned `nextCursor` after rejecting Alice and admitting Bob, leaving Alice byte-for-byte unchanged and assigning only Bob's local update;
- Appendix B.11.7's three-entry response to `itemLimit = 2` is rejected before any entry is processed, leaving identity state, update counter and stored peer cursor unchanged;
- cycles and unavailable peers terminate within shared budgets;
- synchronized invalid or losing input does not alter current state;
- the direct relay commands exercise the production HTTP/CBOR client path, while `followee resolve` exercises the production multi-relay resolver rather than reproducing protocol decisions in CLI code; and
- a shell-level demonstration starts three loopback relay processes with isolated SQLite databases and exercises synchronization and resolution through the production binary surfaces, not only in-process library calls.

### Milestone 5: handles and public demonstration

Deliver:

- production WebFinger lookup under the network policy and shared bounds established for Milestone 4;
- inverse handle verification against a locally verified Followee record;
- optional current-record bootstrap whose supplied record is always verified locally before use;
- all three migration presentation states without automatic re-following;
- minimal non-interactive `followee handle resolve` and `followee handle verify` commands with machine-readable output;
- a minimal `followee handle serve` demonstration-authority command for local black-box testing;
- reproducible container packaging for the same authority on Railway, deployed behind its provider-assigned HTTPS domain; and
- the retained provider-neutral VPS alternative using Caddy or nginx and systemd.

Acceptance:

- exact requested canonical `acct:` subject and exactly-one-Followee-link requirements are tested through the production WebFinger client;
- ASCII-case variants cannot be assigned to different DIDs by the demonstration authority;
- a signed `alsoKnownAs` claim is not called verified without both successful local record verification and inverse mapping of the exact handle to the same DID;
- disappearance or reassignment of a handle does not change the followed DID;
- invalid, mismatched, stale or losing bootstrap records are discarded locally without changing the followed DID or sticky authority state;
- stale claimant and stale counterpart checks each produce **Checked but unverified**, incomplete checks alone produce **Not checked**, and none of the three migration states changes the followed DID without an explicit user action;
- the handle commands exercise the production WebFinger, verification and authority paths rather than implementing parallel CLI policy;
- local black-box tests start the demonstration authority, exercise discovery and inverse verification over HTTP, and pin malformed, ambiguous, reassigned and ASCII-case-variant behaviour;
- the committed container binds to Railway's supplied `PORT`, derives no security decision from provider headers, shuts down cleanly, and serves the same tested JRD semantics through the provider-assigned HTTPS domain;
- public probes cover exact subject, exactly one Followee relation, CORS, `404` for an unknown handle, `400` for a malformed request, production `handle resolve`, and production `handle verify`;
- the VPS/Caddy/nginx/systemd artifacts remain internally consistent with the same authority configuration and public probes; and
- the demonstration works without an ICP dependency or purchased domain.

### Milestone 6: external interoperability

Deliver:

- a reviewed neutral v0.9.2 fixture and interoperability bundle derived from `v0.9.2-reviewed`, with its authoring and coordinator audiences mechanically separated;
- documented raw HTTP/CBOR transcript examples for every mandatory relay operation and the Appendix B.11 hostile-peer cases;
- a reviewed Rust production accessor closing I1 and an exact neutral-interface descriptor projection closing I2, without moving either decision into an adapter;
- a reviewed Motoko descendant correcting W2 and implementing the complete Motoko-serving and Motoko-client HTTP/CBOR surface described in Section 11.8;
- release binaries or clean reproducible-build instructions pinned to an exact source revision, Rust toolchain, target, lockfile and digest-pinned build environment; and
- a complete second interoperability campaign between the reviewed Rust and independently frozen-then-maintained Motoko implementations.

Acceptance:

- the v0.9.1 neutral bundle, Motoko independent freeze and Campaign 1 archive remain byte-for-byte unchanged at the pins in Section 11.8; the original frozen Motoko challenge output retains SHA-256 `e73c5697de68df7ec0f693834165bff7a1753a077959c9d9be50553b5722478e`, and the Campaign 1 archive retains aggregate SHA-256 `13efa5fd8a1f4b3c34786eba0e6be7c16b1dc2f85d6585a675183c4cda062a36`;
- the v0.9.2 bundle manifest pins the reviewed specification commit and SHA-256 from Section 2, identifies every file's provenance and audience, and mechanically proves that coordinator-only expected values are absent from the authoring subset;
- both participant revisions are committed and tagged before the v0.9.2 coordinator comparison begins, and every orchestration entry point refuses a checkout that does not match its recorded pin;
- Rust accepts status `1` both without a reason and with accurate `losingRecord`/`duplicate`, rejects every other registered status-`1` code, enforces the status-`0` and status-`2` combinations, and exercises a status-`2` rejection through HTTP `200`;
- the Motoko W2 regression serves an exactly retained opaque Full byte string without re-verification or substitution, while ordinary ingress still refuses to admit that invalid candidate; its impossible-state injector is test-only and a mechanical production-build gate proves it is absent from the production dependency graph, Candid surface and release Wasm artefact;
- the I1 Rust accessor returns the exact already-validated multihash bytes for every published and challenge identity, and the adapter contains no DID parsing or multihash reconstruction;
- the I2 interface projection is exact, language-neutral and exercised identically by Rust and Motoko without adapter normalization;
- Campaign 2 reruns every Phase 1 expected-vector case and records zero unexplained differences, including permutation invariance and every new v0.9.2 publish-response case; the report labels the Motoko revision as a maintained descendant of an independently frozen ancestor and does not describe Campaign 2 itself as an independent-authoring comparison;
- Campaign 2 preserves the original pre-exposure Motoko challenge bytes, reruns both maintained participants over every Phase 2 input, and records exact agreement on deterministic bytes, DIDs, digests, signatures, verification results and winners; the report distinguishes this maintenance confirmation from a new blind authoring exercise;
- Campaign 2 completes Phase 3 in both directions through real loopback HTTP, with the production Rust participant on one side and Motoko-owned protocol handlers on the other, covering `info`, `directory`, `publish`, `resolve` and `changes`, exact request/response bytes where fixed, pagination, reset, update visibility, final state and Appendix B.11 receiver behaviour;
- any socket or process shim is mechanically shown to be semantic-free: it cannot parse or emit protocol CBOR, choose protocol results, maintain relay state, or repair participant output;
- permitted status-`1` diagnostic variation remains visible in raw results and is classified separately from disagreements; every acceptance/rejection disagreement, implementation defect, interface gap and unresolved specification ambiguity is separately counted;
- there are zero unexplained disagreements, no unresolved specification question affects a claimed role, and the final report maps every Section 20.4 obligation to preserved evidence;
- a clean checkout can build the release executable with the documented locked commands; the release record identifies the source tag, exact Rust version, compilation target, build-environment image digest, binary SHA-256 and dependency/licence evidence, and the produced binary passes a bounded smoke test through its production CLI surfaces; and
- if byte-for-byte reproducibility is claimed, two clean builds in separately created environments must produce the same binary digest; otherwise documentation must say **reproducible build instructions**, not **reproducible binary**; and
- any claimed binary-reproducibility result expires when the Rust toolchain, compilation target, lockfile, build flags, base image or other build-environment input changes, and must be re-established with two new clean matching builds rather than inherited from an earlier release.

No implementation may be described as interoperable merely because it communicates with another process built from the same core library. The interoperability claim is permitted only after every acceptance item above and specification Section 20.4 passes against one pinned v0.9.2 participant set.

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

An independently authored Python model must be assigned through a separate clean session whose context contains its pinned protocol specification and `specification`-status fixtures only. It must not receive Rust source, tests, implementation notes, provisional fixtures, Rust-derived expected outputs or differential reports until the reviewed model is frozen at a recorded revision. Maintenance of the existing clean-room model follows the version-specific v0.8.1 update rules in Section 11.4. The relay-only v0.9 amendment, client-presentation-only v0.9.1 clarification and publish-wrapper-only v0.9.2 clarification do not trigger another Sections 3-through-8 core-model maintenance pass; preserve the reviewed v0.8.1 freeze and correction as immutable evidence. The complete Rust and Motoko conformance and interoperability campaign must nevertheless rerun for v0.9.2 as Section 11.8 requires. Do not ask the Rust implementation agent to produce its own “independent” model after reading the production code; independence cannot be added as a comment after the fact.

The Motoko tag `motoko-v0.9.1-independent-freeze` is likewise immutable. Corrective and transport work begins from a descendant, records the parent and pinned v0.9.2 specification, and freezes a reviewed participant revision before new coordinator expectations are exposed. An agent working on that descendant may use the already public Campaign 1 findings, but it must not describe post-exposure maintenance as a new clean-room implementation or rewrite the original authoring record.

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

External interoperability with the Motoko implementation is Milestone 6's release gate, not something the Rust implementation can prove alone. Campaign 1 is valuable preserved evidence but did not complete the Motoko-serving role surface. Only the complete pinned v0.9.2 Campaign 2 and release evidence defined above can close that gate.
