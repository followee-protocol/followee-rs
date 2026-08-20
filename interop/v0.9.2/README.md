# Followee v0.9.2 — maintained Rust participant (Campaign 2)

This directory holds the **participant-owned** Followee v0.9.2
interoperability material of `followee-rs`: everything this implementation
computed for the Milestone 6 experiment from the neutral authoring subset
alone, produced and preserved **before any coordinator comparison**.

This is a **maintained v0.9.2 Rust participant**, not an independent
implementation, and it is **not yet interoperable**. Campaign 2 is a
maintenance interoperability campaign between two reviewed implementations;
the Motoko participant's original independent-authoring evidence is the
immutable `motoko-v0.9.1-independent-freeze` tag, and Campaign 1 findings
are public to both maintenance passes. No interoperability claim is made or
implied until the complete pinned Campaign 2 defined by IMPLEMENTATION.md
section 13 Milestone 6 and specification section 20.4 passes.

## Pinned inputs

| Input | Pin |
| --- | --- |
| Normative specification | v0.9.2, SHA-256 `47af5fbf0c4505386b4e04d948ef89d013f878ea820fb02522817661d633633a` |
| Specification revision commit | `f1d19fec0dba455d90d473bfad625d1c288e0c15` |
| Protocol repository commit | `ac5a794f2fdadc13cddf5367fa3e047617e3e950` |
| Authoring subset | `interop/v0.9.2/authoring/` in the protocol repository, **revision 2**: exactly 12 files, aggregate SHA-256 `1b6514da0c1a0c5289e0909b648b5de73a302e91b346440624badacf5747855e` |
| Rust toolchain | `1.97.1` (`rust-toolchain.toml`), locked dependencies (`Cargo.lock`) |

Authoring revision 2 corrected exactly one file, `interface/INTERFACE.md`
(revision 1 aggregate `cec54f10520535b405c2eb11952cbe2e14976be3962cb26cacff29031c89ae6b`);
the specification and every vector file are byte-identical across the two
revisions. The revision-1 → revision-2 output delta was predeclared before
regeneration and matched exactly; see
[`REVISION-2-DELTA.md`](REVISION-2-DELTA.md).

**Trust boundary.** This participant pass consumed only the pinned
specification, this repository, and the `authoring/` subset above. No
coordinator expected output, transcript, manifest, verifier result,
classification, or other implementation's source, tests, fixtures, or
frozen results were read. The generator refuses to run unless the
authoring subset's 12-file aggregate hash matches the pin, so nothing
outside the subset can be consumed silently. The frozen Motoko participant
pin (`motoko-v0.9.2-maintained-freeze` at
`6c0af5a933d1d8e98558ae09e3be9b0e193cecfd`) is recorded as provenance
only; its contents were not inspected.

## Outputs (`outputs/`)

Every file was produced by the deterministic generator below. For each
group, `<group>.requests.ndjson` holds the exact interface request lines
and `<group>.responses.ndjson` the exact response lines, both served by the
production `followee::interop` engine (the same engine behind
`followee interop`):

| Group | Content |
| --- | --- |
| `published-identities` | `deriveIdentity` over the three published identity cases; every published member checked |
| `published-records` | `authorRecord` over the five published record cases (B.4, B.5, B.6 a/b, B.9); every published member checked |
| `published-negative` | `verifyRecord` over the eight published negative envelopes (B.8, B.10 ×5, B.12 ×2), with recipe envelopes constructed per the published construction and every published digest, `Sig_structure` length, and error classification checked |
| `wire-b11-report.json` | Appendix B.11 wire-message reproduction: every published request/response length and SHA-256 reproduced, with the production evidence per message (relay-emitted responses for B.11.4/B.11.6, production client rejection/isolation for B.11.2/B.11.3, production synchronization receiver end-state for B.11.5/B.11.7) |
| `challenge-identities` / `challenge-records` / `challenge-verify` / `challenge-selection` | The complete blind-challenge rerun per `CHALLENGES.md`: derivation, authoring with self-derived identity references, self-verification at the file `verifyNowMs`, and selection with enforced permutation-group agreement |
| `MANIFEST.json` | Input hashes (per file and aggregate), output hashes, and fixed parameters; contains no wall-clock value |

The challenge rerun is **maintenance confirmation** of previously blind
inputs, not a new independent-authoring exercise; the genuinely blind
first run is preserved historical evidence in the Campaign 1 archive.

### Deterministic regeneration

```sh
# From a checkout of followee-protocol/followee at ac5a794f… :
cargo run --release --locked --example interop_outputs -- \
    <followee-repo>/interop/v0.9.2/authoring interop/v0.9.2/outputs
```

The generator verifies the authoring aggregate hash, checks every
published expected value, aborts on any mismatch, and writes byte-identical
files on every run (verified by regenerating into a second directory and
`diff -r`). Output hashes are in `outputs/MANIFEST.json`.

## Recorded participant facts

- **HTTP publish request-entity cap:** 65,536 bytes
  (`MAX_PUBLISH_REQUEST_BYTES` in `src/relay/http.rs`, 4 × the 16 KiB
  record cap). Entities above it stop with HTTP `413` before protocol
  parsing. An exactly 16,385-byte validly signed, fault-isolated record is
  below the cap and receives HTTP `200` with protocol status `2` /
  `recordTooLarge`
  (`relay_http::sec_15_1_exactly_16385_byte_validly_signed_record_is_recorded_cap_isolated`,
  with the byte-identical 16,384-byte construction admitted as the
  single-fault control). Exact HTTP pre-parse limits are
  implementation-local under the campaign classifications.
- **Status-`1` publish encoding:** this relay emits the deterministic
  no-code form for both duplicate and losing no-change outcomes. Under
  specification v0.9.2 both the bare and coded forms are conforming;
  reports keep them visibly distinct as permitted diagnostic variation and
  never normalize one into the other. The production client and the
  neutral `receivePublishResponse` operation accept both and reject every
  other status/`errorCode` combination completely.
- **`published-negative` recipient clock:** `nowMs = 1785589201123` (the
  published Appendix B.11.5 clock, at which every Appendix B record is
  admissible); the negative classifications are time-independent.

## Campaign 1 finding closures

- **I1** — `FolloweeDid::multihash_bytes()` (`src/did.rs`) is the narrow
  production accessor returning the exact already-validated 34-byte DID
  multihash (`0x12 || 0x20 || digest`), retained from strict parsing or
  assembled once during derivation. The `deriveIdentity` operation takes
  `multihashHex` from this accessor; no interoperability adapter parses a
  DID or reconstructs a multihash.
- **I2** — the `verifyRecord` accepted result implements authoring
  revision 2's exact definition: the closed eight-member
  `record.descriptor` projection (descriptor content and total functions
  of the descriptor bytes only, every derived member produced by the
  production derivation chain so the contract's coherence relationships
  hold by construction); `record.revocationKey` as the separate
  authority-dependent projection of record-body label `5` (`null` exactly
  for root, the three-member `public-key` projection exactly for
  rootRevoked); the exact structured Contact Document projection with the
  two distinct extension maps (contact label `6` and record label `8`,
  never merged); and lossless presence — `null` for an absent wire label,
  `[]`/`{}`/`""` for a present-empty one, from the production parser's
  `WirePresence` observation. The constructor direction applies the
  revision-2 canonicalization (omitted/`null`/`[]`/`{}` request omission,
  including an all-null migration object; `""` is present-empty text;
  never inside typed extension values). Because authoring cannot
  construct present-empty optional collections, that coverage is provided
  by participant-designed, correctly signed **direct wire fixtures**
  built with the suite's own raw CBOR emitters — independent of every
  neutral authoring vector — and exercised through `verifyRecord`
  (`tests/interop.rs`: `present_empty_collections_project_losslessly_from_direct_wire_fixtures`,
  `entirely_empty_contact_document_projects_to_the_all_null_object`,
  `authored_records_are_a_stable_subset_under_reverification`,
  `present_empty_text_is_reachable_by_authoring_and_projected_exactly`,
  `migration_object_with_all_null_members_requests_omission`; exact
  Appendix B projections in
  `sec_b4_verify_record_result_carries_the_exact_i2_projection` and
  `sec_b5_verify_record_projects_the_root_revoked_record`, including the
  `deriveIdentity` member correspondence). Present-empty wire fixtures
  **were exercised**, as the interface's evidential-scope section asks
  reports to state.

## Reproducible build instructions

These are **reproducible build instructions**, not a claimed reproducible
binary: a binary-reproducibility claim requires two separately created
clean environments producing the identical digest (IMPLEMENTATION.md
section 13 Milestone 6), which is performed and recorded at the freeze
revision, not inherited.

- Source: this repository at the freeze revision (tag below).
- Toolchain: Rust `1.97.1` exactly (`rust-toolchain.toml`); target
  `x86_64-unknown-linux-gnu`; locked dependencies (`Cargo.lock`,
  `--locked`).
- Digest-pinned build environment:
  `docker.io/library/rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3`
  (the same image the reviewed Railway artifact pins).

```sh
podman run --rm -v "$PWD":/src:ro -v "$PWD/target-release":/out \
  docker.io/library/rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 \
  sh -ec 'cp -r /src /build && cd /build \
    && cargo build --release --locked --bin followee \
    && sha256sum target/release/followee \
    && cp target/release/followee /out/'
```

The release record at freeze identifies the source tag, exact Rust
version, target, image digest, produced binary SHA-256, and the
dependency/licence evidence (`cargo audit`, `cargo deny check`), and the
binary passes a bounded smoke test through its production CLI surfaces.

## Intended freeze tag

Before any coordinator comparison material is opened, this maintenance
pass is committed and tagged with the annotated participant tag:

- **Tag:** `rust-v0.9.2-maintained-freeze`
- **Annotation subject:** `Maintained Followee v0.9.2 Rust implementation
  frozen before coordinator comparison`

The tag is created only after review of this pass; nothing in this
directory may change between that tag and the comparison without a new
freeze.
