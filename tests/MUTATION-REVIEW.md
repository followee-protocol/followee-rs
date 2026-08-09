# Mutation-testing review (Milestones 1–3)

`cargo-mutants` runs at milestone gates (IMPLEMENTATION.md section 11.7).
This document is the review evidence for the Milestone 1 gate: the final
sweep results and an individual explanation for every surviving mutant in
normative or security-sensitive code.

Process: an initial full sweep surfaced ~56 survivors. Review classified each
as either a genuine coverage gap (a killer test was added) or an equivalent
mutant (explained below). Gaps closed by added tests included, most notably:

- **the identity-key trivial forgery** (`crypto.rs`: with `A = identity`,
  `R = identity`, `S = 0`, the verification equation holds for every message;
  only the explicit non-identity check stops it — now directly tested);
- per-field and aggregate **at-limit acceptance twins** (envelope just under
  16 KiB, contact at exactly 12 KiB, every string/collection cap, through
  both the verification and the authoring paths);
- **service metadata shape validation** (language/rel/media-type/id helpers
  and their reachability from schema validation, positive parses of the
  optional service fields, absolute-URI service types);
- **extension authoring round-trip** (every value type, every key kind,
  nested-map duplicate detection, `Bool(false)`);
- **error vocabulary** (exhaustive symbol/wire-code table test);
- **CBOR writer width boundaries** (exact bytes at every head-width
  transition) and reserved additional-information bytes;
- **DID edge encodings** (identity multihash code `0x00` → `unsupportedHash`;
  non-minimal multi-byte code varint → `invalidDid`; `Display` canonicality);
- **authoring coherence** (`sign_record` refuses a Root body carrying a
  revocation key and a RootRevoked body missing one);
- COSE shape misparses (three-element array, non-map descriptor and key
  values, descriptor arity).

## Accepted surviving mutants

The final surviving set consists of the categories below. None weakens a
normative or security-sensitive branch: each mutant is behaviourally
equivalent (identical observable results for every input) or lies in
non-protocol scaffolding.

| Mutant | Explanation |
| --- | --- |
| `src/bin/followee.rs` `main -> Default::default()` | Placeholder stub binary that only prints a notice and exits; replaced wholesale by the Milestone 2 CLI. Not protocol code. |
| `src/cbor.rs` `read_wide`: `\|` → `^` | Equivalent: `v << 8` has zero low bits, so OR and XOR of the next byte produce identical values. |
| `src/cbor.rs` `Writer::head`: `ib \|` → `ib ^` (five sites) | Equivalent: `ib` is `major << 5` and the OR operand is always `< 32`, so the operand bits are disjoint and OR equals XOR. The adjacent `&` and boundary mutants at the same sites are killed by the exact-byte width-boundary test. |
| `src/cbor.rs` `read_head`: delete arm `28..=30` (major 7) | Equivalent: control falls through to the wildcard arm, which returns the same `CborError::Invalid`. The corresponding arm for majors 0–6 is killed by the reserved-ai test; for major 7 both paths are identical by construction. |
| `src/did.rs` `parse`: `len > MAX` → `>=`/`==` | Equivalent in observable behaviour: the length guard is a bounded-work (denial-of-service) gate, and any input at or beyond the boundary is a several-times-oversized non-DID that fails with the same `InvalidDid` through the guard or through decoding. |
| `src/did.rs` `read_minimal_varint`: `shift > 63` → `>=`/`==` | Unreachable distinction: the shift guard triggers only for varints longer than nine bytes, which the byte-count guard rejects first for every input the parser can see. |
| `src/cose.rs` `parse_envelope` protected-header/`payload` condition mutants (`\|\|`→`&&`, `==`→`!=` at the null-payload special case) | Equivalent classification: with the mutation, the affected input falls through to an adjacent check that rejects with the same `SchemaViolation`. The null-payload arm exists for clarity of the detached-payload rule, not for a distinct error. |
| `src/cose.rs` `classify_protected` condition mutants | Equivalent classification: `classify_protected` only refines an already-failed protected-header comparison into `UnsupportedSuite` versus `SchemaViolation`; the mutated conditions reroute malformed headers between internal branches that both end in `SchemaViolation`. The `-8` → `UnsupportedSuite` refinement itself is pinned by the item 3 test. |
| `src/record.rs` `parse_descriptor`/`parse_public_key` head-check `\|\|` → `&&` | Equivalent-outcome where surviving: a non-map or wrong-arity value either fails the mutated combined check anyway or misparses into a guaranteed `SchemaViolation`/`InvalidCbor` from the following reads; the distinct-outcome shapes are covered by the non-map descriptor, non-map root-key, and wrong-arity tests. |
| `src/contact.rs` `is_language_tag` entry guard `\|\|` → `&&` | Equivalent: an empty tag fails downstream via the empty-segment check, and every non-ASCII byte fails every subtag character class, so the fast-path guard has no observable effect. |
| `src/contact.rs` `ServiceEntry::validate` media-type length `>` → `>=`/`==` | Unobservable boundary: the v0.6 RFC 6838 grammar caps a media type at 255 bytes (127 + `/` + 127), strictly inside the 256-byte field cap, so no grammar-valid value can reach the length boundary. |

Any mutant not in this table and not killed in the final sweep is a review
finding, not an accepted survivor; the final sweep summary is recorded below.

## Final sweep summary

Full sweep at the Milestone 1 gate (cargo-mutants v27.1.0, `--jobs 2`):
**545 mutants: 489 caught, 34 unviable, 22 missed**, followed by a scoped
confirming sweep after the last boundary fix that killed `verify.rs`
`> with >=` (the 16 KiB cap boundary on the verification path), leaving
**21 accepted survivors** — every one listed and explained in the table
above. No surviving mutant weakens a normative or security-sensitive branch.

The raw `mutants.out/` report is untracked (regenerable) and retained
locally as review evidence.

**Conformance-API addendum (public `validate_cbor` wrapper):** a scoped
sweep over `src/lib.rs` and `src/cbor.rs` after adding the public wrapper
reported 132 mutants: 124 caught, 1 unviable, 7 missed — all seven are the
long-documented `cbor.rs` equivalents above (the disjoint-operand `|` → `^`
family and the major-7 fall-through arm). The wrapper itself (`src/lib.rs`)
has zero surviving mutants; its limit-cap guard and delegation are pinned by
the external `validate_cbor_api` tests.

**Review-fix addendum (post-`d23d660` independent review):** after wiring
`validate_extension_map` into `RecordBody::validate` and adding the Boolean
protected-header case, a scoped sweep over both changed files
(`src/contact.rs`, `src/record.rs`) reported 333 mutants: 312 caught, 16
unviable, 5 missed — all five already explained in the table above (the
`is_language_tag` entry guard, the media-type length-cap pair, and the
descriptor/public-key head-check equivalent-outcome pair). No new survivor.

**v0.7 re-pin addendum:** after the section 7.2 URI-production change and the
Appendix B.7 item 17 additions, a scoped sweep over the changed parser file
(`src/contact.rs`) reported 239 mutants: 226 caught, 10 unviable, 3 missed —
exactly the three survivors already explained above (the `is_language_tag`
entry-guard equivalence and the two unobservable media-type length-cap
boundary mutants). No new survivor was introduced by the v0.7 changes.

**v0.8 re-pin addendum:** the v0.8 maintenance pass changed one production
branch — `src/cbor.rs` map-key validation now classifies duplicate keys as
`Invalid` (basic validity, `invalidCbor`) and misordered keys as
`NonDeterministic` — plus documentation-only updates in `src/error.rs`,
`src/lib.rs`, and `src/verify.rs`. A scoped sweep over all four changed
files (cargo-mutants v27.1.0, `--jobs 2`) reported 165 mutants: 149 caught,
8 unviable, 8 missed. Seven of the eight were the long-documented `cbor.rs`
equivalents above (the disjoint-operand `|` → `^` family and the major-7
fall-through arm). The eighth — `replace < with <=` in the new key-order
comparison — was equivalent only because the preceding equality branch made
`key == prev` unreachable at that point; rather than document another
equivalent, the comparison was restructured as an exhaustive
`key.cmp(prev)` match, removing that mutation surface. A confirming scoped
sweep over `src/cbor.rs` then reported 121 mutants: 113 caught, 1 unviable,
7 missed — exactly the seven pre-existing documented equivalents, none of
which weakens a normative branch. The v0.8 classification change itself is
pinned by the duplicate/misordered split tests in `cbor::tests`,
`validate_cbor_api`, `negative_b7` item 9, and the Appendix B.10 exact
`invalidCbor` conformance suite.

**v0.8.1 re-pin addendum:** the v0.8.1 maintenance pass changed one
production branch — `src/cbor.rs` `read_head` now admits CBOR simple values
other than `false`/`true`/`null`/`undefined` through the deterministic layer
in their shortest encodings (one-byte 0–19, two-byte 32–255), so the
already-present schema-layer rejections classify them as exact
`schemaViolation` (specification v0.8.1 sections 6.1.2/6.1.3; Appendix
B.12) — plus documentation-only updates in `src/contact.rs`, `src/error.rs`,
and `src/lib.rs`. A scoped sweep over all four changed files (cargo-mutants
v27.1.0, `--jobs 2`) reported 375 mutants: 352 caught, 13 unviable, 10
missed. All ten missed are the long-documented equivalents in the table
above: the `cbor.rs` disjoint-operand `|` → `^` family (`read_wide` plus the
five `Writer::head` sites), the major-7 reserved-ai fall-through arm, the
`is_language_tag` entry-guard equivalence, and the two unobservable
media-type length-cap boundary mutants. No new survivor was introduced, and
no surviving mutant touches the v0.8.1 simple-value branch: the
`undefined`-versus-admitted split and the two-byte well-formedness boundary
are pinned by
`cbor::tests::sec_6_1_2_admits_schema_disallowed_simple_values_as_deterministic`,
`validate_cbor_api`, the Appendix B.12 exact `schemaViolation` conformance
suite, and the `negative_b7` item 19 cases.

## Milestone 2 gate (authoring and inspection CLI)

Scoped sweep over every Milestone 2 module (`src/cli/mod.rs`,
`src/cli/json.rs`, `src/cli/keyfile.rs`, `src/bin/followee.rs`,
`src/lib.rs`; cargo-mutants v27.1.0, `--jobs 6`). The initial sweep reported
87 mutants: 71 caught, 10 unviable, 6 missed. One miss was a genuine
boundary gap and was killed with an added test — the revocation clock-sanity
floor comparison (`<` at exactly 2020-01-01), now pinned by
`cli::sec_5_3_revocation_clock_floor_boundary_is_exact`; a confirming sweep
over `src/cli/mod.rs` reports **32 mutants: 30 caught, 2 unviable, 0
missed**. The remaining five survivors are individually explained:

| Mutant | Explanation |
| --- | --- |
| `src/lib.rs` `fuzzing::parse_contact_json` → `()` | Fuzz-harness glue for the `contact_json_parse` target, exercised by the fuzz smoke rather than `cargo test` — the same documented family as the earlier fuzz entry points. The parser itself is fully covered by `cli::json` unit tests and the CLI suites. |
| `src/cli/keyfile.rs` `SecretSeed::drop` → `()` | Deliberate defence-in-depth that safe Rust cannot observe: zeroisation on drop erases freed memory, and asserting on freed memory is undefined behaviour. IMPLEMENTATION.md section 7.4 requires zeroisation "where practical"; the practice is established by review, and every observable secret-exposure channel is separately pinned by the redaction sweeps. |
| `src/cli/keyfile.rs` `open_owner_only_new`, `check_read_safety` ×2 (all in `#[cfg(not(unix))]`) | Platform-conditional fallbacks compiled out on the Unix test platform, so mutations there cannot change tested behaviour. The Unix implementations of the same functions have full mutation coverage (owner-only mode, exclusive create, permission/symlink/regular-file refusals). |

No surviving mutant weakens a normative or security-sensitive branch.

## Milestone 3 gate (single relay)

Scoped sweep over every Milestone 3 production module (`src/relay/mod.rs`,
`src/relay/wire.rs`, `src/relay/cursor.rs`, `src/relay/http.rs`,
`src/store/mod.rs`, `src/store/sqlite.rs`, `src/ordering.rs`, `src/lib.rs`;
cargo-mutants v27.1.0, `--jobs 6`, `PROPTEST_CASES=8`). The initial sweep
reported 265 mutants: 210 caught, 28 unviable, 3 timeouts, 24 missed.
Review classified 19 of the 24 as genuine boundary-coverage gaps and killed
each with an added test:

- resolve batch hard-maximum boundary (256 accepted, 257 → `400`);
- `changes` request maxima (`itemLimit = 1024`, `byteLimit = 4 MiB`,
  128-byte cursor) accepted at their exact bounds;
- the cursor null-check (`false` and a 22-byte byte string must not alias
  CBOR `null`), and a wrong `changes` protocol version;
- a record at exactly 16 KiB admitted through `v1/publish`;
- a 32 KiB publish body classified `recordTooLarge` rather than `413`
  (pinning the transport read bound arithmetic);
- byte-budget accounting pinned to the byte across the 24-entry CBOR
  array-head width transition and at exact-fit/one-under budgets
  (`sec_12_6_byte_budget_accounting_is_exact_across_the_array_head_boundary`,
  `sec_12_6_byte_budget_binds_exactly_at_the_24_entry_head_boundary`);
- SQLite true-path return values for `convert_to_ref`/`drop_entry`, the
  persisted effect of `reset_cursor_generation`, and both `Debug`
  implementations and the `development_mode` accessor.

The confirming sweeps report **265 mutants: 227+ caught, 28 unviable, 3
timeouts, 5 missed**, with every survivor individually explained:

| Mutant | Explanation |
| --- | --- |
| `src/relay/mod.rs` `RELAY_CAPABILITIES` `\|` → `^` (two sites) | Equivalent: the capability bits `0x01`, `0x02`, `0x04` are disjoint, so OR equals XOR — the same family as the long-documented `cbor.rs` disjoint-operand mutants. The composed value `0x07` is pinned by the info-endpoint test. |
| `src/lib.rs` `fuzzing::parse_relay_request` / `fuzzing::decode_cursor` → `()` | Fuzz-harness glue, not protocol code: these `#[doc(hidden)]` entry points only forward arbitrary bytes to the wire/cursor parsers for the `relay_request_parse` and `cursor_decode` fuzz targets, and are exercised by the fuzz smoke rather than `cargo test`. The parsers themselves are fully covered by the wire and cursor test suites. |
| `src/store/sqlite.rs` `entry_from_row`: delete the `(None, None, None)` ordering arm | Defensive corruption classification that is unreachable through the store contract: `SqliteStore` always persists ordering metadata on commit and preserves it on conversion, so a row without it can only be produced by out-of-band database edits. The `ordering: None` contract semantics are exercised through `MemoryStore`. |

Three mutants are reported as timeouts rather than misses: inverting the
development-mode loopback guard (`development_mode -> false`, `delete !` in
`serve`) prevents every test server from starting, and reversing the SQLite
`changes_after` `has_more` comparison makes pagination loop; each hangs the
suite, which a CI run fails by timeout. No surviving mutant weakens a
normative or security-sensitive branch.

## Milestone 3 integration confirmation (post-Milestone-2 rebase)

After integrating the preserved Milestone 3 delivery onto the reviewed
Milestone 2 base, a fresh scoped sweep over every production file touched by
the integration (`src/relay/*`, `src/store/*`, `src/ordering.rs`,
`src/lib.rs`; cargo-mutants v27.1.0, `--jobs 6`, `PROPTEST_CASES=8`)
reported **266 mutants: 230 caught, 28 unviable, 2 timeouts, 6 missed**.
Every survivor is already individually explained above: the three
`#[doc(hidden)]` fuzz-glue entry points (`parse_contact_json`,
`parse_relay_request`, `decode_cursor` — exercised by the fuzz smoke, not
`cargo test`), the two disjoint-bit `RELAY_CAPABILITIES` `|` → `^`
equivalents, and the unreachable SQLite defensive ordering arm. The two
timeouts are the documented development-mode guard inversions that hang the
test servers and fail CI by timeout. No new survivor was introduced by
conflict resolution or integration.

## Milestone 3 executable-surface follow-up (`relay serve`)

The bounded follow-up changed two production files: `src/cli/mod.rs`
(the `relay serve` command and the `Option<Value>` dispatch) and
`src/relay/http.rs` (`serve_with_shutdown`, with `serve` delegating). A
scoped sweep over both (cargo-mutants v27.1.0, `--jobs 6`,
`PROPTEST_CASES=8`) reported 57 mutants: 53 caught, 2 unviable, 1 timeout,
1 missed. The miss — inverting the development-mode determination
(`!base_uri.starts_with("https://")`) — was killed by
`relay_serve_shell::relay_serve_base_uri_selects_conforming_or_development_mode`;
the confirming sweep over `src/cli/mod.rs` reports **37 mutants: 35 caught,
2 unviable, 0 missed**. The one timeout is the `serve_with_shutdown`
loopback-guard inversion, the same documented family as the earlier
development-mode guard timeouts: every test server refuses to start and the
suite hangs, which CI fails by timeout. No new survivor.
