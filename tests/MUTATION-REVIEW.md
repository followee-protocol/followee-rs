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

## v0.9 relay-maintenance pass (concurrent-ingress cursor visibility)

The v0.9 amendment is relay-only: it requires update-number assignment,
accepted-state commitment, and `v1/changes` visibility to form one
observable order (specification sections 12.6, 13.2, 16.17, 20.2). The
maintenance audit traced both backends and found the invariant already
structurally satisfied — every store access serializes through the relay's
single store lock, `commit_current` (the sole update-number assigner, one
production call site) allocates the number inside the same atomic operation
that commits the state, and a failed SQLite commit transaction rolls the
allocation back.

Maintenance review then corrected the write-critical-section boundary in
one production module, `src/relay/mod.rs`: `Relay::publish` previously
acquired the store lock before deterministic-CBOR parsing, record and
signature verification, and descriptor work, making expensive
state-independent processing part of the section that excludes competing
writers and `v1/changes` readers. Publication is now two-phase — phase 1
runs every bounded state-independent step unlocked through the reviewed
production verification core into a private `PreparedCandidate` (wrapping
the unfabricable `VerifiedRecord`, so the locked phase consumes
verification evidence, never caller metadata), and phase 2 holds the lock
only for the sticky recheck, current-state comparison, and the atomic
allocation-and-commit. A `#[doc(hidden)]` test-support gap hook runs
between the phases; it is `None` in every production construction path,
receives no protocol data, returns nothing, and executes while no lock is
held, so it can only delay the calling thread at a point the scheduler may
already preempt arbitrarily. No other production module changed;
`src/store/*` and every core module remain byte-identical, so the
Milestone 1–3 sweeps above remain their applicable evidence.

### Scoped sweep over the changed module

A scoped sweep over `src/relay/mod.rs` (cargo-mutants v27.1.0, `--jobs 6`,
`PROPTEST_CASES=8`) reported **54 mutants: 34 caught, 6 unviable, 2 missed,
12 timeouts**. Nothing survives unexplained:

- The 2 missed are the long-documented `RELAY_CAPABILITIES` disjoint-bit
  `|` -> `^` equivalents from the table above (`0x01 | 0x02 | 0x04` is
  bit-disjoint, so XOR produces the identical value).
- All 12 timeouts are one detected-by-hang family: each mutant makes
  publication inert or inverts an admission decision (`publish` stubbed to
  a constant, `now_ms` stubbed, the `prepare` size/premature comparisons
  inverted, the `admit_prepared` sticky-exclusion condition inverted,
  `claimed_body_id` stubbed, and the previously documented
  `development_mode` guard family). Under such a mutant the deterministic
  concurrency orchestration deadlocks — writer A never reaches its gate —
  and the suite fails through its 60-second hang guard, which exceeds the
  cargo-mutants per-mutant test timeout; CI equally fails such a build by
  timeout. Every one of these mutants is therefore detected, not missed.

The sweep ran against the final production sources; the only later edit to
the module was one documentation-comment line (an intra-doc-link fix),
which cargo-mutants does not mutate.

### Controlled-fault demonstrations (re-run on the corrected code)

Two hand-injected production faults, each an anti-pattern the v0.9 text
names, were applied to the corrected implementation, demonstrated, and
reverted by inverse edit (verified byte-identical afterwards):

1. **Cursor-overtaking fault** (`src/relay/mod.rs`, `changes`): `nextCursor`
   was computed from `store.last_update_number()` — "the greatest committed
   or observed update number" section 12.6 forbids — instead of the last
   included position.
   `relay_concurrency::sec_12_6_success_cursor_cannot_overtake_a_paused_undecided_writer_memory`
   and `_sqlite` both failed deterministically: the `itemLimit = 1` walk
   received cursor position 3 where exactly 2 is conforming, which would
   permanently skip the omitted eligible entry. 5 of 7 suite tests passed,
   those 2 failed.
2. **Reserve-then-commit fault** (`src/store/sqlite.rs`, `commit_current`):
   the update number was allocated in its own immediately committed write
   before the entry transaction — the pattern sections 13.2 and 16.17
   forbid.
   `relay_concurrency::sec_13_2_sqlite_commit_failure_rolls_back_the_allocated_update_number`
   failed deterministically: the counter read 1 after the failed entry
   transaction instead of rolling back to 0, a permanent sequence hole.
   6 of 7 suite tests passed, that 1 failed.

After reverting each fault, `git diff` confirmed `src/store/sqlite.rs`
byte-identical to `milestone-3-v0.8.1-reviewed` content and
`src/relay/mod.rs` carrying only the reviewed two-phase change, and the
complete concurrency suite (7 tests, both backends) passed. The
gate-coordinated pause in the gated tests holds the store lock inside
`commit_current`, so the "no cursor while a writer is undecided" assertions
are ordering guarantees of the production locking discipline, not timing
samples; the unlocked-gap tests prove the complementary boundary, that a
reader completes while another publication is paused after phase-1
preparation with no lock held.

## Milestone 4 gate (relay client, synchronization receiver, resolver)

Scoped sweeps over every changed production module — `src/relay/wire.rs`,
`src/relay/client.rs`, `src/relay/sync.rs`, `src/resolver.rs`,
`src/store/mod.rs`, `src/store/sqlite.rs`, `src/cli/network.rs`,
`src/error.rs` — with `cargo mutants --jobs 6`. No mutant timed out; every
timeout column below is zero and no result is excused as a timeout.

Sweep 1 (initial Milestone 4 code): **538 mutants: 397 caught, 76 missed,
65 unviable**. Review classified the 76 survivors; genuine gaps were closed
with killer tests, most notably:

- an exhaustive `wire_error_symbol` table test (23 survivors in the
  section 15.3 rendering helper);
- exact protocol-boundary twins for the client-side response parsers:
  256-result resolve responses, 4096-entry directories, 1024-entry changes
  responses, 128-byte cursors (request and response side), 2048-byte URIs,
  non-empty typed `relay-info` arrays, the limits-map label domain, and
  change-entry arity/type checks (the directory and changes response
  member-DoS caps were raised so the exact section 15.2 boundaries are
  reachable rather than masked);
- network-policy neighbours: acceptance of addresses adjacent to every
  rejected IPv4 range, rejection of all three IPv4 documentation ranges
  (a genuine policy-test gap), and production-transport refusal tests for
  literal and DNS-resolved destinations without touching the network;
- budget boundaries (byte budget exactly consumed; response exactly at the
  size bound; request/deadline exhaustion), `SyncOptions::max_pages`
  fetching exactly its bound, and `SyncError` symbol stability;
- resolver cache-replacement rules: an earlier same-authority winner never
  displaces the cached later record, the RootRevoked transition replaces
  the cache even at a lower timestamp, depth-exactly-at-budget traversal,
  default-port normalization, and no routing hint for a depth-zero win;
- CLI in-process tests over a real loopback server: a near-cap (14 KiB)
  record through the `relay resolve` budget, a multi-hundred-kilobyte
  `relay sync` page, exact wire-code JSON rendering, the state-file
  read-error guard (isolated with an invalid-UTF-8 state file so a later
  state save cannot mask it), and `--deadline-ms` reaching the shared
  budget.

Sweep 2 (after those tests): **555 mutants: 477 caught, 13 missed,
65 unviable**. Of the 13, four more were genuine and got killer tests plus
one clarity refactor (the change-entry head/arity guard was split so each
check is independently killable; a non-array-entry test and the two new
transport/cursor/route tests were verified by manually applying each
mutation and watching the new test fail). A confirmation sweep over the
four files touched after sweep 2 is recorded below.

### Accepted surviving mutants (Milestone 4)

| Mutant | Explanation |
| --- | --- |
| `src/relay/client.rs` `Debug for RelayClient::fmt -> Ok(Default::default())` | Diagnostic formatting only (`finish_non_exhaustive` output); no protocol value flows through `Debug`. |
| `src/relay/wire.rs` `parse_changes_response` entry guard `\|\|` → `&&` (sweep 2) | Resolved by refactor: the combined head/arity condition was split into two independent checks, each killed by the non-array-entry and arity-2/-4 tests in the confirmation sweep. |
| `src/cli/network.rs` `64 * 1024` → `+`/`/` in `relay_changes`/`relay_sync` command budgets, and `1024 * 1024` → `+` in `relay_publish`, `2 * 1024 * 1024` first `*` → `+` in `relay_resolve` | Generous local head-room constants in one-shot operator command budgets. Every response these commands can accept is independently bounded first (the client enforces the per-request `byteLimit`, the 1 MiB resolve-response bound, and the 64 KiB small-response bound before the command budget can bind), so the mutated head-room remains above every reachable size; the second `relay_resolve` `*` (whose mutation *does* drop below the 16 KiB record path) is killed by the in-process 14 KiB test. Distinguishing the remainder would require multi-megabyte transfers that the protocol bounds themselves already reject. |
| `src/store/sqlite.rs` `entry_from_row` delete arm `(None, None, None)` | Unreachable defensive tolerance: every production write path (`commit_current`, `convert_to_ref`) persists complete ordering metadata, so a row with all three ordering columns NULL cannot be created through the store contract. The arm exists so such a row (hand-edited or from a future schema) reads as `ordering: None` instead of failing; deleting it routes to the adjacent `Corrupt` arm, which is also a rejection. The parity suite pins the reachable `Some`/`Corrupt` classifications. |

Any Milestone 4 mutant not listed above and not caught in the confirmation
sweep is a review finding, not an accepted survivor.

### Confirmation sweep

Confirmation sweep over the four files changed after sweep 2
(`src/relay/wire.rs`, `src/relay/client.rs`, `src/resolver.rs`,
`src/cli/network.rs`): **423 mutants: 375 caught, 7 missed, 41 unviable,
0 timeouts**. The seven survivors are exactly the accepted set above: the
six command-budget head-room constants and the `Debug` formatting impl.
The state-read guard, request-cursor boundary, resolved-address rule,
routing-hint depth condition, and the split change-entry guards were all
killed. `src/relay/sync.rs`, `src/store/mod.rs`, `src/store/sqlite.rs`,
and `src/error.rs` were unchanged after sweep 2, whose results for them
stand (zero missed apart from the documented `entry_from_row` arm).

Combined Milestone 4 evidence: **every mutant in changed production
modules is caught except the seven accepted survivors and the one
documented unreachable-defensive store arm**; no timeout was recorded in
any sweep.

## Milestone 5 gate (WebFinger, handle authority, migration presentation)

Scoped sweeps over every changed production module —
`src/webfinger/mod.rs`, `src/webfinger/jrd.rs`,
`src/webfinger/authority.rs`, `src/resolver.rs`, `src/relay/client.rs`,
`src/cli/handle.rs`, `src/cli/network.rs`, `src/cli/mod.rs` — with
`cargo mutants --jobs 8 -o mutants.m5` (the Milestone 4 `mutants.out`
evidence is left untouched).

Sweep 1 (initial Milestone 5 code): **516 mutants: 420 caught, 37 missed,
57 unviable, 2 timeouts**. Review classified every survivor; genuine gaps
were closed with killer tests:

- **two hang-capable shell tests** were the root cause of both timeouts:
  `handle serve` guard mutants (`development_mode -> false`; the
  case-variant DID comparison `!=` → `==`) let a process the test expected
  to exit keep serving, and `Command::output()` waited forever. The tests
  now use a bounded watchdog (`run_expecting_exit`) that kills a
  still-running process and fails the assertion, so both mutants are
  caught cleanly instead of hanging the suite;
- `Handle` `Display` (protocol-visible in every CLI `handle` field) is
  pinned by an exact-form unit test;
- a moderately large (8 KiB) valid JRD must resolve, pinning
  `MAX_JRD_RESPONSE_BYTES` against silent shrinkage;
- the authority configuration byte bound is pinned at its exact boundary
  (a valid configuration of exactly `MAX_CONFIG_BYTES` loads; one byte
  more is `TooLarge`), and a valid record of exactly 16 KiB is accepted
  by the record-file loader;
- lowercase percent-escape hex (`%3a`) decoding is pinned;
- the unused `HandleAuthority::resource_for_local` convenience helper was
  removed instead of tested (dead code, two survivors);
- CLI handler behaviour: `--no-bootstrap` suppresses fetches, migration
  claims from a bootstrap winner render as deferred `notChecked` rows,
  `authorityState` names render exactly, a near-cap (≥ 14 KiB) bootstrap
  record passes the handle-command budget, `--deadline-ms` drives the
  shared operation deadline, and supplying both `--record` and `--relay`
  is a usage error.

### Accepted surviving mutants (Milestone 5)

| Mutant | Explanation |
| --- | --- |
| `src/webfinger/mod.rs` `canonical_domain` guard mutants (eleven: the pre-IDNA `is_empty`/length gate and the post-IDNA re-check conditions) | Deliberate defence-in-depth redundancy, documented at the function: `idna::domain_to_ascii_strict` (STD3 deny list, hyphen checks, `DnsLength::Verify`) already rejects every input the explicit re-checks reject — empty input, empty/oversized labels, >253 octets, non-LDH bytes, leading/trailing hyphens — and its output is lowercase ASCII by construction, so each mutated guard is unreachable or a no-op given the library invariants pinned by `sec_10_1_invalid_domains_are_rejected`. The re-checks exist precisely so conformance does not silently depend on those library internals; removing them to satisfy the mutation score would invert the design intent. The pre-gate length boundary (`> MAX_URI_BYTES`) is a bounded-work gate with the same both-paths-reject property as the accepted `did.rs` length-gate mutants (Milestone 1). |
| `src/webfinger/jrd.rs` `parse_string` run-flush `>` → `>=` | Equivalent: at `pos == start` the mutant appends an empty, valid UTF-8 run — a no-op producing identical output for every input. |
| `src/webfinger/authority.rs` `AuthorityConfig::load` size-check `==` mutants (config metadata/read pair, record pre-check) | Redundant-pair equivalents: the metadata gate and the post-read gate share one threshold, so weakening either to `==` routes an oversized file to the other, which rejects with the same `TooLarge`; the record pre-check weakened to `==` routes an oversized record to the production verifier's own 16 KiB step-1 check, which rejects with the same `RecordTooLarge` classification. The reachable `>=` boundary mutants at all three sites are killed by the new exact-boundary tests. |
| `src/webfinger/authority.rs` `percent_decode` `(hi << 4) \| lo` → `^` | Equivalent: `hi << 4` has zero low bits, so OR and XOR agree (same category as the accepted Milestone 1 CBOR-writer head mutants). |
| `src/webfinger/mod.rs` `Debug for WebFingerClient::fmt`, `src/relay/client.rs` `Debug for RelayClient::fmt` | Diagnostic formatting only (`finish_non_exhaustive` output); no protocol value flows through `Debug`. Same category as the accepted Milestone 4 `RelayClient` `Debug` mutant. |
| `src/cli/network.rs` command-budget head-room constants (`2 * 1024 * 1024` first `*` in `relay_resolve`; `byte_limit * max_pages` mutants in `relay_sync`) | Already-reviewed Milestone 4 accepted survivors, unchanged by this milestone: every response these commands can accept is independently bounded first by the client's per-request caps, so the mutated head-room remains above every reachable size within protocol bounds. |

Any Milestone 5 mutant not listed above and not caught in the
confirmation sweep is a review finding, not an accepted survivor. The
confirmation sweep result is recorded below.

### Confirmation sweep (Milestone 5)

Confirmation sweep over the same eight modules after the killer tests and
watchdog fixes: **513 mutants: 435 caught, 15 missed, 57 unviable,
6 timeouts** (three mutants fewer than sweep 1 because the dead
`resource_for_local` helper was removed rather than tested).

The 15 missed are exactly the accepted set above: the six surviving
`canonical_domain` defence-in-depth guards (the pre-IDNA `||` gate and the
post-IDNA label re-checks at `src/webfinger/mod.rs` lines 113–127 — the
other five sweep-1 guard survivors are now caught by the added boundary
tests), the `parse_string` empty-run `>=` equivalence, the
already-reviewed Milestone 4 command-budget head-room constants in
`src/cli/network.rs` (`relay_publish`, `relay_resolve`, `relay_changes`,
`relay_sync`), the Milestone 4-accepted `RelayClient` `Debug` mutant, and
two genuine findings killed after this sweep (see the final verification
below): the `parse_hex4` uppercase `A–F` escape arm, and the
`handle_resolve` sticky-transition comparison (`==` → `!=`), which could
have fabricated sticky revocation in the state file for a Root bootstrap
winner and is now pinned in both directions
(`handle_events_never_mutate_the_state_file_identity` asserts the seeded
state stays `root`;
`handle_resolve_persists_a_learned_root_revoked_transition` asserts a
real transition persists).

The 6 timeouts divide into two categories, none a silent survivor:

- `src/cli/mod.rs` `relay_serve -> Ok(None)` and the `relay_serve`
  development-mode `delete !`: both disable or misreport the Milestone 3
  `relay serve` process wholesale, and the suite cannot pass under them —
  the three-relay demonstration script waits for relay startup that never
  happens (or shell startup assertions fail), so the run is detected by
  failure to complete. The mutated behaviour itself is pinned by the
  Milestone 3 `relay_serve_shell` startup-contract tests; the timeout is
  a property of the reviewed demonstration script's readiness wait, which
  this milestone does not modify.
- `WebFingerClient` `Debug` (accepted diagnostic-formatting category),
  the `AuthorityConfig::load` record-size `==`/`>=` pre-check mutants,
  and the `percent_decode` disjoint-bit `|` → `^` (both argued equivalent
  above): equivalent mutants run the entire suite to completion, and
  under eight parallel jobs the full-suite runtime crossed the
  auto-timeout. Sweep 1 recorded the same mutants as ordinary survivors,
  consistent with the equivalence argument rather than any hang. The
  reachable record-size boundary (`>=` at exactly 16 KiB) is killed by
  `sec_15_1_record_file_at_exactly_the_envelope_cap_loads` in the final
  verification.

### Final verification (Milestone 5)

Targeted re-run over the two files whose kills landed after the
confirmation sweep (`src/cli/handle.rs`, `src/webfinger/jrd.rs`):
**106 mutants: 97 caught, 1 missed, 8 unviable, 0 timeouts**. The one
survivor is exactly the accepted `parse_string` empty-run `>=`
equivalence; the uppercase `A–F` escape arm and the `handle_resolve`
sticky-transition comparison are both caught. The other six modules were
unchanged after the confirmation sweep, whose results for them stand.

Combined Milestone 5 evidence: **every mutant in changed production
modules is caught except the documented accepted survivors** — six
`canonical_domain` defence-in-depth guards, one `parse_string` empty-run
equivalence, the redundant-pair size-check `==` mutants and the
disjoint-bit `|`→`^` in the authority loader, two diagnostic `Debug`
impls, and the already-reviewed Milestone 4 command-budget head-room
constants — plus the two `relay_serve` process-disabling mutants detected
by suite failure-to-complete, whose behaviour is pinned by the
Milestone 3 shell tests.

## Milestone 5 correction pass (specification v0.9.1 and Railway packaging)

The v0.9.1 re-pin changed three production modules: `src/resolver.rs`
(the section 14.2 migration classifier: a completed check with a stale
claimant or counterpart is now exactly *Checked but unverified* with
`claimantStale`/`counterpartStale`, staleness never yields *Not
checked*, and the counterpart is resolved even for a stale claimant) and
`src/cli/mod.rs` + `src/cli/handle.rs` (the `relay serve`/`handle serve`
shutdown listener is now registered before the startup object is
written, closing a race in which a SIGTERM arriving immediately after
startup could hit the default disposition instead of the clean shutdown
path — surfaced as a shell-test flake under coverage instrumentation).
The Railway packaging introduces no mutable Rust production code (the
container entrypoint is a shell script exercised end to end by
`tests/handle_railway_packaging.rs` and by a full podman image build and
run).

Fresh scoped sweeps over exactly those modules, with the retained
Milestone 5 evidence standing for every unchanged module:

- `src/resolver.rs`: **67 mutants: 60 caught, 0 missed, 7 unviable,
  0 timeouts** (`mutants.m51/`);
- `src/cli/mod.rs` + `src/cli/handle.rs`: **59 mutants: 55 caught,
  0 missed, 4 unviable, 0 timeouts** (`mutants.m51.cli/`).

No survivor exists in any production module changed by the correction
pass; no new accepted-survivor entry is required. The v0.9.1
classification itself is pinned by
`migration_states::sec_14_2_stale_claimant_is_checked_but_unverified`,
`sec_14_2_stale_counterpart_is_checked_but_unverified_even_when_reciprocal`,
and `sec_14_2_stale_and_non_reciprocal_claims_stay_checked_but_unverified`,
each asserting the state, the diagnostic reason, suppressed
presentation, and byte-identical durable identity and sticky state.

## Milestone 5 deployment-evidence pass (digest pinning and consistency gate)

This pass changed three production modules: `src/webfinger/authority.rs`
(the predeployment `deployment_consistency` report), `src/cli/mod.rs`
(the `--check` flag and `deploymentInconsistent` error), and
`src/cli/handle.rs` (the check handler). Scoped sweeps:

- combined sweep over all three (`mutants.m52/`, run concurrently with
  the container build): **129 mutants: 114 caught, 1 missed, 9 unviable,
  5 timeouts**;
- clean re-verification of `src/webfinger/authority.rs` after review
  (`mutants.m52.authority.final/`): **69 mutants: 63 caught, 1 missed,
  5 unviable, 0 timeouts**.

Review findings, all closed:

- the config-size boundary test was self-referential (it padded to the
  mutated constant), letting `MAX_CONFIG_BYTES` `256 * 1024` → `+`
  survive — killed by asserting the absolute value `262_144`;
- the exact-16-KiB record test exercised only `from_json`, leaving the
  file-path size pre-check in `AuthorityConfig::load` unobserved
  (`>` → `==`/`>=` at the record read) — killed by loading the maximal
  record through a real config file and `AuthorityConfig::load`;
- the two co-loaded-run timeouts at that same site were `relay_properties`
  proptest runtime variance (its randomized cases run near the 60-second
  mark under heavy parallel load), not mutant behaviour: the clean
  re-verification has zero timeouts;
- the `src/cli/mod.rs` `relay_serve` process-disabling timeout pair is
  the documented Milestone 5 category (three-relay demonstration
  readiness wait), unchanged.

The one final survivor is the already-accepted `percent_decode`
`(hi << 4) | lo` → `^` disjoint-bit equivalence. No other survivor
exists in any module changed by this pass.

## Milestone 6 — maintained v0.9.2 participant pass

Scoped sweep over every production file this pass changed or added —
`src/relay/wire.rs`, `src/did.rs`, `src/crypto.rs`, `src/interop/mod.rs`,
`src/interop/json.rs`, `src/cli/network.rs` — with the retained Milestone
1–5 evidence standing for every unchanged module:

- first sweep (`mutants.m6/`, local, gitignored artifacts): **511 mutants:
  407 caught, 48 missed, 56 unviable, 0 timeouts**.

Review of the 48 survivors closed all of them, by added tests, by
production simplification, or as individually explained equivalents:

**Killed by added tests or simplification:**

- `src/interop/json.rs` string/escape survivors (`skip_ws` stub, `\uXXXX`
  hex-digit match arms, surrogate-pair bit arithmetic, writer control-char
  guard and digit arithmetic, `<`→`<=`/`==` on the control boundary) —
  killed by the added unit tests
  `insignificant_whitespace_is_skipped_between_tokens`,
  `unicode_escapes_decode_to_the_exact_code_points`, and
  `writer_escapes_exactly_the_control_characters`; the depth-boundary
  `>`→`>=` killed by `nesting_depth_boundary_is_exact`.
- `src/interop/mod.rs` `handle_line`/`serve_lines` 1 MiB boundary
  survivors — killed by `interop::interface_line_length_boundary_is_exact`
  and `interface_serve_lines_handles_an_unterminated_final_line` (exact-cap
  and cap-plus-one lines; unterminated final line).
- `src/interop/mod.rs` `parse_dec_u64` survivors (`||`→`&&` letting
  `"+5"` through Rust's sign-accepting `u64::from_str`; leading-zero and
  length-boundary mutants) — killed by
  `interface_decimal_string_convention_boundaries` (`"+5"`, `"01"`,
  `"1a"`, `""`, `" 1"` rejected; `"0"` accepted).
- `src/interop/mod.rs` `parse_nint_magnitude` `||` survivors — killed by
  `interface_nint_convention_boundaries` (`-01`, `-+5`, `-`,
  `-(2^64+1)` rejected; exactly `-2^64` accepted); the unreachable
  `magnitude == 0` disjunct (excluded by the leading-zero rule) was
  removed, so its operator no longer exists to mutate.
- `src/interop/mod.rs` `op_select_current` deleted `"root"` sticky arm —
  killed by `select_current_accepts_every_sticky_authority_form`.
- `src/interop/mod.rs` `contact_from_json` deleted `avatar` field — killed
  by `contact_round_trip_preserves_every_member`.
- `src/interop/mod.rs` `encode_key` stub survivors — the conversion-side
  sort was redundant (the deterministic writer sorts every map by encoded
  key, and production validation rejects duplicates before encoding), so
  the sort and its helper were removed rather than pinned.
- `src/cli/network.rs` `relay_publish` `== 1`→`!=` on the status-1 reason
  member — killed by
  `cli_network_inprocess::relay_publish_surfaces_the_status_1_reason_verbatim`
  (canned peer answering `{0:1, 1:1, 2:13}`).

**Individually explained equivalents (accepted survivors):**

- `src/did.rs:50` `s.len() > MAX_URI_BYTES` `>`→`==`/`>=`: a pre-decode
  work bound only. Every affected input (any string over ~55 characters)
  is rejected as `invalidDid` by base58/multihash validation regardless,
  so the observable classification is identical; the bound limits work,
  not outcomes.
- `src/did.rs:167` `shift > 63` `>`→`==`/`>=` in `read_minimal_varint`:
  the nine-byte iteration cap makes `shift` top out at exactly 63, so all
  three comparisons return `None` for the same inputs; the check is
  defence in depth behind the length cap.
- `src/interop/json.rs:98` depth `>`→`==`: nesting depth increases by
  exactly 1 per level, so any chain deeper than the cap passes through
  equality first; the mutant fires on exactly the same inputs.
- `src/relay/wire.rs:638/649` `head.major != ARRAY || head.arg == 0`
  `||`→`&&` in `parse_info_response`: an empty version/suite array now
  also fails the v0.9.2-pass requirement that the arrays contain protocol
  version `1` and suite `-19`, producing the same complete
  `schemaViolation` rejection; the emptiness check is doubly enforced.
- `src/cli/network.rs` command-budget head-room constants
  (`1024 * 1024` in `relay_publish`, first `*` in `relay_resolve`,
  `64 * 1024` in `relay_changes`/`relay_sync`): the already-reviewed
  Milestone 4/5 accepted survivors, unchanged by this pass — every
  response these commands can accept is independently bounded first by
  the client's per-request caps, so the mutated head-room remains above
  every reachable size within protocol bounds.

A verification re-sweep over the three files with new or changed tests
(`src/interop/mod.rs`, `src/interop/json.rs`, `src/cli/network.rs`;
`mutants.m6.rerun/`) confirms the closures: **205 mutants: 159 caught,
6 missed, 39 unviable, 1 timeout**, where the 6 missed are exactly the
already-reviewed Milestone 4/5 accepted budget-constant survivors listed
above and the single timeout was the `relay_publish` whole-function stub
hanging the canned-peer test on its unconditional `join` — detection by
hang rather than assertion. The responder thread was then detached so the
assertions alone must fail, and a spot re-verification of the
`relay_publish` mutants (`mutants.m6.spot/`) shows the stub **caught**
with 0 timeouts: **10 mutants: 7 caught, 1 missed (the accepted
`1024 * 1024` budget constant), 2 unviable**. The `src/did.rs`,
`src/crypto.rs`, and `src/relay/wire.rs` results stand from the first
sweep (0 missed in `src/crypto.rs`; the `src/did.rs` and
`src/relay/wire.rs` survivors are exactly the explained equivalents
above). No unexplained survivor remains in any file this pass touched.

## Milestone 6 — authoring revision 2 adaptation

The neutral authoring input was corrected (revision 2; only
`interface/INTERFACE.md` changed). The adaptation changed
`src/contact.rs`, `src/record.rs`, and `src/verify.rs` (wire-presence
capture for the lossless revision-2 projection) and `src/interop/mod.rs`
(the revision-2 accepted-result projection and constructor
canonicalization). Scoped sweep over those four files (`mutants.m6.rev2/`):
**473 mutants: 415 caught, 6 missed, 52 unviable, 0 timeouts**.

All six survivors closed:

- `src/interop/mod.rs` `contact_from_json` migration `||`→`&&` (a
  single-member migration object would be silently dropped as an omission
  request) — **killed** by the added
  `interop::migration_object_with_one_member_is_authored_and_projected`.
- `src/record.rs` `parse_descriptor` and `parse_public_key` map-head
  `!= MAP || != n` `||`→`&&` — the disjuncts were **removed** by
  splitting each check into two sequential `if`s (behaviour-identical;
  no operator remains to mutate). A spot re-verification over those
  functions and `contact_from_json` (`mutants.m6.rev2spot/`) confirms:
  **23 mutants: 22 caught, 0 missed, 1 unviable, 0 timeouts**.
- `src/contact.rs` `is_language_tag` guard `is_empty() || !is_ascii()`
  `||`→`&&`: **explained equivalent-outcome**. The guard is a fast path:
  an empty tag still fails the empty-segment check on `parts`, and a
  non-ASCII tag cannot match the ASCII grandfathered table or the
  ASCII-strict subtag validators, so every input the guard rejects is
  rejected downstream with the same classification.
- `src/contact.rs` service `mediaType` length `>`→`>=`/`==`:
  **explained equivalent-outcome**. `is_restricted_name` caps each RFC
  6838 name at 127 characters, so the longest grammar-valid `mediaType`
  is 255 bytes; every string the 256-byte length bound rejects already
  fails the grammar check in the same disjunction. The bound is retained
  as defence in depth against future grammar changes.
