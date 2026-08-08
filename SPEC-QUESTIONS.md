# Specification questions

Ambiguities identified in the normative specification
(`followee-protocol/followee`), tracked against the pinned commit in
IMPLEMENTATION.md section 2 (currently
`2d5292e95af022af7beee2d154e7217e29907960`, specification v0.8.1). Per
IMPLEMENTATION.md section 2, questions are resolved in the protocol repository
— never silently in this implementation — and no milestone may pass while an
open question affects code delivered by that milestone. Resolving a question
that amends the specification requires re-pinning IMPLEMENTATION.md section 2
and rerunning the complete conformance and differential suite.

**All recorded questions are resolved**, and every resolution remains in
force in specification v0.8.1 at the pinned commit. Each resolved entry cites
the amending version and records the test obligation the resolution creates.

---

## SQ-1 — Appendix B.7 item 1: identity-binding mismatch construction and errors

**Status:** resolved (spec v0.3, commit `a66228c`) · **Affected:** Milestone 1 · **Spec:** Appendix B.7 item 1; section 8.1 steps 6–9

Resolved by amendment. Section 8.1 now defines the complete identity-binding
invariant `body id = target = DID(authorityDescriptor)` and normatively
assigns the same error, `descriptorMismatch`, to failure of either relation
(steps 7 and 9). Appendix B.7 item 1 fixes three executable cases:

- (a) an unchanged, internally consistent envelope verified against a
  different syntactically valid target DID (multi-fault: both relations fail,
  but the exact error remains portable because both checks share it);
- (b) a body-`id` mutation re-signed by the applicable legitimate key,
  verified against the original target (isolates body-to-target); and
- (c) the same re-signed mutation verified against the mutated target
  (isolates descriptor-to-target).

All three produce the same exact binding error, independent of the section
8.1 permitted reordering of cheap checks. The symbol was renamed
`identityBindingMismatch` (wire code 7 unchanged) by the v0.4 amendment; see
SQ-8.

**Test obligation (Milestone 1):**
`sec_8_1_binding_case_a_foreign_target`, `sec_8_1_binding_case_b_mutated_id_original_target`,
`sec_8_1_binding_case_c_mutated_id_mutated_target`, each asserting
`identityBindingMismatch`, with fixture provenance per IMPLEMENTATION.md
sections 11.1 and 12.

## SQ-2 — Appendix B.7 item 2: `invalidDid` vs `unsupportedHash` classification

**Status:** resolved (spec v0.3, commit `a66228c`) · **Affected:** Milestone 1 · **Spec:** sections 3.1, 8.1 step 6, 15.3; Appendix B.7 item 2

Resolved by amendment adopting the syntax-versus-profile split. Section 3.1
now requires the method-specific identifier to decode to exactly one
structurally well-formed multihash (minimal varints, declared length matching
the bytes present, no trailing bytes): structural failures produce
`invalidDid`; a structurally well-formed multihash naming a code other than
`0x12` or a digest length other than `0x20` produces `unsupportedHash` and
remains unacceptable to v1. The classification explicitly does not enlarge the
set of resolvable v1 DIDs. Appendix B.7 item 2 makes both errors normative and
keeps every case target-only (no signed-envelope mutation).

**Test obligation (Milestone 1):**
`sec_3_1_foreign_code_well_formed_is_unsupported_hash`,
`sec_3_1_foreign_digest_length_well_formed_is_unsupported_hash`,
`sec_3_1_non_minimal_varint_is_invalid_did`,
`sec_3_1_length_byte_disagreement_is_invalid_did`,
`sec_3_1_trailing_bytes_is_invalid_did`.

## SQ-3 — Serving a record that is premature under the relay's current clock

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** sections 5.4, 12.3, 15.3, 20.2

Resolved by amendment: a Relay Resolver holding a Full record that is premature
under its present clock MUST NOT return it as Full and MUST NOT return
`Absent`; it MAY return a usable Ref, otherwise the section 12.3 per-DID
`Error` result with code `10` (`premature`). The former `Unsupported` resolve
result was generalised to `Error`. Serving-time classification has no effect on
stored state, `lastUpdated`, or update numbers.

**Test obligation (Milestone 3):**
`sec_12_3_locally_premature_current_record_is_error_not_absent`.

## SQ-4 — `changes-response`: prose "required on success" vs optional CDDL fields

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** section 12.6; Appendix A

Resolved by amendment: section 12.6 enumerates required and forbidden fields
per status, and Appendix A carries a normative note that the `changes-response`
optional markers express the union across statuses and are not discretionary
within a status.

**Test obligation (Milestone 3):** `sec_12_6_status_dependent_field_combinations`.

## SQ-5 — Overlap between `changes` status `1` (ResetRequired) and a reset error code

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** sections 12.6, 15.3

Resolved by amendment: status `1` is the sole v1 wire encoding of
`ResetRequired`; the separate `resetRequired` error code was removed and the
section 15.3 table renumbered (codes 16–19 are now `responseTooLarge`,
`temporarilyUnavailable`, `invalidCursor`, `internalError`). No code in this
repository had used the old numbering.

**Test obligation (Milestone 3):** `sec_12_6_reset_is_status_1_only`.

## SQ-6 — Handle local-part case policy at registration time

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 5 · **Spec:** section 10.1

Resolved by amendment: a handle authority SHOULD NOT assign ASCII-case
variants of one local part under one domain to different Followee DIDs; it
SHOULD reject the later variant or alias every accepted variant to the same
DID. Lookup remains exact-match.

**Test obligation:** none for the implementation (registration-side guidance);
lookup exactness is already covered by Milestone 5 tests.

## SQ-7 — `changes` ResetRequired: are `nextCursor`, `hasMore`, `directoryGeneration` permitted?

**Status:** resolved (spec v0.3, commit `a66228c`) · **Affected:** Milestone 3 · **Spec:** section 12.6

Resolved by amendment: on status `1` the response contains exactly labels `0`
and `1`; entries, `nextCursor`, `hasMore`, `directoryGeneration`, and
`errorCode` MUST all be absent.

**Test obligation (Milestone 3):** `sec_12_6_reset_response_is_exactly_labels_0_and_1`.

## SQ-8 — Pending v0.4 amendment: `identityBindingMismatch` rename and resolution-continuation rules

**Status:** resolved (spec v0.4/v0.5, commit `41f82fa`) · **Affected:** Milestone 1 (rename), Milestone 4 (continuation) · **Spec:** sections 8.1, 14.1, 15.3, 20.3

Resolved by amendment. The v0.4 amendment renamed the section 15.3 error symbol
`descriptorMismatch` to `identityBindingMismatch`, retaining numeric wire
code `7`. It also clarified that client resolution continues past relay `Absent`
and per-DID `Error` results while budgets and unqueried relays remain, with
`Error(premature)` being relay-local diagnostic information that must not
affect candidates obtained elsewhere.

The v0.4 amendment also added the section 14.1 continuation rules: Absent and
per-DID Error results are non-conclusive and budget-consuming, resolution
continues while selected unqueried relays and shared budgets remain, and
`Error(premature)` is relay-local diagnostic information which must not affect
candidates obtained elsewhere or local sticky state (conformance items in
section 20.3). Specification v0.5 only corrected the Appendix B.8.3
cross-reference.

This implementation used the renamed symbol from the start
(`VerifyError::IdentityBindingMismatch`, wire code 7), so the re-pin required
no code change; Appendix B bytes are unchanged and the complete suite was
rerun against the new pin.

**Test obligation (Milestone 4):**
`sec_14_1_resolution_continues_past_absent_and_error`,
`sec_14_1_error_premature_is_relay_local_diagnostic`.

## SQ-9 — Normative syntax for service `mediaType`, `language`, and `rel`

**Status:** resolved (spec v0.6, commit `44c6866`) · **Affected:** Milestone 1 · **Spec:** section 7.3

Section 7.3 constrains the optional service metadata only loosely ("ASCII
media type", "BCP 47 language tag", "registered link-relation token"), and
this implementation currently fills the gap with lightweight validators:

- `mediaType` accepts any non-empty visible-ASCII string, including strings
  that are not media types;
- `language` accepts strings such as 64 consecutive letters, which are not
  well-formed BCP 47 tags; and
- `rel` permits uppercase letters and `_`, although RFC 8288 `reg-rel-type`
  permits only a lowercase initial letter followed by lowercase letters,
  digits, `.`, or `-`.

Two conforming implementations could have guessed these grammars
differently. Resolved by the v0.6 amendment, which pins each field to a
named syntactic grammar with no registry dependence:

1. `mediaType`: exactly an RFC 6838 `type-name`, `/`, and `subtype-name`,
   each satisfying the section 4.2 `restricted-name` grammar; no parameters;
2. `language`: well-formed RFC 5646 `Language-Tag` ABNF **including the fixed
   grandfathered productions**, verified case-insensitively with the exact
   signed text retained; no registry lookup or canonicalization; and
3. `rel`: RFC 8288 `reg-rel-type` exactly (one lowercase letter, then
   lowercase letters, digits, `.`, or `-`) or an absolute URI; no
   IANA-membership lookup.

Registry contents are explicitly not inputs to record validity: a registry
update cannot change whether existing signed bytes verify. Implemented in
`src/contact.rs` (`is_media_type`/`is_restricted_name`, `is_language_tag`
with the 26 grandfathered tags, `is_relation_token`), replacing the
provisional validators.

**Test obligation (Milestone 1, done):** grammar positive/negative vectors in
`contact::tests` (`sec_7_3_service_token_shape_helpers`), at-limit boundary
twins updated to grammar-valid values, and reachability through
`ServiceEntry::validate`.

## SQ-10 — v0.7 URI production and exact CBOR label typing

**Status:** resolved (spec v0.7, commit `abc9a55`) · **Affected:** Milestone 1 · **Spec:** sections 7.2, 20.1; Appendix B.7 item 17

Recorded for bookkeeping: the v0.7 amendment (driven by independent
clean-room review) changed two Milestone 1 obligations.

1. **URI production.** Section 7.2 now requires the RFC 3986 section 3 `URI`
   production — scheme required, optional query and fragment permitted —
   replacing the fragment-excluding `absolute-URI` reading. Every
   `relative-ref` form remains malformed, and both lowercase and uppercase
   `IPvFuture` introducers are accepted (ABNF string literals are
   case-insensitive under RFC 5234). Implemented by switching the single URI
   validator to the `URI` type (`is_uri` in `src/contact.rs`) and exercising
   it through every URI-bearing position: avatar, `alsoKnownAs`, service
   endpoint, URI-form service type, URI-form `rel`, contact-level extension
   keys (label 6), and record-level extension keys (label 8).

2. **Exact CBOR label typing.** Appendix B.7 item 17 adds conformance cases
   substituting CBOR `false`/`true` for unsigned-integer labels `0`/`1` in
   Authority Descriptors and nested public-key objects, including a complete
   internally consistent, descriptor-bound, correctly signed construction
   failing exactly with `schemaViolation`. This crate's parsers always
   required `MAJOR_UINT` keys (Rust's CBOR head typing cannot alias Booleans
   to integers), so no parser change was needed; the item 17 cases and a
   Boolean-label sweep over every other fixed-label map now prove it through
   the production record path.

**Test obligations (Milestone 1, done):**
`sec_7_2_uri_production_accepts_queries_and_fragments`,
`sec_7_2_rejects_every_relative_reference_form`,
`sec_b7_item17_descriptor_label_0_as_false` (+ three sibling cases),
`boolean_labels_rejected_in_every_other_fixed_label_map`.

## SQ-11 — CBOR basic-validity taxonomy: `invalidCbor` vs `nonDeterministicCbor` for duplicate keys and invalid UTF-8

**Status:** resolved (spec v0.8, commit `610f9a1`) · **Affected:** Milestone 1 · **Spec:** sections 6.1.1–6.1.3, 15.3, 20.1; Appendix B.7 items 9/18; Appendix B.10

Specification v0.7 folded duplicate map keys and UTF-8 validity into the
single section 6.1 deterministic-profile list, making their wire
classification ambiguous between `invalidCbor` ("CBOR cannot be parsed
safely") and `nonDeterministicCbor` ("encoding violates section 6.1"), and
independent implementations classified them differently. Resolved by the
v0.8 amendment, which splits section 6.1 into three successive layers:

1. **6.1.1 well-formedness and basic validity** (RFC 8949 sections 5.3/5.6):
   duplicate map keys under generic-data-model key equivalence and invalid
   RFC 3629 UTF-8 produce exact `invalidCbor`. Key equivalence is by data
   model — differently serialized encodings of one value are one key, while
   values of different types (unsigned `0` versus `false`) stay distinct.
   After deterministic-profile acceptance, comparing received encodings is
   an equivalent implementation of the duplicate check.
2. **6.1.2 deterministic profile**: non-minimal or indefinite encodings,
   misordered keys, tags, floats, and `undefined` on basically valid items
   produce `nonDeterministicCbor`.
3. **6.1.3 schema and multiple faults**: specific assigned errors, with
   `schemaViolation` as the fallback; multi-fault inputs have an
   unspecified exact error unless a normative rule assigns precedence.

Appendix B.10 fixes five fault-isolated `invalidCbor` vectors (one adjacent
duplicate key, four invalid-UTF-8 mutations), each re-signed by Alice's
legitimate root key; B.7 gains item 18 and the note that the unprotected-
header form of item 9 is multi-fault. Implemented by reclassifying duplicate
keys from `NonDeterministic` to `Invalid` in `src/cbor.rs` (invalid UTF-8
already classified `Invalid`).

**Test obligations (Milestone 1, done):**
`cbor::tests::sec_6_1_1_rejects_duplicate_map_keys_as_invalid`,
`sec_6_1_1_key_equivalence_is_data_model_typed`,
`sec_6_1_1_rejects_every_rfc_3629_utf8_exclusion_as_invalid`,
`conformance::sec_b10_fault_isolated_bodies_reproduce_and_fail_exactly_invalid_cbor`,
`negative_b7::sec_b7_item9_duplicate_map_key_is_invalid_cbor`,
`sec_b7_item9_duplicate_unprotected_header_keys_reject_unspecified`,
`validate_cbor_api::sec_6_1_1_*` / `sec_6_1_2_*`.

## SQ-12 — Byte-string opacity: does CBOR validation recurse into byte-string contents?

**Status:** resolved (spec v0.8, commit `610f9a1`) · **Affected:** Milestones 1, 3, 4 · **Spec:** sections 6.1.1, 8.1, 12.1; Appendix A note

Whether a validator must (or may) recursively interpret byte-string contents
that happen to contain CBOR — in particular Identity Record envelopes carried
as relay `Full` byte strings, and the record payload inside the COSE
envelope — was unstated. Resolved by the v0.8 amendment: basic-validity
recursion stops at byte-string boundaries; byte-string contents are opaque to
the enclosing item and MUST NOT be recursively interpreted. The outer COSE
item and the attached record body have separate CBOR boundaries, and a
candidate's invalidity never retroactively invalidates an accepted enclosing
wrapper. Section 22 freezes the opacity boundary.

**Test obligations (Milestone 1, done):**
`cbor::tests::sec_6_1_1_byte_string_contents_are_opaque`,
`validate_cbor_api::sec_6_1_1_key_equivalence_is_typed_and_byte_strings_are_opaque`,
`b11_vectors::sec_b11_3_resolve_candidate_isolation_bytes_reproduce` (wrapper
accepts while the embedded B.8 candidate fails section 8.1). Relay/client
behavioural halves are Milestone 3/4 obligations.

## SQ-13 — Relay batch isolation: outer CBOR faults, per-DID faults, and duplicate request DIDs

**Status:** resolved (spec v0.8, commit `610f9a1`) · **Affected:** Milestone 3 (behaviour); Milestone 1 (byte reproduction) · **Spec:** sections 12.1, 12.3, 15.4, 20.2; Appendix B.11.1/B.11.3/B.11.4/B.11.6

v0.7 said servers "SHOULD use 400 for malformed outer requests" without
fixing the boundary between outer-request CBOR faults and per-item protocol
faults, whether duplicate requested DIDs may be deduplicated, or how an
invalid opaque Full candidate affects neighbouring results. Resolved by the
v0.8 amendment: an outer CBOR-layer fault means protocol processing did not
begin (HTTP `400`, no per-item results); a syntactically malformed DID as
valid UTF-8 inside a valid batch is protocol input (HTTP `200`, aligned
per-DID `Error(invalidDid)`); duplicate DIDs are never deduplicated,
reordered, combined, or omitted and response cardinality must equal request
cardinality; and a failed Full candidate is discarded alone, without
shifting positions or becoming Absent. Appendix B.11 publishes the exact
wrapper bytes and digests.

**Test obligations:** Milestone 1 byte reproduction done
(`b11_vectors::sec_b11_1/3/4/6_*`); HTTP and client behaviours are
Milestone 3/4 acceptance gates (IMPLEMENTATION.md section 13).

## SQ-14 — Synchronization cursor progress despite rejected candidates

**Status:** resolved (spec v0.8, commit `610f9a1`) · **Affected:** Milestone 4 (behaviour); Milestone 1 (byte reproduction) · **Spec:** sections 12.6, 13.3, 16.16, 20.2; Appendix B.11.5/B.11.7

v0.7 did not state whether a receiver that rejects a Full candidate from an
accepted `changes` response advances the peer cursor, nor bound a success
response's entry count by the request's `itemLimit`. Resolved by the v0.8
amendment: the receiver stores the returned `nextCursor` regardless of how
many candidates it admitted (rejection never stalls the cursor or re-requests
the range), while an over-`itemLimit` success response is rejected completely
— no entry processing, no state change, no cursor use. Section 16.16 records
the resulting liveness/convergence trade. Appendix B.11.5 and B.11.7 publish
the exact request/response bytes, cursor values, and digests.

**Test obligations:** Milestone 1 byte reproduction done
(`b11_vectors::sec_b11_5/7_*`); receiver behaviours are Milestone 4
acceptance gates (IMPLEMENTATION.md section 13).

## SQ-15 — Classification of schema-disallowed CBOR simple values: `nonDeterministicCbor` vs `schemaViolation`

**Status:** resolved (spec v0.8.1, commit `2d5292e`) · **Affected:** Milestone 1 · **Spec:** sections 6.1.2, 6.1.3, 15.3, 20.1; Appendix B.7 item 19; Appendix B.12

Specification v0.8 section 6.1.2 rule 4 forbade floats, `undefined`, and
tags, but did not state how to classify a CBOR simple value other than
`false`, `true`, `null`, and `undefined` — for example simple value 16
(`f0`, one-byte) or simple value 32 (`f8 20`, two-byte). Such a value's
shortest encoding is well-formed, basically valid, and deterministic under
RFC 8949, yet no v1 schema in Appendix A admits it. This implementation had
treated the whole class as profile-forbidden (`nonDeterministicCbor`), and
independent implementations could reasonably classify it as either a
section 6.1.2 profile fault or a section 6.1.3 schema fault. Resolved by
the v0.8.1 amendment:

1. a well-formed, basically valid, deterministically encoded simple value
   that no v1 schema admits passes sections 6.1.1 and 6.1.2 and produces
   exact `schemaViolation` under section 6.1.3; it MUST NOT be classified
   `nonDeterministicCbor` merely because the schema assigns it no meaning;
2. external registration of semantics for such a value does not alter the
   closed v1 schemas;
3. rule 4 is unchanged: `undefined` remains profile-forbidden and stays
   `nonDeterministicCbor` (a two-byte simple encoding below 32 likewise
   stays ill-formed, `invalidCbor`, under RFC 8949); and
4. the section 15.3 code 6 description now names data-item types the
   applicable schema does not admit, and Appendix B.7 gains item 19 with
   the two fault-isolated, Alice-root-re-signed Appendix B.12 vectors
   (simple value 16 one-byte, simple value 32 two-byte, both inside an
   otherwise ignored unknown extension, expected `schemaViolation`).

Implemented by admitting unassigned simple values (one-byte 0–19 and
two-byte 32–255, shortest encodings) through `read_head` in `src/cbor.rs`;
the extension-value and typed-schema parsers already rejected non-admitted
CBOR types with `schemaViolation`, so the boundary moved layers without a
new rejection path.

**Test obligations (Milestone 1, done):**
`cbor::tests::sec_6_1_2_admits_schema_disallowed_simple_values_as_deterministic`,
`validate_cbor_api::sec_6_1_2_admits_schema_disallowed_simple_values_as_deterministic`,
`conformance::sec_b12_fault_isolated_bodies_reproduce_and_fail_exactly_schema_violation`,
`negative_b7::sec_b7_item19_schema_disallowed_simple_values_are_exact_schema_violation`,
`sec_b7_item19_undefined_extension_value_remains_non_deterministic_cbor`,
`sec_b7_item19_simple_values_rejected_wherever_the_schema_expects_other_types`.

---

## Milestone 3 derived readings recorded for review (not open questions)

The Milestone 3 relay resolved the following wire details from the pinned
v0.8.1 text alone. Each is judged textually determined — no amendment is
believed necessary — but the readings are recorded here so specification
review can confirm or overturn them explicitly rather than discover them in
code. None affects stored state, update numbers, alignment, or cursor
semantics, which are unambiguous.

1. **Publish status for a sticky-excluded Root record: `2` (rejected) with
   code `11`.** Section 13.1 step 7 assigns "returns no-change" only to
   duplicate and losing records; step 4 "drops" a post-revocation Root,
   section 8.2 forbids admitting it, section 8.1 step 19 makes it fail
   verification-with-state, and `rootRevoked` (11) exists for exactly this
   condition. Step 4's "without state change" describes stored state, not
   the wire status. (`relay_core::sec_8_2_root_revoked_has_absolute_precedence_and_is_sticky`)
2. **Resolve response overflow: aligned per-DID `Error(responseTooLarge)`
   for results that no longer fit the advertised response bound.** Section
   12.3 permits any section 15.3 error as an aligned per-DID Error result,
   and resolve has no batch-level error channel; alignment and cardinality
   are mandatory. (`relay_http::sec_12_3_response_splitting_…`)
3. **`changes` requests violating the section 12.6 value constraints (zero
   or over-maximum `itemLimit`/`byteLimit`, cursor over 128 bytes) are
   HTTP `400`** as section 15.4 top-level schema validation failures; a
   within-bounds cursor that fails to decode is protocol-level
   `invalidCursor` (status 2, code 18), and a structurally valid cursor
   from a foreign generation is the status-1 reset.
   (`relay_http::sec_12_6_changes_request_value_bounds_…`)
4. **Publish body faults are protocol results (HTTP `200`, status 2 with
   the section 15.3 code), not HTTP `400`.** The section 12.1 outer-CBOR
   rule protects per-item batch alignment in `application/cbor` wrappers;
   for publish the record itself is the protocol item, and the record
   classification codes are only expressible through the publish response.
   (`relay_http::sec_15_4_oversized_entities_…`, `relay_core` admission suite)
