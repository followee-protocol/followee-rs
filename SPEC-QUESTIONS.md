# Specification questions

Ambiguities identified in the normative specification
(`followee-protocol/followee`), tracked against the pinned commit in
IMPLEMENTATION.md section 2 (currently
`abc9a55d90f1026e6509207abda73e5dc6d14241`, specification v0.7). Per
IMPLEMENTATION.md section 2, questions are resolved in the protocol repository
— never silently in this implementation — and no milestone may pass while an
open question affects code delivered by that milestone. Resolving a question
that amends the specification requires re-pinning IMPLEMENTATION.md section 2
and rerunning the complete conformance and differential suite.

**All recorded questions are resolved**, and every resolution remains in
force in specification v0.7 at the pinned commit. Each resolved entry cites
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

Recorded for bookkeeping: the v0.7 amendment (driven by clean-room
differential review) changed two Milestone 1 obligations.

1. **URI production.** Section 7.2 now requires the RFC 3986 section 3 `URI`
   production — scheme required, optional query and fragment permitted —
   replacing the fragment-excluding `absolute-URI` reading. Every
   `relative-ref` form remains malformed, and both lowercase and uppercase
   `IPvFuture` introducers are accepted (ABNF string literals are
   case-insensitive under RFC 5234). Implemented by switching the single URI
   validator to the `URI` type (`is_uri` in `src/contact.rs`) and exercising
   it through every URI-bearing position: avatar, `alsoKnownAs`, service
   endpoint, URI-form service type, URI-form `rel`, and extension keys.

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
