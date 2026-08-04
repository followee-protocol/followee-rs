# Specification questions

Ambiguities identified in the normative specification
(`followee-protocol/followee`), tracked against the pinned commit in
IMPLEMENTATION.md section 2 (currently
`a66228cb7907fd131df52636a4b7212f0e642307`, specification v0.3). Per
IMPLEMENTATION.md section 2, questions are resolved in the protocol repository
— never silently in this implementation — and no milestone may pass while an
open question affects code delivered by that milestone. Resolving a question
that amends the specification requires re-pinning IMPLEMENTATION.md section 2
and rerunning the complete conformance and differential suite.

**All recorded questions are currently resolved.** Each resolved entry cites
the resolving specification version and records the test obligation the
resolution creates.

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

All three produce exact error `descriptorMismatch`, independent of the
section 8.1 permitted reordering of cheap checks.

**Test obligation (Milestone 1):**
`sec_8_1_binding_case_a_foreign_target`, `sec_8_1_binding_case_b_mutated_id_original_target`,
`sec_8_1_binding_case_c_mutated_id_mutated_target`, each asserting
`descriptorMismatch`, with fixture provenance per IMPLEMENTATION.md
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
