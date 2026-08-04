# Specification questions

Unresolved ambiguities in the pinned normative specification
(`followee-protocol/followee`, commit `7e81d32f53f40ff8daf6cef77bceec4b6308c0b9`).
Per IMPLEMENTATION.md section 2, questions are resolved in the protocol
repository — never silently in this implementation — and no milestone may pass
while an open question affects code delivered by that milestone. Resolving a
question that amends the specification requires re-pinning IMPLEMENTATION.md
section 2 and rerunning the complete conformance and differential suite.

Each entry names the earliest milestone whose code it affects and the smallest
demonstrating test, which is added as a failing or pending test when that
milestone begins.

---

## SQ-1 — Appendix B.7 item 1: two distinct DID-mismatch tests and their errors

**Status:** open · **Blocks:** Milestone 1 · **Spec:** Appendix B.7 item 1; sections 8.1 steps 6–7, 15.3

Appendix B.7 item 1 ("descriptor digest or DID byte changed") conflates two
different tests:

1. an **unchanged, internally consistent envelope** verified against a
   *different* target DID (no byte of the record changes; section 8.1 step 7
   fails); and
2. a **body-`id` mutation** inside the record, which must be re-signed to be a
   single-fault test (then section 8.1 step 7 or step 9 fails, depending on
   whether the target follows the mutation).

The specification must define both constructions separately and assign each an
exact expected error (or explicitly leave the error unspecified). Until then
these conformance cases remain `implementation`-status fixtures. A proposed
amendment was supplied to the specification authors on 2026-08-04.

**Pending test:** `sec_8_1_step7_target_mismatch_vs_body_id_mutation` (two
cases, exact expected errors per the amended specification).

## SQ-2 — Appendix B.7 item 2: `invalidDid` vs `unsupportedHash` for bad multihash

**Status:** open · **Blocks:** Milestone 1 · **Spec:** Appendix B.7 item 2; sections 3.1, 15.3

For a target DID whose multihash code is not `0x12`, or whose digest length is
not `0x20`, section 3.1 says the identifier is invalid in v1, but the error
table offers both `invalidDid` (code 0) and `unsupportedHash` (code 1). The
specification must state which error each malformation produces and must split
the two mutations into separate target-DID cases that do not also mutate the
signed body. A proposed amendment (syntax-versus-profile split) was supplied to
the specification authors on 2026-08-04.

**Pending test:** `sec_3_1_rejects_foreign_multihash_code` and
`sec_3_1_rejects_wrong_digest_length` with exact expected errors.

## SQ-3 — Serving a record that is premature under the relay's current clock

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** sections 5.4, 12.3, 15.3, 20.2

Resolved by amendment: a Relay Resolver holding a Full record that is premature
under its present clock MUST NOT return it as Full and MUST NOT return
`Absent`; it MAY return a usable Ref, otherwise the section 12.3 per-DID
`Error` result with code `10` (`premature`). The former `Unsupported` resolve
result was generalised to `Error`. Serving-time classification has no effect on
stored state, `lastUpdated`, or update numbers.

**Test obligation:** `sec_12_3_locally_premature_current_record_is_error_not_absent`
(Milestone 3).

## SQ-4 — `changes-response`: prose "required on success" vs optional CDDL fields

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** section 12.6; Appendix A

Resolved by amendment: section 12.6 now enumerates required and forbidden
fields per status, and Appendix A carries a normative note that the
`changes-response` optional markers express the union across statuses and are
not discretionary within a status.

**Test obligation:** `sec_12_6_status_dependent_field_combinations` (Milestone 3).

## SQ-5 — Overlap between `changes` status `1` (ResetRequired) and a reset error code

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 3 · **Spec:** sections 12.6, 15.3

Resolved by amendment: status `1` is the sole v1 wire encoding of
`ResetRequired`; the separate `resetRequired` error code was removed and the
section 15.3 table renumbered (codes 16–19 are now `responseTooLarge`,
`temporarilyUnavailable`, `invalidCursor`, `internalError`).

**Test obligation:** `sec_12_6_reset_is_status_1_only` (Milestone 3). Note for
implementers: error-code numeric values changed relative to spec v0.1; no code
in this repository had used the old numbering.

## SQ-6 — Handle local-part case policy at registration time

**Status:** resolved (spec v0.2, commit `7e81d32`) · **Affected:** Milestone 5 · **Spec:** section 10.1

Resolved by amendment: a handle authority SHOULD NOT assign ASCII-case
variants of one local part under one domain to different Followee DIDs; it
SHOULD reject the later variant or alias every accepted variant to the same
DID. Lookup remains exact-match.

**Test obligation:** none for the implementation (registration-side guidance);
lookup exactness is already covered by Milestone 5 tests.

## SQ-7 — `changes` ResetRequired: are `nextCursor`, `hasMore`, `directoryGeneration` permitted?

**Status:** open · **Blocks:** Milestone 3 · **Spec:** section 12.6

The v0.2 status-conditional field rules require entries, `nextCursor`,
`hasMore`, and `directoryGeneration` on success, and forbid entries and
`errorCode` on status `1` (ResetRequired) — but are silent on whether labels
`3`, `4`, and `5` may appear on status `1`. On status `2` all four are
explicitly forbidden. For deterministic cross-implementation testing the
specification should state the status-`1` policy; forbidding all of labels
`2`–`4` and `6` while leaving `5` (`directoryGeneration`) either forbidden or
required would both be workable, but it must be one of them.

**Pending test:** `sec_12_6_reset_response_field_policy`.
