# Requirement traceability (Milestone 1)

Mapping from testable MUST/MUST NOT requirements in the implemented
specification sections (pinned commit in IMPLEMENTATION.md §2) to tests.
Unit tests live in `src/<module>.rs`; integration tests in `tests/<file>.rs`.
This map covers sections 3–8 and Appendix B; relay, resolver, WebFinger and
DID-document-projection sections arrive with their milestones.

| Spec | Requirement | Tests |
| --- | --- | --- |
| §3.1 | Exact `did:flw` syntax; lowercase prefix; base58btc; multibase `z` | `did::tests::sec_3_1_rejects_malformed_syntax_as_invalid_did`, `parses_the_appendix_b_did` |
| §3.1 | Structurally well-formed multihash (minimal varints, matching length, no trailing) else `invalidDid` | `negative_b7::sec_b7_item2_non_minimal_varint_is_invalid_did`, `…_length_disagreement_…`, `…_trailing_bytes_…`, `did::tests::minimal_varint_rules` |
| §3.1 | Well-formed foreign code/length is `unsupportedHash`, never reinterpreted | `negative_b7::sec_b7_item2_foreign_code_well_formed_is_unsupported_hash`, `…_foreign_digest_length_…` |
| §3.1 | Bounded work before decoding | `did::tests::sec_3_1_rejects_oversized_input_before_decoding` |
| §3.2 | Only suite `-19`; deprecated `-8` rejected as `unsupportedSuite` | `negative_b7::sec_b7_item3_deprecated_alg_minus_8_is_unsupported_suite`; `record.rs` `parse_public_key` suite arm |
| §3.3 | Strict Ed25519 rules 1–7 enforced by the sole entry point | `crypto::tests::*`, `primitive_ed25519::speccheck_vectors_all_violate_a_section_3_3_rule_and_are_rejected`, `conformance::sec_b7_item14_s_plus_l_signature_is_rejected_by_production_path` |
| §3.4 | Exact domain-separation byte strings | Byte-exact reproduction in `conformance::sec_b3_…`, `sec_b4_…`, `sec_b5_…` (any deviation changes every digest) |
| §4.2 | Revocation commitment binds suite and key bytes | `conformance::sec_b3_commitment_descriptor_and_did_reproduce`, `negative_b7::sec_b7_item12_wrong_revealed_key_…` |
| §4.3 | DID derivation from descriptor digest | `conformance::sec_b3_…`, `did::tests::round_trips_derivation_and_parsing` |
| §5.1 | Exact v1 record schema; unknown labels malformed | `negative_b7::rejects_unknown_record_body_label`, `rejects_authority_value_two` |
| §5.1 | Label 5 present exactly when `authority = 1` | `negative_b7::sec_b7_item10_root_record_with_label_5_is_rejected`, `sec_b7_item11_root_revoked_record_missing_label_5_is_rejected` |
| §5.1 | Body `id` redundancy is necessary but not sufficient; independent descriptor hash required | `conformance::sec_b8_descriptor_substitution_fails_binding_despite_valid_signature` |
| §5.3 | Signer timestamp `max(now, previous + 1)` with checked arithmetic | `timestamp::tests::sec_5_3_signer_timestamp_rule` |
| §5.4 | Future bound at exactly `now + 300000`; overflow-safe comparison | `timestamp::tests::sec_5_4_future_boundary_is_exact`, `sec_5_4_comparison_is_overflow_safe`, `authority::sec_5_4_premature_candidates_are_excluded_at_the_exact_boundary` |
| §5.5 | `validUntil_ms >= timestamp_ms`; staleness classification | `negative_b7::sec_b7_item15_valid_until_before_timestamp_is_rejected` (with at-limit twin), `timestamp::tests::sec_5_5_freshness_boundary` |
| §5.6/§7.5 | Extension key/type restrictions; aggregate limits apply | `negative_b7::sec_b7_item16_extension_key_length_boundary`, `…_nesting_depth_boundary`, `…_member_count_boundary` |
| §6.1 | Deterministic profile: definite lengths, minimal encodings, key order, no duplicates, no tags/floats/undefined, valid UTF-8, reject-not-normalize | `cbor::tests::*` (accepts/rejects per rule), `negative_b7::sec_b7_item7_…`, `item8_…`, `item9_…`, `sec_b7_item4_non_minimal_tag_encoding_…` |
| §6.2 | Exact COSE profile: tag 18, protected `a10132`, empty unprotected, attached payload, 64-byte signature, no trailing bytes | `negative_b7::sec_b7_item4_missing_cose_tag_is_rejected`, `item5_…`, `item6_…`, `rejects_trailing_bytes_after_envelope`; positive reproduction in `conformance::sec_b4_…` |
| §6.2 | Exact `Sig_structure` construction | `conformance::sec_b4_root_record_reproduces_byte_for_byte` (byte-exact 327-byte structure), wiring tests |
| §6.3 | Body digest over exact payload bytes, excluding envelope | `conformance` digest assertions; `verify.rs` uses payload slice |
| §7.1–7.3 | Contact field types and limits; empty document valid; service `id` uniqueness; initial type tokens or absolute URI | `negative_b7::sec_b7_item16_*` boundaries, `rejects_relative_uri_in_service_endpoint`, `sec_7_2_uri_production_accepts_queries_and_fragments`, `sec_7_2_rejects_every_relative_reference_form`; `properties::sec_7_2_encode_verify_round_trip`; `contact::tests::sec_7_3_*`, `sec_15_1_per_field_byte_boundaries_are_exact`, `sec_15_1_collection_count_boundaries_via_direct_validation`, `sec_15_1_uri_byte_boundary_is_exact` |
| §5.6/§7.4 | Extension key/value rules and migration round-trip through the wire | `contact::tests::sec_5_6_extension_key_rules`, `properties::sec_7_4_and_5_6_full_feature_round_trip` |
| §7.4 | Migration: ≥1 field, no other labels, canonical DIDs differing from own | `negative_b7::rejects_migration_naming_own_did`, `rejects_empty_migration_map`, `accepts_valid_migration_successor` |
| §8.1 | Complete verification algorithm; valid signature cannot bypass binding, schema, or authority rules | `conformance::sec_b8_…`, entire `negative_b7` suite; steps 7/9 → `sec_b7_item1a/1b/1c` |
| §8.1 | Envelope cap enforced before deep parsing | `negative_b7::sec_b7_item16_envelope_over_16kib_is_record_too_large` |
| §8.2 | Absolute RootRevoked precedence; sticky exclusion of every Root record; no last-good fallback; stale RootRevoked still activates | `authority::sec_8_2_*` (four tests) |
| §8.3 | Greater timestamp wins; equal-time lower digest wins; signature excluded from ordering | `conformance::sec_b6_equal_time_ordering_selects_lower_digest`, `authority::sec_8_3_later_timestamp_wins_within_root_revoked_state`, `properties::sec_8_3_selection_is_order_independent` |
| §8.5 | Discarded sticky state behaves as a fresh observer; retained state remains the boundary | `authority::sec_8_5_discarded_sticky_state_is_a_fresh_observer` |
| §7.2 (v0.7) | RFC 3986 `URI` production in every URI position; relative-ref rejection; IPvFuture case-insensitivity | `negative_b7::sec_7_2_uri_production_accepts_queries_and_fragments`, `sec_7_2_rejects_every_relative_reference_form` |
| §6.1/B.7 item 17 (v0.7) | Exact unsigned-integer label typing; Boolean substitution fails `schemaViolation` even when descriptor-bound and correctly signed | `negative_b7::sec_b7_item17_*` (four cases), `boolean_labels_rejected_in_every_other_fixed_label_map` |
| §15.1 | Every aggregate hard limit binding | `negative_b7::sec_b7_item16_*` |
| §16.15 | Residual-risk cases exercised (id-only check, re-encoding, root-after-revocation, non-strict Ed25519) | `sec_b8_…`, §6.1 reject-not-normalize tests, `authority::sec_8_2_*`, `primitive_ed25519::*` |
| App. B.2–B.6 | Byte-exact reproduction of every published value | `conformance::sec_b2_…` through `sec_b6_…` |
| App. B.7 | Every mutation rejected, fault-isolated per IMPLEMENTATION.md §11.1 | `negative_b7::*`, `conformance::sec_b7_item14_…`; provenance in `fixtures/implementation/PROVENANCE.json` |
| App. B.8 | Rejected at descriptor binding despite valid signature | `conformance::sec_b8_…` |
| §20.4 (partial) | Identical structured input → identical bytes across runs | `conformance::sec_20_4_structured_input_determinism_across_runs`, `properties::sec_7_2_…` |
| IMPL §6.2 | Sole strict entry point; wiring delegation with exact key/message/signature; mechanical call restriction | `verify::wiring_tests::*`, `lint_guard::*`, `clippy.toml` + CI `-D warnings` |
| IMPL §7.3 | Checked arithmetic; injected clock/randomness | `clock::tests::*`, `random::tests::*`, crate-wide `arithmetic_side_effects = "deny"` |

Known intentional gaps at this milestone: relay/resolver behaviour (§§10–14),
DID Document projection (§9.6), WebFinger (§10), and the remote signer (§18)
are later-milestone scope. `validUntil` staleness interacts with selection
only through `authority::sec_8_2_stale_root_revoked_still_activates_transition`;
richer freshness policy is client-milestone scope.
