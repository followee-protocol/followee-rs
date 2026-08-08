# Requirement traceability (Milestones 1 and 3)

Mapping from testable MUST/MUST NOT requirements in the implemented
specification sections (pinned commit in IMPLEMENTATION.md §2) to tests.
Unit tests live in `src/<module>.rs`; integration tests in `tests/<file>.rs`.
This map covers sections 3–8 and Appendix B (Milestone 1) and the relay
sections 5.4 (serving), 11–13, 15.2–15.4, and 20.2 (Milestone 3); resolver,
synchronization-receiver, WebFinger and DID-document-projection sections
arrive with their milestones.

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
| §6.1.1 (v0.8) | Basic validity: duplicate map keys under data-model key equivalence and invalid RFC 3629 UTF-8 are exact `invalidCbor`; recursion through unknown extension values; recursion stops at byte-string boundaries | `cbor::tests::sec_6_1_1_*` (duplicates, typed key equivalence, UTF-8 exclusions, opacity), `negative_b7::sec_b7_item9_duplicate_map_key_is_invalid_cbor`, `conformance::sec_b10_fault_isolated_bodies_…`, `validate_cbor_api::sec_6_1_1_*` |
| §6.1.2 (v0.8) | Deterministic profile: definite lengths, minimal encodings, key order, no tags/floats/undefined, reject-not-normalize; violations on basically valid items are `nonDeterministicCbor` | `cbor::tests::*` (accepts/rejects per rule), `cbor::tests::sec_6_1_2_rejects_misordered_map_keys_…`, `negative_b7::sec_b7_item7_…`, `item8_…`, `sec_b7_item4_non_minimal_tag_encoding_…`, `validate_cbor_api::sec_6_1_2_*` |
| §6.1.2/§6.1.3 (v0.8.1) | Schema-disallowed simple values (other than false/true/null/undefined) pass §6.1.1 and §6.1.2 in shortest encodings and fail as exact `schemaViolation` at the applicable schema; `undefined` stays `nonDeterministicCbor`; two-byte simples below 32 stay ill-formed `invalidCbor` | `cbor::tests::sec_6_1_2_admits_schema_disallowed_simple_values_as_deterministic`, `validate_cbor_api::sec_6_1_2_admits_schema_disallowed_simple_values_as_deterministic`, `conformance::sec_b12_…`, `negative_b7::sec_b7_item19_*` (three tests) |
| §6.1.3 (v0.8) | Multi-fault inputs have an unspecified exact error unless normatively assigned | `negative_b7::sec_b7_item9_duplicate_unprotected_header_keys_reject_unspecified`, `cbor::tests::sec_6_1_1_key_equivalence_is_data_model_typed` (non-minimal duplicate) |
| §6.2 | Exact COSE profile: tag 18, protected `a10132`, empty unprotected, attached payload, 64-byte signature, no trailing bytes | `negative_b7::sec_b7_item4_missing_cose_tag_is_rejected`, `item5_…`, `item6_…`, `rejects_trailing_bytes_after_envelope`; positive reproduction in `conformance::sec_b4_…` |
| §6.2 | Exact `Sig_structure` construction | `conformance::sec_b4_root_record_reproduces_byte_for_byte` (byte-exact 327-byte structure), wiring tests |
| §6.3 | Body digest over exact payload bytes, excluding envelope | `conformance` digest assertions; `verify.rs` uses payload slice |
| §7.1–7.3 | Contact field types and limits; empty document valid; service `id` uniqueness; initial type tokens or URI satisfying specification section 7.2 | `negative_b7::sec_b7_item16_*` boundaries, `rejects_relative_uri_in_service_endpoint`, `sec_7_2_uri_production_accepts_queries_and_fragments`, `sec_7_2_rejects_every_relative_reference_form`; `properties::sec_7_2_encode_verify_round_trip`; `contact::tests::sec_7_3_*`, `sec_15_1_per_field_byte_boundaries_are_exact`, `sec_15_1_collection_count_boundaries_via_direct_validation`, `sec_15_1_uri_byte_boundary_is_exact` |
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
| §15.1 (v0.8 gate) | Effective service maxima derived from the member-counting rule and current schemas compute to 61 (Root) and 60 (RootRevoked); admission at N, aggregate rejection at N + 1; independent 64-entry cap tested separately | `negative_b7::sec_15_1_effective_service_maxima_derive_to_61_root_and_60_root_revoked`, `contact::tests::sec_15_1_collection_count_boundaries_via_direct_validation` |
| §16.15 | Residual-risk cases exercised (id-only check, re-encoding, root-after-revocation, non-strict Ed25519) | `sec_b8_…`, §6.1 reject-not-normalize tests, `authority::sec_8_2_*`, `primitive_ed25519::*` |
| App. B.2–B.6 | Byte-exact reproduction of every published value | `conformance::sec_b2_…` through `sec_b6_…` |
| App. B.7 | Every mutation rejected, fault-isolated per IMPLEMENTATION.md §11.1 | `negative_b7::*`, `conformance::sec_b7_item14_…`; provenance in `fixtures/implementation/PROVENANCE.json` |
| App. B.8 | Rejected at descriptor binding despite valid signature | `conformance::sec_b8_…` |
| App. B.9 (v0.8) | Bob's keys, commitment, descriptor, DID, body, `Sig_structure` (stated length), digest, signature, and envelope reproduce exactly; Alice/Bob sticky authority state keyed independently per DID; mixed-identity pools never elect a foreign winner | `conformance::sec_b9_*`, `authority::sec_b9_sticky_authority_state_is_keyed_independently_per_did`, `sec_b9_mixed_identity_candidates_never_choose_a_foreign_winner` |
| App. B.10 (v0.8) | All five raw bodies rebuilt from structured parts reproduce their stated digests, `Sig_structure` lengths, and Alice-root signatures; each fails exactly `invalidCbor` through the production record path and the public validator | `conformance::sec_b10_fault_isolated_bodies_reproduce_and_fail_exactly_invalid_cbor` |
| App. B.11 (v0.8) | Every published wrapper byte sequence, length, and SHA-256 digest reproduces from structured parts (byte-level Milestone 1 obligation; behaviours are Milestone 3/4 gates) | `b11_vectors::sec_b11_1_…` through `sec_b11_7_…` |
| App. B.12 (v0.8.1) | Both raw bodies rebuilt from structured parts reproduce their stated digests, `Sig_structure` lengths, and Alice-root signatures; the public deterministic-CBOR entry point admits their simple values; each complete signed envelope fails exactly `schemaViolation` (never `invalidCbor`, `nonDeterministicCbor`, or `invalidSignature`) through the production record path | `conformance::sec_b12_fault_isolated_bodies_reproduce_and_fail_exactly_schema_violation`, `negative_b7::sec_b7_item19_schema_disallowed_simple_values_are_exact_schema_violation`, `validate_cbor_api::classification_parity_with_the_record_verification_path` |
| §20.4 (partial) | Identical structured input → identical bytes across runs | `conformance::sec_20_4_structured_input_determinism_across_runs`, `properties::sec_7_2_…` |
| IMPL §6.2 | Sole strict entry point; wiring delegation with exact key/message/signature; mechanical call restriction | `verify::wiring_tests::*`, `lint_guard::*`, `clippy.toml` + CI `-D warnings` |
| IMPL §7.3 | Checked arithmetic; injected clock/randomness | `clock::tests::*`, `random::tests::*`, crate-wide `arithmetic_side_effects = "deny"` |
| Conformance API | Public `followee::validate_cbor` structural gate: §6.1 profile under explicit limits, §15.3 classifications, limits capped at the Followee maxima, single gate shared with fuzzing and the record path | `validate_cbor_api::*` (nine external tests incl. boundary, zero-limit, over-maxima, and record-path parity cases) |

## Milestone 3: single relay

| Spec | Requirement | Tests |
| --- | --- | --- |
| §5.4 | Relay Resolver repeats the future-bound check before serving Full; a stored record that became premature is Error(`premature`), never Full or Absent; serving mutates nothing | `relay_core::sec_12_3_locally_premature_current_record_is_error_not_absent` |
| §11.1 | Partial current map with Full/Ref tiers, authority state, `lastUpdated`; RootRevoked established only by local verification | `relay_core::*` admission suite; store contract tests in `relay_store_parity` |
| §11.2 | Full→Ref conversion preserves learned RootRevoked state; retained ordering metadata prevents same-authority rollback | `relay_core::sec_11_2_conversion_to_ref_preserves_sticky_state_and_metadata`, `sec_11_2_retained_metadata_prevents_same_authority_rollback_through_a_ref` |
| §11.3 | Dropping the entire entry drops sticky state; re-admission is a fresh observation | `relay_core::sec_8_5_dropping_the_entry_makes_the_relay_a_fresh_observer` |
| §11.4 | Directory with 16-byte generation; index change requires fresh random generation (operator surface) | `relay_http::sec_12_4_directory_serves_generation_and_entries` |
| §12.1 | Exact paths and media types; unknown top-level integer labels rejected; outer CBOR faults are HTTP `400` with no per-item body; CORS on public reads | `relay_http::sec_12_1_wrong_media_types_are_rejected_with_415`, `sec_15_4_outer_request_faults_are_http_400`, `sec_b11_1_…`, CORS asserts in `sec_12_2_…`/`sec_12_5_…` |
| §12.2 | Info: version, 16-byte relay id, capability bits (0x07), versions `[1]`, suites `[-19]`, limits map, generations, base URI | `relay_http::sec_12_2_info_reports_identity_capabilities_versions_and_limits` |
| §12.3 | Aligned per-DID results; duplicates never deduplicated/reordered; response count equals request count; malformed DID as valid UTF-8 → per-DID `Error(invalidDid)`; Absent ≠ premature; overflow degrades to aligned `Error(responseTooLarge)` | `relay_http::sec_b11_4_…`, `sec_b11_6_…`, `sec_12_3_response_splitting_…`; `relay_core::sec_12_3_results_align_with_duplicates_and_unknown_dids` |
| §12.5 | Publish statuses: 0 admitted-current, 1 valid-no-change, 2 rejected + section 15.3 code | `relay_http::sec_12_5_publish_statuses_and_exact_byte_resolution`; `relay_core` admission suite |
| §12.6 | Success needs labels 0–5, `errorCode` forbidden; status 1 is exactly `{0:1,1:1}`; status 2 needs `errorCode` and forbids the rest; entries ≤ `itemLimit`, increasing `lastUpdated`, coalesced; cursor never advances past an omitted eligible entry; single unfittable entry → `responseTooLarge`; value bounds are top-level schema faults | `relay_core::sec_12_6_status_dependent_field_combinations`, `sec_12_6_reset_is_status_1_only`, `sec_12_6_reset_response_is_exactly_labels_0_and_1`, `sec_12_6_success_pagination_…`, `sec_12_6_byte_limit_never_advances_…`; `relay_http::sec_12_6_changes_request_value_bounds_…`, `sec_12_6_changes_flow_and_exact_reset_bytes_over_http` |
| §12.7 | Cursor commits to (generation, position), ≤ 128 bytes; foreign generation → ResetRequired; malformed → `invalidCursor`; reset permits complete null-cursor re-enumeration without deleting identity state | `relay::cursor::tests::sec_12_7_*`, `relay_core::sec_12_7_generation_reset_permits_bounded_reenumeration` |
| §13.1 | Cheap limits before verification; complete §8.1 via the production core; premature rejected; sticky-excluded Root rejected (code 11); winner persisted atomically before acknowledgement | `relay_core::sec_13_1_*`, `sec_8_2_root_revoked_has_absolute_precedence_and_is_sticky`; `relay_store_parity::sec_13_1_sqlite_commits_survive_an_ungraceful_reopen` |
| §13.2 | Update number increments iff admitted current state changes; duplicates, losers, invalid input, excluded Roots, and Full→Ref housekeeping never increment | `relay_core::sec_13_2_*`, `sec_8_3_equal_time_lower_digest_wins_and_increments`; `relay_properties::sec_13_2_relay_matches_the_simple_model_on_*` |
| §13.5/§12.7 | Restart preserves identity, generations, entries, sticky state, and the counter; cursor-generation reset available for restore | `relay_http::sec_13_5_restart_preserves_identity_generation_and_sticky_state`, `relay_core::sec_12_7_generation_reset_…` |
| §15.2/§15.4 | Hard message limits enforced; `400`/`413`/`415` classifications; bounded input before expensive processing | `relay_http::sec_15_4_*`, `sec_12_1_wrong_media_types_…`; wire-level fuzz targets |
| §20.2 (peerless subset) | Admission/no-change outcomes, sticky state, Full→Ref conversion, batch alignment and splitting, duplicate cardinality, HTTP 400/200 split, coalesced changes, field combinations, pagination, generation reset, restore, bounded resource use | The suites above; backend parity in `relay_store_parity::impl_9_2_*` |
| IMPL §9.2 | Both storage backends behave identically through one observable contract | `relay_store_parity::impl_9_2_backends_are_observationally_identical_through_the_relay`, `impl_9_2_store_contract_parity_on_direct_operations`, `with_both_backends` HTTP cases, `relay_properties` on both backends |
| IMPL §9.5 | Development mode is loopback-only; conforming mode requires HTTPS base URI | `relay_http::impl_9_5_development_mode_refuses_non_loopback_binding`, `impl_9_5_conforming_config_requires_https_or_explicit_dev_mode` |

Known intentional gaps at this milestone: client/resolver behaviour (§§9.2,
9.6, 14), the synchronization receiver and peer cursors (§13.3, Milestone 4
halves of B.11.2/B.11.3/B.11.5/B.11.7), WebFinger (§10), and the remote
signer (§18) are later-milestone scope. `validUntil` staleness interacts
with selection only through
`authority::sec_8_2_stale_root_revoked_still_activates_transition`;
richer freshness policy is client-milestone scope.
