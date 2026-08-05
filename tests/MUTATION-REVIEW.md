# Mutation-testing review (Milestone 1)

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
