# Authoring revision 2 — predeclared output delta

Recorded **before** regenerating any participant output, from the revised
neutral interface alone.

## Input delta

Authoring revision 1 (aggregate
`cec54f10520535b405c2eb11952cbe2e14976be3962cb26cacff29031c89ae6b`) →
revision 2 (aggregate
`1b6514da0c1a0c5289e0909b648b5de73a302e91b346440624badacf5747855e`).
Exactly one file changed: `interface/INTERFACE.md`
(`f978d25ba5e86c624da4c1c43c85a5a617b313d2232dc0429fe5b9e387f99259` →
`93c05b48fcaed6383d7ba7ec5629e1f2fe50c6e61bcebfb69c9a5550e9a4247c`).
The specification and every vector file are byte-identical, and the
specification retains SHA-256
`47af5fbf0c4505386b4e04d948ef89d013f878ea820fb02522817661d633633a`.

## Predeclared expected differences in `outputs/`

**Byte-identical (stable):**

1. Every `*.requests.ndjson` file — requests are built from unchanged
   vector inputs, and no operation name or input shape changed.
2. `published-identities.responses.ndjson` and
   `challenge-identities.responses.ndjson` — `deriveIdentity` is
   unchanged.
3. `published-records.responses.ndjson` and
   `challenge-records.responses.ndjson` — `authorRecord` semantics and
   authored record bytes are unchanged: the revision-2 constructor
   canonicalization (omitted / `null` / `[]` / `{}` request omission;
   `""` is present-empty text) states exactly what the production
   encoder and the revision-1 conversion already did, and the sealed
   challenge inputs keep their meaning by design.
4. `published-negative.responses.ndjson` — every case is a rejected
   `verifyRecord` result, and the rejection envelope and classifications
   are unchanged.
5. `challenge-selection.responses.ndjson` — `selectCurrent` is
   unchanged.
6. `wire-b11-report.json` — no interface projection is involved.

**Changed:**

7. `challenge-verify.responses.ndjson` — every accepted `verifyRecord`
   result changes shape:
   - `record` gains the always-present `revocationKey` member: `null`
     for the nine root records; a three-member object
     (`suite`, `publicKeyHex`, `publicKeyCborHex`) for the two
     rootRevoked records (`challenge-carol-revoked`,
     `challenge-erin-revoked-empty`);
   - `record.descriptor` becomes the closed eight-member flat projection
     (`descriptorVersion`, `rootKeySuite`, `rootPublicKeyHex`,
     `revocationCommitmentHex`, `authorityDescriptorCborHex`,
     `authorityDescriptorDigestHex`, `multihashHex`, `did`), replacing
     the revision-1 nested three-member form;
   - `record.contact` becomes lossless: members whose wire label is
     absent project to `null` instead of `[]`/`{}`. Every challenge
     record was authored, and authoring cannot construct present-empty
     collections, so every revision-1 `[]`/`{}` for an absent label
     becomes `null`; non-empty arrays/objects and scalar members are
     unchanged;
   - `record.extensions` projects to `null` where record label `8` is
     absent (previously `{}`); it stays an object where extensions were
     authored.
8. `MANIFEST.json` — the recorded authoring aggregate becomes the
   revision-2 value, the per-file hash of `interface/INTERFACE.md`
   changes, and the output-hash entry for
   `challenge-verify.responses.ndjson` changes.

No other output file is expected to change. Case counts and caseIds are
unchanged everywhere.

## Observed differences after regeneration

The observed delta matches the predeclared set exactly, with no
unpredicted change:

- `diff -rq` between the preserved revision-1 outputs and the
  regenerated revision-2 outputs reports exactly two differing files:
  `challenge-verify.responses.ndjson` and `MANIFEST.json`. Every other
  file — all requests, both identity groups, both record groups, the
  negative and selection responses, and `wire-b11-report.json` — is
  byte-identical, confirming stable authoring bytes and stable
  rejections.
- Inside `challenge-verify.responses.ndjson`, all eleven accepted
  results now carry: `record` with exactly
  `descriptor`/`revocationKey`/`contact`/`extensions`; the closed
  eight-member descriptor; `revocationKey: null` on the nine root
  records and the three-member object on `challenge-carol-revoked` and
  `challenge-erin-revoked-empty`; `null` for every absent contact label
  (all previously `[]`/`{}` members of authored records) and
  `record.extensions: null` where label `8` is absent, while
  `challenge-carol-root-full` retains its non-empty arrays and both
  extension maps as objects.
- `MANIFEST.json` records the revision-2 aggregate, the revised
  `interface/INTERFACE.md` per-file hash, and the new
  `challenge-verify.responses.ndjson` output hash.
- Regeneration into a second directory reproduces every file
  byte-identically.
