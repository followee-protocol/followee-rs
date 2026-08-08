//! Strict deterministic CBOR subset (specification section 6.1, v0.8).
//!
//! This is a protocol-specific codec, not a general CBOR library
//! (IMPLEMENTATION.md section 6.1). The reader retains exact received byte
//! slices, rejects every non-deterministic encoding rather than normalising
//! it, and enforces nesting, member, and byte limits before allocation. The
//! writer produces the unique deterministic encoding for every Followee v1
//! structure.
//!
//! Section 6.1 defines three successive layers. Well-formedness and basic
//! validity (section 6.1.1: unique map keys under generic-data-model
//! equivalence, RFC 3629 UTF-8 text) classify as `invalidCbor`; the
//! deterministic profile (section 6.1.2: definite lengths, minimal
//! encodings, bytewise key order, no tags/floats/`undefined`) classifies as
//! `nonDeterministicCbor` for basically valid items; Followee schemas are
//! layered above by the typed parsers. Validation recurses through every
//! array and map — including unknown extension values — and stops at
//! byte-string boundaries: byte-string contents are opaque and are never
//! reinterpreted as CBOR by this validator.

/// Classification of a rejected CBOR input.
///
/// The variants map onto the specification's wire error vocabulary:
/// [`CborError::Invalid`] → `invalidCbor`, [`CborError::NonDeterministic`] →
/// `nonDeterministicCbor`, [`CborError::LimitExceeded`] → `schemaViolation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CborError {
    /// The bytes are not well-formed CBOR, or are well-formed but fail
    /// RFC 8949 basic validity (section 6.1.1): duplicate map keys under
    /// generic-data-model equivalence, or text strings that are not valid
    /// RFC 3629 UTF-8.
    Invalid,
    /// Basically valid CBOR that violates the section 6.1.2 deterministic
    /// profile: non-minimal encodings, indefinite lengths, misordered map
    /// keys, tags, floats, `undefined`, or reserved simples.
    NonDeterministic,
    /// The bytes exceed a nesting-depth or member-count limit.
    LimitExceeded,
}

/// A decoded CBOR item head: major type and argument value.
///
/// For major type 7 the argument is the simple value (only `20`, `21`, `22`
/// survive [`Reader::read_head`]); floats and reserved encodings are rejected
/// during head parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Head {
    pub major: u8,
    pub arg: u64,
}

pub(crate) const MAJOR_UINT: u8 = 0;
pub(crate) const MAJOR_NINT: u8 = 1;
pub(crate) const MAJOR_BSTR: u8 = 2;
pub(crate) const MAJOR_TSTR: u8 = 3;
pub(crate) const MAJOR_ARRAY: u8 = 4;
pub(crate) const MAJOR_MAP: u8 = 5;
pub(crate) const MAJOR_TAG: u8 = 6;
pub(crate) const MAJOR_SIMPLE: u8 = 7;

pub(crate) const SIMPLE_FALSE: u64 = 20;
pub(crate) const SIMPLE_TRUE: u64 = 21;
pub(crate) const SIMPLE_NULL: u64 = 22;

/// Cursor over received bytes. Never copies; slices refer to the input.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Returns the exact received bytes from `start` to the current position.
    pub(crate) fn slice_since(&self, start: usize) -> &'a [u8] {
        // Both bounds were produced by this cursor, so indexing cannot fail.
        &self.buf[start..self.pos]
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::Invalid)?;
        self.pos = self.pos.checked_add(1).ok_or(CborError::Invalid)?;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Invalid)?;
        let s = self.buf.get(self.pos..end).ok_or(CborError::Invalid)?;
        self.pos = end;
        Ok(s)
    }

    fn read_wide(&mut self, n: usize) -> Result<u64, CborError> {
        let mut v: u64 = 0;
        for &b in self.take(n)? {
            v = v << 8 | u64::from(b);
        }
        Ok(v)
    }

    /// Reads one item head, enforcing minimal-length encoding.
    pub(crate) fn read_head(&mut self) -> Result<Head, CborError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major == MAJOR_SIMPLE {
            return match ai {
                0..=23 => match u64::from(ai) {
                    v @ (SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL) => Ok(Head { major, arg: v }),
                    // undefined (23) and unassigned simple values are valid
                    // CBOR but forbidden by the section 6.1 profile.
                    _ => Err(CborError::NonDeterministic),
                },
                24 => {
                    let v = self.byte()?;
                    if v < 32 {
                        // RFC 8949: two-byte simple below 32 is ill-formed.
                        Err(CborError::Invalid)
                    } else {
                        Err(CborError::NonDeterministic)
                    }
                }
                // Floating-point encodings are forbidden by the profile.
                25..=27 => Err(CborError::NonDeterministic),
                28..=30 => Err(CborError::Invalid),
                // A break byte outside an indefinite item is ill-formed.
                _ => Err(CborError::Invalid),
            };
        }

        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(CborError::NonDeterministic);
                }
                v
            }
            25 => {
                let v = self.read_wide(2)?;
                if v < 0x100 {
                    return Err(CborError::NonDeterministic);
                }
                v
            }
            26 => {
                let v = self.read_wide(4)?;
                if v < 0x1_0000 {
                    return Err(CborError::NonDeterministic);
                }
                v
            }
            27 => {
                let v = self.read_wide(8)?;
                if v < 0x1_0000_0000 {
                    return Err(CborError::NonDeterministic);
                }
                v
            }
            28..=30 => return Err(CborError::Invalid),
            // Indefinite lengths are forbidden by the deterministic profile
            // for the container majors; for uint/nint/tag the encoding is
            // ill-formed CBOR.
            _ => {
                return match major {
                    MAJOR_BSTR | MAJOR_TSTR | MAJOR_ARRAY | MAJOR_MAP => {
                        Err(CborError::NonDeterministic)
                    }
                    _ => Err(CborError::Invalid),
                };
            }
        };
        Ok(Head { major, arg })
    }

    fn length_arg(arg: u64) -> Result<usize, CborError> {
        usize::try_from(arg).map_err(|_| CborError::Invalid)
    }

    /// Reads a definite byte string body of `arg` bytes.
    pub(crate) fn read_bytes_body(&mut self, arg: u64) -> Result<&'a [u8], CborError> {
        self.take(Self::length_arg(arg)?)
    }

    /// Reads a definite text string body of `arg` bytes, validating UTF-8.
    pub(crate) fn read_text_body(&mut self, arg: u64) -> Result<&'a str, CborError> {
        let raw = self.take(Self::length_arg(arg)?)?;
        std::str::from_utf8(raw).map_err(|_| CborError::Invalid)
    }

    /// Skips one complete value, assuming the buffer already passed
    /// [`validate`]. Depth is bounded by the validation pass.
    pub(crate) fn skip_value(&mut self) -> Result<(), CborError> {
        let head = self.read_head()?;
        match head.major {
            MAJOR_UINT | MAJOR_NINT | MAJOR_SIMPLE => Ok(()),
            MAJOR_BSTR => self.read_bytes_body(head.arg).map(|_| ()),
            MAJOR_TSTR => self.read_text_body(head.arg).map(|_| ()),
            MAJOR_ARRAY => {
                for _ in 0..head.arg {
                    self.skip_value()?;
                }
                Ok(())
            }
            MAJOR_MAP => {
                for _ in 0..head.arg {
                    self.skip_value()?;
                    self.skip_value()?;
                }
                Ok(())
            }
            _ => Err(CborError::Invalid),
        }
    }
}

/// Validates that `bytes` is exactly one deterministic-profile CBOR item with
/// no trailing bytes, within `max_depth` nesting and `max_members` total map
/// entries plus array elements.
///
/// This is the single structural gate: after it succeeds, typed parsers may
/// assume deterministic encoding and bounded structure, but still perform
/// their own schema checks.
pub(crate) fn validate(bytes: &[u8], max_depth: u32, max_members: u32) -> Result<(), CborError> {
    let mut r = Reader::new(bytes);
    let mut members: u32 = 0;
    validate_value(&mut r, max_depth, &mut members, max_members)?;
    if !r.is_at_end() {
        return Err(CborError::Invalid);
    }
    Ok(())
}

fn validate_value(
    r: &mut Reader<'_>,
    depth_left: u32,
    members: &mut u32,
    max_members: u32,
) -> Result<(), CborError> {
    let head = r.read_head()?;
    match head.major {
        MAJOR_UINT | MAJOR_NINT | MAJOR_SIMPLE => Ok(()),
        MAJOR_BSTR => r.read_bytes_body(head.arg).map(|_| ()),
        MAJOR_TSTR => r.read_text_body(head.arg).map(|_| ()),
        MAJOR_ARRAY => {
            let inner = depth_left.checked_sub(1).ok_or(CborError::LimitExceeded)?;
            for _ in 0..head.arg {
                *members = members.checked_add(1).ok_or(CborError::LimitExceeded)?;
                if *members > max_members {
                    return Err(CborError::LimitExceeded);
                }
                validate_value(r, inner, members, max_members)?;
            }
            Ok(())
        }
        MAJOR_MAP => {
            let inner = depth_left.checked_sub(1).ok_or(CborError::LimitExceeded)?;
            let mut prev_key: Option<&[u8]> = None;
            for _ in 0..head.arg {
                *members = members.checked_add(1).ok_or(CborError::LimitExceeded)?;
                if *members > max_members {
                    return Err(CborError::LimitExceeded);
                }
                let key_start = r.position();
                validate_value(r, inner, members, max_members)?;
                let key = r.slice_since(key_start);
                if let Some(prev) = prev_key {
                    // Every key reaching this comparison already passed
                    // `read_head`, which admits only the one deterministic
                    // encoding per value, so comparing received encodings is
                    // the section 6.1.1 data-model key comparison: equal
                    // bytes are equal values (a basic-validity duplicate,
                    // `invalidCbor`), and keys of different generic types
                    // (for example unsigned `0` and simple `false`) always
                    // encode differently and stay distinct. Descending
                    // bytewise order violates only the section 6.1.2
                    // deterministic profile (`nonDeterministicCbor`). An
                    // input whose duplicate hides behind a non-minimal key
                    // encoding is multi-fault and is reported as the
                    // encoding fault `read_head` met first, as permitted by
                    // sections 6.1.1 and 6.1.3.
                    match key.cmp(prev) {
                        std::cmp::Ordering::Equal => return Err(CborError::Invalid),
                        std::cmp::Ordering::Less => return Err(CborError::NonDeterministic),
                        std::cmp::Ordering::Greater => {}
                    }
                }
                prev_key = Some(key);
                validate_value(r, inner, members, max_members)?;
            }
            Ok(())
        }
        MAJOR_TAG => Err(CborError::NonDeterministic),
        _ => Err(CborError::Invalid),
    }
}

/// Deterministic CBOR writer for Followee v1 structures.
pub(crate) struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Writer { out: Vec::new() }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    pub(crate) fn head(&mut self, major: u8, arg: u64) {
        debug_assert!(major <= 7);
        let ib = major << 5;
        if arg < 24 {
            // Truncation is safe: arg < 24.
            #[allow(clippy::cast_possible_truncation)]
            self.out.push(ib | arg as u8);
        } else if arg < 0x100 {
            self.out.push(ib | 24);
            #[allow(clippy::cast_possible_truncation)]
            self.out.push(arg as u8);
        } else if arg < 0x1_0000 {
            self.out.push(ib | 25);
            #[allow(clippy::cast_possible_truncation)]
            self.out.extend_from_slice(&(arg as u16).to_be_bytes());
        } else if arg < 0x1_0000_0000 {
            self.out.push(ib | 26);
            #[allow(clippy::cast_possible_truncation)]
            self.out.extend_from_slice(&(arg as u32).to_be_bytes());
        } else {
            self.out.push(ib | 27);
            self.out.extend_from_slice(&arg.to_be_bytes());
        }
    }

    pub(crate) fn uint(&mut self, v: u64) {
        self.head(MAJOR_UINT, v);
    }

    /// Writes the negative integer `-(1 + magnitude)`.
    pub(crate) fn nint_from_magnitude(&mut self, magnitude: u64) {
        self.head(MAJOR_NINT, magnitude);
    }

    /// Writes a small signed integer.
    pub(crate) fn int(&mut self, v: i64) {
        if v >= 0 {
            // Sign checked on the branch.
            #[allow(clippy::cast_sign_loss)]
            self.uint(v as u64);
        } else {
            // -(v + 1) for any negative i64 fits u64 without overflow.
            #[allow(clippy::cast_sign_loss)]
            let magnitude = !(v as u64);
            self.nint_from_magnitude(magnitude);
        }
    }

    pub(crate) fn bstr(&mut self, bytes: &[u8]) {
        self.head(MAJOR_BSTR, bytes.len() as u64);
        self.out.extend_from_slice(bytes);
    }

    pub(crate) fn tstr(&mut self, s: &str) {
        self.head(MAJOR_TSTR, s.len() as u64);
        self.out.extend_from_slice(s.as_bytes());
    }

    pub(crate) fn array(&mut self, len: u64) {
        self.head(MAJOR_ARRAY, len);
    }

    pub(crate) fn tag(&mut self, v: u64) {
        self.head(MAJOR_TAG, v);
    }

    pub(crate) fn bool(&mut self, v: bool) {
        self.head(MAJOR_SIMPLE, if v { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }

    pub(crate) fn null(&mut self) {
        self.head(MAJOR_SIMPLE, SIMPLE_NULL);
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Writes a map from pre-encoded entries, sorting by the bytewise
    /// lexicographic order of the encoded keys. Language-container iteration
    /// order never determines wire order (IMPLEMENTATION.md section 7.2).
    ///
    /// # Panics
    ///
    /// Panics on duplicate keys; authoring paths validate uniqueness before
    /// encoding, so a duplicate here is a crate bug.
    pub(crate) fn map_entries(&mut self, mut entries: Vec<(Vec<u8>, Vec<u8>)>) {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in entries.windows(2) {
            assert!(pair[0].0 != pair[1].0, "duplicate map key while encoding");
        }
        self.head(MAJOR_MAP, entries.len() as u64);
        for (k, v) in entries {
            self.out.extend_from_slice(&k);
            self.out.extend_from_slice(&v);
        }
    }
}

/// Encodes one value with a fresh writer.
pub(crate) fn encode_with(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    f(&mut w);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    fn ok(bytes: &[u8]) -> Result<(), CborError> {
        validate(bytes, 8, 256)
    }

    #[test]
    fn accepts_minimal_encodings() {
        assert_eq!(ok(&[0x00]), Ok(())); // 0
        assert_eq!(ok(&[0x17]), Ok(())); // 23
        assert_eq!(ok(&[0x18, 0x18]), Ok(())); // 24
        assert_eq!(ok(&[0x19, 0x01, 0x00]), Ok(())); // 256
        assert_eq!(ok(&[0xf4]), Ok(())); // false
        assert_eq!(ok(&[0xf5]), Ok(())); // true
        assert_eq!(ok(&[0xf6]), Ok(())); // null
        assert_eq!(ok(&[0xa0]), Ok(())); // {}
        assert_eq!(ok(&[0x80]), Ok(())); // []
        assert_eq!(ok(&[0x61, 0x61]), Ok(())); // "a"
    }

    #[test]
    fn rejects_non_minimal_integer_encodings() {
        assert_eq!(ok(&[0x18, 0x17]), Err(CborError::NonDeterministic)); // 23 in 2 bytes
        assert_eq!(ok(&[0x19, 0x00, 0x18]), Err(CborError::NonDeterministic)); // 24 in 3 bytes
        assert_eq!(
            ok(&[0x1a, 0x00, 0x00, 0x01, 0x00]),
            Err(CborError::NonDeterministic)
        );
        assert_eq!(
            ok(&[0x1b, 0, 0, 0, 0, 0, 0, 1, 0]),
            Err(CborError::NonDeterministic)
        );
    }

    #[test]
    fn rejects_indefinite_lengths() {
        assert_eq!(
            ok(&[0x5f, 0x41, 0x00, 0xff]),
            Err(CborError::NonDeterministic)
        );
        assert_eq!(ok(&[0x9f, 0x00, 0xff]), Err(CborError::NonDeterministic));
        assert_eq!(
            ok(&[0xbf, 0x00, 0x00, 0xff]),
            Err(CborError::NonDeterministic)
        );
        assert_eq!(
            ok(&[0x7f, 0x61, 0x61, 0xff]),
            Err(CborError::NonDeterministic)
        );
    }

    #[test]
    fn rejects_tags_floats_undefined_and_reserved() {
        assert_eq!(ok(&[0xc0, 0x00]), Err(CborError::NonDeterministic)); // tag 0
        assert_eq!(ok(&[0xf7]), Err(CborError::NonDeterministic)); // undefined
        assert_eq!(ok(&[0xf9, 0x00, 0x00]), Err(CborError::NonDeterministic)); // float16
        assert_eq!(ok(&[0xfa, 0, 0, 0, 0]), Err(CborError::NonDeterministic)); // float32
        assert_eq!(
            ok(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(CborError::NonDeterministic)
        );
        assert_eq!(ok(&[0xf0]), Err(CborError::NonDeterministic)); // simple 16
        assert_eq!(ok(&[0xf8, 0x20]), Err(CborError::NonDeterministic)); // simple 32
        assert_eq!(ok(&[0xf8, 0x10]), Err(CborError::Invalid)); // ill-formed two-byte simple
        assert_eq!(ok(&[0xff]), Err(CborError::Invalid)); // stray break
    }

    #[test]
    fn sec_6_1_2_rejects_misordered_map_keys_as_non_deterministic() {
        // {1: 0, 0: 0} — reversed order.
        assert_eq!(
            ok(&[0xa2, 0x01, 0x00, 0x00, 0x00]),
            Err(CborError::NonDeterministic)
        );
        // {0: 0, 1: 1} — correct.
        assert_eq!(ok(&[0xa2, 0x00, 0x00, 0x01, 0x01]), Ok(()));
        // Text keys order by encoded bytes: "b" = 61 62, "aa" = 62 61 61;
        // 6162 < 626161 so {"b": 0, "aa": 0} is correctly ordered.
        assert_eq!(
            ok(&[0xa2, 0x61, 0x62, 0x00, 0x62, 0x61, 0x61, 0x00]),
            Ok(())
        );
        // Reversed: "aa" before "b" violates encoded-byte order.
        assert_eq!(
            ok(&[0xa2, 0x62, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00]),
            Err(CborError::NonDeterministic)
        );
    }

    #[test]
    fn sec_6_1_1_rejects_duplicate_map_keys_as_invalid() {
        // {0: 0, 0: 1} — adjacent identical deterministic keys: basic
        // validity (RFC 8949 section 5.6), not the deterministic profile.
        assert_eq!(ok(&[0xa2, 0x00, 0x00, 0x00, 0x01]), Err(CborError::Invalid));
        // Identical text keys.
        assert_eq!(
            ok(&[0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01]),
            Err(CborError::Invalid)
        );
        // Nested: the duplicate map sits inside an array inside a map value.
        assert_eq!(
            ok(&[0xa1, 0x00, 0x81, 0xa2, 0x00, 0x00, 0x00, 0x01]),
            Err(CborError::Invalid)
        );
    }

    #[test]
    fn sec_6_1_1_key_equivalence_is_data_model_typed() {
        // Unsigned 0 and simple false are different generic-data-model
        // values: {0: 0, false: 0} has unique keys and sorts 00 < f4.
        assert_eq!(ok(&[0xa2, 0x00, 0x00, 0xf4, 0x00]), Ok(()));
        // Unsigned 0 and negative -1 (0x20) are likewise distinct.
        assert_eq!(ok(&[0xa2, 0x00, 0x00, 0x20, 0x00]), Ok(()));
        // {0: 0, 0x1800: 0}: the second key is the same unsigned 0 encoded
        // non-minimally, a data-model duplicate hidden behind a profile
        // fault. Multi-fault per section 6.1.3; this implementation reports
        // the encoding fault it meets first.
        assert_eq!(
            ok(&[0xa2, 0x00, 0x00, 0x18, 0x00, 0x00]),
            Err(CborError::NonDeterministic)
        );
    }

    #[test]
    fn sec_6_1_1_byte_string_contents_are_opaque() {
        // A byte string whose contents happen to be malformed CBOR (a stray
        // break byte, truncated heads, invalid UTF-8 for a tstr head) is a
        // valid byte string: recursion stops at byte-string boundaries.
        for contents in [&[0xffu8][..], &[0x19, 0x01], &[0x61, 0xff], &[0xa2]] {
            let mut bytes = vec![0x40 | contents.len() as u8];
            bytes.extend_from_slice(contents);
            assert_eq!(ok(&bytes), Ok(()), "opaque bstr {contents:02x?}");
        }
        // The same bytes as a top-level item are rejected.
        assert_eq!(ok(&[0xff]), Err(CborError::Invalid));
    }

    #[test]
    fn rejects_truncation_trailing_and_bad_utf8() {
        assert_eq!(ok(&[0x41]), Err(CborError::Invalid)); // bstr length 1, no body
        assert_eq!(ok(&[0x19, 0x01]), Err(CborError::Invalid)); // truncated head
        assert_eq!(ok(&[0x00, 0x00]), Err(CborError::Invalid)); // trailing byte
        assert_eq!(ok(&[0x61, 0xff]), Err(CborError::Invalid)); // invalid UTF-8
    }

    #[test]
    fn sec_6_1_1_rejects_every_rfc_3629_utf8_exclusion_as_invalid() {
        // Each text string is CBOR-complete (the head declares exactly the
        // bytes present), so invalid UTF-8 is the only fault: basic
        // validity, `invalidCbor`.
        let cases: [&[u8]; 4] = [
            &[0x62, 0xc0, 0xae],             // overlong U+002E
            &[0x63, 0xed, 0xa0, 0x80],       // lone surrogate U+D800
            &[0x64, 0xf4, 0x90, 0x80, 0x80], // U+110000 above the maximum
            &[0x62, 0xe2, 0x82],             // incomplete three-byte code point
        ];
        for bytes in cases {
            assert_eq!(ok(bytes), Err(CborError::Invalid), "{bytes:02x?}");
        }
    }

    #[test]
    fn enforces_depth_and_member_limits() {
        // Depth: 7 wrapping arrays plus the innermost empty array nest to
        // exactly depth 8; one more wrapper exceeds the limit.
        let mut eight = vec![0x81u8; 7];
        eight.push(0x80);
        assert_eq!(ok(&eight), Ok(()));
        let mut nine = vec![0x81u8; 8];
        nine.push(0x80);
        assert_eq!(ok(&nine), Err(CborError::LimitExceeded));

        // Members: an array of 256 small items is allowed, 257 is not.
        let mut a256 = vec![0x99, 0x01, 0x00];
        a256.extend(std::iter::repeat_n(0x00, 256));
        assert_eq!(ok(&a256), Ok(()));
        let mut a257 = vec![0x99, 0x01, 0x01];
        a257.extend(std::iter::repeat_n(0x00, 257));
        assert_eq!(ok(&a257), Err(CborError::LimitExceeded));
    }

    #[test]
    fn rejects_reserved_additional_information_values() {
        // ai 28–30 are reserved and ill-formed for every major type.
        for b in [0x1c, 0x1d, 0x1e, 0x3c, 0x5d, 0x7e, 0x9c, 0xbd, 0xdc] {
            assert_eq!(ok(&[b]), Err(CborError::Invalid), "byte {b:#04x}");
        }
    }

    #[test]
    fn accepts_minimal_wide_encodings_at_their_lower_bounds() {
        assert_eq!(ok(&[0x19, 0x01, 0x00]), Ok(())); // 256: smallest 2-byte
        assert_eq!(ok(&[0x1a, 0x00, 0x01, 0x00, 0x00]), Ok(())); // 65536: smallest 4-byte
        assert_eq!(ok(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]), Ok(())); // 2^32: smallest 8-byte
    }

    #[test]
    fn map_member_budget_boundary() {
        // 256 map entries consume exactly the member budget; 257 exceed it.
        let mut m256 = vec![0xb9, 0x01, 0x00];
        for k in 0u64..256 {
            m256.extend(encode_with(|w| w.uint(k)));
            m256.push(0x00);
        }
        assert_eq!(ok(&m256), Ok(()));
        let mut m257 = vec![0xb9, 0x01, 0x01];
        for k in 0u64..257 {
            m257.extend(encode_with(|w| w.uint(k)));
            m257.push(0x00);
        }
        assert_eq!(ok(&m257), Err(CborError::LimitExceeded));
    }

    #[test]
    fn writer_exact_bytes_at_every_width_boundary() {
        let cases: [(u64, &[u8]); 8] = [
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65535, &[0x19, 0xff, 0xff]),
            (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (0xffff_ffff, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (0x1_0000_0000, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        ];
        for (value, expected) in cases {
            assert_eq!(encode_with(|w| w.uint(value)), expected, "uint {value}");
            // Every produced encoding must satisfy the strict validator.
            assert_eq!(ok(expected), Ok(()));
        }
        assert_eq!(encode_with(|w| w.bool(false)), vec![0xf4]);
        assert_eq!(encode_with(|w| w.bool(true)), vec![0xf5]);
        assert_eq!(encode_with(|w| w.null()), vec![0xf6]);
        assert_eq!(encode_with(|w| w.tag(18)), vec![0xd2]);
        assert_eq!(encode_with(|w| w.nint_from_magnitude(18)), vec![0x32]);
    }

    #[test]
    fn writer_produces_minimal_heads_and_sorted_maps() {
        let bytes = encode_with(|w| w.uint(23));
        assert_eq!(bytes, vec![0x17]);
        let bytes = encode_with(|w| w.uint(24));
        assert_eq!(bytes, vec![0x18, 0x18]);
        let bytes = encode_with(|w| w.int(-19));
        assert_eq!(bytes, vec![0x32]);
        let bytes = encode_with(|w| {
            let entries = vec![
                (encode_with(|k| k.uint(1)), encode_with(|v| v.uint(7))),
                (encode_with(|k| k.uint(0)), encode_with(|v| v.uint(9))),
            ];
            w.map_entries(entries);
        });
        assert_eq!(bytes, vec![0xa2, 0x00, 0x09, 0x01, 0x07]);
        // Round-trip through the validator.
        assert_eq!(ok(&bytes), Ok(()));
    }
}
