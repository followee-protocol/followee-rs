//! Strict, bounded JSON parsing for untrusted WebFinger JRD responses
//! (specification section 10.2; RFC 7033; RFC 8259).
//!
//! A JRD response is untrusted external input, so it gets the same
//! treatment as untrusted CBOR: explicit byte, nesting, and member bounds
//! are enforced before allocation-heavy work, invalid UTF-8 is rejected,
//! and duplicate object member names are rejected rather than silently
//! collapsed (RFC 8259 leaves duplicate-name behaviour unspecified, and a
//! parser that keeps "the last one" would let an attacker smuggle a second
//! `subject` or `links` past a naive reader). This is why the crate's
//! general-purpose serde_json dependency — which collapses duplicates — is
//! not used on this input.
//!
//! The parser validates full RFC 8259 grammar (strings with escape and
//! surrogate-pair handling, numbers, literals) but keeps only the shapes
//! the WebFinger layer consumes: objects, arrays, strings, and opaque
//! markers for numbers, booleans, and null. Exactly one top-level value is
//! required; trailing data is rejected.

/// Parse-layer fault classification for an untrusted JRD body. Each
/// variant is a distinct, stable classification so tests can pin the exact
/// failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JrdFault {
    /// The body is not valid UTF-8 (RFC 8259 section 8.1).
    #[error("JRD body is not valid UTF-8")]
    InvalidUtf8,
    /// The body is not one well-formed RFC 8259 JSON text, or carries
    /// trailing data after the top-level value.
    #[error("JRD body is not well-formed JSON")]
    MalformedJson,
    /// An object contains two members with the same name; the response is
    /// rejected rather than one member being silently discarded.
    #[error("JRD object contains duplicate member names")]
    DuplicateMember,
    /// The nesting-depth or total-member bound was exceeded.
    #[error("JRD exceeds the nesting or member bound")]
    LimitExceeded,
}

/// A parsed JSON value. Numbers are validated for grammar and carried as
/// their raw text, never interpreted as floating point: no WebFinger field
/// the client consumes is numeric, and this crate admits no
/// floating-point protocol values. (The authority configuration loader
/// compares the raw text of its `version` member.)
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// An object, in received member order, duplicate-free.
    Object(Vec<(String, JsonValue)>),
    /// An array, in received order.
    Array(Vec<JsonValue>),
    /// A string with all escapes decoded.
    String(String),
    /// A grammar-valid number as its raw text, not interpreted.
    Number(String),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
}

impl JsonValue {
    /// The member with `name`, when this value is an object.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(members) => members
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The string content, when this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Bounded recursive-descent parser state.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: u32,
    members_left: u32,
}

/// Parses exactly one bounded JSON text.
///
/// `max_depth` bounds object/array nesting (the top-level value is depth
/// one); `max_members` bounds the total count of object members and array
/// elements across the document. Both are enforced before the offending
/// container content is parsed.
///
/// # Errors
///
/// Returns the [`JrdFault`] classifying the first failure.
pub fn parse_json(bytes: &[u8], max_depth: u32, max_members: u32) -> Result<JsonValue, JrdFault> {
    // UTF-8 validity first: RFC 8259 JSON text exchanged between systems
    // MUST be UTF-8, and rejecting early keeps later byte handling simple.
    if std::str::from_utf8(bytes).is_err() {
        return Err(JrdFault::InvalidUtf8);
    }
    let mut parser = Parser {
        bytes,
        pos: 0,
        max_depth,
        members_left: max_members,
    };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.bytes.len() {
        return Err(JrdFault::MalformedJson);
    }
    Ok(value)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JrdFault> {
        if self.bump() == Some(byte) {
            Ok(())
        } else {
            Err(JrdFault::MalformedJson)
        }
    }

    fn charge_member(&mut self) -> Result<(), JrdFault> {
        match self.members_left.checked_sub(1) {
            Some(left) => {
                self.members_left = left;
                Ok(())
            }
            None => Err(JrdFault::LimitExceeded),
        }
    }

    fn parse_value(&mut self, depth: u32) -> Result<JsonValue, JrdFault> {
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(JrdFault::MalformedJson),
        }
    }

    fn parse_literal(&mut self, text: &[u8], value: JsonValue) -> Result<JsonValue, JrdFault> {
        for expected in text {
            if self.bump() != Some(*expected) {
                return Err(JrdFault::MalformedJson);
            }
        }
        Ok(value)
    }

    fn enter(&self, depth: u32) -> Result<u32, JrdFault> {
        let next = depth.saturating_add(1);
        if next > self.max_depth {
            return Err(JrdFault::LimitExceeded);
        }
        Ok(next)
    }

    fn parse_object(&mut self, depth: u32) -> Result<JsonValue, JrdFault> {
        let depth = self.enter(depth)?;
        self.expect(b'{')?;
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonValue::Object(members));
        }
        loop {
            self.skip_whitespace();
            let name = self.parse_string()?;
            // Duplicate member names are rejected outright: this parser
            // never collapses one and keeps the other.
            if members.iter().any(|(existing, _)| *existing == name) {
                return Err(JrdFault::DuplicateMember);
            }
            self.charge_member()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value(depth)?;
            members.push((name, value));
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(JsonValue::Object(members)),
                _ => return Err(JrdFault::MalformedJson),
            }
        }
    }

    fn parse_array(&mut self, depth: u32) -> Result<JsonValue, JrdFault> {
        let depth = self.enter(depth)?;
        self.expect(b'[')?;
        let mut elements = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonValue::Array(elements));
        }
        loop {
            self.skip_whitespace();
            self.charge_member()?;
            elements.push(self.parse_value(depth)?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(JsonValue::Array(elements)),
                _ => return Err(JrdFault::MalformedJson),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JrdFault> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            // Consume a run of plain bytes; the document was validated as
            // UTF-8 up front, so any multi-byte sequence here is sound.
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos = self.pos.saturating_add(1);
            }
            if self.pos > start {
                let run = std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|_| JrdFault::InvalidUtf8)?;
                out.push_str(run);
            }
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.parse_escape()?),
                // Unescaped control characters and truncation are both
                // malformed (RFC 8259 section 7).
                _ => return Err(JrdFault::MalformedJson),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JrdFault> {
        match self.bump() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{0008}'),
            Some(b'f') => Ok('\u{000C}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => {
                let first = self.parse_hex4()?;
                match first {
                    // High surrogate: a low surrogate escape must follow
                    // (RFC 8259 section 7); anything else is malformed.
                    0xD800..=0xDBFF => {
                        if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                            return Err(JrdFault::MalformedJson);
                        }
                        let second = self.parse_hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err(JrdFault::MalformedJson);
                        }
                        let high = u32::from(first).saturating_sub(0xD800);
                        let low = u32::from(second).saturating_sub(0xDC00);
                        let code = 0x10000u32
                            .saturating_add(high.saturating_mul(0x400))
                            .saturating_add(low);
                        char::from_u32(code).ok_or(JrdFault::MalformedJson)
                    }
                    // A lone low surrogate cannot begin a code point.
                    0xDC00..=0xDFFF => Err(JrdFault::MalformedJson),
                    other => char::from_u32(u32::from(other)).ok_or(JrdFault::MalformedJson),
                }
            }
            _ => Err(JrdFault::MalformedJson),
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JrdFault> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let digit = match self.bump() {
                Some(b @ b'0'..=b'9') => u16::from(b.wrapping_sub(b'0')),
                Some(b @ b'a'..=b'f') => u16::from(b.wrapping_sub(b'a')).saturating_add(10),
                Some(b @ b'A'..=b'F') => u16::from(b.wrapping_sub(b'A')).saturating_add(10),
                _ => return Err(JrdFault::MalformedJson),
            };
            value = value.saturating_mul(16).saturating_add(digit);
        }
        Ok(value)
    }

    /// Validates RFC 8259 number grammar without interpreting the value.
    fn parse_number(&mut self) -> Result<JsonValue, JrdFault> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos = self.pos.saturating_add(1);
        }
        // int: 0, or a nonzero digit followed by digits.
        match self.bump() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos = self.pos.saturating_add(1);
                }
            }
            _ => return Err(JrdFault::MalformedJson),
        }
        // frac
        if self.peek() == Some(b'.') {
            self.pos = self.pos.saturating_add(1);
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JrdFault::MalformedJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        // exp
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos = self.pos.saturating_add(1);
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JrdFault::MalformedJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        let text =
            std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| JrdFault::InvalidUtf8)?;
        Ok(JsonValue::Number(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<JsonValue, JrdFault> {
        parse_json(text.as_bytes(), 8, 256)
    }

    #[test]
    fn sec_10_2_accepts_a_minimal_jrd_shape() {
        let value = parse(
            r#"{"subject":"acct:alice@example.com","links":[{"rel":"r","href":"h"}],"n":1.5e2,"b":true,"z":null}"#,
        )
        .expect("parses");
        assert_eq!(
            value.member("subject").and_then(JsonValue::as_str),
            Some("acct:alice@example.com")
        );
        let links = value.member("links").expect("links");
        let JsonValue::Array(items) = links else {
            panic!("links is an array");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].member("rel").and_then(JsonValue::as_str),
            Some("r")
        );
    }

    #[test]
    fn rfc_8259_rejects_duplicate_member_names_instead_of_collapsing() {
        assert_eq!(
            parse(r#"{"subject":"a","subject":"b"}"#).unwrap_err(),
            JrdFault::DuplicateMember
        );
        // Nested objects are checked independently.
        assert_eq!(
            parse(r#"{"links":[{"rel":"x","rel":"y"}]}"#).unwrap_err(),
            JrdFault::DuplicateMember
        );
        // Equal values are still duplicates.
        assert_eq!(
            parse(r#"{"a":1,"a":1}"#).unwrap_err(),
            JrdFault::DuplicateMember
        );
    }

    #[test]
    fn rfc_8259_rejects_malformed_documents() {
        for text in [
            "",
            "{",
            "}",
            "{\"a\":}",
            "{\"a\":1,}",
            "[1,]",
            "{'a':1}",
            "{\"a\" 1}",
            "nul",
            "truth",
            "01",
            "-",
            "1.",
            "1e",
            "1e+",
            ".5",
            "+1",
            "\"unterminated",
            "\"bad \\x escape\"",
            "\"ctrl \u{0009}\"",
            "{\"a\":1} trailing",
            "{\"a\":1}{}",
            "\"lone high \\ud834\"",
            "\"lone low \\udd1e\"",
            "\"pair order \\udd1e\\ud834\"",
        ] {
            assert_eq!(
                parse(text).unwrap_err(),
                JrdFault::MalformedJson,
                "{text:?}"
            );
        }
    }

    #[test]
    fn rfc_8259_decodes_escapes_and_surrogate_pairs() {
        let value = parse(r#""a\"\\\/\b\f\n\r\t\u0041\ud834\udd1e""#).expect("parses");
        assert_eq!(
            value.as_str(),
            Some("a\"\\/\u{0008}\u{000C}\n\r\t\u{0041}\u{1D11E}")
        );
        // Hex digits in escapes are case-insensitive: uppercase A-F and
        // lowercase a-f decode identically, in every digit position.
        let upper = parse(r#""\u004A\u00Af\uD834\uDD1E""#).expect("parses");
        assert_eq!(upper.as_str(), Some("J\u{00AF}\u{1D11E}"));
        let lower = parse(r#""\u004a\u00af\ud834\udd1e""#).expect("parses");
        assert_eq!(upper, lower);
    }

    #[test]
    fn sec_10_2_rejects_invalid_utf8_bytes() {
        assert_eq!(
            parse_json(b"{\"a\":\"\xff\"}", 8, 256).unwrap_err(),
            JrdFault::InvalidUtf8
        );
        assert_eq!(
            parse_json(b"\xc3\x28", 8, 256).unwrap_err(),
            JrdFault::InvalidUtf8
        );
    }

    #[test]
    fn sec_10_2_enforces_the_nesting_bound_exactly() {
        // Depth 8 (the bound) parses; depth 9 is rejected before content.
        let deep_ok = format!("{}1{}", "[".repeat(7), "]".repeat(7));
        let deep_ok = format!("[{deep_ok}]");
        assert!(parse(&deep_ok).is_ok(), "depth 8 parses");
        let too_deep = format!("{}1{}", "[".repeat(9), "]".repeat(9));
        assert_eq!(parse(&too_deep).unwrap_err(), JrdFault::LimitExceeded);
    }

    #[test]
    fn sec_10_2_enforces_the_member_bound_exactly() {
        let exact: String = format!(
            "[{}]",
            std::iter::repeat_n("1", 256).collect::<Vec<_>>().join(",")
        );
        assert!(parse(&exact).is_ok(), "256 members parse");
        let over: String = format!(
            "[{}]",
            std::iter::repeat_n("1", 257).collect::<Vec<_>>().join(",")
        );
        assert_eq!(parse(&over).unwrap_err(), JrdFault::LimitExceeded);
    }

    #[test]
    fn parser_treats_numbers_booleans_and_null_as_opaque() {
        let value = parse(r#"[0, -1, 1.25, 1e10, -0.5E-2, true, false, null]"#).expect("parses");
        let JsonValue::Array(items) = value else {
            panic!("array");
        };
        assert_eq!(items.len(), 8);
        assert_eq!(items[0], JsonValue::Number("0".to_owned()));
        assert_eq!(items[2], JsonValue::Number("1.25".to_owned()));
        assert_eq!(items[5], JsonValue::Bool(true));
        assert_eq!(items[7], JsonValue::Null);
    }
}
