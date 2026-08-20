//! Strict JSON subset for the neutral interoperability interface.
//!
//! The v0.9.2 interface contract rejects bare JSON numbers, duplicate
//! object members, and unknown object members as input-contract
//! violations. A `serde_json::Value` tree cannot report duplicate members
//! (the last occurrence silently wins), so — in the same spirit as the
//! crate's own strict CBOR codec — this is a small recursive-descent
//! parser over exactly the JSON subset the contract permits: objects,
//! arrays, strings, booleans, and null. Any number token is rejected at
//! the lexical layer, which is correct here because every interface
//! integer is a canonical decimal *string*. Unknown-member rejection is
//! the schema layer's job in `interop`.

/// Maximum nesting depth accepted from one request line. The deepest
/// conforming input is a typed extension tree bounded by the record's
/// CBOR nesting limit (8), each level of which spans a few JSON levels,
/// inside the request envelope; 96 is far above any conforming line while
/// still bounding hostile recursion.
const MAX_DEPTH: u32 = 96;

/// One parsed JSON value from the permitted subset. Object member order is
/// preserved as received; duplicate members were already rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Json {
    /// Object with insertion-ordered, duplicate-free members.
    Object(Vec<(String, Json)>),
    /// Array.
    Array(Vec<Json>),
    /// String.
    Str(String),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
}

impl Json {
    /// Convenience string constructor.
    pub(crate) fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
}

/// Parses exactly one JSON value from the permitted subset, rejecting
/// numbers, duplicate object members, unescaped control characters, and
/// trailing content.
pub(crate) fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err("trailing content after the JSON value".to_owned());
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), String> {
        let end = self.pos.saturating_add(literal.len());
        if self.bytes.get(self.pos..end) == Some(literal.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(format!("expected `{literal}`"))
        }
    }

    fn value(&mut self, depth: u32) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting exceeds the accepted depth".to_owned());
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => {
                self.expect_literal("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.expect_literal("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.expect_literal("null")?;
                Ok(Json::Null)
            }
            Some(b'-' | b'0'..=b'9') => Err(
                "bare JSON numbers are rejected; integers are canonical decimal strings".to_owned(),
            ),
            Some(other) => Err(format!("unexpected byte 0x{other:02x}")),
            None => Err("unexpected end of input".to_owned()),
        }
    }

    fn object(&mut self, depth: u32) -> Result<Json, String> {
        self.bump();
        self.skip_ws();
        let mut members: Vec<(String, Json)> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err("object member name must be a string".to_owned());
            }
            let name = self.string()?;
            if !seen.insert(name.clone()) {
                return Err(format!("duplicate object member `{name}`"));
            }
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err("expected `:` after member name".to_owned());
            }
            self.skip_ws();
            let value = self.value(depth.saturating_add(1))?;
            members.push((name, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(members)),
                _ => return Err("expected `,` or `}` in object".to_owned()),
            }
        }
    }

    fn array(&mut self, depth: u32) -> Result<Json, String> {
        self.bump();
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth.saturating_add(1))?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(items)),
                _ => return Err("expected `,` or `]` in array".to_owned()),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.bump(); // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.bump().ok_or("unterminated string")?;
            match b {
                b'"' => {
                    // The input is a &str and escapes only produce valid
                    // chars, so this cannot fail; kept as a checked error.
                    return String::from_utf8(out).map_err(|_| "invalid UTF-8".to_owned());
                }
                b'\\' => {
                    let esc = self.bump().ok_or("unterminated escape")?;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&unit) {
                                // High surrogate: a low surrogate must follow.
                                self.expect_literal("\\u")?;
                                let low = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err("unpaired surrogate escape".to_owned());
                                }
                                let high_bits = u32::from(unit & 0x3FF) << 10;
                                let code = 0x10000_u32
                                    .saturating_add(high_bits)
                                    .saturating_add(u32::from(low & 0x3FF));
                                char::from_u32(code).ok_or("invalid surrogate pair")?
                            } else if (0xDC00..=0xDFFF).contains(&unit) {
                                return Err("unpaired surrogate escape".to_owned());
                            } else {
                                char::from_u32(u32::from(unit)).ok_or("invalid code point")?
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => return Err(format!("invalid escape `\\{}`", other as char)),
                    }
                }
                0x00..=0x1f => return Err("unescaped control character in string".to_owned()),
                other => out.push(other),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or("truncated \\u escape")?;
            let digit = match b {
                b'0'..=b'9' => b.checked_sub(b'0'),
                b'a'..=b'f' => b.checked_sub(b'a').map(|d| d.saturating_add(10)),
                b'A'..=b'F' => b.checked_sub(b'A').map(|d| d.saturating_add(10)),
                _ => None,
            }
            .ok_or("invalid \\u escape digit")?;
            value = value
                .checked_mul(16)
                .and_then(|v| v.checked_add(u16::from(digit)))
                .ok_or("\\u escape overflow")?;
        }
        Ok(value)
    }
}

/// Serializes a value: members in stored order, minimal escaping, no
/// insignificant whitespace. Deterministic for identical values.
pub(crate) fn write(value: &Json) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Json, out: &mut String) {
    match value {
        Json::Object(members) => {
            out.push('{');
            for (i, (name, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(member, out);
            }
            out.push('}');
        }
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Json::Str(s) => write_string(s, out),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Null => out.push_str("null"),
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Remaining control characters use the uXXXX form.
                let code = c as u32;
                out.push_str("\\u");
                for shift in [12u32, 8, 4, 0] {
                    let digit = (code >> shift) & 0xF;
                    out.push(char::from_digit(digit, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_permitted_subset() {
        let parsed = parse(r#"{"a":["x",true,null,{"b":false}]}"#).expect("parses");
        assert_eq!(
            parsed,
            Json::Object(vec![(
                "a".to_owned(),
                Json::Array(vec![
                    Json::str("x"),
                    Json::Bool(true),
                    Json::Null,
                    Json::Object(vec![("b".to_owned(), Json::Bool(false))]),
                ])
            )])
        );
    }

    #[test]
    fn rejects_bare_numbers_everywhere() {
        for text in [r#"7"#, r#"-1"#, r#"{"a":7}"#, r#"[1]"#, r#"{"a":[true,0]}"#] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_duplicate_object_members() {
        assert!(parse(r#"{"a":"1","a":"2"}"#).is_err());
        assert!(parse(r#"{"a":{"b":"1","b":"1"}}"#).is_err());
    }

    #[test]
    fn rejects_trailing_content_and_bad_escapes() {
        assert!(parse(r#"{} {}"#).is_err());
        assert!(parse(r#""\x""#).is_err());
        assert!(parse("\"\u{0009}\"").is_err(), "unescaped control");
        assert!(parse(r#""\ud800""#).is_err(), "unpaired surrogate");
    }

    #[test]
    fn escape_round_trip_preserves_text() {
        let parsed = parse(r#""Carol Éxample 测试 😀 \n""#).expect("parses");
        assert_eq!(parsed, Json::str("Carol Éxample 测试 😀 \n"));
        let rendered = write(&parsed);
        assert_eq!(parse(&rendered).expect("round trip"), parsed);
    }

    #[test]
    fn writer_output_is_deterministic_and_ordered() {
        let value = Json::Object(vec![
            ("b".to_owned(), Json::str("2")),
            ("a".to_owned(), Json::Null),
        ]);
        assert_eq!(write(&value), r#"{"b":"2","a":null}"#);
    }

    #[test]
    fn insignificant_whitespace_is_skipped_between_tokens() {
        let parsed = parse(" { \"a\" :\t[ \"x\" ,\r\n true ] } ").expect("parses");
        assert_eq!(
            parsed,
            Json::Object(vec![(
                "a".to_owned(),
                Json::Array(vec![Json::str("x"), Json::Bool(true)])
            )])
        );
    }

    #[test]
    fn nesting_depth_boundary_is_exact() {
        // Arrays nested to the exact boundary parse; one deeper is rejected.
        let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&nested(97)).is_ok(), "at the boundary");
        assert!(parse(&nested(98)).is_err(), "one past the boundary");
    }

    #[test]
    fn unicode_escapes_decode_to_the_exact_code_points() {
        // Each hex-digit class, both letter cases, and a surrogate pair.
        assert_eq!(parse(r#""\u0041""#).expect("parses"), Json::str("A"));
        assert_eq!(
            parse(r#""\u00e9""#).expect("parses"),
            Json::str("\u{e9}"),
            "lowercase hex digits"
        );
        assert_eq!(
            parse(r#""\u00E9""#).expect("parses"),
            Json::str("\u{e9}"),
            "uppercase hex digits"
        );
        assert_eq!(
            parse(r#""\ud83d\ude00""#).expect("parses"),
            Json::str("\u{1f600}"),
            "surrogate pair reassembles to the exact code point"
        );
        assert!(parse(r#""\u00g1""#).is_err(), "non-hex escape digit");
    }

    #[test]
    fn writer_escapes_exactly_the_control_characters() {
        assert_eq!(write(&Json::str("a b")), r#""a b""#, "space is unescaped");
        assert_eq!(write(&Json::str("\u{1}")), r#""\u0001""#);
        assert_eq!(write(&Json::str("\u{1f}")), r#""\u001f""#);
        assert_eq!(write(&Json::str("\n\t")), r#""\n\t""#);
        // Escaped output re-parses to the identical value.
        for text in ["\u{1}", "\u{1f}", "a b", "line\nbreak"] {
            let value = Json::str(text);
            assert_eq!(parse(&write(&value)).expect("round trip"), value);
        }
    }
}
