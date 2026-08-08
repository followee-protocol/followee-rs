//! Friendly JSON Contact Document authoring format
//! (IMPLEMENTATION.md section 7.5).
//!
//! This JSON is an implementation convenience, not a Followee wire format.
//! It maps unambiguously onto the normative Contact Document, rejects
//! unknown fields by default, and always describes a complete document.
//! Every limit and grammar is enforced by the reviewed core schema
//! ([`ContactDocument::validate`] and the signing path) before anything is
//! signed; this module performs shape mapping only and duplicates no
//! protocol validation.
//!
//! Extension values follow the specification section 9.6 JSON conventions:
//! byte strings are objects of the exact form `{"bytes": "<unpadded
//! base64url>"}`, and integer map keys are decimal strings prefixed with
//! `#`. Those two spellings are reserved by the mapping.

use crate::contact::{ContactDocument, ExtensionKey, ExtensionMap, ExtensionValue, ServiceEntry};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

/// Authoring-format rejection: the JSON does not map onto a complete v1
/// Contact Document. Protocol limits and grammars are enforced separately by
/// the core schema at signing time.
#[derive(Debug, thiserror::Error)]
#[error("contact JSON: {0}")]
pub struct ContactJsonError(String);

fn err<T>(message: impl Into<String>) -> Result<T, ContactJsonError> {
    Err(ContactJsonError(message.into()))
}

fn as_string(value: &Value, field: &str) -> Result<String, ContactJsonError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        _ => err(format!("field {field} must be a JSON string")),
    }
}

/// Parses the authoring JSON text into a [`ContactDocument`].
///
/// # Errors
///
/// Returns [`ContactJsonError`] for syntax errors, unknown fields, or shapes
/// that do not map onto the v1 document.
pub fn contact_from_json(text: &str) -> Result<ContactDocument, ContactJsonError> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| ContactJsonError(format!("not valid JSON: {e}")))?;
    let Value::Object(map) = value else {
        return err("the document must be a JSON object");
    };
    let mut doc = ContactDocument::default();
    for (field, value) in &map {
        match field.as_str() {
            "displayName" => doc.display_name = Some(as_string(value, field)?),
            "summary" => doc.summary = Some(as_string(value, field)?),
            "avatar" => doc.avatar = Some(as_string(value, field)?),
            "alsoKnownAs" => {
                let Value::Array(items) = value else {
                    return err("alsoKnownAs must be an array of strings");
                };
                for item in items {
                    doc.also_known_as.push(as_string(item, "alsoKnownAs[]")?);
                }
            }
            "services" => {
                let Value::Array(items) = value else {
                    return err("services must be an array of objects");
                };
                for item in items {
                    doc.services.push(service_from_json(item)?);
                }
            }
            "migration" => doc.migration = Some(migration_from_json(value)?),
            "extensions" => doc.extensions = extensions_from_json(value)?,
            // Unknown fields are rejected by default (IMPLEMENTATION.md
            // section 7.5): a typo must not silently drop authored data.
            other => return err(format!("unknown field {other:?}")),
        }
    }
    Ok(doc)
}

fn service_from_json(value: &Value) -> Result<ServiceEntry, ContactJsonError> {
    let Value::Object(map) = value else {
        return err("each service must be a JSON object");
    };
    let mut id = None;
    let mut service_type = None;
    let mut endpoint = None;
    let mut media_type = None;
    let mut label = None;
    let mut language = None;
    let mut rel = None;
    for (field, value) in map {
        match field.as_str() {
            "id" => id = Some(as_string(value, "service id")?),
            "type" => service_type = Some(as_string(value, "service type")?),
            "endpoint" => endpoint = Some(as_string(value, "service endpoint")?),
            "mediaType" => media_type = Some(as_string(value, "service mediaType")?),
            "label" => label = Some(as_string(value, "service label")?),
            "language" => language = Some(as_string(value, "service language")?),
            "rel" => rel = Some(as_string(value, "service rel")?),
            other => return err(format!("unknown service field {other:?}")),
        }
    }
    Ok(ServiceEntry {
        id: id.ok_or(ContactJsonError("service id is required".to_owned()))?,
        service_type: service_type
            .ok_or(ContactJsonError("service type is required".to_owned()))?,
        endpoint: endpoint.ok_or(ContactJsonError("service endpoint is required".to_owned()))?,
        media_type,
        label,
        language,
        rel,
    })
}

fn migration_from_json(value: &Value) -> Result<crate::contact::Migration, ContactJsonError> {
    let Value::Object(map) = value else {
        return err("migration must be a JSON object");
    };
    let mut predecessor = None;
    let mut successor = None;
    for (field, value) in map {
        let text = as_string(value, field)?;
        let did = crate::did::FolloweeDid::parse(&text)
            .map_err(|e| ContactJsonError(format!("migration {field}: {e}")))?;
        match field.as_str() {
            "predecessor" => predecessor = Some(did),
            "successor" => successor = Some(did),
            other => return err(format!("unknown migration field {other:?}")),
        }
    }
    Ok(crate::contact::Migration {
        predecessor,
        successor,
    })
}

fn extensions_from_json(value: &Value) -> Result<ExtensionMap, ContactJsonError> {
    let Value::Object(map) = value else {
        return err("extensions must be a JSON object keyed by URI");
    };
    let mut extensions = ExtensionMap::new();
    for (key, value) in map {
        extensions.insert(key.clone(), extension_value_from_json(value)?);
    }
    Ok(extensions)
}

fn extension_value_from_json(value: &Value) -> Result<ExtensionValue, ContactJsonError> {
    match value {
        Value::Null => Ok(ExtensionValue::Null),
        Value::Bool(b) => Ok(ExtensionValue::Bool(*b)),
        Value::Number(n) => {
            if let Some(unsigned) = n.as_u64() {
                Ok(ExtensionValue::Unsigned(unsigned))
            } else if let Some(signed) = n.as_i64() {
                // -(1 + magnitude) = signed  =>  magnitude = !(signed as u64).
                #[allow(clippy::cast_sign_loss)]
                Ok(ExtensionValue::Negative(!(signed as u64)))
            } else {
                err("extension numbers must be JSON-representable integers; floats are forbidden")
            }
        }
        Value::String(s) => Ok(ExtensionValue::Text(s.clone())),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(extension_value_from_json(item)?);
            }
            Ok(ExtensionValue::Array(out))
        }
        Value::Object(map) => {
            // The exact one-field {"bytes": "..."} form is a byte string.
            if map.len() == 1
                && let Some(Value::String(encoded)) = map.get("bytes")
            {
                let bytes = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| ContactJsonError("invalid base64url in bytes value".to_owned()))?;
                return Ok(ExtensionValue::Bytes(bytes));
            }
            let mut entries = Vec::with_capacity(map.len());
            for (key, value) in map {
                entries.push((
                    extension_key_from_json(key)?,
                    extension_value_from_json(value)?,
                ));
            }
            Ok(ExtensionValue::Map(entries))
        }
    }
}

fn extension_key_from_json(key: &str) -> Result<ExtensionKey, ContactJsonError> {
    if let Some(decimal) = key.strip_prefix('#') {
        if let Some(negative) = decimal.strip_prefix('-') {
            let magnitude: u64 = negative
                .parse::<u64>()
                .ok()
                .and_then(|v| v.checked_sub(1))
                .ok_or(ContactJsonError(format!("invalid integer map key {key:?}")))?;
            return Ok(ExtensionKey::Negative(magnitude));
        }
        let unsigned: u64 = decimal
            .parse()
            .map_err(|_| ContactJsonError(format!("invalid integer map key {key:?}")))?;
        return Ok(ExtensionKey::Unsigned(unsigned));
    }
    Ok(ExtensionKey::Text(key.to_owned()))
}

/// Renders a Contact Document as authoring-format JSON (used by inspection;
/// round-trips with [`contact_from_json`]).
#[must_use]
pub fn contact_to_json(doc: &ContactDocument) -> Value {
    let mut map = Map::new();
    if let Some(v) = &doc.display_name {
        map.insert("displayName".to_owned(), Value::String(v.clone()));
    }
    if let Some(v) = &doc.summary {
        map.insert("summary".to_owned(), Value::String(v.clone()));
    }
    if let Some(v) = &doc.avatar {
        map.insert("avatar".to_owned(), Value::String(v.clone()));
    }
    if !doc.also_known_as.is_empty() {
        map.insert(
            "alsoKnownAs".to_owned(),
            Value::Array(
                doc.also_known_as
                    .iter()
                    .map(|v| Value::String(v.clone()))
                    .collect(),
            ),
        );
    }
    if !doc.services.is_empty() {
        map.insert(
            "services".to_owned(),
            Value::Array(doc.services.iter().map(service_to_json).collect()),
        );
    }
    if let Some(migration) = &doc.migration {
        let mut m = Map::new();
        if let Some(v) = &migration.predecessor {
            m.insert(
                "predecessor".to_owned(),
                Value::String(v.as_str().to_owned()),
            );
        }
        if let Some(v) = &migration.successor {
            m.insert("successor".to_owned(), Value::String(v.as_str().to_owned()));
        }
        map.insert("migration".to_owned(), Value::Object(m));
    }
    if !doc.extensions.is_empty() {
        let mut m = Map::new();
        for (key, value) in &doc.extensions {
            m.insert(key.clone(), extension_value_to_json(value));
        }
        map.insert("extensions".to_owned(), Value::Object(m));
    }
    Value::Object(map)
}

fn service_to_json(service: &ServiceEntry) -> Value {
    let mut map = Map::new();
    map.insert("id".to_owned(), Value::String(service.id.clone()));
    map.insert(
        "type".to_owned(),
        Value::String(service.service_type.clone()),
    );
    map.insert(
        "endpoint".to_owned(),
        Value::String(service.endpoint.clone()),
    );
    if let Some(v) = &service.media_type {
        map.insert("mediaType".to_owned(), Value::String(v.clone()));
    }
    if let Some(v) = &service.label {
        map.insert("label".to_owned(), Value::String(v.clone()));
    }
    if let Some(v) = &service.language {
        map.insert("language".to_owned(), Value::String(v.clone()));
    }
    if let Some(v) = &service.rel {
        map.insert("rel".to_owned(), Value::String(v.clone()));
    }
    Value::Object(map)
}

fn extension_value_to_json(value: &ExtensionValue) -> Value {
    match value {
        ExtensionValue::Unsigned(v) => Value::Number((*v).into()),
        ExtensionValue::Negative(magnitude) => {
            // -(1 + magnitude); magnitudes beyond i64 render as the decimal
            // string form since JSON numbers cannot carry them exactly.
            i64::try_from(*magnitude)
                .ok()
                .and_then(|m| m.checked_add(1))
                .and_then(i64::checked_neg)
                .map_or_else(
                    || Value::String(format!("-{}", u128::from(*magnitude).saturating_add(1))),
                    |negative| Value::Number(negative.into()),
                )
        }
        ExtensionValue::Bytes(bytes) => {
            let mut map = Map::new();
            map.insert(
                "bytes".to_owned(),
                Value::String(URL_SAFE_NO_PAD.encode(bytes)),
            );
            Value::Object(map)
        }
        ExtensionValue::Text(s) => Value::String(s.clone()),
        ExtensionValue::Bool(b) => Value::Bool(*b),
        ExtensionValue::Null => Value::Null,
        ExtensionValue::Array(items) => {
            Value::Array(items.iter().map(extension_value_to_json).collect())
        }
        ExtensionValue::Map(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                let rendered_key = match key {
                    ExtensionKey::Unsigned(v) => format!("#{v}"),
                    ExtensionKey::Negative(magnitude) => {
                        format!("#-{}", u128::from(*magnitude).saturating_add(1))
                    }
                    ExtensionKey::Text(s) => s.clone(),
                };
                map.insert(rendered_key, extension_value_to_json(value));
            }
            Value::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impl_7_5_unknown_fields_are_rejected_by_default() {
        for text in [
            r#"{"displayNme": "typo"}"#,
            r#"{"services": [{"id": "a", "type": "Website", "endpoint": "https://e.com/", "extra": 1}]}"#,
            r#"{"migration": {"succesor": "did:flw:zQm"}}"#,
        ] {
            assert!(contact_from_json(text).is_err(), "{text}");
        }
    }

    #[test]
    fn impl_7_5_round_trips_every_field_kind() {
        let text = r##"{
            "displayName": "Alice",
            "summary": "Writer",
            "avatar": "https://example.com/a.png",
            "alsoKnownAs": ["acct:alice@example.com"],
            "services": [{
                "id": "feed", "type": "Feed",
                "endpoint": "https://example.com/feed.xml",
                "mediaType": "application/atom+xml",
                "label": "Writing", "language": "en", "rel": "alternate"
            }],
            "extensions": {
                "https://example.com/ext": {
                    "#0": 1, "#-2": "x", "text": [true, null, -5,
                    {"bytes": "AQID"}]
                }
            }
        }"##;
        let doc = contact_from_json(text).expect("parses");
        assert!(
            doc.validate(None).is_ok(),
            "maps onto a schema-valid document"
        );
        let rendered = contact_to_json(&doc);
        let reparsed = contact_from_json(&serde_json::to_string(&rendered).expect("serialises"))
            .expect("round-trips");
        assert_eq!(doc, reparsed);
        // The byte-string form decoded to the expected raw bytes.
        let ExtensionValue::Map(entries) = &doc.extensions["https://example.com/ext"] else {
            panic!("extension object expected");
        };
        assert!(entries.iter().any(|(k, v)| {
            matches!(k, ExtensionKey::Text(t) if t == "text")
                && matches!(v, ExtensionValue::Array(items)
                    if matches!(&items[3], ExtensionValue::Bytes(b) if b == &vec![1, 2, 3]))
        }));
        assert!(entries.iter().any(|(k, _)| *k == ExtensionKey::Negative(1)));
    }

    #[test]
    fn impl_7_5_floats_and_non_integer_numbers_are_rejected() {
        for text in [
            r#"{"extensions": {"https://e.com/x": 1.5}}"#,
            r#"{"extensions": {"https://e.com/x": 1e300}}"#,
        ] {
            assert!(contact_from_json(text).is_err(), "{text}");
        }
    }

    #[test]
    fn impl_7_5_document_must_be_an_object() {
        assert!(contact_from_json("[]").is_err());
        assert!(contact_from_json("null").is_err());
        assert!(contact_from_json("not json").is_err());
        assert!(
            contact_from_json("{}")
                .expect("empty document is valid")
                .validate(None)
                .is_ok()
        );
    }
}
