use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn schema() -> Value {
    serde_json::from_str(&read("json-schema/atto-local-source-v1.schema.json")).unwrap()
}

fn candidate(length: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "scope": "local-pre-encryption",
        "language": "atto",
        "extension": ".atto",
        "encoding": "utf-8",
        "byteLength": length
    })
}

fn accepts(schema: &Value, record: &Value) -> bool {
    let Some(fields) = record.as_object() else {
        return false;
    };
    let Some(properties) = schema["properties"].as_object() else {
        return false;
    };
    let Some(required) = schema["required"].as_array() else {
        return false;
    };
    if schema["additionalProperties"] != false
        || fields.keys().any(|name| !properties.contains_key(name))
        || required
            .iter()
            .any(|name| name.as_str().is_none_or(|key| !fields.contains_key(key)))
    {
        return false;
    }

    properties.iter().all(|(name, rule)| {
        let Some(value) = fields.get(name) else {
            return true;
        };
        if !rule["const"].is_null() && rule["const"] != *value {
            return false;
        }
        if rule["type"] == "integer" {
            return value.as_i64().is_some_and(|number| {
                number >= rule["minimum"].as_i64().unwrap_or(i64::MAX)
                    && number <= rule["maximum"].as_i64().unwrap_or(i64::MIN)
            });
        }
        true
    })
}

#[test]
fn atto_metadata_schema_is_closed_and_admits_only_bounded_local_utf8_source() {
    let schema = schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    let declared: BTreeSet<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().expect("required name"))
        .collect();
    assert_eq!(declared, required);
    for length in [0, 1, 1048575, 1048576] {
        assert!(
            accepts(&schema, &candidate(json!(length))),
            "length {length}"
        );
    }
    for length in [
        json!(-1),
        json!(1048577),
        json!(1.5),
        json!("4"),
        Value::Null,
    ] {
        assert!(!accepts(&schema, &candidate(length)));
    }
}

#[test]
fn negative_canaries_reject_wrong_extension_scope_secret_fields_and_missing_keys() {
    let schema = schema();
    for (key, changed) in [
        ("extension", json!(".txt")),
        ("extension", json!(".ATTO")),
        ("scope", json!("remote")),
        ("encoding", json!("binary")),
        ("language", json!("javascript")),
        ("plaintext", json!("secret")),
        ("filename", json!("private.atto")),
        ("access_token", json!("never")),
    ] {
        let mut record = candidate(json!(14));
        record[key] = changed;
        assert!(!accepts(&schema, &record), "accepted invalid {key}");
    }

    let mut missing = candidate(json!(14));
    missing.as_object_mut().unwrap().remove("scope");
    assert!(!accepts(&schema, &missing));
}

#[test]
fn atto_examples_remain_preflight_only_not_network_transport() {
    let source = read("examples/atto/local_source_boundary.atto");
    for fragment in [
        "fnc nonnegative_source_size(int byte_length) -> bool",
        "return byte_length >= 0;",
        "fnc within_source_size_limit(int byte_length) -> bool",
        "return byte_length <= 1048576;",
    ] {
        assert!(source.contains(fragment), "missing Atto guard: {fragment}");
    }
    assert_eq!(source.matches("fnc ").count(), 2);
    for forbidden in [
        "fetch(",
        "http(",
        "socket(",
        "private_key(",
        "bearer_token(",
    ] {
        assert!(
            !source.contains(forbidden),
            "unexpected transport: {forbidden}"
        );
    }
}
