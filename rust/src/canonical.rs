use percent_encoding::percent_decode_str;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::Error;

const INT_MIN: i64 = i64::MIN;
const INT_MAX: i64 = i64::MAX;

pub fn canonical_dumps(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn operation_id(document: &Value) -> Result<String, Error> {
    Ok(sha256_hex(canonical_dumps(document)?.as_bytes()))
}

pub fn token_for(scope_id: &str, op_id: &str) -> String {
    sha256_hex(format!("{scope_id}\n{op_id}").as_bytes())
}

pub fn http_document(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Value, Error> {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    Ok(json_map(vec![
        ("body", body_document(&pairs, body)?),
        ("headers", Value::Array(identity_headers(&pairs))),
        ("kind", Value::String("http".into())),
        ("method", Value::String(method.to_ascii_uppercase())),
        ("url", Value::String(canonical_url(url)?)),
    ]))
}

pub fn db_document(target: &Value, statements: &[Value], isolation: &str) -> Result<Value, Error> {
    let target_object = target.as_object().ok_or_else(|| Error::Canonical("database target must be an object".into()))?;
    if target_object.contains_key("password") {
        return Err(Error::Canonical("password is not part of the database target".into()));
    }
    let port = target_object.get("port").cloned().unwrap_or_else(|| Value::Number(0.into()));
    if port.as_i64().is_none() || port.as_bool().is_some() {
        return Err(Error::Canonical("database port must be an integer".into()));
    }
    let mut typed_statements = Vec::new();
    for statement in statements {
        let sql = statement
            .get("sql")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Canonical("statement sql is required".into()))?;
        let params = statement.get("params").and_then(Value::as_array);
        let mut typed = Vec::new();
        if let Some(params) = params {
            for param in params {
                typed.push(typed_param(param)?);
            }
        }
        typed_statements.push(json_map(vec![
            ("params", Value::Array(typed)),
            ("sql", Value::String(sql.into())),
        ]));
    }
    Ok(json_map(vec![
        ("kind", Value::String("db".into())),
        ("statements", Value::Array(typed_statements)),
        (
            "target",
            json_map(vec![
                ("database", string_field(target_object, "database")),
                ("driver", string_field(target_object, "driver")),
                ("host", string_field(target_object, "host")),
                ("port", port),
                ("user", string_field(target_object, "user")),
            ]),
        ),
        (
            "transaction",
            json_map(vec![
                ("boundary", Value::String("single_transaction".into())),
                ("isolation", Value::String(isolation.into())),
            ]),
        ),
    ]))
}

pub fn typed_param(value: &Value) -> Result<Value, Error> {
    match value {
        Value::Null => Ok(json_map(vec![("type", Value::String("null".into())), ("value", Value::Null)])),
        Value::Bool(flag) => Ok(json_map(vec![
            ("type", Value::String("bool".into())),
            ("value", Value::Bool(*flag)),
        ])),
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .ok_or_else(|| Error::Canonical("json numbers must be integers".into()))?;
            Ok(json_map(vec![
                ("type", Value::String("int".into())),
                ("value", Value::Number(integer.into())),
            ]))
        }
        Value::String(text) => Ok(json_map(vec![
            ("type", Value::String("string".into())),
            ("value", Value::String(text.clone())),
        ])),
        Value::Array(_) | Value::Object(_) => {
            canonical_dumps(value)?;
            Ok(json_map(vec![("type", Value::String("json".into())), ("value", value.clone())]))
        }
    }
}

pub fn canonical_url(url: &str) -> Result<String, Error> {
    let parsed = Url::parse(url).map_err(|_| Error::Canonical("url could not be parsed".into()))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(Error::Canonical("url scheme must be http or https".into()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Canonical("url host is required".into()))?
        .to_ascii_lowercase();
    let host = if host.contains(':') { format!("[{host}]") } else { host };
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let path = canonical_path(parsed.path());
    let query = canonical_query(parsed.query().unwrap_or(""));
    if query.is_empty() {
        Ok(format!("{scheme}://{authority}{path}"))
    } else {
        Ok(format!("{scheme}://{authority}{path}?{query}"))
    }
}

pub fn success_envelope(body: Value) -> Value {
    json_map(vec![("body", body), ("outcome", Value::String("success".into()))])
}

pub fn error_envelope(code: &str, message: &str) -> Value {
    let message = message.chars().take(500).collect::<String>();
    json_map(vec![
        (
            "body",
            json_map(vec![
                ("code", Value::String(code.into())),
                ("message", Value::String(message)),
            ]),
        ),
        ("outcome", Value::String("error".into())),
    ])
}

pub fn json_map(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

fn string_field(object: &Map<String, Value>, key: &str) -> Value {
    Value::String(object.get(key).and_then(Value::as_str).unwrap_or("").to_string())
}

fn write_value(out: &mut String, value: &Value) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => write_number(out, number)?,
        Value::String(text) => {
            out.push('"');
            out.push_str(&escape(text));
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape(key));
                out.push_str("\":");
                write_value(out, &map[*key])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(out: &mut String, number: &Number) -> Result<(), Error> {
    let Some(integer) = number.as_i64() else {
        return Err(Error::Canonical("json numbers must be integers".into()));
    };
    if integer < INT_MIN || integer > INT_MAX {
        return Err(Error::Canonical("integer out of range".into()));
    }
    out.push_str(&integer.to_string());
    Ok(())
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{code:04x}", code = ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn identity_headers(pairs: &[(String, String)]) -> Vec<Value> {
    let mut kept = Vec::new();
    for (name, value) in pairs {
        let lowered = name.trim().to_ascii_lowercase();
        if lowered == "accept" || lowered == "content-type" {
            kept.push(Value::Array(vec![
                Value::String(lowered),
                Value::String(value.trim().to_string()),
            ]));
        }
    }
    kept.sort_by(|left, right| left.as_array().unwrap()[0].as_str().cmp(&right.as_array().unwrap()[0].as_str()));
    kept
}

fn body_document(pairs: &[(String, String)], body: &[u8]) -> Result<Value, Error> {
    if body.is_empty() {
        return Ok(json_map(vec![("kind", Value::String("empty".into()))]));
    }
    let content_type = pairs
        .iter()
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    if is_json_type(&content_type) {
        let Ok(text) = std::str::from_utf8(body) else {
            return Ok(bytes_body(body));
        };
        match serde_json::from_str::<Value>(text) {
            Ok(parsed) => {
                reject_float_numbers(&parsed)?;
                canonical_dumps(&parsed)?;
                Ok(json_map(vec![
                    ("kind", Value::String("json".into())),
                    ("value", parsed),
                ]))
            }
            Err(_) => Ok(bytes_body(body)),
        }
    } else {
        Ok(bytes_body(body))
    }
}

fn reject_float_numbers(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(number) if number.as_i64().is_none() => Err(Error::Canonical("json numbers must be integers".into())),
        Value::Array(items) => {
            for item in items {
                reject_float_numbers(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for item in map.values() {
                reject_float_numbers(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn bytes_body(body: &[u8]) -> Value {
    json_map(vec![
        ("hex", Value::String(hex::encode(body))),
        ("kind", Value::String("bytes".into())),
    ])
}

fn is_json_type(value: &str) -> bool {
    let media = value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    media == "application/json" || media.ends_with("+json")
}

fn canonical_path(path: &str) -> String {
    let decoded = percent_decode_str(path).decode_utf8_lossy();
    let normalized = norm_path(&decoded);
    encode_path(&normalized)
}

fn norm_path(path: &str) -> String {
    let mut stack = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            stack.pop();
            continue;
        }
        stack.push(segment);
    }
    format!("/{}", stack.join("/"))
}

fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs = Vec::new();
    for piece in query.split('&') {
        if piece.is_empty() {
            continue;
        }
        let (key, value) = piece.split_once('=').unwrap_or((piece, ""));
        let key = percent_decode_str(key).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(value).decode_utf8_lossy().into_owned();
        pairs.push((key, value));
    }
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", encode_component(&key), encode_component(&value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_path(path: &str) -> String {
    let mut out = String::new();
    for byte in path.as_bytes() {
        if is_unreserved(*byte) || *byte == b'/' {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    if out.is_empty() {
        "/".into()
    } else {
        out
    }
}

fn encode_component(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        if is_unreserved(*byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}
