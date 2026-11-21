use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{Map, Value};

use crate::canonical::{canonical_dumps, json_map};
use crate::error::Error;

pub fn parse_record_key(text: Option<&str>) -> Result<Option<Vec<u8>>, Error> {
    let Some(text) = text.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let key = hex::decode(text).map_err(|_| Error::Config("IDEMPOTENCY_RECORD_KEY must be 64 hex characters".into()))?;
    if key.len() != 32 {
        return Err(Error::Config("IDEMPOTENCY_RECORD_KEY must be 32 bytes".into()));
    }
    Ok(Some(key))
}

pub fn seal(key: &[u8], nonce: &[u8], token: &str, obj: &Value) -> Result<Value, Error> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(Error::Config("record key must be 32 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Config("record key must be 32 bytes".into()))?;
    let plain = canonical_dumps(obj)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plain.as_bytes(),
                aad: token.as_bytes(),
            },
        )
        .map_err(|_| Error::Config("encryption failed".into()))?;
    Ok(json_map(vec![
        ("ct", Value::String(STANDARD.encode(ciphertext))),
        ("enc", Value::String("aes-256-gcm".into())),
        ("nonce", Value::String(STANDARD.encode(nonce))),
    ]))
}

pub fn encrypt(key: Option<&[u8]>, token: &str, obj: &Value) -> Result<Value, Error> {
    let Some(key) = key else {
        return Ok(obj.clone());
    };
    if key.len() != 32 {
        return Err(Error::Config("record key must be 32 bytes".into()));
    }
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Config("random nonce failed".into()))?;
    seal(key, &nonce, token, obj)
}

pub fn decrypt(key: Option<&[u8]>, token: &str, obj: &Value) -> Result<Value, Error> {
    let Some(enc) = obj.get("enc").and_then(Value::as_str) else {
        return Ok(obj.clone());
    };
    if enc != "aes-256-gcm" {
        return Ok(obj.clone());
    }
    let Some(key) = key.filter(|value| value.len() == 32) else {
        return Err(Error::Config("stored record is encrypted and IDEMPOTENCY_RECORD_KEY is missing".into()));
    };
    let nonce = STANDARD
        .decode(obj.get("nonce").and_then(Value::as_str).unwrap_or(""))
        .map_err(|_| Error::Config("encrypted record nonce is invalid".into()))?;
    let ciphertext = STANDARD
        .decode(obj.get("ct").and_then(Value::as_str).unwrap_or(""))
        .map_err(|_| Error::Config("encrypted record is invalid".into()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Config("record key must be 32 bytes".into()))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: token.as_bytes(),
            },
        )
        .map_err(|_| Error::Config("decryption failed".into()))?;
    let text = String::from_utf8(plain).map_err(|_| Error::Config("encrypted record is not utf-8".into()))?;
    let value: Value = serde_json::from_str(&text).map_err(|_| Error::Config("encrypted record is not json".into()))?;
    if !value.is_object() {
        return Err(Error::Config("encrypted record is not an object".into()));
    }
    Ok(value)
}

pub fn redact(value: &Value) -> Value {
    use regex::Regex;
    use std::sync::OnceLock;
    static SECRET: OnceLock<Regex> = OnceLock::new();
    let secret = SECRET.get_or_init(|| {
        Regex::new("(?i)password|secret|token|authorization|api[_-]?key|credential|set-cookie").unwrap()
    });
    match value {
        Value::Object(map) => {
            let mut cleaned = Map::new();
            for (key, item) in map {
                if secret.is_match(key) {
                    cleaned.insert(key.clone(), Value::String("***".into()));
                } else {
                    cleaned.insert(key.clone(), redact(item));
                }
            }
            Value::Object(cleaned)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        other => other.clone(),
    }
}
