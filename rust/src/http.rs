use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

use crate::canonical::{canonical_dumps, http_document, json_map};
use crate::client::Client;
use crate::error::Error;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: i64,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn contract(&self) -> Value {
        let mut kept = Vec::new();
        for (name, value) in &self.headers {
            let lowered = name.to_ascii_lowercase();
            if matches!(lowered.as_str(), "authorization" | "cookie" | "date" | "proxy-authorization" | "set-cookie") {
                continue;
            }
            kept.push(Value::Array(vec![Value::String(lowered), Value::String(value.clone())]));
        }
        kept.sort_by(|left, right| left[0].as_str().cmp(&right[0].as_str()));
        json_map(vec![
            ("body_base64", Value::String(STANDARD.encode(&self.body))),
            ("headers", Value::Array(kept)),
            ("kind", Value::String("http_response".into())),
            ("status", Value::Number(self.status.into())),
        ])
    }

    pub fn from_contract(body: &Value) -> Result<Self, Error> {
        let status = body.get("status").and_then(Value::as_i64).unwrap_or(0);
        let headers = body
            .get("headers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| {
                let pair = item.as_array()?;
                Some((pair.first()?.as_str()?.to_string(), pair.get(1)?.as_str()?.to_string()))
            })
            .collect();
        let raw = body.get("body_base64").and_then(Value::as_str).unwrap_or("");
        let bytes = STANDARD.decode(raw).map_err(|_| Error::Nonserializable("http body is not base64".into()))?;
        Ok(Self { status, headers, body: bytes })
    }
}

pub enum TransportError {
    Failure { reason: String, bytes_written: Option<usize> },
    Other(String),
}

pub trait HttpTransport {
    fn send(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse, TransportError>;
}

pub fn request(
    client: &Client,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    transport: &dyn HttpTransport,
) -> Result<HttpResponse, Error> {
    let document = http_document(method, url, headers, body)?;
    let canonical_url = document.get("url").and_then(Value::as_str).unwrap_or(url).to_string();
    let stored = client.once(&document, || {
        match transport.send(method, &canonical_url, headers, body) {
            Ok(response) => {
                let contract = response.contract();
                canonical_dumps(&contract)?;
                Ok(contract)
            }
            Err(TransportError::Failure { reason, bytes_written: Some(0) }) => Err(Error::NotApplied(reason)),
            Err(TransportError::Failure { .. }) | Err(TransportError::Other(_)) => {
                Err(Error::Uncertain("uncertain_http_outcome".into()))
            }
        }
    })?;
    HttpResponse::from_contract(&stored)
}
