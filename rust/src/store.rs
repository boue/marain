use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::error::Error;

const LUA: &str = include_str!("../../protocol/redis/record.lua");

#[derive(Clone, Debug)]
pub struct Record {
    pub state: String,
    pub dispatched: bool,
    pub scope_id: String,
    pub operation_id: String,
    pub owner: String,
    pub fence: i64,
    pub lock_expires_at_ms: Option<i64>,
    pub snapshot: Value,
    pub result: Value,
    pub reason: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StoreResponse {
    pub status: String,
    pub record: Option<Record>,
}

pub struct StoreRequest<'a> {
    pub op: &'a str,
    pub token: &'a str,
    pub owner: &'a str,
    pub fence: i64,
    pub lock_ttl_ms: i64,
    pub record_ttl_seconds: i64,
    pub max_bytes: i64,
    pub body: &'a str,
}

pub trait Store: Send + Sync {
    fn call(&self, request: StoreRequest<'_>) -> Result<StoreResponse, Error>;
    fn peek(&self, token: &str) -> Result<Option<Record>, Error>;
}

struct Slot {
    record: Record,
    expires_at: i64,
}

struct Fence {
    value: i64,
    expires_at: i64,
}

pub struct MemoryStore {
    inner: Mutex<MemoryInner>,
}

struct MemoryInner {
    now_ms: Option<i64>,
    keys: HashMap<String, Slot>,
    fences: HashMap<String, Fence>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MemoryInner {
                now_ms: None,
                keys: HashMap::new(),
                fences: HashMap::new(),
            }),
        }
    }

    pub fn set_now(&self, now_ms: i64) {
        self.inner.lock().expect("memory store").now_ms = Some(now_ms);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for MemoryStore {
    fn call(&self, request: StoreRequest<'_>) -> Result<StoreResponse, Error> {
        let mut inner = self.inner.lock().expect("memory store");
        Ok(inner.call(request))
    }

    fn peek(&self, token: &str) -> Result<Option<Record>, Error> {
        let mut inner = self.inner.lock().expect("memory store");
        let now = inner.clock();
        Ok(inner.live(token, now).cloned())
    }
}

impl MemoryInner {
    fn call(&mut self, request: StoreRequest<'_>) -> StoreResponse {
        let now = self.clock();
        let rec = self.live(request.token, now).cloned();
        if request.op == "claim" {
            if rec.is_none() {
                let Ok(payload) = decode_object(request.body) else {
                    return StoreResponse { status: "rejected".into(), record: None };
                };
                let fence = self.next_fence(request.token, now, request.record_ttl_seconds);
                let record = Record {
                    state: "in_progress".into(),
                    dispatched: false,
                    scope_id: payload.get("scope_id").and_then(Value::as_str).unwrap_or("").into(),
                    operation_id: payload.get("operation_id").and_then(Value::as_str).unwrap_or("").into(),
                    owner: request.owner.into(),
                    fence,
                    lock_expires_at_ms: Some(now + request.lock_ttl_ms),
                    snapshot: Value::Null,
                    result: Value::Null,
                    reason: None,
                    evidence: None,
                };
                self.keys.insert(
                    request.token.into(),
                    Slot {
                        record: record.clone(),
                        expires_at: now + request.record_ttl_seconds * 1000,
                    },
                );
                return StoreResponse { status: "claimed".into(), record: Some(record) };
            }
            let record = rec.unwrap();
            let status = public_state(&record);
            return StoreResponse { status, record: Some(record) };
        }
        let Some(mut record) = rec else {
            return StoreResponse { status: "empty".into(), record: None };
        };
        if request.op == "read" {
            let status = public_state(&record);
            return StoreResponse { status, record: Some(record) };
        }
        if request.op == "resolve" {
            return self.resolve(request.token, &mut record, request.max_bytes, request.body);
        }
        if !same_owner(&record, request.owner, request.fence) {
            return StoreResponse { status: "stale_owner".into(), record: Some(record) };
        }
        if record.state == "blocked" {
            return StoreResponse { status: "blocked".into(), record: Some(record) };
        }
        if record.state != "in_progress" {
            return StoreResponse { status: "rejected".into(), record: Some(record) };
        }
        let status = match request.op {
            "mark_dispatched" => {
                if record.dispatched {
                    "rejected"
                } else if request.body.is_empty() {
                    record.dispatched = true;
                    "marked"
                } else if let Ok(payload) = decode_object(request.body) {
                    record.snapshot = payload;
                    record.dispatched = true;
                    "marked"
                } else {
                    "rejected"
                }
            }
            "abort" => {
                if record.dispatched {
                    "rejected"
                } else {
                    self.keys.remove(request.token);
                    return StoreResponse { status: "aborted".into(), record: None };
                }
            }
            "release_not_applied" => {
                if !record.dispatched {
                    "rejected"
                } else {
                    self.keys.remove(request.token);
                    return StoreResponse { status: "released".into(), record: None };
                }
            }
            "block" => match decode_object(request.body) {
                Ok(payload) => match payload.get("reason").and_then(Value::as_str) {
                    Some(reason) => {
                        record.state = "blocked".into();
                        record.reason = Some(reason.into());
                        record.lock_expires_at_ms = None;
                        record.result = Value::Null;
                        "blocked"
                    }
                    None => "rejected",
                },
                Err(_) => "rejected",
            },
            "complete" => {
                if !record.dispatched {
                    "rejected"
                } else if request.body.len() as i64 > request.max_bytes {
                    record.state = "blocked".into();
                    record.reason = Some("oversized_result".into());
                    record.lock_expires_at_ms = None;
                    record.result = Value::Null;
                    "blocked"
                } else if let Ok(payload) = decode_object(request.body) {
                    record.state = "completed".into();
                    record.reason = None;
                    record.lock_expires_at_ms = None;
                    record.result = payload;
                    "completed"
                } else {
                    "rejected"
                }
            }
            _ => "rejected",
        };
        if let Some(slot) = self.keys.get_mut(request.token) {
            slot.record = record.clone();
        }
        StoreResponse { status: status.into(), record: Some(record) }
    }

    fn resolve(&mut self, token: &str, record: &mut Record, max_bytes: i64, body: &str) -> StoreResponse {
        if record.state != "blocked" {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        }
        let Ok(payload) = decode_object(body) else {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        };
        let evidence = payload.get("evidence").and_then(Value::as_str).unwrap_or("");
        let scope_id = payload.get("scope_id").and_then(Value::as_str).unwrap_or("");
        if scope_id != record.scope_id || evidence.is_empty() {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        }
        if payload.get("decision").and_then(Value::as_str) == Some("release") {
            self.keys.remove(token);
            return StoreResponse { status: "released".into(), record: None };
        }
        let Some(result_json) = payload.get("result_json").and_then(Value::as_str) else {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        };
        if payload.get("decision").and_then(Value::as_str) != Some("complete") || result_json.len() as i64 > max_bytes {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        }
        let Ok(result) = serde_json::from_str::<Value>(result_json) else {
            return StoreResponse { status: "rejected".into(), record: Some(record.clone()) };
        };
        record.state = "completed".into();
        record.reason = None;
        record.result = result;
        record.evidence = Some(evidence.into());
        if let Some(slot) = self.keys.get_mut(token) {
            slot.record = record.clone();
        }
        StoreResponse { status: "completed".into(), record: Some(record.clone()) }
    }

    fn live(&mut self, token: &str, now: i64) -> Option<&Record> {
        let expired = self.keys.get(token).map(|slot| now >= slot.expires_at).unwrap_or(false);
        if expired {
            self.keys.remove(token);
            return None;
        }
        let slot = self.keys.get_mut(token)?;
        if slot.record.state == "in_progress" {
            if let Some(lock_at) = slot.record.lock_expires_at_ms {
                if lock_at <= now {
                    slot.record.state = "blocked".into();
                    slot.record.reason = Some("lock_expired".into());
                    slot.record.lock_expires_at_ms = None;
                }
            }
        }
        Some(&slot.record)
    }

    fn next_fence(&mut self, token: &str, now: i64, ttl_seconds: i64) -> i64 {
        let value = match self.fences.get(token) {
            Some(fence) if now < fence.expires_at => fence.value + 1,
            _ => 1,
        };
        self.fences.insert(
            token.into(),
            Fence {
                value,
                expires_at: now + ttl_seconds * 1000,
            },
        );
        value
    }

    fn clock(&self) -> i64 {
        if let Some(now) = self.now_ms {
            return now;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }
}

pub struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    pub fn open(url: &str) -> Result<Self, Error> {
        let client = redis::Client::open(url).map_err(|error| Error::RedisUnavailable(error.to_string()))?;
        Ok(Self { client })
    }
}

impl Store for RedisStore {
    fn call(&self, request: StoreRequest<'_>) -> Result<StoreResponse, Error> {
        let mut connection = self
            .client
            .get_connection_with_timeout(std::time::Duration::from_millis(400))
            .map_err(|error| Error::RedisUnavailable(error.to_string()))?;
        let raw: String = redis::cmd("EVAL")
            .arg(LUA)
            .arg(2)
            .arg(format!("idempotency:v1:{}", request.token))
            .arg(format!("idempotency:v1:fence:{}", request.token))
            .arg(request.op)
            .arg(request.owner)
            .arg(request.fence.to_string())
            .arg(request.lock_ttl_ms.to_string())
            .arg(request.record_ttl_seconds.to_string())
            .arg(request.max_bytes.to_string())
            .arg(request.body)
            .query(&mut connection)
            .map_err(|error| Error::RedisUnavailable(error.to_string()))?;
        parse_response(&raw)
    }

    fn peek(&self, token: &str) -> Result<Option<Record>, Error> {
        let mut connection = self
            .client
            .get_connection_with_timeout(std::time::Duration::from_millis(400))
            .map_err(|error| Error::RedisUnavailable(error.to_string()))?;
        let raw: Option<String> = redis::cmd("GET")
            .arg(format!("idempotency:v1:{token}"))
            .query(&mut connection)
            .map_err(|error| Error::RedisUnavailable(error.to_string()))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let value: Value = serde_json::from_str(&raw).map_err(|_| Error::RedisUnavailable("redis record is not json".into()))?;
        Ok(Some(parse_record(&value)))
    }
}

fn parse_response(raw: &str) -> Result<StoreResponse, Error> {
    let value: Value = serde_json::from_str(raw).map_err(|_| Error::RedisUnavailable("redis returned non-json".into()))?;
    let status = value.get("status").and_then(Value::as_str).unwrap_or("rejected").to_string();
    let record = value.get("record").filter(|item| !item.is_null()).map(parse_record);
    Ok(StoreResponse { status, record })
}

fn parse_record(value: &Value) -> Record {
    Record {
        state: value.get("state").and_then(Value::as_str).unwrap_or("").into(),
        dispatched: value.get("dispatched").and_then(Value::as_bool).unwrap_or(false),
        scope_id: value.get("scope_id").and_then(Value::as_str).unwrap_or("").into(),
        operation_id: value.get("operation_id").and_then(Value::as_str).unwrap_or("").into(),
        owner: value.get("owner").and_then(Value::as_str).unwrap_or("").into(),
        fence: value.get("fence").and_then(Value::as_i64).unwrap_or(0),
        lock_expires_at_ms: value.get("lock_expires_at_ms").and_then(Value::as_i64),
        snapshot: value.get("snapshot").cloned().unwrap_or(Value::Null),
        result: value.get("result").cloned().unwrap_or(Value::Null),
        reason: value.get("reason").and_then(Value::as_str).map(str::to_string),
        evidence: value.get("evidence").and_then(Value::as_str).map(str::to_string),
    }
}

fn decode_object(body: &str) -> Result<Value, ()> {
    if body.is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    let value: Value = serde_json::from_str(body).map_err(|_| ())?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(())
    }
}

fn same_owner(record: &Record, owner: &str, fence: i64) -> bool {
    record.owner == owner && record.fence == fence
}

fn public_state(record: &Record) -> String {
    if record.state == "completed" {
        "completed".into()
    } else if record.state == "blocked" {
        "blocked".into()
    } else {
        "in_progress".into()
    }
}
