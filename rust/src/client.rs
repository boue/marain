use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use uuid::Uuid;

use crate::audit::write_claim;
use crate::canonical::{canonical_dumps, error_envelope, operation_id, resource_key, success_envelope, token_for, token_for_repo};
use crate::crypto::{decrypt, encrypt, parse_record_key, redact};
use crate::error::Error;
use crate::scope::{GitScope, ScopeSource};
use crate::store::{RedisStore, Store, StoreRequest};

const CONTRACT_KINDS: &[&str] = &["value", "http_response", "db_result"];

pub struct Client {
    store: Box<dyn Store>,
    scope: Box<dyn ScopeSource>,
    pub record_ttl_seconds: i64,
    pub lock_ttl_ms: i64,
    pub wait_ms: u64,
    pub poll_ms: u64,
    pub max_result_bytes: usize,
    pub record_key: Option<Vec<u8>>,
    pub require_tls: bool,
    pub redis_url: String,
}

impl Client {
    pub fn new(store: Box<dyn Store>, scope: Box<dyn ScopeSource>) -> Self {
        Self {
            store,
            scope,
            record_ttl_seconds: 86_400,
            lock_ttl_ms: 120_000,
            wait_ms: 120_000,
            poll_ms: 100,
            max_result_bytes: 65_536,
            record_key: None,
            require_tls: false,
            redis_url: String::new(),
        }
    }

    pub fn from_env() -> Result<Self, Error> {
        let url = std::env::var("IDEMPOTENCY_REDIS_URL").unwrap_or_default();
        if url.is_empty() {
            return Err(Error::Config("IDEMPOTENCY_REDIS_URL is required".into()));
        }
        let require_tls = std::env::var("IDEMPOTENCY_REQUIRE_TLS").ok().as_deref() == Some("1");
        if require_tls && !url.starts_with("rediss://") {
            return Err(Error::Config("IDEMPOTENCY_REQUIRE_TLS refuses a non-rediss URL".into()));
        }
        let mut client = Self::new(Box::new(RedisStore::open(&url)?), Box::new(GitScope::from_env()?));
        client.record_ttl_seconds = env_i64("IDEMPOTENCY_RECORD_TTL_SECONDS", 86_400);
        client.lock_ttl_ms = env_i64("IDEMPOTENCY_LOCK_TTL_MS", 120_000);
        client.wait_ms = env_i64("IDEMPOTENCY_WAIT_MS", 120_000) as u64;
        client.poll_ms = env_i64("IDEMPOTENCY_POLL_MS", 100) as u64;
        client.max_result_bytes = env_i64("IDEMPOTENCY_MAX_RESULT_BYTES", 65_536) as usize;
        client.record_key = parse_record_key(std::env::var("IDEMPOTENCY_RECORD_KEY").ok().as_deref())?;
        client.require_tls = require_tls;
        client.redis_url = url;
        Ok(client)
    }

    pub fn once<F>(&self, document: &Value, run: F) -> Result<Value, Error>
    where
        F: FnOnce() -> Result<Value, Error>,
    {
        let scope = self.scope.current()?;
        self.guard_config()?;
        let op_id = operation_id(document)?;
        let repo_wide = document.get("repo_wide").and_then(Value::as_bool).unwrap_or(false);
        let token = if repo_wide {
            let repo_id = scope.repo_id.as_str();
            if repo_id.is_empty() {
                return Err(Error::Canonical("repo_wide requires repo_id in scope".into()));
            }
            token_for_repo(repo_id, &op_id)
        } else {
            token_for(&scope.scope_id, &op_id)
        };
        let owner = Uuid::new_v4().simple().to_string();
        let claim_body = canonical_dumps(&serde_json::json!({
            "operation_id": op_id,
            "scope_id": scope.scope_id,
        }))?;
        let claimed = self.store_call("claim", &token, &owner, 0, &claim_body)?;
        if claimed.status == "corrupt" {
            return Err(Error::RedisUnavailable("idempotency record is corrupt".into()));
        }
        if claimed.status != "claimed" {
            write_claim(
                std::path::Path::new("."),
                &scope.agent_id,
                &scope.scope_id,
                &op_id,
                "replayed",
                repo_wide,
            );
            return self.follow_existing(&token, &claimed);
        }
        let record = claimed.record.ok_or_else(|| Error::RedisUnavailable("claim did not return a record".into()))?;
        write_claim(
            std::path::Path::new("."),
            &scope.agent_id,
            &scope.scope_id,
            &op_id,
            "sent",
            repo_wide,
        );
        self.owned(&token, &record.owner, record.fence, document, run)
    }

    pub fn resolve_blocked(
        &self,
        document: &Value,
        decision: &str,
        evidence: &str,
        result: Option<&Value>,
    ) -> Result<Option<Value>, Error> {
        let cleaned = evidence.trim();
        if decision != "release" && decision != "complete" {
            return Err(Error::Canonical("resolve decision must be release or complete".into()));
        }
        if cleaned.is_empty() {
            return Err(Error::Canonical("evidence is required".into()));
        }
        let scope = self.scope.current()?;
        self.guard_config()?;
        let op_id = operation_id(document)?;
        let token = token_for(&scope.scope_id, &op_id);
        let mut result_json = String::new();
        if decision == "complete" {
            let body = result.cloned().ok_or_else(|| Error::Nonserializable("result is outside the serialization contract".into()))?;
            let contract = contract_value(body)?;
            let envelope = success_envelope(contract);
            self.check_size(&envelope)?;
            result_json = canonical_dumps(&encrypt(self.record_key.as_deref(), &token, &envelope)?)?;
        }
        let body = canonical_dumps(&serde_json::json!({
            "decision": decision,
            "evidence": cleaned,
            "result_json": result_json,
            "scope_id": scope.scope_id,
        }))?;
        let done = self.store_call("resolve", &token, "", 0, &body)?;
        if decision == "release" {
            if done.status != "released" {
                return Err(status_error(&done));
            }
            return Ok(None);
        }
        if done.status != "completed" {
            return Err(status_error(&done));
        }
        Ok(result.cloned())
    }

    fn owned<F>(&self, token: &str, owner: &str, fence: i64, document: &Value, run: F) -> Result<Value, Error>
    where
        F: FnOnce() -> Result<Value, Error>,
    {
        let snapshot = match encrypt(self.record_key.as_deref(), token, &redact(document)).and_then(|value| canonical_dumps(&value)) {
            Ok(text) => text,
            Err(error) => {
                let _ = self.store_call("abort", token, owner, fence, "");
                return Err(error);
            }
        };
        let marked = match self.store_call("mark_dispatched", token, owner, fence, &snapshot) {
            Ok(response) if response.status == "marked" => response,
            Ok(response) => {
                let _ = self.store_call("abort", token, owner, fence, "");
                return Err(status_error(&response));
            }
            Err(error) => {
                let _ = self.store_call("abort", token, owner, fence, "");
                return Err(error);
            }
        };
        let _ = marked;
        match run() {
            Ok(produced) => {
                let contract = match contract_value(produced) {
                    Ok(value) => value,
                    Err(error) => {
                        self.block(token, owner, fence, "nonserializable_result");
                        return Err(error);
                    }
                };
                let envelope = success_envelope(contract.clone());
                if let Err(error) = self.check_size(&envelope) {
                    self.block(token, owner, fence, "oversized_result");
                    return Err(error);
                }
                let stored = match encrypt(self.record_key.as_deref(), token, &envelope).and_then(|value| canonical_dumps(&value)) {
                    Ok(text) => text,
                    Err(_) => {
                        self.block(token, owner, fence, "uncertain_exception");
                        return Err(Error::Blocked { reason: "uncertain_exception".into() });
                    }
                };
                let done = match self.store_call("complete", token, owner, fence, &stored) {
                    Ok(response) => response,
                    Err(_) => return Err(Error::Blocked { reason: "uncertain_exception".into() }),
                };
                if done.status != "completed" {
                    return Err(status_error(&done));
                }
                Ok(contract)
            }
            Err(Error::NotApplied(_)) => {
                let _ = self.store_call("release_not_applied", token, owner, fence, "");
                Err(Error::NotApplied("not applied".into()))
            }
            Err(Error::ConfirmedRollback(message)) => {
                let envelope = error_envelope("rolled_back", &message);
                self.check_size(&envelope)?;
                let stored = canonical_dumps(&encrypt(self.record_key.as_deref(), token, &envelope)?)?;
                let done = self.store_call("complete", token, owner, fence, &stored)?;
                if done.status != "completed" {
                    return Err(status_error(&done));
                }
                Err(Error::Replay { code: "rolled_back".into(), message: message.chars().take(500).collect() })
            }
            Err(Error::Oversized) => {
                self.block(token, owner, fence, "oversized_result");
                Err(Error::Oversized)
            }
            Err(Error::Nonserializable(message)) => {
                self.block(token, owner, fence, "nonserializable_result");
                Err(Error::Nonserializable(message))
            }
            Err(Error::Uncertain(reason)) => {
                self.block(token, owner, fence, &reason);
                Err(Error::Blocked { reason })
            }
            Err(error @ (Error::Blocked { .. } | Error::Replay { .. } | Error::RedisUnavailable(_) | Error::StaleOwner)) => Err(error),
            Err(_) => {
                self.block(token, owner, fence, "uncertain_exception");
                Err(Error::Blocked { reason: "uncertain_exception".into() })
            }
        }
    }

    fn follow_existing(&self, token: &str, claimed: &crate::store::StoreResponse) -> Result<Value, Error> {
        match claimed.status.as_str() {
            "completed" => self.replay(token, claimed.record.as_ref()),
            "blocked" => Err(blocked(claimed.record.as_ref())),
            "in_progress" => self.wait(token),
            other => Err(Error::RedisUnavailable(format!("unexpected claim status {other}"))),
        }
    }

    fn wait(&self, token: &str) -> Result<Value, Error> {
        let deadline = Instant::now() + Duration::from_millis(self.wait_ms);
        loop {
            if let Some(value) = self.wait_step(token)? {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                if let Some(value) = self.wait_step(token)? {
                    return Ok(value);
                }
                return Err(Error::WaiterTimeout);
            }
            thread::sleep(Duration::from_millis(self.poll_ms.max(1)));
        }
    }

    fn wait_step(&self, token: &str) -> Result<Option<Value>, Error> {
        let current = self.store_call("read", token, "", 0, "")?;
        match current.status.as_str() {
            "completed" => self.replay(token, current.record.as_ref()).map(Some),
            "blocked" => Err(blocked(current.record.as_ref())),
            "empty" => Err(Error::InProgressCleared),
            "corrupt" => Err(Error::RedisUnavailable("idempotency record is corrupt".into())),
            "in_progress" => Ok(None),
            other => Err(Error::RedisUnavailable(format!("unexpected record status {other}"))),
        }
    }

    fn replay(&self, token: &str, record: Option<&crate::store::Record>) -> Result<Value, Error> {
        let Some(record) = record else {
            return Err(Error::Replay { code: "replay_undecodable".into(), message: "stored result is missing".into() });
        };
        if !record.result.is_object() {
            return Err(Error::Replay { code: "replay_undecodable".into(), message: "stored result is missing".into() });
        }
        let opened = decrypt(self.record_key.as_deref(), token, &record.result).map_err(|_| {
            Error::Replay { code: "replay_undecodable".into(), message: "stored result cannot be opened".into() }
        })?;
        match opened.get("outcome").and_then(Value::as_str) {
            Some("success") => Ok(opened.get("body").cloned().unwrap_or(Value::Null)),
            Some("error") => {
                let body = opened.get("body");
                let code = body.and_then(|item| item.get("code")).and_then(Value::as_str).unwrap_or("replay_error");
                let message = body.and_then(|item| item.get("message")).and_then(Value::as_str).unwrap_or("");
                Err(Error::Replay { code: code.into(), message: message.into() })
            }
            _ => Err(Error::Replay { code: "replay_undecodable".into(), message: "stored result is not an envelope".into() }),
        }
    }

    fn block(&self, token: &str, owner: &str, fence: i64, reason: &str) {
        let Ok(body) = canonical_dumps(&serde_json::json!({ "reason": reason })) else {
            return;
        };
        let _ = self.store_call("block", token, owner, fence, &body);
    }

    fn store_call(&self, op: &str, token: &str, owner: &str, fence: i64, body: &str) -> Result<crate::store::StoreResponse, Error> {
        self.store.call(StoreRequest {
            op,
            token,
            owner,
            fence,
            lock_ttl_ms: self.lock_ttl_ms,
            record_ttl_seconds: self.record_ttl_seconds,
            max_bytes: (self.max_result_bytes * 2 + 4096) as i64,
            body,
        })
    }

    fn guard_config(&self) -> Result<(), Error> {
        if self.require_tls && !self.redis_url.starts_with("rediss://") {
            return Err(Error::Config("IDEMPOTENCY_REQUIRE_TLS refuses a non-rediss URL".into()));
        }
        Ok(())
    }

    fn check_size(&self, envelope: &Value) -> Result<(), Error> {
        if canonical_dumps(envelope)?.len() > self.max_result_bytes {
            return Err(Error::Oversized);
        }
        Ok(())
    }
}

pub fn contract_value(value: Value) -> Result<Value, Error> {
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
    if !CONTRACT_KINDS.contains(&kind) {
        return Err(Error::Nonserializable("result is outside the serialization contract".into()));
    }
    canonical_dumps(&value).map_err(|error| Error::Nonserializable(error.to_string()))?;
    Ok(value)
}

fn blocked(record: Option<&crate::store::Record>) -> Error {
    let reason = record.and_then(|item| item.reason.clone()).unwrap_or_else(|| "blocked".into());
    Error::Blocked { reason }
}

fn status_error(response: &crate::store::StoreResponse) -> Error {
    if response.status == "blocked" {
        return blocked(response.record.as_ref());
    }
    if response.status == "stale_owner" {
        return Error::StaleOwner;
    }
    if let Some(reason) = response.record.as_ref().and_then(|record| record.reason.clone()) {
        return Error::Blocked { reason };
    }
    Error::RedisUnavailable(format!("idempotency transition was {}", response.status))
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}
