use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use agent_idempotency::audit::call_unprotected;
use agent_idempotency::canonical::{canonical_dumps, operation_id, token_for};
use agent_idempotency::client::Client;
use agent_idempotency::db::{execute, DbSession, DbTarget, Statement, StatementResult};
use agent_idempotency::error::Error;
use agent_idempotency::http::{request, HttpResponse, HttpTransport, TransportError};
use agent_idempotency::scope::StaticScope;
use agent_idempotency::store::{MemoryStore, Store};
use serde_json::{json, Value};

fn scope() -> StaticScope {
    StaticScope { scope_id: "11".repeat(32) }
}

fn doc() -> Value {
    json!({"kind": "op", "name": "ping"})
}

fn value(payload: &str) -> Value {
    json!({"kind": "value", "value": payload})
}

fn client(store: MemoryStore) -> Client {
    Client::new(Box::new(store), Box::new(scope()))
}

#[test]
fn second_call_replays() {
    let calls = Arc::new(Mutex::new(0));
    let seen = calls.clone();
    let wrapper = client(MemoryStore::new());
    let run = || {
        *seen.lock().unwrap() += 1;
        Ok(value("one"))
    };
    assert_eq!(wrapper.once(&doc(), run).unwrap(), value("one"));
    assert_eq!(wrapper.once(&doc(), run).unwrap(), value("one"));
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn overlapping_callers_dispatch_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut wrapper = client(MemoryStore::new());
    wrapper.wait_ms = 2000;
    wrapper.poll_ms = 10;
    let wrapper = Arc::new(wrapper);
    let calls = Arc::new(Mutex::new(0));
    let started = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let wrapper = wrapper.clone();
        let calls = calls.clone();
        let started = started.clone();
        let release = release.clone();
        handles.push(thread::spawn(move || {
            wrapper.once(&doc(), || {
                *calls.lock().unwrap() += 1;
                started.store(true, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(value("shared"))
            })
        }));
    }
    while !started.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(30));
    release.store(true, Ordering::SeqCst);
    let results: Vec<_> = handles.into_iter().map(|handle| handle.join().unwrap().unwrap()).collect();
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(results, vec![value("shared"), value("shared")]);
}

struct SharedMemory(Arc<MemoryStore>);

impl Store for SharedMemory {
    fn call(&self, request: agent_idempotency::store::StoreRequest<'_>) -> Result<agent_idempotency::store::StoreResponse, Error> {
        self.0.call(request)
    }
    fn peek(&self, token: &str) -> Result<Option<agent_idempotency::store::Record>, Error> {
        self.0.peek(token)
    }
}

#[test]
fn lock_expiry_and_retention() {
    let store = Arc::new(MemoryStore::new());
    store.set_now(1_000_000);
    let mut wrapper = Client::new(Box::new(SharedMemory(store.clone())), Box::new(scope()));
    wrapper.lock_ttl_ms = 1000;
    wrapper.record_ttl_seconds = 3600;
    let calls = Arc::new(Mutex::new(0));
    let seen = calls.clone();
    let clock = store.clone();
    let error = wrapper
        .once(&doc(), || {
            *seen.lock().unwrap() += 1;
            clock.set_now(1_001_000);
            Ok(value("late"))
        })
        .unwrap_err();
    assert_eq!(error.code(), "blocked");
    let retry = wrapper.once(&doc(), || {
        *calls.lock().unwrap() += 1;
        Ok(value("late"))
    });
    assert_eq!(retry.unwrap_err().code(), "blocked");
    assert_eq!(*calls.lock().unwrap(), 1);

    store.set_now(0);
    wrapper.record_ttl_seconds = 10;
    let fresh = json!({"kind": "op", "name": "fresh"});
    wrapper.once(&fresh, || Ok(value("done"))).unwrap();
    store.set_now(10_000);
    let mut ran = false;
    wrapper
        .once(&fresh, || {
            ran = true;
            Ok(value("again"))
        })
        .unwrap();
    assert!(ran);
}

#[test]
fn failure_before_dispatch_clears_the_key() {
    let store = Arc::new(MemoryStore::new());
    let mut wrapper = Client::new(Box::new(SharedMemory(store.clone())), Box::new(scope()));
    wrapper.record_key = Some(b"short".to_vec());
    let error = wrapper.once(&doc(), || Ok(value("x"))).unwrap_err();
    assert_eq!(error.code(), "config");
    let token = token_for(&scope().scope_id, &operation_id(&doc()).unwrap());
    assert!(store.peek(&token).unwrap().is_none());
    wrapper.record_key = None;
    assert_eq!(wrapper.once(&doc(), || Ok(value("ok"))).unwrap(), value("ok"));
}

#[test]
fn missing_scope_and_tls_do_not_dispatch() {
    struct Missing;
    impl agent_idempotency::scope::ScopeSource for Missing {
        fn current(&self) -> Result<agent_idempotency::scope::Scope, Error> {
            Err(Error::MissingScope("absent".into()))
        }
    }
    let wrapper = Client::new(Box::new(MemoryStore::new()), Box::new(Missing));
    assert_eq!(wrapper.once(&doc(), || Ok(value("x"))).unwrap_err().code(), "missing_scope");
    let mut tls = Client::new(Box::new(MemoryStore::new()), Box::new(scope()));
    tls.require_tls = true;
    tls.redis_url = "redis://127.0.0.1/0".into();
    assert_eq!(tls.once(&doc(), || Ok(value("x"))).unwrap_err().code(), "config");
}

#[test]
fn oversized_can_be_resolved() {
    let mut wrapper = client(MemoryStore::new());
    wrapper.max_result_bytes = 64;
    let error = wrapper.once(&doc(), || Ok(value(&"x".repeat(80)))).unwrap_err();
    assert_eq!(error.code(), "oversized_result");
    assert_eq!(wrapper.once(&doc(), || Ok(value("no"))).unwrap_err().code(), "blocked");
    let summary = value("summary");
    wrapper.resolve_blocked(&doc(), "complete", "stored elsewhere", Some(&summary)).unwrap();
    assert_eq!(wrapper.once(&doc(), || Ok(value("no"))).unwrap(), summary);
}

#[test]
fn http_replay_and_uncertain_timeout() {
    struct Scripted {
        calls: Mutex<Vec<String>>,
    }
    impl HttpTransport for Scripted {
        fn send(&self, method: &str, url: &str, _headers: &[(&str, &str)], _body: &[u8]) -> Result<HttpResponse, TransportError> {
            self.calls.lock().unwrap().push(format!("{method} {url}"));
            if url.ends_with("/other") {
                return Err(TransportError::Failure { reason: "timeout".into(), bytes_written: None });
            }
            Ok(HttpResponse { status: 201, headers: vec![("Set-Cookie".into(), "hide".into())], body: b"{\"ok\":true}".to_vec() })
        }
    }
    let transport = Scripted { calls: Mutex::new(Vec::new()) };
    let wrapper = client(MemoryStore::new());
    let first = request(&wrapper, "post", "https://example.com/items", &[("Authorization", "secret")], b"{}", &transport).unwrap();
    let second = request(&wrapper, "POST", "https://example.com/items", &[("Authorization", "other")], b"{}", &transport).unwrap();
    assert_eq!(first.status, 201);
    assert_eq!(second.body, first.body);
    let timeout = request(&wrapper, "POST", "https://example.com/other", &[], b"{}", &transport).unwrap_err();
    assert_eq!(timeout.code(), "blocked");
    assert!(matches!(timeout, Error::Blocked { ref reason } if reason == "uncertain_http_outcome"));
    let _ = request(&wrapper, "POST", "https://example.com/other", &[], b"{}", &transport);
    assert_eq!(transport.calls.lock().unwrap().iter().filter(|item| item.contains("/other")).count(), 1);
}

#[test]
fn database_rollback_is_not_a_successful_replay() {
    struct Fake {
        committed: bool,
        calls: Vec<String>,
        fail_second: bool,
    }
    impl DbSession for Fake {
        fn in_transaction(&self) -> bool {
            false
        }
        fn begin(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn execute(&mut self, sql: &str, _params: &[Value]) -> Result<StatementResult, String> {
            self.calls.push(sql.into());
            if self.fail_second && self.calls.len() == 2 {
                return Err("unique".into());
            }
            Ok(StatementResult { rows_affected: 1, rows: vec![] })
        }
        fn commit(&mut self) -> Result<(), String> {
            self.committed = true;
            Ok(())
        }
        fn rollback(&mut self) -> Result<(), String> {
            self.committed = false;
            Ok(())
        }
    }
    let wrapper = client(MemoryStore::new());
    let target = DbTarget { driver: "sqlite".into(), host: String::new(), port: 0, database: "app".into(), user: "agent".into() };
    let mut session = Fake { committed: false, calls: Vec::new(), fail_second: false };
    let stored = execute(
        &wrapper,
        &target,
        &[Statement { sql: "insert into t values (?)".into(), params: vec![json!(1)] }],
        &mut session,
        "deferred",
    )
    .unwrap();
    assert_eq!(stored["committed"], json!(true));
    let again = execute(
        &wrapper,
        &target,
        &[Statement { sql: "insert into t values (?)".into(), params: vec![json!(1)] }],
        &mut session,
        "deferred",
    )
    .unwrap();
    assert_eq!(again, stored);
    assert_eq!(session.calls.len(), 1);

    session.fail_second = true;
    session.calls.clear();
    let failing = [
        Statement { sql: "insert into t values (?)".into(), params: vec![json!(2)] },
        Statement { sql: "insert into t values (?)".into(), params: vec![json!(2)] },
    ];
    let error = execute(&wrapper, &target, &failing, &mut session, "deferred").unwrap_err();
    assert_eq!(error.code(), "rolled_back");
    assert!(!session.committed);
    let replay = execute(&wrapper, &target, &failing, &mut session, "deferred").unwrap_err();
    assert_eq!(replay.code(), "rolled_back");
    assert_eq!(session.calls.len(), 2);
}

#[test]
fn bypass_is_visible_and_repeats() {
    let root = std::env::temp_dir().join(format!("idempotency-bypass-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let calls = Mutex::new(0);
    call_unprotected(&root, "raw", "", || *calls.lock().unwrap() += 1);
    call_unprotected(&root, "raw", "", || *calls.lock().unwrap() += 1);
    let log = std::fs::read_to_string(root.join(".idempotency/bypasses.jsonl")).unwrap();
    assert_eq!(*calls.lock().unwrap(), 2);
    assert_eq!(log.lines().count(), 2);
    assert!(log.contains("\"protected\":false"));
    let _ = canonical_dumps(&json!({"kind": "value", "value": "ok"}));
}

#[test]
fn stale_owner_cannot_complete_a_newer_record() {
    let store = MemoryStore::new();
    store.set_now(0);
    let body = canonical_dumps(&json!({"operation_id": "op", "scope_id": "sc"})).unwrap();
    let first = store
        .call(agent_idempotency::store::StoreRequest {
            op: "claim",
            token: "tok",
            owner: "owner-a",
            fence: 0,
            lock_ttl_ms: 1000,
            record_ttl_seconds: 100,
            max_bytes: 10000,
            body: &body,
        })
        .unwrap();
    store.set_now(5000);
    assert_eq!(
        store
            .call(agent_idempotency::store::StoreRequest {
                op: "read",
                token: "tok",
                owner: "",
                fence: 0,
                lock_ttl_ms: 1000,
                record_ttl_seconds: 100,
                max_bytes: 10000,
                body: "",
            })
            .unwrap()
            .status,
        "blocked"
    );
    let release = canonical_dumps(&json!({"decision":"release","evidence":"remote call was absent","result_json":"","scope_id":"sc"})).unwrap();
    assert_eq!(
        store
            .call(agent_idempotency::store::StoreRequest {
                op: "resolve",
                token: "tok",
                owner: "",
                fence: 0,
                lock_ttl_ms: 1000,
                record_ttl_seconds: 100,
                max_bytes: 10000,
                body: &release,
            })
            .unwrap()
            .status,
        "released"
    );
    store
        .call(agent_idempotency::store::StoreRequest {
            op: "claim",
            token: "tok",
            owner: "owner-b",
            fence: 0,
            lock_ttl_ms: 1000,
            record_ttl_seconds: 100,
            max_bytes: 10000,
            body: &body,
        })
        .unwrap();
    let stale = store
        .call(agent_idempotency::store::StoreRequest {
            op: "complete",
            token: "tok",
            owner: "owner-a",
            fence: first.record.unwrap().fence,
            lock_ttl_ms: 1000,
            record_ttl_seconds: 100,
            max_bytes: 10000,
            body: &canonical_dumps(&json!({"body": {"kind": "value", "value": "stolen"}, "outcome": "success"})).unwrap(),
        })
        .unwrap();
    assert_eq!(stale.status, "stale_owner");
    assert_eq!(store.peek("tok").unwrap().unwrap().owner, "owner-b");
}

#[test]
fn waiter_does_not_dispatch_when_the_record_disappears() {
    struct Scripted;
    impl Store for Scripted {
        fn call(&self, request: agent_idempotency::store::StoreRequest<'_>) -> Result<agent_idempotency::store::StoreResponse, Error> {
            let status = if request.op == "claim" { "in_progress" } else { "empty" };
            Ok(agent_idempotency::store::StoreResponse { status: status.into(), record: None })
        }
        fn peek(&self, _token: &str) -> Result<Option<agent_idempotency::store::Record>, Error> {
            Ok(None)
        }
    }
    let mut wrapper = Client::new(Box::new(Scripted), Box::new(scope()));
    wrapper.wait_ms = 20;
    wrapper.poll_ms = 5;
    assert_eq!(wrapper.once(&doc(), || Ok(value("x"))).unwrap_err().code(), "in_progress_cleared");
    thread::sleep(Duration::from_millis(1));
}
