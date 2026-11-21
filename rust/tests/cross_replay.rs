use agent_idempotency::client::Client;
use agent_idempotency::scope::StaticScope;
use agent_idempotency::store::RedisStore;
use serde_json::json;

#[test]
fn python_record_replays_and_rust_writes_one() {
    let Ok(url) = std::env::var("IDEMPOTENCY_TEST_REDIS_URL") else {
        return;
    };
    let mut client = Client::new(
        Box::new(RedisStore::open(&url).unwrap()),
        Box::new(StaticScope { scope_id: "33".repeat(32) }),
    );
    client.record_ttl_seconds = 120;
    let mut called = false;
    let replayed = client
        .once(&json!({"kind": "op", "name": "from-python"}), || {
            called = true;
            Ok(json!({"kind": "value", "value": "should-not-run"}))
        })
        .unwrap();
    assert!(!called, "rust dispatched a call python had already completed");
    assert_eq!(replayed["value"], "from-python");

    let stored = client
        .once(&json!({"kind": "op", "name": "from-rust"}), || {
            Ok(json!({"kind": "value", "value": "from-rust"}))
        })
        .unwrap();
    assert_eq!(stored["value"], "from-rust");
    let mut called_again = false;
    let replay = client
        .once(&json!({"kind": "op", "name": "from-rust"}), || {
            called_again = true;
            Ok(json!({"kind": "value", "value": "no"}))
        })
        .unwrap();
    assert!(!called_again);
    assert_eq!(replay["value"], "from-rust");
}
