use std::fs;
use std::path::PathBuf;

use agent_idempotency::canonical::{canonical_dumps, db_document, http_document, operation_id, token_for};
use agent_idempotency::crypto::seal;
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn tokens_match_the_shared_fixtures() {
    let payload: Value = serde_json::from_str(&fs::read_to_string(root().join("protocol/fixtures/tokens.json")).unwrap()).unwrap();
    for case in payload["cases"].as_array().unwrap() {
        let document = document_from_case(case);
        let text = canonical_dumps(&document).unwrap();
        assert_eq!(text, case["canonical"].as_str().unwrap(), "{}", case["name"]);
        let op_id = operation_id(&document).unwrap();
        assert_eq!(op_id, case["operation_id"].as_str().unwrap(), "{}", case["name"]);
        assert_eq!(
            token_for(case["scope_id"].as_str().unwrap(), &op_id),
            case["token"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn aes_seal_matches_the_shared_fixture() {
    let payload: Value = serde_json::from_str(&fs::read_to_string(root().join("protocol/fixtures/aes.json")).unwrap()).unwrap();
    let sealed = seal(
        &hex::decode(payload["key_hex"].as_str().unwrap()).unwrap(),
        &hex::decode(payload["nonce_hex"].as_str().unwrap()).unwrap(),
        payload["token"].as_str().unwrap(),
        &payload["plaintext"],
    )
    .unwrap();
    assert_eq!(sealed["ct"].as_str().unwrap(), payload["ct"].as_str().unwrap());
    assert_eq!(sealed["nonce"].as_str().unwrap(), payload["nonce"].as_str().unwrap());
}

fn document_from_case(case: &Value) -> Value {
    match case["kind"].as_str().unwrap() {
        "http" => {
            let headers = case["headers"].as_object().unwrap();
            let pairs: Vec<(String, String)> = headers
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
                .collect();
            let refs: Vec<(&str, &str)> = pairs.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
            let body = case["body_utf8"].as_str().unwrap().as_bytes();
            http_document(case["method"].as_str().unwrap(), case["url"].as_str().unwrap(), &refs, body).unwrap()
        }
        "db" => db_document(&case["target"], case["statements"].as_array().unwrap(), case["isolation"].as_str().unwrap()).unwrap(),
        _ => case["document"].clone(),
    }
}
