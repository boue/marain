use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::canonical::canonical_dumps;

pub fn call_unprotected<T>(root: &Path, name: &str, detail: &str, run: impl FnOnce() -> T) -> T {
    let directory = root.join(".idempotency");
    let _ = fs::create_dir_all(&directory);
    let record = json!({
        "agent_id": std::env::var("IDEMPOTENCY_AGENT_ID").unwrap_or_default(),
        "detail": detail,
        "name": name,
        "protected": false,
    });
    if let Ok(line) = canonical_dumps(&record) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(directory.join("bypasses.jsonl")) {
            let _ = writeln!(file, "{line}");
        }
    }
    run()
}

pub fn claims_log(root: Option<&Path>) -> String {
    let base = root.map(|r| r.to_path_buf()).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });
    base.join(".idempotency").join("claims.jsonl").to_string_lossy().into_owned()
}

pub fn write_claim(
    root: &Path,
    agent_id: &str,
    scope_id: &str,
    operation_id: &str,
    outcome: &str,
    repo_wide: bool,
) {
    let directory = root.join(".idempotency");
    let _ = fs::create_dir_all(&directory);
    let record = json!({
        "v": 1,
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "agent_id": agent_id,
        "scope_id": scope_id,
        "operation_id": operation_id,
        "outcome": outcome,
        "repo_wide": repo_wide,
    });
    if let Ok(line) = canonical_dumps(&record) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(directory.join("claims.jsonl")) {
            let _ = writeln!(file, "{line}");
        }
    }
}
