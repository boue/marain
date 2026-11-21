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
