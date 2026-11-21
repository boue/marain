use std::fs;
use std::path::Path;
use std::process::Command;

use agent_idempotency::scope::{GitScope, ScopeSource};

#[test]
fn git_scope_follows_the_shared_fingerprint() {
    let tmp = std::env::temp_dir().join(format!("idempotency-scope-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let repo = tmp.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init"]);
    git(&repo, &["config", "user.email", "t@example.com"]);
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    fs::write(repo.join("README"), "one\n").unwrap();
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-m", "init"]);

    std::env::set_var("IDEMPOTENCY_AGENT_ID", "rust-scope");
    std::env::remove_var("IDEMPOTENCY_SCOPE_FILE");
    let status = Command::new("agent-idempotency")
        .env("IDEMPOTENCY_AGENT_ID", "rust-scope")
        .env_remove("IDEMPOTENCY_SCOPE_FILE")
        .arg("establish")
        .current_dir(&repo)
        .status()
        .unwrap();
    assert!(status.success());
    let current = GitScope::open(&repo).current().unwrap();
    fs::write(repo.join("README"), "two\n").unwrap();
    let stale = GitScope::open(&repo).current().unwrap_err();
    assert_eq!(stale.code(), "stale_scope");
    assert!(!current.scope_id.is_empty());
    let _ = fs::remove_dir_all(&tmp);
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git").arg("-C").arg(repo).args(args).status().unwrap();
    assert!(status.success());
}
