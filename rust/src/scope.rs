use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;

#[derive(Clone, Debug)]
pub struct Scope {
    pub scope_id: String,
    pub agent_id: String,
}

pub trait ScopeSource: Send + Sync {
    fn current(&self) -> Result<Scope, Error>;
}

pub struct StaticScope {
    pub scope_id: String,
}

impl ScopeSource for StaticScope {
    fn current(&self) -> Result<Scope, Error> {
        Ok(Scope { scope_id: self.scope_id.clone(), agent_id: String::new() })
    }
}

pub struct GitScope {
    pub repo: PathBuf,
}

impl GitScope {
    pub fn from_env() -> Result<Self, Error> {
        let repo = find_repo(".")?;
        Ok(Self { repo })
    }

    pub fn open(repo: impl Into<PathBuf>) -> Self {
        Self { repo: repo.into() }
    }
}

impl ScopeSource for GitScope {
    fn current(&self) -> Result<Scope, Error> {
        let agent = resolve_agent(&self.repo)?;
        let path = scope_path(&self.repo, &agent);
        if !path.is_file() {
            return Err(Error::MissingScope("scope file is absent".into()));
        }
        let text = fs::read_to_string(&path).map_err(|error| Error::StaleScope(error.to_string()))?;
        let file: ScopeFile = serde_json::from_str(&text).map_err(|_| Error::StaleScope("scope file is not readable".into()))?;
        if file.agent_id != agent {
            return Err(Error::StaleScope("scope belongs to another agent".into()));
        }
        if file.stale {
            return Err(Error::StaleScope(file.stale_reason.unwrap_or_else(|| "scope is marked stale".into())));
        }
        let fresh = fingerprint(&self.repo, &file.base_head)?;
        if fresh.repo_id != file.repo_id || fresh.worktree_id != file.worktree_id || fresh.execution_id != file.execution_id {
            return Err(Error::StaleScope("execution identity changed".into()));
        }
        Ok(Scope { scope_id: file.scope_id, agent_id: file.agent_id })
    }
}

#[derive(Deserialize)]
struct ScopeFile {
    scope_id: String,
    repo_id: String,
    worktree_id: String,
    agent_id: String,
    execution_id: String,
    base_head: String,
    stale: bool,
    stale_reason: Option<String>,
}

#[derive(Deserialize)]
struct Fingerprint {
    execution_id: String,
    repo_id: String,
    worktree_id: String,
}

pub fn resolve_agent(repo: &Path) -> Result<String, Error> {
    if let Ok(agent) = std::env::var("IDEMPOTENCY_AGENT_ID") {
        let agent = agent.trim().to_string();
        if !agent.is_empty() {
            return Ok(agent);
        }
    }
    let path = repo.join(".idempotency").join("agent-id");
    if path.is_file() {
        let agent = fs::read_to_string(path).unwrap_or_default();
        let agent = agent.trim().to_string();
        if !agent.is_empty() {
            return Ok(agent);
        }
    }
    Err(Error::MissingScope("agent id is not set".into()))
}

pub fn scope_path(repo: &Path, agent: &str) -> PathBuf {
    if let Ok(override_path) = std::env::var("IDEMPOTENCY_SCOPE_FILE") {
        let override_path = override_path.trim();
        if !override_path.is_empty() {
            let path = PathBuf::from(override_path);
            return if path.is_absolute() { path } else { repo.join(path) };
        }
    }
    let name = if is_safe_agent(agent) {
        agent.to_string()
    } else {
        crate::canonical::sha256_hex(agent.as_bytes())
    };
    repo.join(".idempotency").join("scopes").join(format!("{name}.json"))
}

fn fingerprint(repo: &Path, base: &str) -> Result<Fingerprint, Error> {
    let output = Command::new("agent-idempotency")
        .args(["fingerprint", "--repo", &repo.to_string_lossy(), "--base", base])
        .output()
        .map_err(|error| Error::StaleScope(error.to_string()))?;
    if !output.status.success() {
        return Err(Error::StaleScope(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(text.trim()).map_err(|_| Error::StaleScope("fingerprint output is not json".into()))?;
    serde_json::from_value(value).map_err(|_| Error::StaleScope("fingerprint output is incomplete".into()))
}

fn is_safe_agent(agent: &str) -> bool {
    !agent.is_empty()
        && agent.len() <= 128
        && agent.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub fn find_repo(start: &str) -> Result<PathBuf, Error> {
    let output = Command::new("git")
        .args(["-C", start, "rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| Error::MissingScope(error.to_string()))?;
    if !output.status.success() {
        return Err(Error::MissingScope("not a git repository".into()));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
}
