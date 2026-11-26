//! Hotspot report: rank resources by agent diversity and flag duplicate operations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use serde_json::Value;

use crate::audit::claims_log;
use crate::error::Error;

#[derive(Debug, Clone)]
pub struct Claim {
    pub agent_id: String,
    pub scope_id: String,
    pub operation_id: String,
    pub resource_key: String,
    pub outcome: String,
    pub ts: u64,
    pub repo_wide: bool,
}

#[derive(Debug, Clone)]
pub struct OperationSummary {
    pub operation_id: String,
    pub scopes: Vec<String>,
    pub scope_count: usize,
    pub outcomes: Vec<String>,
    pub duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct Hotspot {
    pub resource_key: String,
    pub agents: Vec<String>,
    pub agent_count: usize,
    pub operations: Vec<OperationSummary>,
    pub duplicate_operations: usize,
}

pub fn read_claims(path: Option<&str>, since_days: u64) -> Result<Vec<Claim>, Error> {
    let log_path = path.map(String::from).unwrap_or_else(|| claims_log(None));
    if !std::path::Path::new(&log_path).is_file() {
        return Ok(Vec::new());
    }
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(since_days * 86400);
    let text = fs::read_to_string(&log_path).map_err(|e| Error::Canonical(e.to_string()))?;
    let mut claims = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ts = value.get("ts").and_then(Value::as_u64).unwrap_or(0);
        if ts < cutoff {
            continue;
        }
        claims.push(Claim {
            agent_id: value.get("agent_id").and_then(Value::as_str).unwrap_or("").to_string(),
            scope_id: value.get("scope_id").and_then(Value::as_str).unwrap_or("").to_string(),
            operation_id: value.get("operation_id").and_then(Value::as_str).unwrap_or("").to_string(),
            resource_key: value.get("resource_key").and_then(Value::as_str).unwrap_or("").to_string(),
            outcome: value.get("outcome").and_then(Value::as_str).unwrap_or("").to_string(),
            ts,
            repo_wide: value.get("repo_wide").and_then(Value::as_bool).unwrap_or(false),
        });
    }
    Ok(claims)
}

pub fn hotspots(claims: &[Claim], min_agents: usize, agent_filter: Option<&str>) -> Vec<Hotspot> {
    let mut by_resource: BTreeMap<&str, Vec<&Claim>> = BTreeMap::new();
    for claim in claims {
        if let Some(filter) = agent_filter {
            if claim.agent_id != filter {
                continue;
            }
        }
        by_resource.entry(&claim.resource_key).or_default().push(claim);
    }

    let mut results = Vec::new();
    for (resource_key, resource_claims) in by_resource {
        let agents: BTreeSet<&str> = resource_claims.iter().map(|c| c.agent_id.as_str()).collect();
        let agent_count = agents.len();
        if agent_count < min_agents {
            continue;
        }

        let mut by_operation: BTreeMap<&str, Vec<&Claim>> = BTreeMap::new();
        for claim in &resource_claims {
            by_operation.entry(&claim.operation_id).or_default().push(claim);
        }

        let mut operations = Vec::new();
        let mut duplicate_count = 0;
        for (op_id, op_claims) in by_operation {
            let scopes: BTreeSet<&str> = op_claims.iter().map(|c| c.scope_id.as_str()).collect();
            let scope_count = scopes.len();
            let outcomes: Vec<String> = op_claims.iter().map(|c| c.outcome.clone()).collect();
            let is_duplicate = scope_count > 1;
            if is_duplicate {
                duplicate_count += 1;
            }
            operations.push(OperationSummary {
                operation_id: op_id.to_string(),
                scopes: scopes.into_iter().map(String::from).collect(),
                scope_count,
                outcomes,
                duplicate: is_duplicate,
            });
        }

        results.push(Hotspot {
            resource_key: resource_key.to_string(),
            agents: agents.into_iter().map(String::from).collect(),
            agent_count,
            operations,
            duplicate_operations: duplicate_count,
        });
    }

    results.sort_by(|a, b| {
        b.agent_count
            .cmp(&a.agent_count)
            .then(b.duplicate_operations.cmp(&a.duplicate_operations))
    });
    results
}

pub fn format_table(results: &[Hotspot]) -> String {
    if results.is_empty() {
        return "No hotspots found.".into();
    }
    let mut lines = Vec::new();
    lines.push(format!("{:<60} {:<8} {:<12}", "Resource Key", "Agents", "Duplicates"));
    lines.push("-".repeat(82));
    for r in results {
        lines.push(format!("{:<60} {:<8} {:<12}", r.resource_key, r.agent_count, r.duplicate_operations));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(resource: &str, agent: &str, scope: &str, op: &str) -> Claim {
        Claim {
            agent_id: agent.into(),
            scope_id: scope.into(),
            operation_id: op.into(),
            resource_key: resource.into(),
            outcome: "sent".into(),
            ts: 1000,
            repo_wide: false,
        }
    }

    #[test]
    fn groups_by_resource_and_flags_duplicates() {
        let claims = vec![
            claim("http:POST:api:/users/:id", "a1", "s1", "op1"),
            claim("http:POST:api:/users/:id", "a2", "s2", "op1"),
            claim("http:POST:api:/users/:id", "a1", "s1", "op2"),
            claim("db:sqlite:app:users", "a1", "s1", "op3"),
        ];
        let results = hotspots(&claims, 2, None);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.resource_key, "http:POST:api:/users/:id");
        assert_eq!(r.agent_count, 2);
        assert_eq!(r.duplicate_operations, 1);
        assert_eq!(r.operations.len(), 2);
    }

    #[test]
    fn min_agents_filter() {
        let claims = vec![
            claim("http:POST:api:/users/:id", "a1", "s1", "op1"),
            claim("http:POST:api:/users/:id", "a1", "s1", "op2"),
        ];
        let results = hotspots(&claims, 2, None);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn agent_filter() {
        let claims = vec![
            claim("http:POST:api:/users/:id", "a1", "s1", "op1"),
            claim("http:POST:api:/users/:id", "a2", "s2", "op1"),
        ];
        let results = hotspots(&claims, 1, Some("a1"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_count, 1);
    }
}
