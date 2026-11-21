use serde_json::Value;

use crate::canonical::{db_document, json_map};
use crate::client::Client;
use crate::error::Error;

pub struct DbTarget {
    pub driver: String,
    pub host: String,
    pub port: i64,
    pub database: String,
    pub user: String,
}

pub struct Statement {
    pub sql: String,
    pub params: Vec<Value>,
}

pub struct StatementResult {
    pub rows_affected: i64,
    pub rows: Vec<Vec<Value>>,
}

pub trait DbSession {
    fn in_transaction(&self) -> bool;
    fn begin(&mut self) -> Result<(), String>;
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<StatementResult, String>;
    fn commit(&mut self) -> Result<(), String>;
    fn rollback(&mut self) -> Result<(), String>;
}

pub fn execute(client: &Client, target: &DbTarget, statements: &[Statement], session: &mut dyn DbSession, isolation: &str) -> Result<Value, Error> {
    if session.in_transaction() {
        return Err(Error::TransactionBoundary);
    }
    let target_value = json_map(vec![
        ("database", Value::String(target.database.clone())),
        ("driver", Value::String(target.driver.clone())),
        ("host", Value::String(target.host.clone())),
        ("port", Value::Number(target.port.into())),
        ("user", Value::String(target.user.clone())),
    ]);
    let statement_values: Vec<Value> = statements
        .iter()
        .map(|statement| {
            json_map(vec![
                ("params", Value::Array(statement.params.clone())),
                ("sql", Value::String(statement.sql.clone())),
            ])
        })
        .collect();
    let document = db_document(&target_value, &statement_values, isolation)?;
    client.once(&document, || {
        if let Err(error) = session.begin() {
            return Err(Error::NotApplied(format!("begin failed: {error}")));
        }
        let mut results = Vec::new();
        for statement in statements {
            match session.execute(&statement.sql, &statement.params) {
                Ok(result) => results.push(result),
                Err(error) => {
                    if let Err(rollback_error) = session.rollback() {
                        return Err(Error::Uncertain(format!("uncertain_database: {rollback_error}")));
                    }
                    return Err(Error::ConfirmedRollback(error));
                }
            }
        }
        if let Err(error) = session.commit() {
            return Err(Error::Uncertain(format!("uncertain_database: {error}")));
        }
        Ok(contract(&results))
    })
}

fn contract(results: &[StatementResult]) -> Value {
    json_map(vec![
        ("committed", Value::Bool(true)),
        ("kind", Value::String("db_result".into())),
        (
            "rows",
            Value::Array(
                results
                    .iter()
                    .map(|result| Value::Array(result.rows.iter().map(|row| Value::Array(row.clone())).collect()))
                    .collect(),
            ),
        ),
        (
            "rows_affected",
            Value::Array(results.iter().map(|result| Value::Number(result.rows_affected.into())).collect()),
        ),
    ])
}
