//! Idempotency wrappers for coding-agent API and database calls.
//!
//! A repeated call is suppressed only inside `Client::once`, `http::request`, or `db::execute`,
//! and only while the scope file is current and the Redis record is still inside its retention TTL.

pub mod audit;
pub mod canonical;
pub mod client;
pub mod crypto;
pub mod db;
pub mod error;
pub mod http;
pub mod scope;
pub mod store;

pub use client::Client;
pub use error::Error;
