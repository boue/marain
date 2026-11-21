use std::fmt;

#[derive(Debug)]
pub enum Error {
    MissingScope(String),
    StaleScope(String),
    RedisUnavailable(String),
    Blocked { reason: String },
    WaiterTimeout,
    InProgressCleared,
    StaleOwner,
    NotApplied(String),
    ConfirmedRollback(String),
    Uncertain(String),
    Oversized,
    Nonserializable(String),
    Canonical(String),
    Replay { code: String, message: String },
    Config(String),
    TransactionBoundary,
}

impl Error {
    pub fn code(&self) -> &str {
        match self {
            Error::MissingScope(_) => "missing_scope",
            Error::StaleScope(_) => "stale_scope",
            Error::RedisUnavailable(_) => "redis_unavailable",
            Error::Blocked { .. } => "blocked",
            Error::WaiterTimeout => "waiter_timeout",
            Error::InProgressCleared => "in_progress_cleared",
            Error::StaleOwner => "stale_owner",
            Error::NotApplied(_) => "not_applied",
            Error::ConfirmedRollback(_) => "rolled_back",
            Error::Uncertain(_) => "uncertain",
            Error::Oversized => "oversized_result",
            Error::Nonserializable(_) => "nonserializable_result",
            Error::Canonical(_) => "canonical",
            Error::Replay { code, .. } => code.as_str(),
            Error::Config(_) => "config",
            Error::TransactionBoundary => "transaction_boundary",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Blocked { reason } => write!(formatter, "{reason}"),
            Error::Replay { message, .. } => write!(formatter, "{message}"),
            Error::MissingScope(message)
            | Error::StaleScope(message)
            | Error::RedisUnavailable(message)
            | Error::NotApplied(message)
            | Error::ConfirmedRollback(message)
            | Error::Uncertain(message)
            | Error::Nonserializable(message)
            | Error::Canonical(message)
            | Error::Config(message) => write!(formatter, "{message}"),
            other => write!(formatter, "{}", other.code()),
        }
    }
}

impl std::error::Error for Error {}
