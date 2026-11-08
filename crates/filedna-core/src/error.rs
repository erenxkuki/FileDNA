use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileDnaError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("parse error in {subsystem}: {message}")]
    Parse { subsystem: String, message: String },

    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("cancelled")]
    Cancelled,

    #[error("analysis failed for {path}: {message}")]
    AnalysisFailed { path: PathBuf, message: String },

    #[error("unknown error: {0}")]
    Unknown(String),
}

impl From<rusqlite::Error> for FileDnaError {
    fn from(e: rusqlite::Error) -> Self {
        FileDnaError::Database(e.to_string())
    }
}

impl From<serde_json::Error> for FileDnaError {
    fn from(e: serde_json::Error) -> Self {
        FileDnaError::Parse {
            subsystem: "json".into(),
            message: e.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, FileDnaError>;

/// Structured error descriptor for APIs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
    pub subsystem: String,
    pub operation: String,
    pub recoverable: bool,
}
