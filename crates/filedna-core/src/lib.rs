//! FileDNA core engine.
//!
//! Structural intelligence engine for files. See project documentation.

pub mod analysis;
pub mod config;
pub mod discovery;
pub mod duplicate;
pub mod error;
pub mod evidence;
pub mod fingerprint;
pub mod identification;
pub mod integrity;
pub mod metadata;
pub mod parsers;
pub mod pipeline;
pub mod relationship;
pub mod report;
pub mod similarity;
pub mod storage;
pub mod types;

pub use error::{FileDnaError, Result};
pub use types::*;
