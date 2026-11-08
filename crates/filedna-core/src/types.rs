use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// A unique identifier for a file record within a storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(pub i64);

/// Discovered file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub canonical_path: Option<PathBuf>,
    pub name: String,
    pub extension: Option<String>,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub created: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
    pub os_file_type: Option<String>,
}

/// A bounded reader over a file. Never reads entire large files unless explicitly requested.
#[derive(Debug)]
pub struct FileHandle {
    pub path: PathBuf,
    pub size: u64,
}

/// Identification confidence classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatConfidence {
    Confirmed,
    HighlyProbable,
    Probable,
    Possible,
    Unknown,
    Ambiguous,
    Conflicting,
    Unsupported,
    Malformed,
}

impl FormatConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::HighlyProbable => "highly_probable",
            Self::Probable => "probable",
            Self::Possible => "possible",
            Self::Unknown => "unknown",
            Self::Ambiguous => "ambiguous",
            Self::Conflicting => "conflicting",
            Self::Unsupported => "unsupported",
            Self::Malformed => "malformed",
        }
    }
}

/// A candidate format match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatCandidate {
    pub format_id: String,
    pub format_name: String,
    pub mime_type: Option<String>,
    pub known_extensions: Vec<String>,
    pub format_family: String,
    pub confidence: FormatConfidence,
    pub confidence_score: f64,
    pub evidence_ids: Vec<String>,
}

/// Result of format identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentificationResult {
    pub claimed_extension: Option<String>,
    pub extension_mismatch: bool,
    pub candidates: Vec<FormatCandidate>,
    pub primary: Option<FormatCandidate>,
    pub evidence_ids: Vec<String>,
}

/// Status of a structural node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Valid,
    Invalid,
    Partial,
    Skipped,
    Unknown,
}

/// A normalized structural node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralNode {
    pub node_type: String,
    pub offset: u64,
    pub length: Option<u64>,
    pub status: NodeStatus,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub children: Vec<StructuralNode>,
    pub errors: Vec<String>,
}

/// Structural analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralReport {
    pub format_id: String,
    pub format_version: Option<String>,
    pub root: Option<StructuralNode>,
    pub nodes_flat: Vec<StructuralNode>,
    pub parsed_bytes: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub complete: bool,
}

/// Metadata container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetadataReport {
    pub fields: BTreeMap<String, serde_json::Value>,
    pub missing: Vec<String>,
}

/// Evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub file_id: Option<FileId>,
    pub stage: String,
    pub category: String,
    pub description: String,
    pub raw: Option<String>,
    pub source: String,
    pub algorithm_version: String,
    pub confidence: Option<f64>,
    pub timestamp: DateTime<Utc>,
    pub offset: Option<u64>,
    pub length: Option<u64>,
}

/// Integrity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityState {
    VerifiedAgainstExpectedHash,
    HashMismatch,
    StructurallyValid,
    StructurallyInconsistent,
    PartiallyVerified,
    InsufficientEvidence,
    AnalysisFailed,
}

impl IntegrityState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifiedAgainstExpectedHash => "verified_against_expected_hash",
            Self::HashMismatch => "hash_mismatch",
            Self::StructurallyValid => "structurally_valid",
            Self::StructurallyInconsistent => "structurally_inconsistent",
            Self::PartiallyVerified => "partially_verified",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::AnalysisFailed => "analysis_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheck {
    pub name: String,
    pub passed: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub state: IntegrityState,
    pub checks: Vec<IntegrityCheck>,
    pub evidence_ids: Vec<String>,
}

/// Fingerprint records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFingerprint {
    pub algorithm: String,
    pub version: String,
    pub hex: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralFingerprint {
    pub version: String,
    pub value: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataFingerprint {
    pub version: String,
    pub value: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkFingerprint {
    pub algorithm: String,
    pub version: String,
    pub chunk_size: u64,
    pub chunks: Vec<(u64, String)>,
    pub created: DateTime<Utc>,
}

/// FileDNA profile (aggregated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProfile {
    pub file_id: Option<FileId>,
    pub discovered: DiscoveredFile,
    pub identification: Option<IdentificationResult>,
    pub structure: Option<StructuralReport>,
    pub metadata: Option<MetadataReport>,
    pub content_fingerprint: Option<ContentFingerprint>,
    pub structural_fingerprint: Option<StructuralFingerprint>,
    pub metadata_fingerprint: Option<MetadataFingerprint>,
    pub integrity: Option<IntegrityResult>,
    pub evidence: Vec<Evidence>,
    pub analysis_errors: Vec<String>,
}

/// Duplicate categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DuplicateKind {
    ExactContent,
    Metadata,
    Structural,
    Potential,
}

/// Duplicate group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub id: String,
    pub kind: DuplicateKind,
    pub files: Vec<PathBuf>,
    pub content_hash: Option<String>,
    pub evidence: Vec<String>,
}

/// Similarity result between two files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    pub file_a: PathBuf,
    pub file_b: PathBuf,
    pub score: f64,
    pub signals: Vec<String>,
    pub algorithm: String,
    pub version: String,
}

/// Relationship edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub from: PathBuf,
    pub to: PathBuf,
    pub rel_type: String,
    pub evidence: Vec<String>,
    pub confidence: Option<f64>,
    pub algorithm: String,
    pub created: DateTime<Utc>,
}

/// Configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub max_file_size: u64,
    pub max_parse_depth: u32,
    pub max_metadata_size: u64,
    pub max_archive_entries: u64,
    pub max_nested_depth: u32,
    pub max_decompressed_bytes: u64,
    pub max_parser_time_ms: u64,
    pub max_memory_bytes: u64,
    pub chunk_size: u64,
    pub follow_symlinks: bool,
    pub include_hidden: bool,
    pub worker_threads: usize,
    pub enable_blake3: bool,
    pub hash_algorithm_primary: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024 * 1024, // 10 GiB
            max_parse_depth: 64,
            max_metadata_size: 64 * 1024 * 1024,
            max_archive_entries: 100_000,
            max_nested_depth: 8,
            max_decompressed_bytes: 256 * 1024 * 1024,
            max_parser_time_ms: 30_000,
            max_memory_bytes: 512 * 1024 * 1024,
            chunk_size: 1024 * 1024,
            follow_symlinks: false,
            include_hidden: false,
            worker_threads: 4,
            enable_blake3: false,
            hash_algorithm_primary: "sha256".into(),
        }
    }
}

/// Analysis job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub id: String,
    pub root: PathBuf,
    pub status: JobStatus,
    pub files_discovered: u64,
    pub files_completed: u64,
    pub bytes_processed: u64,
    pub errors: u64,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
}
