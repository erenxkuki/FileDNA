use crate::error::Result;
use crate::types::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn sha256_file(path: &Path, chunk_size: usize) -> Result<ContentFingerprint> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(ContentFingerprint {
        algorithm: "sha256".into(),
        version: "1.0".into(),
        hex: hex::encode(digest),
        created: chrono::Utc::now(),
    })
}

pub fn blake3_file(path: &Path, chunk_size: usize) -> Result<ContentFingerprint> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(ContentFingerprint {
        algorithm: "blake3".into(),
        version: "1.0".into(),
        hex: digest.to_hex().to_string(),
        created: chrono::Utc::now(),
    })
}

pub fn structural_fingerprint(report: &StructuralReport) -> StructuralFingerprint {
    // Normalize: format + version + sequence of node types and statuses + top-level fields keys.
    let mut s = String::new();
    s.push_str(&report.format_id);
    s.push('|');
    s.push_str(report.format_version.as_deref().unwrap_or(""));
    s.push('|');
    for n in &report.nodes_flat {
        s.push_str(&n.node_type);
        s.push(':');
        s.push_str(match n.status {
            NodeStatus::Valid => "V",
            NodeStatus::Invalid => "I",
            NodeStatus::Partial => "P",
            NodeStatus::Skipped => "S",
            NodeStatus::Unknown => "U",
        });
        s.push(',');
    }
    // include top-level field keys
    if let Some(root) = &report.root {
        let mut keys: Vec<&String> = root.fields.keys().collect();
        keys.sort();
        for k in keys {
            s.push_str(k);
            s.push(';');
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    StructuralFingerprint {
        version: "1.0".into(),
        value: hex::encode(hasher.finalize()),
        created: chrono::Utc::now(),
    }
}

pub fn metadata_fingerprint(report: &crate::types::MetadataReport) -> MetadataFingerprint {
    // sort keys
    let mut keys: Vec<&String> = report.fields.keys().collect();
    keys.sort();
    let mut s = String::new();
    for k in keys {
        s.push_str(k);
        s.push('=');
        s.push_str(&report.fields[k].to_string());
        s.push('|');
    }
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    MetadataFingerprint {
        version: "1.0".into(),
        value: hex::encode(hasher.finalize()),
        created: chrono::Utc::now(),
    }
}

pub fn chunk_fingerprint(
    path: &Path,
    chunk_size: u64,
    algorithm: &str,
) -> Result<ChunkFingerprint> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; chunk_size as usize];
    let mut chunks = Vec::new();
    let mut offset = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let h = if algorithm == "blake3" {
            blake3::hash(&buf[..n]).to_hex().to_string()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&buf[..n]);
            hex::encode(hasher.finalize())
        };
        chunks.push((offset, h));
        offset += n as u64;
    }
    Ok(ChunkFingerprint {
        algorithm: algorithm.into(),
        version: "1.0".into(),
        chunk_size,
        chunks,
        created: chrono::Utc::now(),
    })
}
