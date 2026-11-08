use crate::discovery::{open_prefix, read_bytes_bounded};
use crate::error::Result;
use crate::parsers;
use crate::types::*;
use chrono::Utc;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Signature {
    pub format_id: &'static str,
    pub format_name: &'static str,
    pub mime_type: Option<&'static str>,
    pub extensions: &'static [&'static str],
    pub family: &'static str,
    pub bytes: &'static [u8],
    pub offset: usize,
    pub weight: f64,
}

pub static SIGNATURES: &[Signature] = &[
    Signature {
        format_id: "png",
        format_name: "PNG image",
        mime_type: Some("image/png"),
        extensions: &["png"],
        family: "image",
        bytes: b"\x89PNG\r\n\x1a\n",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "jpeg",
        format_name: "JPEG image",
        mime_type: Some("image/jpeg"),
        extensions: &["jpg", "jpeg", "jpe"],
        family: "image",
        bytes: b"\xff\xd8\xff",
        offset: 0,
        weight: 0.85,
    },
    Signature {
        format_id: "gif",
        format_name: "GIF image",
        mime_type: Some("image/gif"),
        extensions: &["gif"],
        family: "image",
        bytes: b"GIF87a",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "gif",
        format_name: "GIF image",
        mime_type: Some("image/gif"),
        extensions: &["gif"],
        family: "image",
        bytes: b"GIF89a",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "webp",
        format_name: "WebP image",
        mime_type: Some("image/webp"),
        extensions: &["webp"],
        family: "image",
        bytes: b"RIFF",
        offset: 0,
        weight: 0.5,
    },
    Signature {
        format_id: "bmp",
        format_name: "BMP image",
        mime_type: Some("image/bmp"),
        extensions: &["bmp"],
        family: "image",
        bytes: b"BM",
        offset: 0,
        weight: 0.7,
    },
    Signature {
        format_id: "tiff",
        format_name: "TIFF image",
        mime_type: Some("image/tiff"),
        extensions: &["tif", "tiff"],
        family: "image",
        bytes: b"II*\x00",
        offset: 0,
        weight: 0.8,
    },
    Signature {
        format_id: "tiff",
        format_name: "TIFF image",
        mime_type: Some("image/tiff"),
        extensions: &["tif", "tiff"],
        family: "image",
        bytes: b"MM\x00*",
        offset: 0,
        weight: 0.8,
    },
    Signature {
        format_id: "zip",
        format_name: "ZIP archive",
        mime_type: Some("application/zip"),
        extensions: &["zip", "jar", "docx", "xlsx", "pptx", "odt"],
        family: "archive",
        bytes: b"PK\x03\x04",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "zip",
        format_name: "ZIP archive (empty)",
        mime_type: Some("application/zip"),
        extensions: &["zip"],
        family: "archive",
        bytes: b"PK\x05\x06",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "gzip",
        format_name: "GZIP compressed",
        mime_type: Some("application/gzip"),
        extensions: &["gz", "tgz"],
        family: "archive",
        bytes: b"\x1f\x8b",
        offset: 0,
        weight: 0.85,
    },
    Signature {
        format_id: "tar",
        format_name: "TAR archive",
        mime_type: Some("application/x-tar"),
        extensions: &["tar"],
        family: "archive",
        bytes: b"ustar",
        offset: 257,
        weight: 0.85,
    },
    Signature {
        format_id: "pdf",
        format_name: "PDF document",
        mime_type: Some("application/pdf"),
        extensions: &["pdf"],
        family: "document",
        bytes: b"%PDF-",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "wav",
        format_name: "WAV audio",
        mime_type: Some("audio/wav"),
        extensions: &["wav"],
        family: "audio",
        bytes: b"RIFF",
        offset: 0,
        weight: 0.4,
    },
    Signature {
        format_id: "flac",
        format_name: "FLAC audio",
        mime_type: Some("audio/flac"),
        extensions: &["flac"],
        family: "audio",
        bytes: b"fLaC",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "mp3",
        format_name: "MP3 audio (ID3)",
        mime_type: Some("audio/mpeg"),
        extensions: &["mp3"],
        family: "audio",
        bytes: b"ID3",
        offset: 0,
        weight: 0.8,
    },
    Signature {
        format_id: "mp4",
        format_name: "MP4 video",
        mime_type: Some("video/mp4"),
        extensions: &["mp4", "m4v", "mov"],
        family: "video",
        bytes: b"ftyp",
        offset: 4,
        weight: 0.8,
    },
    Signature {
        format_id: "matroska",
        format_name: "Matroska media",
        mime_type: Some("video/x-matroska"),
        extensions: &["mkv", "webm"],
        family: "video",
        bytes: &[0x1a, 0x45, 0xdf, 0xa3],
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "ttf",
        format_name: "TrueType font",
        mime_type: Some("font/ttf"),
        extensions: &["ttf"],
        family: "font",
        bytes: b"\x00\x01\x00\x00",
        offset: 0,
        weight: 0.6,
    },
    Signature {
        format_id: "otf",
        format_name: "OpenType font",
        mime_type: Some("font/otf"),
        extensions: &["otf"],
        family: "font",
        bytes: b"OTTO",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "ttc",
        format_name: "TrueType collection",
        mime_type: Some("font/collection"),
        extensions: &["ttc"],
        family: "font",
        bytes: b"ttcf",
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "sqlite",
        format_name: "SQLite database",
        mime_type: Some("application/vnd.sqlite3"),
        extensions: &["sqlite", "db"],
        family: "database",
        bytes: b"SQLite format 3\x00",
        offset: 0,
        weight: 0.95,
    },
    Signature {
        format_id: "elf",
        format_name: "ELF binary",
        mime_type: Some("application/x-elf"),
        extensions: &[""],
        family: "executable",
        bytes: b"\x7fELF",
        offset: 0,
        weight: 0.95,
    },
    Signature {
        format_id: "pe",
        format_name: "PE executable",
        mime_type: Some("application/vnd.microsoft.portable-executable"),
        extensions: &["exe", "dll"],
        family: "executable",
        bytes: b"MZ",
        offset: 0,
        weight: 0.6,
    },
    Signature {
        format_id: "macho",
        format_name: "Mach-O binary",
        mime_type: Some("application/x-mach-binary"),
        extensions: &[""],
        family: "executable",
        bytes: &[0xcf, 0xfa, 0xed, 0xfe],
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "macho",
        format_name: "Mach-O binary",
        mime_type: Some("application/x-mach-binary"),
        extensions: &[""],
        family: "executable",
        bytes: &[0xce, 0xfa, 0xed, 0xfe],
        offset: 0,
        weight: 0.9,
    },
    Signature {
        format_id: "xml",
        format_name: "XML text",
        mime_type: Some("application/xml"),
        extensions: &["xml"],
        family: "structured_text",
        bytes: b"<?xml",
        offset: 0,
        weight: 0.8,
    },
    Signature {
        format_id: "json",
        format_name: "JSON text",
        mime_type: Some("application/json"),
        extensions: &["json"],
        family: "structured_text",
        bytes: b"{",
        offset: 0,
        weight: 0.3,
    },
];

pub fn identify(
    path: &Path,
    config: &crate::types::Config,
) -> Result<(IdentificationResult, Vec<Evidence>)> {
    let mut evidence: Vec<Evidence> = Vec::new();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let claimed_ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());

    // bounded prefix read
    let prefix_len = 65536.min(size as usize);
    let prefix = open_prefix(path, prefix_len).unwrap_or_default();

    // signature matching
    let mut cand_map: std::collections::BTreeMap<String, FormatCandidate> =
        std::collections::BTreeMap::new();

    for sig in SIGNATURES {
        if sig.offset + sig.bytes.len() <= prefix.len() {
            if prefix[sig.offset..sig.offset + sig.bytes.len()] == *sig.bytes {
                // webp needs RIFF....WEBP
                if sig.format_id == "webp" {
                    if prefix.len() < 12 || &prefix[8..12] != b"WEBP" {
                        continue;
                    }
                }
                if sig.format_id == "wav" {
                    if prefix.len() < 12 || &prefix[8..12] != b"WAVE" {
                        continue;
                    }
                }
                if sig.format_id == "mp4" {
                    // need ftyp at offset 4
                    if prefix.len() < 8 {
                        continue;
                    }
                }
                let id = format!("ev-sig-{}-{}", sig.format_id, evidence.len());
                evidence.push(Evidence {
                    id: id.clone(),
                    file_id: None,
                    stage: "identification".into(),
                    category: "signature".into(),
                    description: format!(
                        "Magic bytes matched {} at offset {}",
                        sig.format_name, sig.offset
                    ),
                    raw: Some(hex::encode(
                        &prefix[sig.offset..sig.offset + sig.bytes.len()],
                    )),
                    source: "signature_registry".into(),
                    algorithm_version: "1.0".into(),
                    confidence: Some(sig.weight),
                    timestamp: Utc::now(),
                    offset: Some(sig.offset as u64),
                    length: Some(sig.bytes.len() as u64),
                });
                let cand = FormatCandidate {
                    format_id: sig.format_id.into(),
                    format_name: sig.format_name.into(),
                    mime_type: sig.mime_type.map(str::to_string),
                    known_extensions: sig.extensions.iter().map(|s| s.to_string()).collect(),
                    format_family: sig.family.into(),
                    confidence: FormatConfidence::Possible,
                    confidence_score: sig.weight,
                    evidence_ids: vec![id],
                };
                // merge: keep highest score
                let entry = cand_map.entry(sig.format_id.into()).or_insert(cand.clone());
                if cand.confidence_score > entry.confidence_score {
                    *entry = cand;
                } else {
                    // append evidence id
                    entry.evidence_ids.extend(cand.evidence_ids);
                }
            }
        }
    }

    // Heuristic structured text detection
    if cand_map.is_empty() {
        // try text
        let is_text = prefix
            .iter()
            .all(|&b| b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127));
        if is_text && !prefix.is_empty() {
            let trimmed = std::str::from_utf8(&prefix).unwrap_or("").trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                let id = format!("ev-heur-json-{}", evidence.len());
                evidence.push(Evidence {
                    id: id.clone(),
                    file_id: None,
                    stage: "identification".into(),
                    category: "heuristic".into(),
                    description: "Content appears to be JSON text".into(),
                    raw: None,
                    source: "heuristic".into(),
                    algorithm_version: "1.0".into(),
                    confidence: Some(0.6),
                    timestamp: Utc::now(),
                    offset: None,
                    length: None,
                });
                cand_map.insert(
                    "json".into(),
                    FormatCandidate {
                        format_id: "json".into(),
                        format_name: "JSON text".into(),
                        mime_type: Some("application/json".into()),
                        known_extensions: vec!["json".into()],
                        format_family: "structured_text".into(),
                        confidence: FormatConfidence::Probable,
                        confidence_score: 0.6,
                        evidence_ids: vec![id],
                    },
                );
            } else if trimmed.starts_with('<') {
                let id = format!("ev-heur-xml-{}", evidence.len());
                evidence.push(Evidence {
                    id: id.clone(),
                    file_id: None,
                    stage: "identification".into(),
                    category: "heuristic".into(),
                    description: "Content appears to be XML text".into(),
                    raw: None,
                    source: "heuristic".into(),
                    algorithm_version: "1.0".into(),
                    confidence: Some(0.6),
                    timestamp: Utc::now(),
                    offset: None,
                    length: None,
                });
                cand_map.insert(
                    "xml".into(),
                    FormatCandidate {
                        format_id: "xml".into(),
                        format_name: "XML text".into(),
                        mime_type: Some("application/xml".into()),
                        known_extensions: vec!["xml".into()],
                        format_family: "structured_text".into(),
                        confidence: FormatConfidence::Probable,
                        confidence_score: 0.6,
                        evidence_ids: vec![id],
                    },
                );
            }
        }
    }

    // Empty file handling
    if size == 0 {
        let id = format!("ev-empty-{}", evidence.len());
        evidence.push(Evidence {
            id: id.clone(),
            file_id: None,
            stage: "identification".into(),
            category: "observation".into(),
            description: "File is empty (0 bytes)".into(),
            raw: None,
            source: "discovery".into(),
            algorithm_version: "1.0".into(),
            confidence: None,
            timestamp: Utc::now(),
            offset: None,
            length: None,
        });
    }

    // Parser validation: for each candidate, try parser identify to adjust confidence
    let mut candidates: Vec<FormatCandidate> = cand_map.into_values().collect();
    for c in candidates.iter_mut() {
        if let Some(parser) = parsers::get_parser(&c.format_id) {
            let (matched, delta, notes) = parser.identify(&prefix, size);
            if matched {
                c.confidence_score = (c.confidence_score + delta).min(1.0);
                if c.confidence_score >= 0.9 {
                    c.confidence = FormatConfidence::Confirmed;
                } else if c.confidence_score >= 0.75 {
                    c.confidence = FormatConfidence::HighlyProbable;
                } else if c.confidence_score >= 0.55 {
                    c.confidence = FormatConfidence::Probable;
                }
                for n in notes {
                    let id = format!("ev-parser-{}-{}", c.format_id, evidence.len());
                    evidence.push(Evidence {
                        id: id.clone(),
                        file_id: None,
                        stage: "identification".into(),
                        category: "parser_validation".into(),
                        description: n,
                        raw: None,
                        source: format!("parser:{}", c.format_id),
                        algorithm_version: "1.0".into(),
                        confidence: Some(c.confidence_score),
                        timestamp: Utc::now(),
                        offset: None,
                        length: None,
                    });
                    c.evidence_ids.push(id);
                }
            } else {
                // parser says no; reduce
                c.confidence_score *= 0.5;
                c.confidence = FormatConfidence::Possible;
            }
        }
    }

    // sort candidates by score desc
    candidates.sort_by(|a, b| {
        b.confidence_score
            .partial_cmp(&a.confidence_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let extension_mismatch = if let Some(ext) = &claimed_ext {
        if let Some(primary) = candidates.first() {
            !primary.known_extensions.iter().any(|e| e == ext)
                && !primary.known_extensions.is_empty()
        } else {
            false
        }
    } else {
        false
    };

    // If conflicting: multiple high-scoring candidates from different families
    let conflicting = candidates.len() >= 2
        && candidates[0].confidence_score >= 0.7
        && candidates[1].confidence_score >= 0.7
        && candidates[0].format_family != candidates[1].format_family;

    let primary = if candidates.is_empty() {
        None
    } else if conflicting {
        // still provide primary but mark? We'll set confidence to Conflicting on primary
        let mut p = candidates[0].clone();
        p.confidence = FormatConfidence::Conflicting;
        Some(p)
    } else {
        Some(candidates[0].clone())
    };

    // If no candidates and not empty, unknown
    if candidates.is_empty() && size > 0 {
        let id = format!("ev-unknown-{}", evidence.len());
        evidence.push(Evidence {
            id: id.clone(),
            file_id: None,
            stage: "identification".into(),
            category: "observation".into(),
            description: "No known signature matched; format unknown".into(),
            raw: None,
            source: "identification".into(),
            algorithm_version: "1.0".into(),
            confidence: None,
            timestamp: Utc::now(),
            offset: None,
            length: None,
        });
    }

    // extension mismatch evidence
    if extension_mismatch {
        let id = format!("ev-extmismatch-{}", evidence.len());
        evidence.push(Evidence {
            id: id.clone(),
            file_id: None,
            stage: "identification".into(),
            category: "extension_mismatch".into(),
            description: format!(
                "Claimed extension '{}' does not match detected format '{}'",
                claimed_ext.clone().unwrap_or_default(),
                primary
                    .as_ref()
                    .map(|p| p.format_id.clone())
                    .unwrap_or_default()
            ),
            raw: None,
            source: "identification".into(),
            algorithm_version: "1.0".into(),
            confidence: None,
            timestamp: Utc::now(),
            offset: None,
            length: None,
        });
    }

    let result = IdentificationResult {
        claimed_extension: claimed_ext,
        extension_mismatch,
        candidates,
        primary,
        evidence_ids: evidence.iter().map(|e| e.id.clone()).collect(),
    };

    // resource limit check on file size
    if size > config.max_file_size {
        return Err(crate::FileDnaError::ResourceLimit(format!(
            "file size {} exceeds configured max {}",
            size, config.max_file_size
        )));
    }

    Ok((result, evidence))
}
