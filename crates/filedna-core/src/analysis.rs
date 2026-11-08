use crate::discovery;
use crate::fingerprint;
use crate::identification;
use crate::integrity;
use crate::parsers;
use crate::types::*;
use std::path::Path;

pub fn analyze_file(path: &Path, config: &Config) -> FileProfile {
    let mut profile = FileProfile {
        file_id: None,
        discovered: discovery::inspect_file(path).unwrap_or_else(|| DiscoveredFile {
            path: path.to_path_buf(),
            canonical_path: None,
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            extension: path.extension().map(|e| e.to_string_lossy().to_lowercase()),
            size: 0,
            modified: None,
            created: None,
            accessed: None,
            is_symlink: false,
            symlink_target: None,
            os_file_type: None,
        }),
        identification: None,
        structure: None,
        metadata: None,
        content_fingerprint: None,
        structural_fingerprint: None,
        metadata_fingerprint: None,
        integrity: None,
        evidence: Vec::new(),
        analysis_errors: Vec::new(),
    };

    // Identification
    match identification::identify(path, config) {
        Ok((res, ev)) => {
            profile.identification = Some(res);
            profile.evidence.extend(ev);
        }
        Err(e) => {
            profile
                .analysis_errors
                .push(format!("identification: {}", e));
        }
    }

    // Structural parse if parser available and size within limits
    let format_id = profile
        .identification
        .as_ref()
        .and_then(|i| i.primary.as_ref().map(|p| p.format_id.clone()));
    if let Some(fid) = format_id {
        if let Some(parser) = parsers::get_parser(&fid) {
            if profile.discovered.size <= config.max_file_size {
                // read file bounded
                match std::fs::read(path) {
                    Ok(data) => {
                        match parser.parse(&data, profile.discovered.size, config) {
                            Ok(report) => {
                                // metadata
                                let meta = parser.metadata(&report);
                                // structural fingerprint
                                let sf = fingerprint::structural_fingerprint(&report);
                                let mf = fingerprint::metadata_fingerprint(&meta);
                                profile.structural_fingerprint = Some(sf);
                                profile.metadata = Some(meta);
                                profile.metadata_fingerprint = Some(mf);
                                profile.structure = Some(report);
                            }
                            Err(e) => {
                                profile.analysis_errors.push(format!("parse: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        profile.analysis_errors.push(format!("read: {}", e));
                    }
                }
            } else {
                profile
                    .analysis_errors
                    .push("file exceeds max size for parsing".into());
            }
        }
    }

    // Content fingerprint (streaming)
    match fingerprint::sha256_file(path, 1024 * 1024) {
        Ok(fp) => profile.content_fingerprint = Some(fp),
        Err(e) => profile.analysis_errors.push(format!("hash: {}", e)),
    }
    if config.enable_blake3 {
        if let Ok(fp) = fingerprint::blake3_file(path, 1024 * 1024) {
            // store? We only have one slot; skip or store in evidence? Keep sha256 primary.
            let _ = fp;
        }
    }

    // Integrity
    profile.integrity = Some(integrity::evaluate(&profile, None));

    profile
}

pub fn analyze_paths(paths: &[std::path::PathBuf], config: &Config) -> Vec<FileProfile> {
    let mut out = Vec::new();
    for p in paths {
        out.push(analyze_file(p, config));
    }
    out
}
