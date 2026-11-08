use crate::types::*;
use std::path::Path;

pub fn to_json(
    profiles: &[FileProfile],
    job: Option<&AnalysisJob>,
) -> Result<String, crate::FileDnaError> {
    let mut v = serde_json::json!({
        "files": profiles,
        "job": job,
    });
    Ok(
        serde_json::to_string_pretty(&v)
            .map_err(|e| crate::FileDnaError::Unknown(e.to_string()))?,
    )
}

pub fn to_text(profiles: &[FileProfile]) -> String {
    let mut out = String::new();
    out.push_str("FileDNA Report\n");
    out.push_str(&format!("Files analyzed: {}\n\n", profiles.len()));
    for p in profiles {
        out.push_str(&format!("--- {}\n", p.discovered.path.display()));
        out.push_str(&format!("  size: {} bytes\n", p.discovered.size));
        if let Some(id) = &p.identification {
            if let Some(primary) = &id.primary {
                out.push_str(&format!(
                    "  detected format: {} ({})\n",
                    primary.format_id,
                    primary.confidence.as_str()
                ));
                out.push_str(&format!(
                    "  confidence score: {:.2}\n",
                    primary.confidence_score
                ));
            } else {
                out.push_str("  detected format: unknown\n");
            }
            if id.extension_mismatch {
                out.push_str(&format!(
                    "  extension mismatch: claimed '{}'\n",
                    id.claimed_extension.clone().unwrap_or_default()
                ));
            }
        }
        if let Some(fp) = &p.content_fingerprint {
            out.push_str(&format!("  sha256: {}\n", fp.hex));
        }
        if let Some(int) = &p.integrity {
            out.push_str(&format!("  integrity: {}\n", int.state.as_str()));
        }
        if !p.analysis_errors.is_empty() {
            out.push_str(&format!("  errors: {}\n", p.analysis_errors.join("; ")));
        }
        out.push('\n');
    }
    out
}

pub fn write_report(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}
