use crate::types::*;
use std::path::Path;

pub fn evaluate(profile: &FileProfile, expected_hash: Option<&str>) -> IntegrityResult {
    let mut checks = Vec::new();
    let mut evidence_ids = profile
        .evidence
        .iter()
        .map(|e| e.id.clone())
        .collect::<Vec<_>>();

    // structural consistency
    let struct_ok = profile
        .structure
        .as_ref()
        .map(|s| s.errors.is_empty())
        .unwrap_or(false);
    let struct_complete = profile
        .structure
        .as_ref()
        .map(|s| s.complete)
        .unwrap_or(false);

    checks.push(IntegrityCheck {
        name: "structural_parse".into(),
        passed: Some(struct_ok),
        detail: if struct_ok {
            "parser reported no errors".into()
        } else {
            format!(
                "parser reported {} errors",
                profile
                    .structure
                    .as_ref()
                    .map(|s| s.errors.len())
                    .unwrap_or(0)
            )
        },
    });

    if let Some(exp) = expected_hash {
        let actual = profile.content_fingerprint.as_ref().map(|f| f.hex.clone());
        let matched = actual.as_deref() == Some(exp);
        checks.push(IntegrityCheck {
            name: "expected_hash".into(),
            passed: Some(matched),
            detail: if matched {
                "content hash matches expected".into()
            } else {
                format!(
                    "expected {} but got {}",
                    exp,
                    actual.unwrap_or_else(|| "<none>".into())
                )
            },
        });
        let state = if matched {
            IntegrityState::VerifiedAgainstExpectedHash
        } else {
            IntegrityState::HashMismatch
        };
        return IntegrityResult {
            state,
            checks,
            evidence_ids,
        };
    }

    // no expected hash
    if profile.structure.is_none() {
        checks.push(IntegrityCheck {
            name: "structure_available".into(),
            passed: Some(false),
            detail: "no structural analysis available".into(),
        });
        return IntegrityResult {
            state: IntegrityState::InsufficientEvidence,
            checks,
            evidence_ids,
        };
    }

    if struct_ok && struct_complete {
        IntegrityResult {
            state: IntegrityState::StructurallyValid,
            checks,
            evidence_ids,
        }
    } else if struct_ok {
        IntegrityResult {
            state: IntegrityState::PartiallyVerified,
            checks,
            evidence_ids,
        }
    } else {
        IntegrityResult {
            state: IntegrityState::StructurallyInconsistent,
            checks,
            evidence_ids,
        }
    }
}

pub fn verify_hash_file(path: &Path, expected: &str, algo: &str) -> crate::Result<bool> {
    let fp = if algo == "blake3" {
        crate::fingerprint::blake3_file(path, 1024 * 1024)?
    } else {
        crate::fingerprint::sha256_file(path, 1024 * 1024)?
    };
    Ok(fp.hex.eq_ignore_ascii_case(expected))
}
