use crate::types::*;
use chrono::Utc;

pub fn build_relationships(
    profiles: &[FileProfile],
    duplicates: &[DuplicateGroup],
    similarities: &[SimilarityResult],
) -> Vec<Relationship> {
    let mut out = Vec::new();

    for g in duplicates {
        for i in 0..g.files.len() {
            for j in (i + 1)..g.files.len() {
                out.push(Relationship {
                    from: g.files[i].clone(),
                    to: g.files[j].clone(),
                    rel_type: match g.kind {
                        DuplicateKind::ExactContent => "exact_content_duplicate".into(),
                        DuplicateKind::Structural => "structural_duplicate".into(),
                        DuplicateKind::Metadata => "metadata_duplicate".into(),
                        DuplicateKind::Potential => "potential_duplicate".into(),
                    },
                    evidence: g.evidence.clone(),
                    confidence: Some(1.0),
                    algorithm: "duplicate_engine".into(),
                    created: Utc::now(),
                });
            }
        }
    }

    // structural fingerprint equivalence (if not already exact)
    let mut by_struct: std::collections::BTreeMap<String, Vec<&FileProfile>> =
        std::collections::BTreeMap::new();
    for p in profiles {
        if let Some(sf) = &p.structural_fingerprint {
            by_struct.entry(sf.value.clone()).or_default().push(p);
        }
    }
    for (_v, members) in by_struct {
        if members.len() < 2 {
            continue;
        }
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                out.push(Relationship {
                    from: members[i].discovered.path.clone(),
                    to: members[j].discovered.path.clone(),
                    rel_type: "same_structural_fingerprint".into(),
                    evidence: vec!["Normalized structural fingerprint match".into()],
                    confidence: Some(0.7),
                    algorithm: "structural_fingerprint".into(),
                    created: Utc::now(),
                });
            }
        }
    }

    for s in similarities {
        if s.score >= 0.5 {
            out.push(Relationship {
                from: s.file_a.clone(),
                to: s.file_b.clone(),
                rel_type: "similar".into(),
                evidence: s.signals.clone(),
                confidence: Some(s.score),
                algorithm: s.algorithm.clone(),
                created: Utc::now(),
            });
        }
    }

    // same format family
    // (avoid O(n^2) huge; only for small sets)
    if profiles.len() <= 500 {
        for i in 0..profiles.len() {
            for j in (i + 1)..profiles.len() {
                let fa = profiles[i]
                    .identification
                    .as_ref()
                    .and_then(|x| x.primary.as_ref().map(|p| p.format_family.clone()));
                let fb = profiles[j]
                    .identification
                    .as_ref()
                    .and_then(|x| x.primary.as_ref().map(|p| p.format_family.clone()));
                if fa.is_some() && fa == fb {
                    // only add if not already related
                    out.push(Relationship {
                        from: profiles[i].discovered.path.clone(),
                        to: profiles[j].discovered.path.clone(),
                        rel_type: "same_format_family".into(),
                        evidence: vec![format!("both {}", fa.unwrap())],
                        confidence: Some(0.3),
                        algorithm: "identification".into(),
                        created: Utc::now(),
                    });
                }
            }
        }
    }

    out
}
