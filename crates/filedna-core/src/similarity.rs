use crate::types::*;

pub fn compare_profiles(a: &FileProfile, b: &FileProfile) -> SimilarityResult {
    let mut signals = Vec::new();
    let mut score = 0.0f64;
    let mut count = 0;

    // format family
    let fa = a
        .identification
        .as_ref()
        .and_then(|i| i.primary.as_ref().map(|p| p.format_family.clone()));
    let fb = b
        .identification
        .as_ref()
        .and_then(|i| i.primary.as_ref().map(|p| p.format_family.clone()));
    if fa.is_some() && fa == fb {
        score += 0.2;
        signals.push(format!("same format family: {}", fa.unwrap()));
        count += 1;
    }

    // size equality
    if a.discovered.size == b.discovered.size && a.discovered.size > 0 {
        score += 0.1;
        signals.push("same file size".into());
        count += 1;
    }

    // dimensions (from metadata)
    let dim_a = a.metadata.as_ref().and_then(|m| {
        let w = m.fields.get("width")?.as_u64()?;
        let h = m.fields.get("height")?.as_u64()?;
        Some((w, h))
    });
    let dim_b = b.metadata.as_ref().and_then(|m| {
        let w = m.fields.get("width")?.as_u64()?;
        let h = m.fields.get("height")?.as_u64()?;
        Some((w, h))
    });
    if let (Some(da), Some(db)) = (dim_a, dim_b) {
        if da == db {
            score += 0.3;
            signals.push(format!("same dimensions {}x{}", da.0, da.1));
        } else {
            // closeness
            let dw = (da.0 as i64 - db.0 as i64).abs() as f64;
            let dh = (da.1 as i64 - db.1 as i64).abs() as f64;
            if dw < 100.0 && dh < 100.0 {
                score += 0.1;
                signals.push("similar dimensions".into());
            }
        }
        count += 1;
    }

    // structural fingerprint equality
    if let (Some(sa), Some(sb)) = (&a.structural_fingerprint, &b.structural_fingerprint) {
        if sa.value == sb.value {
            score += 0.3;
            signals.push("identical structural fingerprint".into());
        }
        count += 1;
    }

    // content hash equality handled by duplicates; if equal score 1
    if let (Some(ha), Some(hb)) = (&a.content_fingerprint, &b.content_fingerprint) {
        if ha.hex == hb.hex {
            score = 1.0;
            signals.push("identical content hash".into());
        }
        count += 1;
    }

    if count == 0 {
        score = 0.0;
    }
    let score = score.min(1.0);
    SimilarityResult {
        file_a: a.discovered.path.clone(),
        file_b: b.discovered.path.clone(),
        score,
        signals,
        algorithm: "basic_multi_signal".into(),
        version: "1.0".into(),
    }
}

pub fn compare_all(profiles: &[FileProfile]) -> Vec<SimilarityResult> {
    let mut out = Vec::new();
    for i in 0..profiles.len() {
        for j in (i + 1)..profiles.len() {
            let r = compare_profiles(&profiles[i], &profiles[j]);
            if r.score >= 0.3 {
                out.push(r);
            }
        }
    }
    out
}
