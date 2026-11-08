use crate::types::*;
use std::collections::BTreeMap;

pub fn find_exact_duplicates(profiles: &[FileProfile]) -> Vec<DuplicateGroup> {
    let mut groups_map: BTreeMap<String, Vec<&FileProfile>> = BTreeMap::new();
    for p in profiles {
        if let Some(fp) = &p.content_fingerprint {
            groups_map.entry(fp.hex.clone()).or_default().push(p);
        }
    }
    let mut out = Vec::new();
    for (hash, members) in groups_map {
        if members.len() < 2 {
            continue;
        }
        out.push(DuplicateGroup {
            id: format!("dup-exact-{}", hash[..8].to_string()),
            kind: DuplicateKind::ExactContent,
            files: members.iter().map(|p| p.discovered.path.clone()).collect(),
            content_hash: Some(hash),
            evidence: vec!["Complete content hash match (SHA-256)".into()],
        });
    }
    out
}

pub fn find_structural_duplicates(profiles: &[FileProfile]) -> Vec<DuplicateGroup> {
    let mut groups_map: BTreeMap<String, Vec<&FileProfile>> = BTreeMap::new();
    for p in profiles {
        if let Some(fp) = &p.structural_fingerprint {
            groups_map.entry(fp.value.clone()).or_default().push(p);
        }
    }
    let mut out = Vec::new();
    for (fp, members) in groups_map {
        if members.len() < 2 {
            continue;
        }
        // ensure not all exact same content? structural duplicate can include exact; still report
        out.push(DuplicateGroup {
            id: format!("dup-struct-{}", fp[..8].to_string()),
            kind: DuplicateKind::Structural,
            files: members.iter().map(|p| p.discovered.path.clone()).collect(),
            content_hash: None,
            evidence: vec!["Normalized structural fingerprint match".into()],
        });
    }
    out
}

pub fn find_metadata_duplicates(profiles: &[FileProfile]) -> Vec<DuplicateGroup> {
    let mut groups_map: BTreeMap<String, Vec<&FileProfile>> = BTreeMap::new();
    for p in profiles {
        if let Some(fp) = &p.metadata_fingerprint {
            groups_map.entry(fp.value.clone()).or_default().push(p);
        }
    }
    let mut out = Vec::new();
    for (fp, members) in groups_map {
        if members.len() < 2 {
            continue;
        }
        out.push(DuplicateGroup {
            id: format!("dup-meta-{}", fp[..8].to_string()),
            kind: DuplicateKind::Metadata,
            files: members.iter().map(|p| p.discovered.path.clone()).collect(),
            content_hash: None,
            evidence: vec!["Metadata fingerprint match".into()],
        });
    }
    out
}

pub fn find_potential_duplicates(profiles: &[FileProfile]) -> Vec<DuplicateGroup> {
    // Group by file size; within same size with differing content hashes => potential.
    let mut by_size: BTreeMap<u64, Vec<&FileProfile>> = BTreeMap::new();
    for p in profiles {
        by_size.entry(p.discovered.size).or_default().push(p);
    }
    let mut out = Vec::new();
    for (size, members) in by_size {
        if members.len() < 2 {
            continue;
        }
        // if not all exact duplicates
        let hashes: std::collections::BTreeSet<_> = members
            .iter()
            .filter_map(|p| p.content_fingerprint.as_ref().map(|f| f.hex.clone()))
            .collect();
        if hashes.len() <= 1 {
            continue;
        }
        out.push(DuplicateGroup {
            id: format!("dup-potential-{}", size),
            kind: DuplicateKind::Potential,
            files: members.iter().map(|p| p.discovered.path.clone()).collect(),
            content_hash: None,
            evidence: vec![format!(
                "Same size ({} bytes) but differing content hashes",
                size
            )],
        });
    }
    out
}
