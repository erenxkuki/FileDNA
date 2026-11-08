use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

fn octal_field(b: &[u8]) -> u64 {
    let s = String::from_utf8_lossy(b);
    let s = s.trim_matches('\0').trim();
    if s.is_empty() {
        return 0;
    }
    u64::from_str_radix(s.trim_start_matches('0').max("0"), 8).unwrap_or(0)
}

pub struct TarParser;
impl FormatParser for TarParser {
    fn format_id(&self) -> &'static str {
        "tar"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 263 && &data[257..262] == b"ustar" {
            return (true, 0.3, vec!["TAR ustar magic matched".into()]);
        }
        // fallback: maybe no magic but blocks; require at least one valid header? keep simple
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 512 {
            return Err(FileDnaError::Parse {
                subsystem: "tar".into(),
                message: "too short".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut pos = 0usize;
        let mut entry_count = 0u64;
        let mut total_size = 0u64;
        while pos + 512 <= data.len() {
            let block = &data[pos..pos + 512];
            if block.iter().all(|&b| b == 0) {
                // end
                break;
            }
            if block.len() < 512 {
                break;
            }
            let name = String::from_utf8_lossy(&block[0..100])
                .trim_matches('\0')
                .to_string();
            if name.is_empty() {
                warnings.push("empty entry name".into());
            }
            let size = octal_field(&block[124..136]);
            let typeflag = block[156];
            let magic = &block[257..263];
            let mut fields = BTreeMap::new();
            fields.insert("name".into(), serde_json::json!(name));
            fields.insert("size".into(), serde_json::json!(size));
            fields.insert("typeflag".into(), serde_json::json!(typeflag));
            fields.insert(
                "magic".into(),
                serde_json::json!(String::from_utf8_lossy(magic)),
            );
            let mut n = pmod::node(
                "entry",
                pos as u64,
                Some(512 + ((size + 511) / 512) * 512),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            total_size += size;
            pos += 512 + (((size as usize) + 511) / 512) * 512;
            entry_count += 1;
            if entry_count > config.max_archive_entries {
                errors.push("too many entries".into());
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        root_fields.insert("entry_count".into(), serde_json::json!(entry_count));
        root_fields.insert("total_size".into(), serde_json::json!(total_size));
        let mut root = pmod::node(
            "tar",
            0,
            Some(file_size),
            if errors.is_empty() {
                NodeStatus::Valid
            } else {
                NodeStatus::Partial
            },
        );
        root.fields = root_fields;
        root.children = nodes.clone();
        Ok(pmod::make_report(
            "tar",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            true,
            None,
        ))
    }
    fn metadata(&self, report: &StructuralReport) -> MetadataReport {
        let mut fields = BTreeMap::new();
        if let Some(root) = &report.root {
            for (k, v) in &root.fields {
                fields.insert(k.clone(), v.clone());
            }
        }
        fields.insert("format".into(), serde_json::json!("TAR"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
