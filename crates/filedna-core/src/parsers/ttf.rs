use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct FontParser;
impl FormatParser for FontParser {
    fn format_id(&self) -> &'static str {
        "ttf"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 4 {
            if data[..4] == [0x00, 0x01, 0x00, 0x00]
                || data[..4] == *b"OTTO"
                || data[..4] == *b"ttcf"
                || data[..4] == *b"true"
            {
                return (true, 0.25, vec!["Font sfnt header matched".into()]);
            }
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 12 {
            return Err(FileDnaError::Parse {
                subsystem: "font".into(),
                message: "too short".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let version = &data[..4];
        let num_tables = u16::from_be_bytes([data[4], data[5]]) as usize;
        let mut pos = 12usize;
        let mut table_tags = Vec::new();
        for _ in 0..num_tables {
            if pos + 16 > data.len() {
                errors.push("truncated table dir".into());
                break;
            }
            let tag = String::from_utf8_lossy(&data[pos..pos + 4]).to_string();
            let checksum =
                u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let offset =
                u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
            let length = u32::from_be_bytes([
                data[pos + 12],
                data[pos + 13],
                data[pos + 14],
                data[pos + 15],
            ]);
            // validate bounds
            if offset as usize + length as usize > data.len() {
                warnings.push(format!("table {} out of bounds", tag));
            }
            let mut fields = BTreeMap::new();
            fields.insert("tag".into(), serde_json::json!(tag));
            fields.insert("checksum".into(), serde_json::json!(checksum));
            fields.insert("offset".into(), serde_json::json!(offset));
            fields.insert("length".into(), serde_json::json!(length));
            let mut n = pmod::node(
                &format!("table:{}", tag),
                pos as u64,
                Some(16),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            table_tags.push(tag);
            pos += 16;
        }
        let mut root_fields = BTreeMap::new();
        root_fields.insert(
            "sfnt_version".into(),
            serde_json::json!(String::from_utf8_lossy(version)),
        );
        root_fields.insert("num_tables".into(), serde_json::json!(num_tables));
        root_fields.insert("tables".into(), serde_json::json!(table_tags));
        let mut root = pmod::node(
            "font",
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
            "ttf",
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
        fields.insert("format".into(), serde_json::json!("Font"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
