use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::BTreeMap;
use std::io::Cursor;

pub struct ZipParser;
impl FormatParser for ZipParser {
    fn format_id(&self) -> &'static str {
        "zip"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 4
            && (data[..4] == *b"PK\x03\x04"
                || data[..4] == *b"PK\x05\x06"
                || data[..4] == *b"PK\x07\x08")
        {
            return (true, 0.3, vec!["ZIP signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 22 {
            return Err(FileDnaError::Parse {
                subsystem: "zip".into(),
                message: "too short".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        // find EOCD
        let search_start = data.len().saturating_sub(65557);
        let mut eocd_pos = None;
        let mut i = data.len().saturating_sub(22);
        while i >= search_start {
            if i + 4 <= data.len() && data[i..i + 4] == *b"PK\x05\x06" {
                eocd_pos = Some(i);
                break;
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let mut entry_count = 0u64;
        let mut total_uncompressed = 0u64;
        let mut cd_offset = 0usize;
        if let Some(ep) = eocd_pos {
            nodes.push(pmod::node("EOCD", ep as u64, Some(22), NodeStatus::Valid));
            if ep + 22 <= data.len() {
                let disk = u16::from_le_bytes([data[ep + 4], data[ep + 5]]) as u64;
                let cd_disk = u16::from_le_bytes([data[ep + 6], data[ep + 7]]) as u64;
                entry_count = u16::from_le_bytes([data[ep + 8], data[ep + 9]]) as u64;
                let total_entries = u16::from_le_bytes([data[ep + 10], data[ep + 11]]) as u64;
                let cd_size = u32::from_le_bytes([
                    data[ep + 12],
                    data[ep + 13],
                    data[ep + 14],
                    data[ep + 15],
                ]) as usize;
                cd_offset = u32::from_le_bytes([
                    data[ep + 16],
                    data[ep + 17],
                    data[ep + 18],
                    data[ep + 19],
                ]) as usize;
                let comment_len = u16::from_le_bytes([data[ep + 20], data[ep + 21]]) as usize;
                if disk != 0 || cd_disk != 0 {
                    warnings.push("multi-disk zip not fully supported".into());
                }
                if entry_count != total_entries {
                    warnings.push("entry count mismatch between this disk and total".into());
                }
                if config.max_archive_entries > 0 && entry_count > config.max_archive_entries {
                    errors.push(format!(
                        "entry count {} exceeds limit {}",
                        entry_count, config.max_archive_entries
                    ));
                }
                // parse central directory
                let mut pos = cd_offset;
                let cd_end = (cd_offset + cd_size).min(data.len());
                let mut parsed = 0u64;
                while pos + 46 <= cd_end && parsed < entry_count {
                    if data[pos..pos + 4] != *b"PK\x01\x02" {
                        break;
                    }
                    let method = u16::from_le_bytes([data[pos + 10], data[pos + 11]]);
                    let usize_file = u32::from_le_bytes([
                        data[pos + 24],
                        data[pos + 25],
                        data[pos + 26],
                        data[pos + 27],
                    ]) as u64;
                    let csize = u32::from_le_bytes([
                        data[pos + 20],
                        data[pos + 21],
                        data[pos + 22],
                        data[pos + 23],
                    ]) as u64;
                    let name_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
                    let extra_len = u16::from_le_bytes([data[pos + 30], data[pos + 31]]) as usize;
                    let comment_len_e =
                        u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;
                    let name = if pos + 46 + name_len <= data.len() {
                        String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).to_string()
                    } else {
                        String::new()
                    };
                    total_uncompressed = total_uncompressed.saturating_add(usize_file);
                    let mut fields = BTreeMap::new();
                    fields.insert("name".into(), serde_json::json!(name));
                    fields.insert("method".into(), serde_json::json!(method));
                    fields.insert("compressed_size".into(), serde_json::json!(csize));
                    fields.insert("uncompressed_size".into(), serde_json::json!(usize_file));
                    let mut n = pmod::node(
                        "central_entry",
                        pos as u64,
                        Some((46 + name_len + extra_len + comment_len_e) as u64),
                        NodeStatus::Valid,
                    );
                    n.fields = fields;
                    nodes.push(n);
                    pos += 46 + name_len + extra_len + comment_len_e;
                    parsed += 1;
                }
                if parsed < entry_count {
                    warnings.push(format!(
                        "parsed {} of {} central entries",
                        parsed, entry_count
                    ));
                }
                // zip bomb check
                if total_uncompressed > config.max_decompressed_bytes {
                    warnings.push(format!(
                        "declared uncompressed size {} exceeds configured limit {}",
                        total_uncompressed, config.max_decompressed_bytes
                    ));
                }
            }
        } else {
            warnings.push("EOCD not found; may be truncated or not a zip".into());
        }
        let mut root_fields = BTreeMap::new();
        root_fields.insert("entry_count".into(), serde_json::json!(entry_count));
        root_fields.insert(
            "total_uncompressed_declared".into(),
            serde_json::json!(total_uncompressed),
        );
        let mut root = pmod::node(
            "zip",
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
            "zip",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            eocd_pos.is_some(),
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
        // count entries from children
        fields.insert("format".into(), serde_json::json!("ZIP"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
