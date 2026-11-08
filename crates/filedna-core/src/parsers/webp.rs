use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::BTreeMap;
use std::io::Cursor;

pub struct WebpParser;
impl FormatParser for WebpParser {
    fn format_id(&self) -> &'static str {
        "webp"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
            return (true, 0.35, vec!["WebP RIFF/WEBP signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
            return Err(FileDnaError::Parse {
                subsystem: "webp".into(),
                message: "missing RIFF/WEBP".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let riff_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        nodes.push(pmod::node("RIFF_header", 0, Some(12), NodeStatus::Valid));
        let mut pos = 12usize;
        let mut width = None;
        let mut height = None;
        let mut chunk_count = 0;
        while pos + 8 <= data.len() {
            let ctype = &data[pos..pos + 4];
            let csize =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                    as usize;
            if pos + 8 + csize > data.len() {
                errors.push(format!(
                    "chunk {} truncated",
                    String::from_utf8_lossy(ctype)
                ));
                break;
            }
            let mut fields = BTreeMap::new();
            fields.insert(
                "type".into(),
                serde_json::json!(String::from_utf8_lossy(ctype)),
            );
            fields.insert("size".into(), serde_json::json!(csize));
            // parse dimensions for VP8X
            if ctype == b"VP8X" && csize >= 10 {
                let d = &data[pos + 8..];
                let w = 1 + u32::from_le_bytes([d[4], d[5], d[6], 0]);
                let h = 1 + u32::from_le_bytes([d[7], d[8], d[9], 0]);
                width = Some(w);
                height = Some(h);
                fields.insert("width".into(), serde_json::json!(w));
                fields.insert("height".into(), serde_json::json!(h));
            }
            if ctype == b"VP8 " && csize >= 10 {
                // VP8 bitstream: dimensions at offset 6-9 (3 bytes each? actually 14 bits)
                let d = &data[pos + 10..]; // skip frame tag? approximate
                if d.len() >= 4 {
                    let w = u16::from_le_bytes([d[0], d[1]]) as u32 & 0x3FFF;
                    let h = u16::from_le_bytes([d[2], d[3]]) as u32 & 0x3FFF;
                    width = Some(w);
                    height = Some(h);
                    fields.insert("width".into(), serde_json::json!(w));
                    fields.insert("height".into(), serde_json::json!(h));
                }
            }
            let mut n = pmod::node(
                &format!("chunk:{}", String::from_utf8_lossy(ctype)),
                pos as u64,
                Some((8 + csize) as u64),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            pos += 8 + csize;
            if csize % 2 == 1 {
                pos += 1;
            } // padding
            chunk_count += 1;
            if chunk_count as u64 > config.max_parse_depth as u64 * 100 {
                errors.push("too many chunks".into());
                break;
            }
            if pos >= 12 + riff_size {
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        if let Some(w) = width {
            root_fields.insert("width".into(), serde_json::json!(w));
        }
        if let Some(h) = height {
            root_fields.insert("height".into(), serde_json::json!(h));
        }
        let mut root = pmod::node(
            "webp",
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
            "webp",
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
        fields.insert("format".into(), serde_json::json!("WebP"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
