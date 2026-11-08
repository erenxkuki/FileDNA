use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct JpegParser;

impl FormatParser for JpegParser {
    fn format_id(&self) -> &'static str {
        "jpeg"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
            return (true, 0.3, vec!["JPEG SOI signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
            return Err(FileDnaError::Parse {
                subsystem: "jpeg".into(),
                message: "missing SOI".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut width = None;
        let mut height = None;
        nodes.push(pmod::node("SOI", 0, Some(2), NodeStatus::Valid));
        let mut i = 2usize;
        let mut complete = false;
        let mut seg_count = 0;
        while i < data.len() {
            // skip padding zeros
            while i < data.len() && data[i] == 0x00 {
                i += 1;
            }
            if i >= data.len() {
                break;
            }
            if data[i] != 0xFF {
                // entropy data; stop
                break;
            }
            while i < data.len() && data[i] == 0xFF {
                i += 1;
            }
            if i >= data.len() {
                break;
            }
            let marker = data[i];
            let marker_offset = i - 1; // position of first 0xFF? approximate
            i += 1;
            if marker == 0xD9 {
                nodes.push(pmod::node(
                    "EOI",
                    marker_offset as u64,
                    Some(2),
                    NodeStatus::Valid,
                ));
                complete = true;
                break;
            }
            if marker == 0xDA {
                nodes.push(pmod::node(
                    "SOS",
                    marker_offset as u64,
                    Some(2),
                    NodeStatus::Valid,
                ));
                // find EOI
                let mut j = i;
                let mut found = false;
                while j + 1 < data.len() {
                    if data[j] == 0xFF && data[j + 1] == 0xD9 {
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if found {
                    complete = true;
                } else {
                    warnings.push("EOI not found after SOS".into());
                }
                break;
            }
            if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
                nodes.push(pmod::node(
                    &format!("marker:{:02X}", marker),
                    marker_offset as u64,
                    Some(1),
                    NodeStatus::Valid,
                ));
                continue;
            }
            if i + 2 > data.len() {
                errors.push("truncated segment length".into());
                break;
            }
            let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
            if len < 2 || i + len > data.len() {
                errors.push(format!("invalid segment length {} at {}", len, i));
                break;
            }
            let seg_data = &data[i + 2..i + len];
            let mut fields = BTreeMap::new();
            fields.insert(
                "marker".into(),
                serde_json::json!(format!("{:02X}", marker)),
            );
            fields.insert("length".into(), serde_json::json!(len));
            if matches!(
                marker,
                0xC0 | 0xC1
                    | 0xC2
                    | 0xC3
                    | 0xC5
                    | 0xC6
                    | 0xC7
                    | 0xC9
                    | 0xCA
                    | 0xCB
                    | 0xCD
                    | 0xCE
                    | 0xCF
            ) {
                if seg_data.len() >= 5 {
                    let precision = seg_data[0];
                    let h = u16::from_be_bytes([seg_data[1], seg_data[2]]);
                    let w = u16::from_be_bytes([seg_data[3], seg_data[4]]);
                    height = Some(h as u32);
                    width = Some(w as u32);
                    fields.insert("precision".into(), serde_json::json!(precision));
                    fields.insert("height".into(), serde_json::json!(h));
                    fields.insert("width".into(), serde_json::json!(w));
                }
            }
            let mut n = pmod::node(
                &format!("segment:{:02X}", marker),
                marker_offset as u64,
                Some(len as u64),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            i += len;
            seg_count += 1;
            if seg_count as u64 > config.max_parse_depth as u64 * 100 {
                errors.push("too many segments".into());
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
            "jpeg",
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
            "jpeg",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            complete,
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
        fields.insert("format".into(), serde_json::json!("JPEG"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
