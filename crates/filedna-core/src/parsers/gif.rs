use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct GifParser;
impl FormatParser for GifParser {
    fn format_id(&self) -> &'static str {
        "gif"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 6 && (data[..6] == *b"GIF87a" || data[..6] == *b"GIF89a") {
            return (true, 0.3, vec!["GIF signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        if data.len() < 13 {
            return Err(FileDnaError::Parse {
                subsystem: "gif".into(),
                message: "too short".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let sig = &data[..6];
        nodes.push(pmod::node("header", 0, Some(6), NodeStatus::Valid));
        // logical screen descriptor
        let width = u16::from_le_bytes([data[6], data[7]]);
        let height = u16::from_le_bytes([data[8], data[9]]);
        let packed = data[10];
        let bg = data[11];
        let aspect = data[12];
        let mut fields = BTreeMap::new();
        fields.insert("width".into(), serde_json::json!(width));
        fields.insert("height".into(), serde_json::json!(height));
        fields.insert("packed".into(), serde_json::json!(packed));
        fields.insert("bg_color_index".into(), serde_json::json!(bg));
        fields.insert("aspect_ratio".into(), serde_json::json!(aspect));
        let mut lsd = pmod::node("logical_screen_descriptor", 6, Some(7), NodeStatus::Valid);
        lsd.fields = fields;
        nodes.push(lsd);
        // color table if flag
        let mut pos = 13usize;
        if packed & 0x80 != 0 {
            let size = 3 * (1usize << ((packed & 0x07) + 1));
            if pos + size <= data.len() {
                nodes.push(pmod::node(
                    "global_color_table",
                    pos as u64,
                    Some(size as u64),
                    NodeStatus::Valid,
                ));
                pos += size;
            } else {
                errors.push("truncated color table".into());
            }
        }
        // parse blocks
        let mut complete = false;
        let mut block_count = 0;
        while pos < data.len() {
            match data[pos] {
                0x3B => {
                    // trailer
                    nodes.push(pmod::node(
                        "trailer",
                        pos as u64,
                        Some(1),
                        NodeStatus::Valid,
                    ));
                    complete = true;
                    pos += 1;
                    break;
                }
                0x21 => {
                    // extension
                    if pos + 2 > data.len() {
                        errors.push("truncated extension".into());
                        break;
                    }
                    let label = data[pos + 1];
                    // skip blocks
                    pos += 2;
                    while pos < data.len() && data[pos] != 0 {
                        let sz = data[pos] as usize;
                        pos += 1 + sz;
                        if pos > data.len() {
                            errors.push("truncated extension block".into());
                            break;
                        }
                    }
                    pos += 1; // terminator
                    nodes.push(pmod::node(
                        &format!("extension:{:02X}", label),
                        pos as u64,
                        None,
                        NodeStatus::Valid,
                    ));
                }
                0x2C => {
                    // image descriptor
                    if pos + 10 > data.len() {
                        errors.push("truncated image descriptor".into());
                        break;
                    }
                    pos += 10;
                    // local color table
                    // we don't deeply parse; skip LZW min code size
                    if pos < data.len() {
                        pos += 1; // lzw min
                    }
                    // skip data sub-blocks
                    while pos < data.len() && data[pos] != 0 {
                        let sz = data[pos] as usize;
                        pos += 1 + sz;
                        if pos > data.len() {
                            break;
                        }
                    }
                    pos += 1;
                    nodes.push(pmod::node("image", pos as u64, None, NodeStatus::Valid));
                }
                _ => {
                    warnings.push(format!("unexpected byte {} at {}", data[pos], pos));
                    pos += 1;
                }
            }
            block_count += 1;
            if block_count > 100000 {
                errors.push("too many blocks".into());
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        root_fields.insert("width".into(), serde_json::json!(width));
        root_fields.insert("height".into(), serde_json::json!(height));
        root_fields.insert(
            "version".into(),
            serde_json::json!(String::from_utf8_lossy(sig)),
        );
        let mut root = pmod::node(
            "gif",
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
            "gif",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            complete,
            Some(String::from_utf8_lossy(sig).to_string()),
        ))
    }
    fn metadata(&self, report: &StructuralReport) -> MetadataReport {
        let mut fields = BTreeMap::new();
        if let Some(root) = &report.root {
            for (k, v) in &root.fields {
                fields.insert(k.clone(), v.clone());
            }
        }
        fields.insert("format".into(), serde_json::json!("GIF"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
