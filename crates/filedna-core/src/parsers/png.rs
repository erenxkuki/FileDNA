use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::BTreeMap;
use std::io::Cursor;

pub struct PngParser;

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &b in data {
        let mut c = crc ^ (b as u32);
        for _ in 0..8 {
            if c & 1 == 1 {
                c = 0xedb88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        crc = c;
    }
    crc ^ 0xffffffff
}

impl FormatParser for PngParser {
    fn format_id(&self) -> &'static str {
        "png"
    }

    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 8 && data[..8] == *PNG_SIG {
            let mut notes = vec!["PNG signature matched".into()];
            // check IHDR chunk at offset 8
            if data.len() >= 24 {
                let len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
                if &data[12..16] == b"IHDR" && len == 13 {
                    notes.push("IHDR chunk present with correct length".into());
                    return (true, 0.35, notes);
                }
            }
            return (true, 0.2, notes);
        }
        (false, 0.0, vec![])
    }

    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 8 || data[..8] != *PNG_SIG {
            return Err(FileDnaError::Parse {
                subsystem: "png".into(),
                message: "missing PNG signature".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut offset: usize = 8;

        // signature node
        nodes.push(pmod::node("signature", 0, Some(8), NodeStatus::Valid));

        // IHDR fields
        let mut width = None;
        let mut height = None;
        let mut bit_depth = None;
        let mut color_type = None;

        let mut chunk_index = 0;
        let mut seen_iend = false;
        while offset < data.len() {
            if offset + 12 > data.len() {
                errors.push(format!("truncated chunk header at offset {}", offset));
                break;
            }
            let length = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            let ctype = &data[offset + 4..offset + 8];
            let ctype_str = String::from_utf8_lossy(ctype).to_string();
            if offset + 12 + length > data.len() {
                errors.push(format!(
                    "chunk {} length {} exceeds file at offset {}",
                    ctype_str, length, offset
                ));
                break;
            }
            let chunk_data = &data[offset + 8..offset + 8 + length];
            let crc_expected = u32::from_be_bytes([
                data[offset + 8 + length],
                data[offset + 9 + length],
                data[offset + 10 + length],
                data[offset + 11 + length],
            ]);
            let mut crc_input = Vec::with_capacity(4 + length);
            crc_input.extend_from_slice(ctype);
            crc_input.extend_from_slice(chunk_data);
            let crc_calc = crc32(&crc_input);
            let crc_ok = crc_calc == crc_expected;

            let mut fields = BTreeMap::new();
            fields.insert("type".into(), serde_json::json!(ctype_str));
            fields.insert("length".into(), serde_json::json!(length));
            fields.insert("crc_ok".into(), serde_json::json!(crc_ok));
            if !crc_ok {
                warnings.push(format!(
                    "CRC mismatch in chunk {} at offset {}",
                    ctype_str, offset
                ));
            }

            if ctype == b"IHDR" && length == 13 {
                let mut c = Cursor::new(chunk_data);
                width = Some(c.read_u32::<BigEndian>().unwrap_or(0));
                height = Some(c.read_u32::<BigEndian>().unwrap_or(0));
                bit_depth = Some(c.read_u8().unwrap_or(0));
                color_type = Some(c.read_u8().unwrap_or(0));
                fields.insert("width".into(), serde_json::json!(width));
                fields.insert("height".into(), serde_json::json!(height));
                fields.insert("bit_depth".into(), serde_json::json!(bit_depth));
                fields.insert("color_type".into(), serde_json::json!(color_type));
            }

            let status = if crc_ok {
                NodeStatus::Valid
            } else {
                NodeStatus::Invalid
            };
            let mut n = pmod::node(
                &format!("chunk:{}", ctype_str),
                offset as u64,
                Some((12 + length) as u64),
                status,
            );
            n.fields = fields;
            nodes.push(n);

            if ctype == b"IEND" {
                seen_iend = true;
            }

            offset += 12 + length;
            chunk_index += 1;
            if chunk_index as u64 > config.max_parse_depth as u64 * 1000 {
                errors.push("too many chunks".into());
                break;
            }
        }

        if !seen_iend {
            warnings.push("missing IEND chunk".into());
        }

        let mut root_fields = BTreeMap::new();
        if let Some(w) = width {
            root_fields.insert("width".into(), serde_json::json!(w));
        }
        if let Some(h) = height {
            root_fields.insert("height".into(), serde_json::json!(h));
        }
        if let Some(bd) = bit_depth {
            root_fields.insert("bit_depth".into(), serde_json::json!(bd));
        }
        if let Some(ct) = color_type {
            root_fields.insert("color_type".into(), serde_json::json!(ct));
        }
        let mut root = pmod::node(
            "png",
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

        let complete = errors.is_empty() && seen_iend;
        Ok(pmod::make_report(
            "png",
            Some(root),
            nodes,
            offset as u64,
            errors,
            warnings,
            complete,
            Some("1.2".into()),
        ))
    }

    fn metadata(&self, report: &StructuralReport) -> MetadataReport {
        let mut fields = BTreeMap::new();
        if let Some(root) = &report.root {
            for (k, v) in &root.fields {
                fields.insert(k.clone(), v.clone());
            }
        }
        fields.insert("format".into(), serde_json::json!("PNG"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
