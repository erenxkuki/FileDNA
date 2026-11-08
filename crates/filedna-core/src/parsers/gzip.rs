use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct GzipParser;
impl FormatParser for GzipParser {
    fn format_id(&self) -> &'static str {
        "gzip"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8 {
            return (
                true,
                0.3,
                vec!["GZIP magic and deflate method matched".into()],
            );
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        if data.len() < 10 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
            return Err(FileDnaError::Parse {
                subsystem: "gzip".into(),
                message: "bad header".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let flags = data[3];
        let mtime = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let xfl = data[8];
        let os = data[9];
        let mut pos = 10usize;
        // extra
        if flags & 0x04 != 0 {
            if pos + 2 > data.len() {
                errors.push("truncated extra".into());
            } else {
                let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2 + xlen;
                nodes.push(pmod::node(
                    "extra",
                    10,
                    Some((2 + xlen) as u64),
                    NodeStatus::Valid,
                ));
            }
        }
        // name
        if flags & 0x08 != 0 {
            let start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
            nodes.push(pmod::node(
                "filename",
                start as u64,
                Some((pos - start) as u64),
                NodeStatus::Valid,
            ));
        }
        // comment
        if flags & 0x10 != 0 {
            let start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
            nodes.push(pmod::node(
                "comment",
                start as u64,
                Some((pos - start) as u64),
                NodeStatus::Valid,
            ));
        }
        // crc16
        if flags & 0x02 != 0 {
            pos += 2;
            nodes.push(pmod::node("crc16", pos as u64, Some(2), NodeStatus::Valid));
        }
        // trailer last 8 bytes
        if data.len() >= 8 {
            let crc = u32::from_le_bytes([
                data[data.len() - 8],
                data[data.len() - 7],
                data[data.len() - 6],
                data[data.len() - 5],
            ]);
            let isize = u32::from_le_bytes([
                data[data.len() - 4],
                data[data.len() - 3],
                data[data.len() - 2],
                data[data.len() - 1],
            ]);
            nodes.push(pmod::node(
                "trailer",
                (data.len() - 8) as u64,
                Some(8),
                NodeStatus::Valid,
            ));
            let mut tf = BTreeMap::new();
            tf.insert("crc32".into(), serde_json::json!(crc));
            tf.insert("isize".into(), serde_json::json!(isize));
            let last = nodes.last_mut().unwrap();
            last.fields = tf;
            let _ = (crc, isize);
        }
        let mut fields = BTreeMap::new();
        fields.insert("mtime".into(), serde_json::json!(mtime));
        fields.insert("xfl".into(), serde_json::json!(xfl));
        fields.insert("os".into(), serde_json::json!(os));
        fields.insert("flags".into(), serde_json::json!(flags));
        let mut root = pmod::node("gzip", 0, Some(file_size), NodeStatus::Valid);
        root.fields = fields;
        root.children = nodes.clone();
        Ok(pmod::make_report(
            "gzip",
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
        fields.insert("format".into(), serde_json::json!("GZIP"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
