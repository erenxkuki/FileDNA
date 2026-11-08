use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct FlacParser;
impl FormatParser for FlacParser {
    fn format_id(&self) -> &'static str {
        "flac"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 4 && data[..4] == *b"fLaC" {
            return (true, 0.3, vec!["FLAC magic matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 4 || data[..4] != *b"fLaC" {
            return Err(FileDnaError::Parse {
                subsystem: "flac".into(),
                message: "bad magic".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut pos = 4usize;
        let mut is_last = false;
        let mut block_count = 0;
        let mut sample_rate = None;
        let mut channels = None;
        let mut bits = None;
        let mut total_samples = None;
        while pos + 4 <= data.len() && !is_last {
            let header = data[pos];
            is_last = header & 0x80 != 0;
            let btype = header & 0x7F;
            let length = ((data[pos + 1] as usize) << 16)
                | ((data[pos + 2] as usize) << 8)
                | (data[pos + 3] as usize);
            if pos + 4 + length > data.len() {
                errors.push("truncated metadata block".into());
                break;
            }
            let mut fields = BTreeMap::new();
            fields.insert("type".into(), serde_json::json!(btype));
            fields.insert("length".into(), serde_json::json!(length));
            fields.insert("is_last".into(), serde_json::json!(is_last));
            if btype == 0 && length >= 34 {
                let d = &data[pos + 4..];
                let min_block = u16::from_be_bytes([d[0], d[1]]);
                let max_block = u16::from_be_bytes([d[2], d[3]]);
                let min_frame = ((d[4] as u32) << 16) | ((d[5] as u32) << 8) | (d[6] as u32);
                let max_frame = ((d[7] as u32) << 16) | ((d[8] as u32) << 8) | (d[9] as u32);
                // sample rate 20 bits, channels 3, bps 5, total 36
                let b10 = d[10] as u32;
                let b11 = d[11] as u32;
                let b12 = d[12] as u32;
                let b13 = d[13] as u32;
                let sr = ((b10 as u64) << 12) | ((b11 as u64) << 4) | ((b12 as u64) >> 4);
                let ch = ((b12 & 0x0E) >> 1) + 1;
                let bps = (((b12 & 0x01) << 4) | (b13 >> 4)) + 1;
                let total = (((b13 & 0x0F) as u64) << 32)
                    | ((d[14] as u64) << 24)
                    | ((d[15] as u64) << 16)
                    | ((d[16] as u64) << 8)
                    | (d[17] as u64);
                sample_rate = Some(sr as u32);
                channels = Some(ch as u32);
                bits = Some(bps as u32);
                total_samples = Some(total);
                fields.insert("min_block_size".into(), serde_json::json!(min_block));
                fields.insert("max_block_size".into(), serde_json::json!(max_block));
                fields.insert("min_frame_size".into(), serde_json::json!(min_frame));
                fields.insert("max_frame_size".into(), serde_json::json!(max_frame));
                fields.insert("sample_rate".into(), serde_json::json!(sr));
                fields.insert("channels".into(), serde_json::json!(ch));
                fields.insert("bits_per_sample".into(), serde_json::json!(bps));
                fields.insert("total_samples".into(), serde_json::json!(total));
            }
            let mut n = pmod::node(
                &format!("metadata_block:{}", btype),
                pos as u64,
                Some((4 + length) as u64),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            pos += 4 + length;
            block_count += 1;
            if block_count as u64 > config.max_parse_depth as u64 * 100 {
                errors.push("too many blocks".into());
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        if let Some(v) = sample_rate {
            root_fields.insert("sample_rate".into(), serde_json::json!(v));
        }
        if let Some(v) = channels {
            root_fields.insert("channels".into(), serde_json::json!(v));
        }
        if let Some(v) = bits {
            root_fields.insert("bits_per_sample".into(), serde_json::json!(v));
        }
        if let Some(v) = total_samples {
            root_fields.insert("total_samples".into(), serde_json::json!(v));
        }
        let mut root = pmod::node(
            "flac",
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
            "flac",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            is_last,
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
        fields.insert("format".into(), serde_json::json!("FLAC"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
