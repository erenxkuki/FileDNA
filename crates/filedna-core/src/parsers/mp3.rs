use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct Mp3Parser;
impl FormatParser for Mp3Parser {
    fn format_id(&self) -> &'static str {
        "mp3"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 3 && data[..3] == *b"ID3" {
            return (true, 0.25, vec!["MP3 ID3 tag matched".into()]);
        }
        // MPEG sync
        if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
            return (true, 0.2, vec!["MPEG frame sync matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.is_empty() {
            return Err(FileDnaError::Parse {
                subsystem: "mp3".into(),
                message: "empty".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut pos = 0usize;
        // ID3v2
        if data.len() >= 10 && data[..3] == *b"ID3" {
            let size = ((data[6] as usize) << 21)
                | ((data[7] as usize) << 14)
                | ((data[8] as usize) << 7)
                | (data[9] as usize);
            let flags = data[5];
            nodes.push(pmod::node(
                "ID3v2",
                0,
                Some((10 + size) as u64),
                NodeStatus::Valid,
            ));
            let mut f = BTreeMap::new();
            f.insert(
                "version".into(),
                serde_json::json!(format!("{}.{}", data[3], data[4])),
            );
            f.insert("flags".into(), serde_json::json!(flags));
            f.insert("size".into(), serde_json::json!(size));
            nodes.last_mut().unwrap().fields = f;
            pos = 10 + size;
        }
        // parse frames
        let mut frame_count = 0u64;
        let mut first_sr = None;
        let mut first_ch = None;
        while pos + 4 <= data.len() && frame_count < 1000 {
            if data[pos] != 0xFF || (data[pos + 1] & 0xE0) != 0xE0 {
                pos += 1;
                continue;
            }
            let b1 = data[pos + 1];
            let b2 = data[pos + 2];
            let version = (b1 >> 3) & 0x03;
            let layer = (b1 >> 1) & 0x03;
            let bitrate_idx = (b2 >> 4) & 0x0F;
            let sr_idx = (b2 >> 2) & 0x03;
            let padding = (b2 >> 1) & 0x01;
            let channel_mode = (data[pos + 3] >> 6) & 0x03;
            let srs = match (version, sr_idx) {
                (3, 0) => Some(44100),
                (3, 1) => Some(48000),
                (3, 2) => Some(32000),
                (2, 0) => Some(22050),
                (2, 1) => Some(24000),
                (2, 2) => Some(16000),
                (0, 0) => Some(11025),
                (0, 1) => Some(12000),
                (0, 2) => Some(8000),
                _ => None,
            };
            if first_sr.is_none() {
                first_sr = srs;
            }
            if first_ch.is_none() {
                first_ch = Some(if channel_mode == 3 { 1 } else { 2 });
            }
            let mut fields = BTreeMap::new();
            fields.insert("version".into(), serde_json::json!(version));
            fields.insert("layer".into(), serde_json::json!(layer));
            fields.insert("bitrate_index".into(), serde_json::json!(bitrate_idx));
            fields.insert("sample_rate".into(), serde_json::json!(srs));
            fields.insert("padding".into(), serde_json::json!(padding));
            let mut n = pmod::node("frame", pos as u64, Some(4), NodeStatus::Valid);
            n.fields = fields;
            nodes.push(n);
            // advance: estimate frame size for Layer III
            // simplified: skip 1 byte to avoid infinite? Better advance by 1 and resync; but could be slow. Use heuristic: if layer==3 (Layer I) not. We'll advance by 1 and rely on sync search.
            pos += 1;
            frame_count += 1;
            if frame_count > config.max_parse_depth as u64 * 1000 {
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        root_fields.insert("frame_count".into(), serde_json::json!(frame_count));
        if let Some(v) = first_sr {
            root_fields.insert("sample_rate".into(), serde_json::json!(v));
        }
        if let Some(v) = first_ch {
            root_fields.insert("channels".into(), serde_json::json!(v));
        }
        let mut root = pmod::node(
            "mp3",
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
            "mp3",
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
        fields.insert("format".into(), serde_json::json!("MP3"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
