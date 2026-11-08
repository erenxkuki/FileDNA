use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct WavParser;
impl FormatParser for WavParser {
    fn format_id(&self) -> &'static str {
        "wav"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
            return (true, 0.3, vec!["WAV RIFF/WAVE signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
            return Err(FileDnaError::Parse {
                subsystem: "wav".into(),
                message: "missing RIFF/WAVE".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut pos = 12usize;
        let mut sample_rate = None;
        let mut channels = None;
        let mut bits = None;
        let mut audio_format = None;
        let mut data_size = None;
        let mut chunk_count = 0;
        while pos + 8 <= data.len() {
            let cid = &data[pos..pos + 4];
            let csize =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                    as usize;
            if pos + 8 + csize > data.len() {
                errors.push(format!("chunk {} truncated", String::from_utf8_lossy(cid)));
                break;
            }
            let mut fields = BTreeMap::new();
            fields.insert("id".into(), serde_json::json!(String::from_utf8_lossy(cid)));
            fields.insert("size".into(), serde_json::json!(csize));
            if cid == b"fmt " && csize >= 16 {
                let d = &data[pos + 8..];
                audio_format = Some(u16::from_le_bytes([d[0], d[1]]));
                channels = Some(u16::from_le_bytes([d[2], d[3]]));
                sample_rate = Some(u32::from_le_bytes([d[4], d[5], d[6], d[7]]));
                let byte_rate = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
                let block_align = u16::from_le_bytes([d[12], d[13]]);
                bits = Some(u16::from_le_bytes([d[14], d[15]]));
                fields.insert("audio_format".into(), serde_json::json!(audio_format));
                fields.insert("channels".into(), serde_json::json!(channels));
                fields.insert("sample_rate".into(), serde_json::json!(sample_rate));
                fields.insert("byte_rate".into(), serde_json::json!(byte_rate));
                fields.insert("block_align".into(), serde_json::json!(block_align));
                fields.insert("bits_per_sample".into(), serde_json::json!(bits));
            }
            if cid == b"data" {
                data_size = Some(csize);
            }
            let mut n = pmod::node(
                &format!("chunk:{}", String::from_utf8_lossy(cid)),
                pos as u64,
                Some((8 + csize) as u64),
                NodeStatus::Valid,
            );
            n.fields = fields;
            nodes.push(n);
            pos += 8 + csize;
            if csize % 2 == 1 {
                pos += 1;
            }
            chunk_count += 1;
            if chunk_count as u64 > config.max_parse_depth as u64 * 100 {
                errors.push("too many chunks".into());
                break;
            }
        }
        let mut root_fields = BTreeMap::new();
        if let Some(v) = audio_format {
            root_fields.insert("audio_format".into(), serde_json::json!(v));
        }
        if let Some(v) = channels {
            root_fields.insert("channels".into(), serde_json::json!(v));
        }
        if let Some(v) = sample_rate {
            root_fields.insert("sample_rate".into(), serde_json::json!(v));
        }
        if let Some(v) = bits {
            root_fields.insert("bits_per_sample".into(), serde_json::json!(v));
        }
        if let Some(v) = data_size {
            root_fields.insert("data_size".into(), serde_json::json!(v));
        }
        let mut root = pmod::node(
            "wav",
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
            "wav",
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
        fields.insert("format".into(), serde_json::json!("WAV"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
