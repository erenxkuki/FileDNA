use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct BmpParser;
impl FormatParser for BmpParser {
    fn format_id(&self) -> &'static str {
        "bmp"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 2 && data[0] == b'B' && data[1] == b'M' {
            return (true, 0.2, vec!["BMP signature matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        if data.len() < 54 {
            return Err(FileDnaError::Parse {
                subsystem: "bmp".into(),
                message: "too short".into(),
            });
        }
        let file_size_hdr = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let dib = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
        let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        let height = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
        let bpp = u16::from_le_bytes([data[28], data[29]]);
        let mut fields = BTreeMap::new();
        fields.insert("file_size_header".into(), serde_json::json!(file_size_hdr));
        fields.insert("pixel_offset".into(), serde_json::json!(offset));
        fields.insert("dib_header_size".into(), serde_json::json!(dib));
        fields.insert("width".into(), serde_json::json!(width));
        fields.insert("height".into(), serde_json::json!(height));
        fields.insert("bits_per_pixel".into(), serde_json::json!(bpp));
        let mut root = pmod::node("bmp", 0, Some(file_size), NodeStatus::Valid);
        root.fields = fields;
        Ok(pmod::make_report(
            "bmp",
            Some(root),
            vec![],
            file_size,
            vec![],
            vec![],
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
        fields.insert("format".into(), serde_json::json!("BMP"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
