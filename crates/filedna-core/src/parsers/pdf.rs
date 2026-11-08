use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct PdfParser;
impl FormatParser for PdfParser {
    fn format_id(&self) -> &'static str {
        "pdf"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 5 && data[..5] == *b"%PDF-" {
            return (true, 0.3, vec!["PDF header matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        if data.len() < 5 || data[..5] != *b"%PDF-" {
            return Err(FileDnaError::Parse {
                subsystem: "pdf".into(),
                message: "bad header".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        // header
        let mut version = None;
        if data.len() >= 8 {
            let v = String::from_utf8_lossy(&data[5..8]).to_string();
            version = Some(v);
        }
        nodes.push(pmod::node("header", 0, Some(8), NodeStatus::Valid));
        // count objects
        let text = String::from_utf8_lossy(data);
        let obj_count = text.matches(" obj").count();
        // find startxref
        let mut xref_offset = None;
        if let Some(idx) = text.rfind("startxref") {
            let rest = &text[idx..];
            // parse number
            let nums: String = rest
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = nums.parse::<u64>() {
                xref_offset = Some(n);
            }
        }
        // trailer dict
        let mut root_fields = BTreeMap::new();
        if let Some(v) = version.clone() {
            root_fields.insert("version".into(), serde_json::json!(v));
        }
        root_fields.insert("object_count_estimate".into(), serde_json::json!(obj_count));
        if let Some(x) = xref_offset {
            root_fields.insert("startxref".into(), serde_json::json!(x));
        }
        // EOF marker
        let has_eof = text.contains("%%EOF");
        if !has_eof {
            warnings.push("%%EOF marker not found".into());
        }
        let mut root = pmod::node(
            "pdf",
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
            "pdf",
            Some(root),
            nodes,
            file_size,
            errors,
            warnings,
            has_eof,
            version,
        ))
    }
    fn metadata(&self, report: &StructuralReport) -> MetadataReport {
        let mut fields = BTreeMap::new();
        if let Some(root) = &report.root {
            for (k, v) in &root.fields {
                fields.insert(k.clone(), v.clone());
            }
        }
        fields.insert("format".into(), serde_json::json!("PDF"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
