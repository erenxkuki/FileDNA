use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct XmlParser;
impl FormatParser for XmlParser {
    fn format_id(&self) -> &'static str {
        "xml"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        let t = String::from_utf8_lossy(data).trim_start().to_string();
        if t.starts_with("<?xml") || (t.starts_with('<') && t.contains('>')) {
            return (true, 0.2, vec!["XML-like structure detected".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        let text = String::from_utf8_lossy(data);
        let tag_count = text.matches('<').count();
        let mut fields = BTreeMap::new();
        fields.insert("tag_count".into(), serde_json::json!(tag_count));
        fields.insert(
            "has_declaration".into(),
            serde_json::json!(text.trim_start().starts_with("<?xml")),
        );
        let mut root = pmod::node("xml", 0, Some(file_size), NodeStatus::Valid);
        root.fields = fields;
        Ok(pmod::make_report(
            "xml",
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
        fields.insert("format".into(), serde_json::json!("XML"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
