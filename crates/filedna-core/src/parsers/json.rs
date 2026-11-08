use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct JsonParser;
impl FormatParser for JsonParser {
    fn format_id(&self) -> &'static str {
        "json"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        let t = String::from_utf8_lossy(data).trim_start().to_string();
        if t.starts_with('{') || t.starts_with('[') {
            // validate
            if serde_json::from_str::<serde_json::Value>(&t).is_ok() {
                return (true, 0.35, vec!["JSON parsed successfully".into()]);
            }
            return (
                true,
                0.15,
                vec!["JSON-like structure (invalid syntax)".into()],
            );
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, _config: &Config) -> Result<StructuralReport> {
        let text = String::from_utf8_lossy(data);
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| FileDnaError::Parse {
                subsystem: "json".into(),
                message: e.to_string(),
            })?;
        let mut nodes = Vec::new();
        // top-level type
        let t = match &value {
            serde_json::Value::Object(m) => format!("object({})", m.len()),
            serde_json::Value::Array(a) => format!("array({})", a.len()),
            _ => value.to_string(),
        };
        let mut fields = BTreeMap::new();
        fields.insert("top_level".into(), serde_json::json!(t));
        let mut root = pmod::node("json", 0, Some(file_size), NodeStatus::Valid);
        root.fields = fields;
        Ok(pmod::make_report(
            "json",
            Some(root),
            nodes,
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
        fields.insert("format".into(), serde_json::json!("JSON"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
