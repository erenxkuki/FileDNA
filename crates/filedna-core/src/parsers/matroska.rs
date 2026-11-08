use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

fn vint(data: &[u8], pos: usize) -> Option<(u64, usize, bool)> {
    // returns (value, bytes_consumed, is_id)
    if pos >= data.len() {
        return None;
    }
    let first = data[pos];
    if first == 0 {
        return None;
    }
    let mut len = 1usize;
    let mut mask = 0x80u8;
    while len <= 8 && (first & mask) == 0 {
        mask >>= 1;
        len += 1;
    }
    if len > 8 {
        return None;
    }
    if pos + len > data.len() {
        return None;
    }
    let mut value: u64 = (first & (mask - 1)) as u64;
    for i in 1..len {
        value = (value << 8) | data[pos + i] as u64;
    }
    // unknown size: all bits 1
    let unknown = value == ((1u64 << (7 * len)) - 1);
    Some((value, len, unknown))
}

// Master element IDs (subset)
fn is_master(id: u64) -> bool {
    matches!(
        id,
        0x1A45DFA3 | 0x18538067 | 0x1F43B675 | 0x1654AE6B | 0x1043A770 | 0x1254C367
    )
}

pub struct MatroskaParser;
impl FormatParser for MatroskaParser {
    fn format_id(&self) -> &'static str {
        "matroska"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        if data.len() >= 4 && data[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
            return (true, 0.3, vec!["EBML header matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 4 || data[..4] != [0x1A, 0x45, 0xDF, 0xA3] {
            return Err(FileDnaError::Parse {
                subsystem: "matroska".into(),
                message: "bad EBML".into(),
            });
        }
        let mut nodes: Vec<StructuralNode> = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut doc_type = None;
        // recursive parse
        fn parse_elems(
            data: &[u8],
            start: usize,
            end: usize,
            depth: u32,
            config: &Config,
            nodes: &mut Vec<StructuralNode>,
            errors: &mut Vec<String>,
            warnings: &mut Vec<String>,
            doc_type: &mut Option<String>,
        ) {
            if depth > config.max_parse_depth {
                errors.push("max depth".into());
                return;
            }
            let mut pos = start;
            let mut count = 0;
            while pos < end {
                let (id, idlen, _) = match vint(data, pos) {
                    Some(x) => x,
                    None => {
                        errors.push("bad id vint".into());
                        break;
                    }
                };
                pos += idlen;
                let (size, sizelen, unknown) = match vint(data, pos) {
                    Some(x) => x,
                    None => {
                        errors.push("bad size vint".into());
                        break;
                    }
                };
                pos += sizelen;
                let elem_end = if unknown {
                    end
                } else {
                    (pos as u64 + size).min(end as u64) as usize
                };
                let mut fields = BTreeMap::new();
                fields.insert("id".into(), serde_json::json!(format!("{:X}", id)));
                fields.insert("size".into(), serde_json::json!(size));
                // DocType string (0x4282) often in EBML header
                if id == 0x4282 {
                    let s =
                        String::from_utf8_lossy(&data[pos..elem_end.min(data.len())]).to_string();
                    *doc_type = Some(s.clone());
                    fields.insert("value".into(), serde_json::json!(s));
                }
                let mut n = pmod::node(
                    &format!("element:{:X}", id),
                    (pos - idlen - sizelen) as u64,
                    Some((idlen + sizelen) as u64 + if unknown { 0 } else { size }),
                    NodeStatus::Valid,
                );
                n.fields = fields;
                if is_master(id) && !unknown {
                    let mut children = Vec::new();
                    let mut ce = Vec::new();
                    let mut cw = Vec::new();
                    parse_elems(
                        data,
                        pos,
                        elem_end,
                        depth + 1,
                        config,
                        &mut children,
                        &mut ce,
                        &mut cw,
                        doc_type,
                    );
                    n.children = children;
                    errors.extend(ce);
                    warnings.extend(cw);
                }
                nodes.push(n);
                if unknown {
                    break;
                }
                pos = elem_end;
                count += 1;
                if count > 100000 {
                    errors.push("too many elements".into());
                    break;
                }
            }
        }
        let mut root_nodes = Vec::new();
        parse_elems(
            data,
            0,
            data.len(),
            0,
            config,
            &mut root_nodes,
            &mut errors,
            &mut warnings,
            &mut doc_type,
        );
        let mut root_fields = BTreeMap::new();
        if let Some(dt) = doc_type {
            root_fields.insert("doc_type".into(), serde_json::json!(dt));
        }
        let mut root = pmod::node(
            "matroska",
            0,
            Some(file_size),
            if errors.is_empty() {
                NodeStatus::Valid
            } else {
                NodeStatus::Partial
            },
        );
        root.fields = root_fields;
        root.children = root_nodes.clone();
        Ok(pmod::make_report(
            "matroska",
            Some(root),
            root_nodes,
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
        fields.insert("format".into(), serde_json::json!("Matroska"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
