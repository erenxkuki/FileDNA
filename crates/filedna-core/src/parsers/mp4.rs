use crate::error::{FileDnaError, Result};
use crate::parsers as pmod;
use crate::parsers::FormatParser;
use crate::types::*;
use std::collections::BTreeMap;

pub struct Mp4Parser;
impl FormatParser for Mp4Parser {
    fn format_id(&self) -> &'static str {
        "mp4"
    }
    fn identify(&self, data: &[u8], _size: u64) -> (bool, f64, Vec<String>) {
        // ftyp at offset 4
        if data.len() >= 8 && &data[4..8] == b"ftyp" {
            return (true, 0.3, vec!["MP4 ftyp box matched".into()]);
        }
        (false, 0.0, vec![])
    }
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport> {
        if data.len() < 8 {
            return Err(FileDnaError::Parse {
                subsystem: "mp4".into(),
                message: "too short".into(),
            });
        }
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut width = None;
        let mut height = None;
        let mut duration = None;
        let mut timescale = None;
        // recursive
        fn parse_boxes(
            data: &[u8],
            start: usize,
            end: usize,
            depth: u32,
            config: &Config,
            nodes: &mut Vec<StructuralNode>,
            errors: &mut Vec<String>,
            warnings: &mut Vec<String>,
            width: &mut Option<u32>,
            height: &mut Option<u32>,
            duration: &mut Option<u64>,
            timescale: &mut Option<u32>,
        ) {
            if depth > config.max_parse_depth {
                errors.push("max depth exceeded".into());
                return;
            }
            let mut pos = start;
            while pos + 8 <= end {
                let mut size =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                        as u64;
                let btype = &data[pos + 4..pos + 8];
                let type_str = String::from_utf8_lossy(btype).to_string();
                let header_size;
                if size == 0 {
                    size = (end - pos) as u64;
                    header_size = 8;
                } else if size == 1 {
                    if pos + 16 > end {
                        errors.push("truncated extended size".into());
                        break;
                    }
                    size = u64::from_be_bytes([
                        data[pos + 8],
                        data[pos + 9],
                        data[pos + 10],
                        data[pos + 11],
                        data[pos + 12],
                        data[pos + 13],
                        data[pos + 14],
                        data[pos + 15],
                    ]);
                    header_size = 16;
                } else {
                    header_size = 8;
                }
                if size < header_size as u64 || pos as u64 + size > end as u64 {
                    errors.push(format!("invalid box size for {} at {}", type_str, pos));
                    break;
                }
                let payload_start = pos + header_size;
                let payload_end = pos + size as usize;
                // parse mvhd/tkhd if applicable (need path). We'll inspect by type only here; deeper parsing below for mdhd/mvhd/tkhd.
                let mut fields = BTreeMap::new();
                fields.insert("type".into(), serde_json::json!(type_str));
                fields.insert("size".into(), serde_json::json!(size));
                // mvhd
                if type_str == "mvhd" {
                    // version at payload_start
                    if payload_start + 16 <= payload_end {
                        let version = data[payload_start];
                        let (ts, dur) = if version == 0 {
                            let ts = u32::from_be_bytes([
                                data[payload_start + 12],
                                data[payload_start + 13],
                                data[payload_start + 14],
                                data[payload_start + 15],
                            ]);
                            let dur = u32::from_be_bytes([
                                data[payload_start + 16],
                                data[payload_start + 17],
                                data[payload_start + 18],
                                data[payload_start + 19],
                            ]) as u64;
                            (ts, dur)
                        } else {
                            let ts = u32::from_be_bytes([
                                data[payload_start + 20],
                                data[payload_start + 21],
                                data[payload_start + 22],
                                data[payload_start + 23],
                            ]);
                            let dur = u64::from_be_bytes([
                                data[payload_start + 24],
                                data[payload_start + 25],
                                data[payload_start + 26],
                                data[payload_start + 27],
                                data[payload_start + 28],
                                data[payload_start + 29],
                                data[payload_start + 30],
                                data[payload_start + 31],
                            ]);
                            (ts, dur)
                        };
                        *timescale = Some(ts);
                        *duration = Some(dur);
                        fields.insert("timescale".into(), serde_json::json!(ts));
                        fields.insert("duration".into(), serde_json::json!(dur));
                    }
                }
                if type_str == "tkhd" {
                    // dimensions are fixed-point 16.16 at end of tkhd
                    // version 0: width/height at offset 76/80? Let's search last 8 bytes of box
                    if payload_end >= payload_start + 8 {
                        let w = u32::from_be_bytes([
                            data[payload_end - 8],
                            data[payload_end - 7],
                            data[payload_end - 6],
                            data[payload_end - 5],
                        ]) >> 16;
                        let h = u32::from_be_bytes([
                            data[payload_end - 4],
                            data[payload_end - 3],
                            data[payload_end - 2],
                            data[payload_end - 1],
                        ]) >> 16;
                        if w > 0 && h > 0 {
                            *width = Some(w);
                            *height = Some(h);
                            fields.insert("width".into(), serde_json::json!(w));
                            fields.insert("height".into(), serde_json::json!(h));
                        }
                    }
                }
                let mut n = pmod::node(
                    &format!("box:{}", type_str),
                    pos as u64,
                    Some(size),
                    NodeStatus::Valid,
                );
                n.fields = fields;
                // recurse into containers
                let is_container = matches!(
                    type_str.as_str(),
                    "moov" | "trak" | "mdia" | "minf" | "stbl" | "udta" | "meta" | "dinf" | "edts"
                );
                if is_container {
                    let mut child_nodes = Vec::new();
                    let mut child_errors = Vec::new();
                    let mut child_warnings = Vec::new();
                    parse_boxes(
                        data,
                        payload_start,
                        payload_end,
                        depth + 1,
                        config,
                        &mut child_nodes,
                        &mut child_errors,
                        &mut child_warnings,
                        width,
                        height,
                        duration,
                        timescale,
                    );
                    n.children = child_nodes;
                    errors.extend(child_errors);
                    warnings.extend(child_warnings);
                }
                nodes.push(n);
                pos = payload_end;
            }
        }
        parse_boxes(
            data,
            0,
            data.len(),
            0,
            config,
            &mut nodes,
            &mut errors,
            &mut warnings,
            &mut width,
            &mut height,
            &mut duration,
            &mut timescale,
        );
        let mut root_fields = BTreeMap::new();
        if let Some(w) = width {
            root_fields.insert("width".into(), serde_json::json!(w));
        }
        if let Some(h) = height {
            root_fields.insert("height".into(), serde_json::json!(h));
        }
        if let Some(ts) = timescale {
            root_fields.insert("timescale".into(), serde_json::json!(ts));
        }
        if let Some(d) = duration {
            root_fields.insert("duration".into(), serde_json::json!(d));
        }
        let mut root = pmod::node(
            "mp4",
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
            "mp4",
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
        fields.insert("format".into(), serde_json::json!("MP4"));
        MetadataReport {
            fields,
            missing: vec![],
        }
    }
}
