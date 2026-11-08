use crate::error::Result;
use crate::types::*;
use std::collections::BTreeMap;

pub mod bmp;
pub mod flac;
pub mod gif;
pub mod gzip;
pub mod jpeg;
pub mod json;
pub mod matroska;
pub mod mp3;
pub mod mp4;
pub mod pdf;
pub mod png;
pub mod tar;
pub mod ttf;
pub mod wav;
pub mod webp;
pub mod xml;
pub mod zip;

pub trait FormatParser: Send + Sync {
    fn format_id(&self) -> &'static str;
    fn identify(&self, data: &[u8], file_size: u64) -> (bool, f64, Vec<String>);
    fn parse(&self, data: &[u8], file_size: u64, config: &Config) -> Result<StructuralReport>;
    fn metadata(&self, report: &StructuralReport) -> MetadataReport;
}

pub fn get_parser(id: &str) -> Option<Box<dyn FormatParser>> {
    match id {
        "png" => Some(Box::new(png::PngParser)),
        "jpeg" => Some(Box::new(jpeg::JpegParser)),
        "gif" => Some(Box::new(gif::GifParser)),
        "webp" => Some(Box::new(webp::WebpParser)),
        "bmp" => Some(Box::new(bmp::BmpParser)),
        "zip" => Some(Box::new(zip::ZipParser)),
        "gzip" => Some(Box::new(gzip::GzipParser)),
        "tar" => Some(Box::new(tar::TarParser)),
        "wav" => Some(Box::new(wav::WavParser)),
        "flac" => Some(Box::new(flac::FlacParser)),
        "mp3" => Some(Box::new(mp3::Mp3Parser)),
        "mp4" => Some(Box::new(mp4::Mp4Parser)),
        "matroska" => Some(Box::new(matroska::MatroskaParser)),
        "pdf" => Some(Box::new(pdf::PdfParser)),
        "json" => Some(Box::new(json::JsonParser)),
        "xml" => Some(Box::new(xml::XmlParser)),
        "ttf" | "otf" | "ttc" => Some(Box::new(ttf::FontParser)),
        _ => None,
    }
}

pub fn all_parser_ids() -> Vec<&'static str> {
    vec![
        "png", "jpeg", "gif", "webp", "bmp", "zip", "gzip", "tar", "wav", "flac", "mp3", "mp4",
        "matroska", "pdf", "json", "xml", "ttf",
    ]
}

fn node(t: &str, offset: u64, length: Option<u64>, status: NodeStatus) -> StructuralNode {
    StructuralNode {
        node_type: t.into(),
        offset,
        length,
        status,
        fields: BTreeMap::new(),
        children: Vec::new(),
        errors: Vec::new(),
    }
}

pub fn make_report(
    format_id: &str,
    root: Option<StructuralNode>,
    nodes: Vec<StructuralNode>,
    parsed_bytes: u64,
    errors: Vec<String>,
    warnings: Vec<String>,
    complete: bool,
    version: Option<String>,
) -> StructuralReport {
    StructuralReport {
        format_id: format_id.into(),
        format_version: version,
        root,
        nodes_flat: nodes,
        parsed_bytes,
        errors,
        warnings,
        complete,
    }
}
