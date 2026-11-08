// Metadata extraction is performed by format parsers.
// This module provides aggregation helpers.

use crate::types::{MetadataReport, StructuralReport};

pub fn from_structural(report: &StructuralReport, parser_meta: MetadataReport) -> MetadataReport {
    parser_meta
}

pub fn merge(base: &mut MetadataReport, extra: &MetadataReport) {
    for (k, v) in &extra.fields {
        base.fields.insert(k.clone(), v.clone());
    }
    for m in &extra.missing {
        if !base.missing.contains(m) {
            base.missing.push(m.clone());
        }
    }
}
