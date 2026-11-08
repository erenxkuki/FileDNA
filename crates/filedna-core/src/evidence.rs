use crate::types::*;
use chrono::Utc;
use uuid::Uuid;

pub fn new_evidence(stage: &str, category: &str, description: &str, source: &str) -> Evidence {
    Evidence {
        id: format!("ev-{}", Uuid::new_v4()),
        file_id: None,
        stage: stage.into(),
        category: category.into(),
        description: description.into(),
        raw: None,
        source: source.into(),
        algorithm_version: "1.0".into(),
        confidence: None,
        timestamp: Utc::now(),
        offset: None,
        length: None,
    }
}
