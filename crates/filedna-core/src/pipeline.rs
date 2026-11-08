use crate::analysis;
use crate::discovery;
use crate::types::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

pub struct ScanContext {
    pub cancelled: Arc<AtomicBool>,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub fn scan(
    roots: &[PathBuf],
    config: &Config,
    opts: &discovery::DiscoveryOptions,
    ctx: &ScanContext,
) -> (Vec<FileProfile>, AnalysisJob) {
    let started = chrono::Utc::now();
    let mut job = AnalysisJob {
        id: uuid::Uuid::new_v4().to_string(),
        root: roots.first().cloned().unwrap_or_default(),
        status: JobStatus::Running,
        files_discovered: 0,
        files_completed: 0,
        bytes_processed: 0,
        errors: 0,
        started,
        finished: None,
    };

    let discovered = match discovery::DiscoveryEngine::discover_paths(roots, opts) {
        Ok(v) => v,
        Err(_) => {
            job.status = JobStatus::Failed;
            job.finished = Some(chrono::Utc::now());
            return (Vec::new(), job);
        }
    };
    job.files_discovered = discovered.len() as u64;

    let mut profiles = Vec::with_capacity(discovered.len());
    for f in discovered {
        if ctx.cancelled.load(Ordering::Relaxed) {
            job.status = JobStatus::Cancelled;
            break;
        }
        let p = analysis::analyze_file(&f.path, config);
        job.files_completed += 1;
        job.bytes_processed += f.size;
        if !p.analysis_errors.is_empty() {
            job.errors += 1;
        }
        profiles.push(p);
    }
    if job.status == JobStatus::Running {
        job.status = if job.errors > 0 && job.files_completed < job.files_discovered {
            JobStatus::Partial
        } else {
            JobStatus::Completed
        };
    }
    job.finished = Some(chrono::Utc::now());
    (profiles, job)
}
