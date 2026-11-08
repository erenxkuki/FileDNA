use crate::Result;
use crate::types::DiscoveredFile;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub include_hidden: bool,
    pub max_depth: Option<usize>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_symlinks: false,
            include_hidden: false,
            max_depth: None,
        }
    }
}

pub struct DiscoveryEngine;

impl DiscoveryEngine {
    pub fn discover_paths(
        roots: &[PathBuf],
        opts: &DiscoveryOptions,
    ) -> Result<Vec<DiscoveredFile>> {
        let mut out = Vec::new();
        for root in roots {
            if root.is_file() {
                if let Some(f) = inspect_file(root) {
                    out.push(f);
                }
                continue;
            }
            if !root.exists() {
                continue;
            }
            let mut walker = WalkDir::new(root);
            if !opts.recursive {
                walker = walker.max_depth(1);
            }
            if let Some(d) = opts.max_depth {
                walker = walker.max_depth(d);
            }
            walker = walker.follow_links(opts.follow_symlinks);
            for entry in walker.into_iter() {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let path = entry.path();
                if !entry.file_type().is_file() {
                    // skip dirs and (by default) symlinks-to-dirs
                    if entry.file_type().is_symlink() && opts.follow_symlinks {
                        // walkdir handles following; still need file check below
                    } else {
                        continue;
                    }
                }
                if !opts.include_hidden {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with('.') {
                            // allow root itself? skip hidden files
                            if path != *root {
                                continue;
                            }
                        }
                    }
                }
                if let Some(f) = inspect_file(path) {
                    out.push(f);
                }
            }
        }
        Ok(out)
    }
}

pub fn inspect_file(path: &Path) -> Option<DiscoveredFile> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return None,
    };
    let is_symlink = meta.file_type().is_symlink();
    let (size, modified, created, accessed, os_file_type) = if is_symlink {
        (0, None, None, None, Some("symlink".into()))
    } else {
        let m2 = fs::metadata(path).ok();
        let size = m2.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = m2.as_ref().and_then(|m| m.modified().ok());
        let created = m2.as_ref().and_then(|m| m.created().ok());
        let accessed = m2.as_ref().and_then(|m| m.accessed().ok());
        let ft = if meta.is_file() {
            "file"
        } else if meta.is_dir() {
            "directory"
        } else {
            "other"
        };
        (size, modified, created, accessed, Some(ft.into()))
    };
    // Only regular files (or symlinks if followed) are reported; skip non-files.
    if !is_symlink && !meta.is_file() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let symlink_target = if is_symlink {
        fs::read_link(path).ok()
    } else {
        None
    };
    Some(DiscoveredFile {
        path: path.to_path_buf(),
        canonical_path: canonical,
        name,
        extension,
        size,
        modified,
        created,
        accessed,
        is_symlink,
        symlink_target,
        os_file_type,
    })
}

pub fn read_bytes_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let meta = fs::metadata(path)?;
    if meta.len() > max {
        return Err(crate::FileDnaError::ResourceLimit(format!(
            "file size {} exceeds max {}",
            meta.len(),
            max
        )));
    }
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn open_prefix(path: &Path, n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let mut total = 0;
    while total < n {
        let r = f.read(&mut buf[total..])?;
        if r == 0 {
            break;
        }
        total += r;
    }
    buf.truncate(total);
    Ok(buf)
}
