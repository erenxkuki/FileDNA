use filedna_core::analysis;
use filedna_core::config;
use filedna_core::discovery;
use filedna_core::pipeline;
use filedna_core::storage::Database;
use filedna_core::types::*;
use std::fs;
use std::path::PathBuf;

#[test]
fn scan_temp_dir() {
    let tmp = std::env::temp_dir().join("filedna_test_scan");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("a.txt"), "hello").unwrap();
    fs::write(
        tmp.join("b.bin"),
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    )
    .unwrap();
    let cfg = config::default_config();
    let opts = discovery::DiscoveryOptions::default();
    let ctx = pipeline::ScanContext::default();
    let (profiles, job) = pipeline::scan(&[tmp.clone()], &cfg, &opts, &ctx);
    assert!(profiles.len() >= 2, "expected at least 2 files");
    assert_eq!(job.files_discovered as usize, profiles.len());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn png_parse_valid() {
    // minimal valid PNG 1x1
    let bytes: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8,
        0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    let tmp = std::env::temp_dir().join("filedna_png.png");
    fs::write(&tmp, &bytes).unwrap();
    let cfg = config::default_config();
    let profile = analysis::analyze_file(&tmp, &cfg);
    assert!(
        profile
            .identification
            .as_ref()
            .unwrap()
            .primary
            .as_ref()
            .unwrap()
            .format_id
            == "png"
    );
    assert!(profile.structure.is_some());
    let _ = fs::remove_file(&tmp);
}

#[test]
fn storage_roundtrip() {
    let tmpdb = std::env::temp_dir().join("filedna_test.db");
    let _ = fs::remove_file(&tmpdb);
    let db = Database::open(&tmpdb).unwrap();
    let tmp = std::env::temp_dir().join("filedna_store.txt");
    fs::write(&tmp, "data").unwrap();
    let cfg = config::default_config();
    let profile = analysis::analyze_file(&tmp, &cfg);
    let id = db.save_profile(&profile).unwrap();
    let loaded = db.get_profile(id.0).unwrap().unwrap();
    assert_eq!(loaded.discovered.size, profile.discovered.size);
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_file(&tmpdb);
}

#[test]
fn malformed_does_not_crash() {
    let tmp = std::env::temp_dir().join("filedna_malformed.bin");
    fs::write(&tmp, [0xFFu8; 100]).unwrap();
    let cfg = config::default_config();
    let profile = analysis::analyze_file(&tmp, &cfg);
    // no panic
    let _ = profile;
    let _ = fs::remove_file(&tmp);
}
