# Changelog

## 0.1.0 (initial)

- Core engine implemented in Rust.
- File discovery with safe traversal.
- Content-based format identification with signature registry and parser validation.
- Structural parsers: PNG, JPEG, GIF, WebP, BMP, ZIP, TAR, GZIP, WAV, FLAC, MP3, MP4, Matroska, PDF, JSON, XML, TTF/OTF.
- Fingerprinting: SHA-256, optional BLAKE3, structural, metadata, chunk.
- Integrity evaluation.
- Duplicate detection: exact, structural, metadata, potential.
- Similarity analysis (basic multi-signal).
- Relationship graph construction.
- SQLite storage.
- CLI with scan, inspect, identify, hash, compare, duplicates, report, config.
- Documentation: architecture overview, threat model.

Deferred: desktop application, plugin system, advanced parser isolation.
