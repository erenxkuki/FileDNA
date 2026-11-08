# FileDNA Architecture Overview

FileDNA is a modular, local-first file structural intelligence engine.

## Layers

1. Discovery: safe filesystem traversal.
2. Acquisition: bounded file reads.
3. Identification: content-based format detection.
4. Parsing: format-specific structural validation.
5. Metadata: extracted properties.
6. Fingerprinting: content, structural, metadata, chunk.
7. Integrity: structural consistency and hash verification.
8. Duplicate detection: exact, structural, metadata, potential.
9. Similarity: multi-signal approximate comparison.
10. Relationships: typed graph edges with evidence.
11. Evidence: traceable observations.
12. Storage: SQLite local database.
13. Reporting: JSON/text output.
14. CLI: command-line interface.
15. Plugins: (planned) extension point.

## Technology

- Core: Rust (memory safety, performance).
- Storage: SQLite (rusqlite bundled).
- CLI: clap.
- Serialization: serde JSON.

## Security model

All file contents treated as untrusted. Parsers enforce resource limits. No execution of file content. Read-only analysis.

## Status

See README for implementation status labels.
