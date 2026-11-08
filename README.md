<div align="center">

# FileDNA

**Structural intelligence for digital files.**

Understand what a file *actually* is — not what its extension claims.

[![Status](https://img.shields.io/badge/status-foundation%20built-brightgreen)](#status)
[![Language](https://img.shields.io/badge/core-Rust-orange)](#technology)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)
[![Local-first](https://img.shields.io/badge/local--first-yes-success)](#principles)
[![CLI](https://img.shields.io/badge/interface-CLI-informational)](#command-line-interface)

</div>

---

## What is FileDNA?

A `.jpg` extension does not prove a file is a JPEG. A file named `backup.zip` may not be a valid archive. Two files with different names can contain identical bytes. Two files with identical hashes can differ in metadata and context.

**FileDNA** is an open-source structural intelligence engine that builds an **evidence-backed profile** for every file it analyzes:

- What the file actually is
- How it is constructed internally
- Whether its structure matches its claimed format
- Whether it is complete and consistent
- Whether you have seen identical content before
- How it relates to other files
- What changed between versions
- What evidence supports every conclusion

> FileDNA is not an antivirus. It identifies suspicious structural characteristics, but it communicates uncertainty instead of claiming a file is safe.

---

## Why FileDNA?

Existing tools solve fragments of the problem:

| Tool type | What it does | What it misses |
|---|---|---|
| File type detectors | Magic-byte matching | Structural validity, metadata, relationships |
| Hash utilities | Content identity | Format, structure, provenance |
| Duplicate finders | Byte equality | Structural similarity, metadata differences |
| Metadata viewers | Property extraction | Integrity, format conflicts |
| Antivirus | Threat signatures | Structural understanding, explainability |

FileDNA unifies these into one extensible, local-first engine — with evidence for every conclusion.

---

## Core principles

1. **Content before extension** — extensions are hints, never proof.
2. **Evidence before conclusions** — every classification retains its supporting observations.
3. **Local-first** — no network, no account, no cloud, no telemetry by default.
4. **Read-only by default** — source files are never modified during analysis.
5. **Explainability** — no unexplained scores.
6. **Graceful uncertainty** — unknown formats are reported as unknown, never invented.
7. **Extensibility** — new format analyzers plug in without rewriting the core.

---

## Architecture

FileDNA is a modular pipeline. Each stage has explicit interfaces and responsibilities.

```
                    USER
                     |
          CLI (desktop app planned)
                     |
               Application API
                     |
              Analysis Manager
                     |
             File Discovery
                     |
             File Acquisition
                     |
          Content Identification
                     |
          Structural Inspection
                     |
             Format Parsers
                     |
          Metadata Extraction
                     |
          Fingerprint Generation
                     |
           Integrity Evaluation
                     |
          Similarity / Duplicate
                     |
           Relationship Engine
                     |
            Evidence Engine
                     |
             Result Builder
                     |
          Local Storage / Reports
```

### Components

| Layer | Responsibility |
|---|---|
| Discovery | Safe traversal of files and directories |
| Identification | Multi-signal format detection with confidence |
| Parsing | Format-specific structural validation |
| Metadata | Extracted properties per format |
| Fingerprinting | Content, structural, metadata, chunk identities |
| Integrity | Structural consistency and hash verification |
| Duplicates | Exact, structural, metadata, potential matches |
| Similarity | Multi-signal approximate comparison |
| Relationships | Typed graph edges with evidence |
| Evidence | Traceable observations and reasoning |
| Storage | SQLite-backed local index |
| Reporting | JSON and human-readable output |

---

## Supported formats

Initial format set with structural parsing:

| Category | Formats |
|---|---|
| Images | PNG, JPEG, GIF, WebP, BMP, TIFF |
| Audio | WAV, FLAC, MP3 |
| Video | MP4, Matroska |
| Archives | ZIP, TAR, GZIP |
| Documents | PDF |
| Structured text | JSON, XML |
| Fonts | TTF, OTF, TTC |
| Databases | SQLite |
| Binaries | ELF, PE, Mach-O (signature) |

Prefer a smaller number of reliable parsers over dozens of superficial signature matches.

---

## FileDNA profile

Each analyzed file receives a structural profile:

```
{
  "format": "png",
  "version": "1.2",
  "structure": [
    { "type": "signature", "offset": 0, "length": 8, "status": "valid" },
    { "type": "chunk:IHDR", "offset": 8, "length": 25, "status": "valid" },
    { "type": "chunk:IDAT", "offset": 33, "length": 21, "status": "valid" },
    { "type": "chunk:IEND", "offset": 54, "length": 12, "status": "valid" }
  ],
  "metadata": {
    "width": 1,
    "height": 1,
    "bit_depth": 8,
    "color_type": 2
  },
  "fingerprints": {
    "content": "sha256:...",
    "structural": "...",
    "metadata": "..."
  },
  "integrity": "structurally_valid",
  "evidence": [ ... ]
}
```

---

## Quick start

### Build

```bash
cargo build --release
```

Binary location: `target/release/filedna` (or `filedna.exe` on Windows).

### Scan a directory

```bash
filedna scan ./documents
```

### Inspect a single file

```bash
filedna inspect ./unknown.bin
```

### Identify format (content-based)

```bash
filedna identify ./sample.dat
```

### Hash a file

```bash
filedna hash ./sample.dat
filedna hash ./sample.dat --blake3
```

### Compare two files

```bash
filedna compare ./first.bin ./second.bin
```

### Find duplicates

```bash
filedna duplicates ./documents
```

### Generate a report

```bash
filedna report ./documents --out report.txt
filedna report ./documents --json
```

### JSON output for any command

```bash
filedna scan ./documents --json
filedna identify ./sample.dat --json
```

---

## Example: extension mismatch

```
$ filedna identify photo.png
Detected: jpeg (confirmed)
Score: 1.00
Extension mismatch: claimed 'png'
```

FileDNA reports the contradiction and the evidence behind it.

---

## Command-line interface

```
filedna scan <path> [--json] [--db <path>] [--recursive]
filedna inspect <path> [--json]
filedna identify <path> [--json]
filedna hash <path> [--blake3]
filedna compare <a> <b> [--json]
filedna duplicates <path> [--json]
filedna report <path> [--out <file>] [--json]
filedna config show
```

Exit codes are documented for success, partial success, invalid arguments, unsupported format, integrity mismatch, analysis failure, permission failure, and cancellation.

---

## Security model

All file contents, filenames, metadata, and embedded values are treated as untrusted.

- No execution of analyzed files
- No loading analyzed binaries as native libraries
- No evaluation of embedded scripts
- No automatic archive extraction
- No automatic launching of associated applications
- Resource limits on file size, parse depth, metadata size, archive entries, nested depth, decompressed bytes, and parser time
- Path traversal and symlink handling
- Malformed inputs produce structured errors, not crashes

Parser isolation via separate processes is planned. Current parsers run in-process with resource limits and are not a security sandbox.

See [`docs/security/threat-model.md`](docs/security/threat-model.md).

---

## Technology

| Component | Technology |
|---|---|
| Core engine | Rust |
| Storage | SQLite (rusqlite, bundled) |
| CLI | clap |
| Serialization | serde (JSON) |
| Hashing | sha2, blake3 |

Rust was selected for memory safety, efficient binary processing, strong typing, concurrency support, and cross-platform compilation. SQLite provides a robust embedded local database.

---

## Repository structure

```
FileDNA/
├── crates/
│   ├── filedna-core/       # Engine library
│   └── filedna-cli/        # CLI binary
├── docs/
│   ├── architecture/
│   └── security/
├── tests/                  # Integration tests
├── README.md
├── LICENSE
├── CHANGELOG.md
└── Cargo.toml
```

---

## Status

| Deliverable | Status |
|---|---|
| Core engine | Implemented |
| File discovery | Implemented |
| Format identification | Implemented |
| Structural parsers | Implemented |
| Fingerprinting | Implemented |
| Integrity checks | Implemented |
| Duplicate detection | Implemented |
| Similarity analysis | Implemented |
| Relationships | Implemented |
| SQLite storage | Implemented |
| CLI | Implemented |
| Automated tests | Implemented (4 integration) |
| Desktop application | Deferred |
| Plugin system | Deferred |

Status labels: Planned, In progress, Implemented, Tested, Verified, Deferred. Capabilities are marked honestly — no placeholder implementations are presented as working.

---

## Testing

```bash
cargo test --workspace
```

Testing strategy includes unit tests, integration tests, property-based invariants, fuzz targets for malformed inputs, and regression tests.

---

## Documentation

- [Architecture overview](docs/architecture/overview.md)
- [Threat model](docs/security/threat-model.md)

---

## Contributing

FileDNA is open source and welcomes contributors.

- Follow the engineering rules in the project specification
- Add tests for new behavior
- Document format support and limitations
- Never claim a capability works unless implemented and tested

---

## License

MIT. See [LICENSE](LICENSE).

---

## Final vision

FileDNA should not just say:

> "This is a PNG."

It should be able to explain:

> "This file claims to be a PNG, and its extension agrees. Its content signature matches PNG. Its internal chunk structure is consistent. Its dimensions are 1920 × 1080. Its content hash matches another file in your collection. Its metadata differs, but its actual content is identical."

That is the difference between identifying a file and understanding it.

**Build a reliable foundation first. Expand capabilities only when the engineering justifies them.**
