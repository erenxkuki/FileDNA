# FileDNA Threat Model

## Untrusted inputs
All file contents, filenames, metadata, and embedded values are untrusted.

## Protections
- No execution of analyzed files.
- No loading binaries as native libraries.
- No evaluation of embedded scripts.
- No automatic archive extraction.
- Resource limits: file size, parse depth, metadata size, archive entries, nested depth, decompressed bytes, parser time.
- Path traversal handling via canonicalization and no filename-based storage paths.
- Parsers validate bounds; malformed inputs produce errors not crashes.

## Limitations
Parser isolation via separate processes is planned (Phase 9). Current parsers run in-process with resource limits. This is not a security sandbox.
