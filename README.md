# cliptown-interfaces

Versioned contracts shared by the ClipTown API, Flutter app, browser extension, CLI, and SDKs.

## Contract rules

- `proto/cliptown/v1` is the canonical wire contract for sync and peer-to-peer envelopes.
- `openapi/cliptown.openapi.yaml` is the HTTP contract exposed by the Rust backend.
- `json-schema/clip-envelope.schema.json` is the browser-extension/runtime validation contract.
- `generated/` contains reviewable generated snapshots. CI regenerates and fails on drift.
- Clipboard plaintext, encryption keys, voiceprints, and biometric templates are never part of a server contract.

## Generate

```bash
./scripts/generate.sh
```

The generated Rust snapshot intentionally contains a small hand-reviewable model layer so sibling repositories can compile without requiring code generation during every build.
