# cliptown-interfaces

Versioned contracts shared by the ClipTown API, Flutter app, browser extension, CLI, and SDKs.

## Contract rules

- `proto/cliptown/v1` is the canonical wire contract for sync and peer-to-peer envelopes.
- `proto/cliptown/v1/security.proto` defines revisioned device lifecycle, Signal Protocol public prekeys/envelopes, recovery channels, and local-unlock policy without PINs, biometric templates, or private keys.
- `proto/cliptown/v1/encrypted_object.proto` defines chunked encrypted file/object manifests and recipient-specific wrapped content keys for Cloudflare R2 or compatible object stores.
- `openapi/cliptown.openapi.yaml` is the HTTP contract exposed by the Rust backend.
- `json-schema/*.schema.json` are runtime validation contracts for browser/Flutter boundaries.
- `generated/` contains reviewable Rust, TypeScript, and Dart model snapshots. CI validates all three languages.
- Clipboard plaintext, encryption keys, OTPs, PINs, voiceprints, and biometric templates are never part of a server storage contract.

## Security architecture

See [`docs/signal-device-sync-and-recovery.md`](docs/signal-device-sync-and-recovery.md). Signal Protocol sessions authorize devices and deliver small wrapped account/clip/object keys. Text, metadata, images, and files are encrypted on trusted devices before PostgreSQL, Supabase, Rust services, or Cloudflare R2 receive them.

## Reviewed toolchain

The contract repository intentionally avoids floating compiler channels:

- Buf CLI `1.72.0`
- Rust `1.88.0` with `rustfmt` and Clippy
- Dart `3.12.2`
- Node.js `22.x`

CI verifies the exact Buf, Rust, and Dart versions before contract or generated-model checks run. Version changes must be explicit reviewable pull requests rather than silent updates from `stable` channels.

## Generate

```bash
./scripts/generate.sh
```

The generated Rust snapshot intentionally contains a small hand-reviewable model layer so sibling repositories can compile without requiring code generation during every build.
