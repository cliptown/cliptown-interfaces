# cliptown-interfaces

Versioned contracts shared by the ClipTown API, Flutter app, browser extension, CLI, and SDKs.

## Contract rules

- `proto/cliptown/v1` is the canonical wire contract for sync and peer-to-peer envelopes.
- `proto/cliptown/v1/security.proto` defines revisioned device lifecycle, Signal Protocol public prekeys/envelopes, recovery channels, and local-unlock policy without PINs, biometric templates, or private keys.
- `proto/cliptown/v1/encrypted_object.proto` defines chunked encrypted file/object manifests and recipient-specific wrapped content keys for Cloudflare R2 or compatible object stores.
- `openapi/cliptown.openapi.yaml` is the HTTP contract exposed by the Rust backend.
- `json-schema/*.schema.json` are runtime validation contracts for browser/Flutter boundaries.
- `json-schema/memebank-clipboard-v1.schema.json` is the additive compatibility subset ClipTown may retain when Memebank explicitly exports an image. The canonical schema remains owned by `memebank/mb-interfaces`.
- `generated/` contains reviewable Rust, TypeScript, and Dart model snapshots. CI validates all three languages.
- Clipboard plaintext, encryption keys, OTPs, PINs, voiceprints, biometric templates, bearer tokens, cloud credentials, and signed upload URLs are never part of a server storage contract or companion-app clipboard metadata.

## Companion metadata policy

Companion metadata never replaces a standard clipboard representation. A Memebank-aware clipboard write should still include image bytes, a safe temporary file reference, or user-authorized text so ClipTown remains usable without network access or a live Memebank session. Unknown additive fields are retained only when permitted by the user's normal ClipTown policy; unsupported major schema versions are not interpreted.

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
