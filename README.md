# cliptown-interfaces

Versioned contracts shared by the ClipTown API, Flutter app, browser extension, CLI, SDKs, companion applications, and isolated product application vaults.

## Contract rules

- `proto/cliptown/v1` is the canonical wire contract for sync and peer-to-peer envelopes.
- `proto/cliptown/v1/security.proto` defines revisioned device lifecycle, Signal Protocol public prekeys/envelopes, recovery channels, local-unlock policy, and one-time external step-up proofs without PINs, biometric templates, private keys, or reusable bearer credentials.
- `proto/cliptown/v1/app_vault.proto` defines ciphertext-only mutations for product data that must never enter clipboard history, search, RAG, preview, paste, pinning, export, notification, or ordinary clip-retention paths.
- `proto/cliptown/v1/encrypted_object.proto` defines chunked encrypted file/object manifests and recipient-specific wrapped content keys for Cloudflare R2 or compatible object stores.
- `openapi/cliptown.openapi.yaml` is the primary ClipTown HTTP contract exposed by the Rust backend.
- `openapi/memebank-integration.openapi.yaml` is the API-first MemeBank transfer contract. It is independent of mobile app installation, deep links, local IPC, and clipboard monitoring.
- `json-schema/*.schema.json` are runtime validation contracts for browser, Flutter, API, and SDK boundaries.
- `json-schema/memebank-api-transfer-v1.schema.json` validates ciphertext-only MemeBank API transfer requests.
- `json-schema/memebank-clipboard-v1.schema.json` is only an additive local clipboard compatibility subset when MemeBank explicitly copies an image. The canonical clipboard schema remains owned by `memebank/mb-interfaces`, and it is not the product-integration transport.
- `generated/` contains reviewable Rust, TypeScript, and Dart model snapshots. CI validates all three languages.
- Clipboard plaintext, encryption keys, OTP seeds/codes, PINs, voiceprints, biometric templates, private Signal state, access/refresh or other bearer tokens, sibling-device service credentials, cloud credentials, and signed upload URLs are never part of a server storage contract or companion-app metadata.

## MemeBank interoperability

MemeBank and ClipTown interoperate through versioned HTTP contracts and official SDKs. Neither product requires or probes whether the other's mobile application is installed. Web, desktop, CLI, worker, and server callers use the same API surface without deep links, local IPC, shared databases, shared cloud credentials, or hidden clipboard monitoring.

MemeBank obtains a short-lived ClipTown token through shared-auth delegation. ClipTown pins the shared-auth issuer, `aud=cliptown-api`, `azp=memebank-api`, an active session, the exact `cliptown:memebank:*` scope, and the delegated subject for resource ownership. Sensitive write/delete scopes require recent LOA2 under shared-auth policy. MemeBank never calls a 3FA backend or validates a 3FA-specific proof; TOTP, passkey, email OTP, SMS OTP, and compatible 3FA-imported ceremonies appear only as normalized shared-auth assurance claims.

See [`docs/memebank-api-interoperability.md`](docs/memebank-api-interoperability.md).

## Companion clipboard metadata policy

Companion clipboard metadata never replaces a standard clipboard representation. An explicit MemeBank **Copy** action should still include image bytes, a safe temporary file reference, or user-authorized text so ordinary paste targets work without network access. Unknown additive fields are retained only when permitted by the user's normal ClipTown policy; unsupported major schema versions are not interpreted.

This local clipboard path is intentionally separate from the API integration. It must not be used to test whether MemeBank or ClipTown is installed, authenticate a cross-product request, transfer a bearer or capability, or determine whether interoperability is available.

Companion clipboard metadata and isolated application-vault records are different trust domains. Companion metadata may accompany an explicit user clipboard export; application-vault records are opaque ciphertext and are never interpreted, indexed, previewed, pasted, retained, or exported as clipboard content. Route validation, generated models, and wire-contract CI enforce this separation rather than relying only on application convention.

## 3FA reciprocal integration

3FA may use ClipTown's authenticated device substrate only through the isolated application-vault contract. ClipTown's own legacy/additive external step-up surface remains a separate trust domain from MemeBank interoperability.

MemeBank routes do not accept `X-3FA-Step-Up`, a 3FA bearer, a 3FA app-presence signal, or direct factor-app callbacks. They accept only shared-auth delegated tokens and evaluate normalized assurance plus product authorization. Shared-auth/Supabase remains the primary identity source, and every ClipTown installation receives its own independently revocable service-local credential.

See [`docs/3fa-app-vault-and-step-up.md`](docs/3fa-app-vault-and-step-up.md) for the isolated app-vault bootstrap, revocation, replay, privacy, and rollout requirements.

## Security architecture

See [`docs/signal-device-sync-and-recovery.md`](docs/signal-device-sync-and-recovery.md). Signal Protocol sessions authorize devices and deliver small wrapped account/clip/object/app-vault keys. Text, metadata, images, files, product-vault records, and MemeBank transfer payloads are encrypted before PostgreSQL, Supabase, Rust services, or Cloudflare R2 receive them.

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
