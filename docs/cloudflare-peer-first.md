# Cloudflare peer-first text sync v1: additive contract

Status: draft / fail-closed. This does not enable Cloudflare-hosted synchronization or WebRTC. Existing ClipTown sync v1, enrolled-device signatures, Signal key-wrapping and BLE proximity contract remain authoritative.

## Reuse and compatibility

- Existing proto/cliptown/v1/sync.proto and json-schema/sync-protocol-v1.schema.json plus opto-sync reconciliation govern immutable mutation identity, ordering, tombstone precedence, monotonic acknowledgment and revocation.
- This contract only adds a Cloudflare rendezvous transport and bounded ciphertext-only cloud cache. No second merge algorithm.
- The peer-signaling JSON Schema describes encrypted SDP/ICE negotiation, never plaintext SDP/ICE. Sender/recipient metadata is visible to the signaling service and must be short-lived, rate limited and redacted in logs.

## Enrolled-device admission

Workers must validate official Shared Auth (or an approved fail-closed protected verification path), account ownership, active device registration, revocation epoch, envelope signatures and nonce/replay windows before routing to an account Durable Object. An asserted account ID or WebSocket message alone never authenticates a peer. WebRTC DTLS itself is not a substitute for ClipTown signed, encrypted sync mutations.

Before forwarding a signal, enforce: closed schema/version, enrolled Ed25519 public key and signature, sender/recipient/session/purpose/epoch bindings, canonical field signature, SHA-256 of decoded ciphertext and canonical unpadded base64url, non-future issue time, expiry <=120 seconds and strictly later than issue time, monotonic per-session sequence, unique message ID, <=12 KiB decoded ciphertext, bounded fanout, and distinct authorized active sender/recipient belonging to the same account. Review races with revocation/key rotation. Never log SDP candidates, ciphertext, signatures, device pairs, credentials or presence graphs.

## Cache contract

- Store authenticated encrypted text envelopes only: no plaintext, images/files, vectors, auth tokens, 3FA or app-vault records.
- Per-account quota: 2,000 newest text envelopes or 5 MiB measured logical bytes, whichever limit is reached first. Charge actual ciphertext length + 512 reserved metadata bytes; this is NOT a physical D1 disk cap.
- Newest prefix ordering: descending server-issued sequence, then descending ASCII envelope ID. Do not re-include smaller older records after a byte-threshold gap.
- Cache eviction never propagates as a peer delete/tombstone. Full restore depends on an enrolled full-history device.
- Account-serialized D1 transaction must atomically allocate sequence and insert+prune, while independently preserving bounded control-plane tombstones and revocation.

## Cross-compiler and borrow/ownership parity

fixtures/cloudflare-text-cache-v1.json is the shared contract for independent Rust, Dart and TypeScript implementations.
- Rust measures immutable borrowed &[u8] ciphertext views with compiler-enforced lifetimes and no unsafe code. No ciphertext copying is needed.
- Dart takes Uint8List; TypeScript takes Uint8Array. Neither has Rust-style borrow checking. Synchronous policies measure actual buffers, do not mutate them, and return fresh immutable ID lists. The caller must retain an owned immutable snapshot before passing data to asynchronous transport.
- All three must reject duplicate IDs, invalid IDs, zero sequence, empty/oversized ciphertext and non-text kinds; the 5 MiB prefix, 2,000-item limit and tie-breaker must agree.
- Do not count skipped/noncompiled tests as PASS. Hosted compilation does not certify physical BLE or live TURN/D1 delivery.

Follow-on: implement authenticated provider adapters in cliptown-infra and transport integration in independent Flutter/native Rust desktop products.
