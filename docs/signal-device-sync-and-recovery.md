# Signal Protocol device sync, recovery, and encrypted object storage

Tracking: DEN-42, DEN-47, and DEN-51.

## Security boundary

ClipTown encrypts clipboard text, metadata, images, and files on a trusted device before any upload. PostgreSQL, Supabase, the Rust backend, and Cloudflare R2 receive only authenticated metadata and opaque ciphertext.

The account master key, per-device private keys, Signal Protocol session state, per-clip keys, per-object keys, PINs, OTP codes, and biometric templates never enter server storage or telemetry.

## Device lifecycle

Each device owns a distinct identity key and Signal Protocol prekey bundle. A new device starts `pending`, publishes public prekeys, and is approved through a trusted-device QR/safety-number ceremony. Approval transfers the random account master key through a recipient-specific Signal ciphertext envelope. Device-list snapshots are revisioned and signed.

Users can name, list, verify, suspend, and revoke devices. Revocation immediately invalidates auth and mailbox access, removes the device from future key fan-out and object-download authorization, and triggers wrapping-key rotation on remaining devices. An unexpected identity-key change pauses delivery until explicit re-verification.

## Backup email, phone OTP, biometrics, passkeys, and PIN

Backup email and phone OTP are verified recovery/step-up channels. They are short-lived, one-time, rate-limited, replay-protected, and never used as content-encryption keys.

Prefer passkeys/platform authenticators for primary authentication. Flutter uses Apple LocalAuthentication/Keychain/Secure Enclave, Android BiometricPrompt/Keystore, Windows Hello, and platform equivalents to unlock device-bound key material. ClipTown never receives a fingerprint, face, voice, or other biometric template.

A six-digit PIN is a local unlock factor only. It may protect a random wrapped device key using a bounded Argon2id/scrypt policy plus device-bound throttling, exponential backoff, lockout, and optional wipe policy. The PIN is never the account master key, a clip/file key, a recovery key, a server credential, or synchronized plaintext.

Recovery without a trusted device requires an explicitly opted-in encrypted recovery package or human-readable recovery key. Successful email/SMS/biometric verification alone does not reveal the account master key.

## Text and metadata encryption

Each clip receives a random content-encryption key and nonce. AEAD associated data binds at least the account, source device, clip identifier, kind, logical clock, ciphertext version, and deletion/pin state. Search is local by default; keyed blind indexes and vector embeddings are separately opt-in.

## File and R2 encryption

Large files use a fresh random content-encryption key and chunked authenticated encryption. Every chunk has its own nonce, index, ciphertext digest, and randomized R2 storage key. The encrypted manifest commits to chunk order, sizes, aggregate ciphertext digest, encrypted metadata, and recipient-specific wrapped content keys.

Signal sessions carry small wrapped content keys and device-control messages; they do not directly ratchet-encrypt multi-megabyte R2 objects. No plaintext hash is used as a public object name or cross-account deduplication key. Optional deduplication is local-only or uses an account-keyed digest.

## Logging and retention

Never log or label metrics with contact destinations, OTPs, PINs, account/device identifiers, key bytes, safety numbers, ciphertext, object paths, or request bodies. Use bounded aggregate counters and stable error classes only.

Account/clip deletion removes database metadata, mailbox entries, upload grants, and R2 ciphertext according to the reviewed retention policy. Revoked devices cannot obtain fresh download grants or wrapped keys.
