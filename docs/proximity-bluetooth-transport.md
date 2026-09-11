# Bluetooth and proximity transport v1

Bluetooth is an optional offline transport for the same encrypted ClipTown and
Shared Auth workflows used over the network. It is never an identity provider,
an authentication factor, or evidence that a nearby device is trusted.

## Roles and platform boundary

- The Flutter client supports the BLE central role on Windows, macOS, Linux,
  Android, and iOS. Android, iOS, macOS, and Windows may also advertise the
  ClipTown GATT service; Linux is central-only until its reviewed peripheral
  backend exists.
- The independent Rust desktop client supports the BLE central role on Windows,
  macOS, and Linux. Both desktop clients must pass the same fixtures; neither is
  a wrapper around or release substitute for the other.
- Discovery advertisements contain only the fixed service UUID, a bounded
  rotation epoch, and an HMAC-derived rotating identifier. They never contain
  account, clip, email, phone, stable device, or assurance identifiers.
- BLE frames are capped at 32 KiB. Images and files remain encrypted objects and
  use digest-checked chunks; advertisements never carry clip data.

## Pairing and consent

Pairing starts only from an explicit foreground action. The initiator already
has the intended device identity from a QR or authenticated account device list,
then finds the matching rotating advertisement. Both screens display a six-digit
code derived from the complete ephemeral handshake transcript. A session becomes
eligible for application requests only after both users confirm the code.

Each clipboard offer has its own one-use consent showing the peer, item types,
count, byte total, and expiry. Remembering a peer does not grant silent clipboard
import or background capture. Backgrounding, radio loss, endpoint substitution,
permission revocation, cancellation, or timeout tears down the session and erases
its ephemeral keys.

## Wire and cryptographic rules

`proximity-advertisement.schema.json` and
`proximity-envelope.schema.json` are closed v1 schemas. Every envelope is bound
to the protocol, purpose, session, sender, recipient, sequence, issue/expiry
times, ciphertext digest, and enrolled device signing key. Consumers must:

1. reject unknown fields, unsupported versions/purposes, malformed base64url,
   payloads over 32 KiB, lifetimes over two minutes, future messages, expiry,
   wrong sender/recipient/session/scope, reused message IDs, and non-increasing
   sequence numbers before decryption or UI import;
2. verify the Ed25519 signature against a currently enrolled, non-revoked device
   key and validate the ciphertext SHA-256 before decrypting;
3. keep clip payloads inside the existing end-to-end encrypted ClipTown envelope
   and preserve mutation IDs/logical clocks for later server reconciliation;
4. redact ciphertext, signatures, discovery IDs, safety codes, device IDs, and
   Shared Auth request material from logs, analytics, notifications, and crash
   reports.

## Shared Auth and 3FA boundary

The only authentication-related proximity purpose is
`shared_auth:step-up:relay`. Its ciphertext is an opaque, one-use Shared Auth
request conforming to the reviewed 3FA proximity contract. It is bound to the
issuer, relying-party audience, recipient 3FA device, exchange, requested AAL,
and expiry of at most 120 seconds.

ClipTown cannot inspect, extend, or treat delivery of that request as success.
The 3FA app submits it through its ordinary authenticated Shared Auth channel.
ClipTown changes authorization only after independently receiving and verifying
a fresh, audience/device-bound and revocation-aware Shared Auth result. Passwords,
PINs, OTP/TOTP values or seeds, recovery codes, bearer tokens, private keys,
biometric material, factor proofs/results, and final assurance claims are never
proximity payloads. Bluetooth presence, RSSI, pairing, bonding, and a matching
code never raise AAL.

If Shared Auth is unreachable, ClipTown may continue encrypted clipboard
transfer between already enrolled devices, but authentication step-up remains
`authority_unavailable`; it must not be converted into an offline success.

## Evidence gates

Hosted tests cover schema parity and simulated radio/error paths on Windows,
macOS, Linux, Android, and iOS. Release enablement additionally requires
physical Android-to-Android, iOS-to-iOS, Android-to-iOS, mobile-to-each-desktop,
radio-off, wrong-code, one-sided-consent, replay, reorder, expiry, revocation,
oversize, digest/signature mismatch, background, disconnect, and reconnect
canaries. Emulator and mocked BLE results are not physical-radio evidence.
