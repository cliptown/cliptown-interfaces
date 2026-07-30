# ClipTown and 3FA trust boundary

Tracking: DEN-44, DEN-42, DEN-150, and DEN-603.

## Reciprocal integration

The products use each other through two independent interfaces:

- **3FA → ClipTown:** encrypted authenticator-vault mutations use ClipTown's
  authenticated multi-device transport through the app-vault API.
- **ClipTown → 3FA:** sensitive ClipTown actions may require a one-time signed
  step-up proof approved by an enrolled 3FA device.

This is not a shared database, shared bearer token, shared cookie, or package
cycle. Shared-auth/Supabase remains the primary identity authority. Every
ClipTown and 3FA installation enrolls independently and receives a distinct,
revocable service-local device credential.

## Authenticator records versus authentication credentials

“Share tokens across authenticated devices” means replicate the encrypted
TOTP/HOTP/OATH authenticator vault to the user's other active, authorized
devices. It does **not** mean replicate any of the following:

- Supabase/shared-auth access or refresh tokens;
- ClipTown or 3FA service-local device tokens;
- browser sessions or cookies;
- Signal identity private keys or ratchet state;
- platform keystore handles;
- current OTP codes;
- local PINs or biometric material.

A compromised or revoked device credential must be independently removable.
No endpoint accepts a sibling device's bearer token as proof of enrollment.

## Application vault isolation

`proto/cliptown/v1/app_vault.proto` and the corresponding OpenAPI/JSON schemas
are deliberately separate from `ClipEnvelope` and clipboard sync.

An `AppVaultMutation` contains only:

- protocol and mutation identifiers;
- reverse-DNS app id;
- non-semantic namespace;
- opaque record id (random id or account-keyed digest);
- optional ciphertext envelope or a deletion tombstone;
- source device, logical clock, timestamps, and device signature.

It cannot represent clipboard kind, pin state, source app, preview, title,
provider/account label, search terms, embeddings, paste hints, retention class,
or plaintext metadata. Application-vault records must be excluded from:

- clipboard capture and injection;
- clipboard history and pinned-item views;
- local/server search and blind-index pipelines;
- embeddings and RAG candidate generation;
- notification previews and analytics;
- clipboard export, paste, sharing, and browser-draft recovery;
- ordinary clip retention and deletion jobs.

The URL path's `appId` must match every mutation's `app_id`. The server applies a
per-account/per-app allowlist and bounded quotas before storing mutations.
`app.3fa.authenticator` is the stable 3FA identifier.

## Encryption and recipient authorization

ClipTown never encrypts or decrypts 3FA records. The 3FA client seals the entire
semantic record, including local namespace/key/provider/account metadata, before
transport. The visible `opaque_record_id` is derived with a random identifier or
account-keyed digest so repeated provider labels do not become server metadata.

A fresh record/content key is bound to version, mutation id, app id, namespace,
opaque record id, source device, logical clock, deletion state, timestamps,
algorithm, and key id. The device signature covers canonical metadata plus the
payload nonce, ciphertext, and associated-data hash.

The corresponding app-vault key is delivered only to active recipient devices
through Signal Protocol envelopes with purpose `app_vault_key`. The ClipTown
server stores public prekeys and opaque ciphertext but never device private keys,
ratchet state, vault keys, OTP seeds, or plaintext mutations.

## Device bootstrap without circular dependency

1. The new installation signs in through shared-auth/Supabase.
2. ClipTown and 3FA independently issue device-bound credentials.
3. The device creates platform-protected private key material and publishes only
   public enrollment/prekey data.
4. A trusted device or explicitly enabled recovery path approves enrollment.
5. Recipient-specific Signal envelopes deliver account/app-vault wrapping keys.
6. App-vault pulls become decryptable only after acknowledgement.

ClipTown remains usable for ordinary operations while 3FA is unavailable; only
policies requiring recent step-up fail closed or use an explicitly configured
recovery path. 3FA remains locally usable while ClipTown transport is unavailable
and retries encrypted replication later.

## External step-up proof

`ExternalStepUpProof` is an additive authorization signal for one sensitive
action. A ClipTown challenge is approved by a registered 3FA device after local
biometric, passkey, or PIN-gated unlock of its device key.

The proof binds protocol version, proof id, issuer, shared subject, audience
(`cliptown`), approving device, challenge id, action, timestamps, signing key,
and signature. Its maximum lifetime is five minutes.

The backend must verify all fields, device/account status, issuer key, signature,
and recent-auth policy, then atomically consume both proof id and challenge id in
the same transaction as the protected action. A proof cannot be refreshed,
replayed, changed to another action, used for another account/device, or accepted
as a general bearer token.

The `X-3FA-Step-Up` header carries a compact signed representation. Never place it
in a URL, query parameter, log, trace attribute, metric label, crash report, or
persistent client preference.

## Revocation requirements

Revocation immediately blocks the device's local service token, app-vault
push/pull, prekey operations, mailbox access, object grants, and future key
fan-out. It invalidates outstanding step-up challenges and unconsumed proofs and
causes remaining devices to rotate affected wrapping keys. Signed tombstones and
audit state remain long enough to prevent stale-device resurrection.

Revocation in one product may prompt the user to review linked enrollment in the
other, but must not silently infer that two records represent the same device
without a verified link.

## Backend implementation gates

Do not enable the OpenAPI routes in production until:

- app-vault tables/RLS are separate from clipboard tables and policies;
- active device id is derived from a verified device-bound credential, not a
  caller-supplied body field;
- app id, batch, ciphertext, mailbox, cursor, timestamp, and quota bounds are
  enforced before allocation/storage;
- mutation id/idempotency and logical-clock conflict handling are transactional;
- step-up challenge/proof replay records are consumed atomically;
- revoked/suspended devices fail both service authorization and RLS tests;
- canonical Dart/Rust/TypeScript signing fixtures match;
- adversarial tests cover duplicates, replay, gaps, out-of-order delivery,
  concurrent edits, tombstone resurrection, identity-key changes, and revocation;
- telemetry-redaction tests prove that payloads, identifiers, signatures, codes,
  credentials, and key material do not escape.
