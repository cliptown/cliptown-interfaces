# MemeBank API and SDK interoperability

MemeBank and ClipTown are independently deployable products. Their canonical
integration is the versioned ClipTown HTTP API consumed through an official SDK.
It is not an app-to-app mobile bridge.

## Non-negotiable boundary

A user may connect MemeBank to ClipTown even when:

- only one of the two mobile applications is installed;
- the interaction originates from a web app, desktop app, CLI, worker, or server;
- the phone is offline or not involved;
- operating-system deep links, local IPC, and clipboard access are unavailable.

Neither product may require or probe the other's installation state. Neither may
background-monitor the clipboard to infer an integration event. Native clipboard
copy/paste remains a useful standalone feature, but it is not the integration
transport and is not a prerequisite for API interoperability.

## Authentication and 3FA

MemeBank authenticates through shared-auth. It never calls a 3FA backend, imports
a 3FA service SDK, validates a 3FA-specific proof, or deep-links into 3FA as part
of this integration.

The caller exchanges its normal shared-auth token for a short-lived delegated
token. ClipTown pins:

- `iss` to the shared-auth issuer;
- `aud` to `cliptown-api`;
- `azp` to `memebank-api`;
- an active revocation-aware `sid`;
- the exact required `cliptown:memebank:*` scope;
- expiry, not-before, and a new delegated `jti`;
- the stable subject used for resource ownership.

For sensitive writes or cancellation, the shared-auth delegation policy requires
recent LOA2. A verified ceremony may have used TOTP, passkey, email OTP, SMS OTP,
or a compatible 3FA-imported factor. ClipTown and MemeBank consume only the
normalized shared-auth `aal`, `acr`, `amr`, and `auth_time`; they do not contact
the factor application.

## Transfer API

The canonical contract is
[`openapi/memebank-integration.openapi.yaml`](../openapi/memebank-integration.openapi.yaml).
The runtime request schema is
[`json-schema/memebank-api-transfer-v1.schema.json`](../json-schema/memebank-api-transfer-v1.schema.json).

The API exposes a subject-owned, idempotent transfer queue:

- create a ciphertext-only transfer;
- list or retrieve transfers using opaque cursors;
- acknowledge an imported, ignored, or rejected transfer;
- cancel a pending transfer with the delete scope and recent LOA2.

Every record is authorized against the delegated `sub`. A service credential is
not a cross-tenant bypass. Not-found behavior does not reveal whether a transfer
exists for another subject.

## Payload rules

The transfer envelope contains encrypted content plus bounded routing and
integrity metadata. It must never contain:

- access or refresh tokens;
- shared-auth introspection credentials;
- OTP seeds or codes;
- PINs, biometric material, or private keys;
- provider OAuth credentials;
- durable private object-store URLs;
- signed upload or download URLs;
- plaintext OCR, captions, tags, or image bytes;
- local app paths, app-presence flags, or deep links used as the transport.

The source item identifier is opaque and non-dereferenceable. Ciphertext larger
than the inline contract limit uses the reviewed encrypted-object API and a
recipient-specific wrapped content key, never a signed URL pasted into metadata.

## Idempotency and replay

Create and acknowledgement operations require an `Idempotency-Key`. ClipTown
binds the key to the subject, route, operation, and canonical request digest.
Reusing a key with the same request returns the existing result; reusing it with
a different digest returns a conflict. Terminal transfer states cannot be
silently reopened.

## SDK requirements

Official SDKs must:

- refuse plaintext remote HTTP and redirects carrying authorization;
- set the delegated bearer only on ClipTown API requests;
- bound request and response bodies;
- validate identifiers, cursors, media types, timestamps, and idempotency keys
  before network I/O;
- expose deterministic status errors without logging tokens or ciphertext;
- treat unknown major contract versions as incompatible;
- require no mobile-app discovery, deep-link handler, or clipboard permission.

The legacy `memebank-clipboard-v1` metadata schema remains an optional additive
clipboard representation for an explicit local copy action. It is not the API
contract and must not be used to decide whether integration is available.
