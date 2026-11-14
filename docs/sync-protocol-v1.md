# ClipTown sync protocol v1

This document freezes the observable sync contract tracked by DEN-47. It does not claim that every client or transport is already conformant.

## Cursor and pagination

`cursor` is a monotonic server sequence position and is independent of `has_more`. A successful page advances the durable cursor to the greatest contiguous server sequence covered by that response, including a final page where `has_more` is false. Clients must not infer the next cursor from page size or row count. A response that cannot prove contiguous coverage must not advance the durable cursor.

## Mutation identity and replay

Every sendable mutation has an immutable positive-decimal `mutation_id`, stable `device_id`, logical clock, entity identity, operation kind, and payload digest. Retries after timeout or ambiguous response loss reuse the exact mutation identity and idempotency key. Acknowledgement removes only the exact immutable mutations covered by the authoritative response; it must not delete newer local mutations for the same entity.

Implementations must bound idempotency retention and document that bound. Expiry of server-side deduplication state must not cause a client to silently mint a replacement identity for already-durable work.

## Conflict ordering

For two operations on the same entity, implementations compare these dimensions in order:

1. deletion precedence: an authoritative delete/tombstone is never resurrected by an older non-delete;
2. logical clock (`physical_ms`, then `logical`);
3. authoritative `server_sequence` when present;
4. stable `device_id` as the deterministic final tie-breaker.

The same inputs must select the same winner on every runtime. Incidental SQL row order, wall-clock arrival order, thread scheduling, and container iteration order are not valid tie-breakers.

## Lifecycle events

Protocol v1 carries ordinary upserts/deletes plus pin changes, attachment-manifest changes, device revocations, and key-rotation events. Revocation and key-rotation events are security state: clients must process them before sending subsequently queued work that depends on the invalidated device/key authorization epoch.

## Offline and peer transport

Cloud and local peer transports reuse the same signed/encrypted logical envelope and immutable mutation identities. A transport switch must not renumber, reorder, or unwrap queued work. Peer discovery and pairing are authenticated; downgrade to an unauthenticated or plaintext transport is not permitted.

## Restart and failure boundary

Durable cursor, pending mutations, tombstones, and security lifecycle state are committed atomically with their local effects. On interruption, reopen must observe either the prior committed state or the complete new state, never a partially advanced cursor with missing local effects. Backend unavailability must not reset the cursor or discard durable pending work.

## Conformance requirements

Release certification must include property/integration coverage for final-page cursor advancement, replay after ambiguous response loss, concurrent edits, duplicate pushes, tombstones, offline mutation creation, restart/reconnect, and transport switching. Synthetic and test-org fixtures are preferred; production credentials and real user clipboard contents are forbidden in conformance artifacts.

Machine-readable envelope: `json-schema/sync-protocol-v1.schema.json`.
