import type { CipherEnvelope } from './index.js';

export const APP_VAULT_PROTOCOL_VERSION = 1 as const;
export const MAX_APP_VAULT_BATCH = 500;

export interface AppVaultMutation {
  protocol_version: 1;
  mutation_id: string;
  app_id: string;
  namespace: string;
  opaque_record_id: string;
  payload?: CipherEnvelope | null;
  deleted: boolean;
  source_device_id: string;
  logical_clock: number;
  created_at: string;
  updated_at: string;
  device_signature: string;
}

export interface AppVaultCursor {
  server_sequence: number;
}

export interface AppVaultChange {
  server_sequence: number;
  mutation: AppVaultMutation;
}

export interface AppVaultPushRequest {
  mutations: AppVaultMutation[];
  base?: AppVaultCursor | null;
}

export interface AppVaultPushResponse {
  accepted: AppVaultMutation[];
  rejected_mutation_ids: string[];
  cursor: AppVaultCursor;
}

export interface AppVaultPullRequest {
  after?: AppVaultCursor | null;
  limit?: number;
}

export interface AppVaultPullResponse {
  changes: AppVaultChange[];
  cursor: AppVaultCursor;
  has_more: boolean;
}

export function validateAppVaultMutation(mutation: AppVaultMutation): void {
  if (mutation.protocol_version !== APP_VAULT_PROTOCOL_VERSION) {
    throw new Error('unsupported app-vault protocol version');
  }
  requirePortableIdentifier(mutation.mutation_id, 'mutation_id');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(mutation.app_id)) {
    throw new Error('app_id must be a bounded reverse-DNS-style identifier');
  }
  requirePortableIdentifier(mutation.namespace, 'namespace');
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(mutation.opaque_record_id)) {
    throw new Error('opaque_record_id must be a random id or account-keyed digest');
  }
  requirePortableIdentifier(mutation.source_device_id, 'source_device_id');
  if (!Number.isSafeInteger(mutation.logical_clock) || mutation.logical_clock < 0) {
    throw new Error('logical_clock must be a non-negative safe integer');
  }
  const createdAt = Date.parse(mutation.created_at);
  const updatedAt = Date.parse(mutation.updated_at);
  if (!Number.isFinite(createdAt) || !Number.isFinite(updatedAt) || updatedAt < createdAt) {
    throw new Error('app-vault mutation timestamps are invalid');
  }
  if (mutation.deleted === (mutation.payload != null)) {
    throw new Error('a mutation must contain ciphertext or be a tombstone, never both');
  }
  if (mutation.payload != null) validateAppVaultCiphertext(mutation.payload);
  if (mutation.device_signature.length < 43 || mutation.device_signature.length > 684) {
    throw new Error('device_signature length is invalid');
  }
}

export function validateAppVaultPushRequest(request: AppVaultPushRequest): void {
  if (request.mutations.length > MAX_APP_VAULT_BATCH) {
    throw new Error('app-vault push batch is too large');
  }
  request.mutations.forEach(validateAppVaultMutation);
  if (request.base != null) validateAppVaultCursor(request.base);
}

export function validateAppVaultPullResponse(response: AppVaultPullResponse): void {
  if (response.changes.length > MAX_APP_VAULT_BATCH) {
    throw new Error('app-vault pull result is too large');
  }
  validateAppVaultCursor(response.cursor);
  let previous = 0;
  for (const change of response.changes) {
    if (!Number.isSafeInteger(change.server_sequence) || change.server_sequence < 1) {
      throw new Error('server_sequence must be a positive safe integer');
    }
    if (change.server_sequence <= previous || change.server_sequence > response.cursor.server_sequence) {
      throw new Error('app-vault server sequences must be increasing and cursor-bounded');
    }
    validateAppVaultMutation(change.mutation);
    previous = change.server_sequence;
  }
}

function validateAppVaultCursor(cursor: AppVaultCursor): void {
  if (!Number.isSafeInteger(cursor.server_sequence) || cursor.server_sequence < 0) {
    throw new Error('server_sequence must be a non-negative safe integer');
  }
}

function validateAppVaultCiphertext(payload: CipherEnvelope): void {
  if (payload.algorithm !== 'xchacha20poly1305-v1' && payload.algorithm !== 'aes-256-gcm-v1') {
    throw new Error('unsupported app-vault cipher');
  }
  if (!payload.nonce || !payload.ciphertext || payload.ciphertext.length > 699052 || !payload.key_id) {
    throw new Error('app-vault cipher envelope is incomplete or oversized');
  }
  if (!payload.associated_data_hash) {
    throw new Error('app-vault associated_data_hash is required');
  }
  if (payload.key_id.length > 128) {
    throw new Error('app-vault key_id is too long');
  }
}

function requirePortableIdentifier(value: string, field: string): void {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) {
    throw new Error(`${field} must use bounded portable ASCII characters`);
  }
}
