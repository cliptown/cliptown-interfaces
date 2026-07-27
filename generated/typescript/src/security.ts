export type DeviceLifecycleState = 'pending' | 'active' | 'suspended' | 'revoked';
export type RecoveryChannelKind = 'email' | 'phone';
export type SignalEnvelopePurpose =
  | 'account_key_transfer'
  | 'clip_key'
  | 'object_key'
  | 'device_control'
  | 'recovery_package'
  | 'acknowledgement';

export interface PinKdfPolicy {
  algorithm: 'argon2id-v1' | 'scrypt-v1';
  memory_kib: number;
  iterations: number;
  parallelism: number;
  max_attempts: number;
  lockout_seconds: number;
}

export interface LocalUnlockPolicy {
  pin_enabled: boolean;
  biometric_enabled: boolean;
  passkey_enabled: boolean;
  pin_kdf?: PinKdfPolicy | null;
}

export interface SignalPreKeyBundle {
  device_id: string;
  protocol_version: 1;
  registration_id: number;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey: string;
  signed_prekey_signature: string;
  pq_signed_prekey_id: number;
  pq_signed_prekey: string;
  pq_signed_prekey_signature: string;
  one_time_prekey_id?: number | null;
  one_time_prekey?: string | null;
  bundle_revision: number;
  published_at: string;
  expires_at: string;
}

export interface DeviceRecord {
  device_id: string;
  device_name: string;
  platform: string;
  state: DeviceLifecycleState;
  device_list_revision: number;
  identity_key_fingerprint: string;
  local_unlock: LocalUnlockPolicy;
  created_at: string;
  verified_at?: string | null;
  last_seen_at?: string | null;
  revoked_at?: string | null;
}

export interface RecoveryChannel {
  channel_id: string;
  kind: RecoveryChannelKind;
  masked_destination: string;
  created_at: string;
  verified_at?: string | null;
  disabled_at?: string | null;
}

export interface SignalEnvelopeMetadata {
  protocol_version: 1;
  envelope_id: string;
  account_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  session_id: string;
  message_number: number;
  purpose: SignalEnvelopePurpose;
  created_at: string;
  expires_at: string;
}

export interface SignalCiphertextEnvelope {
  metadata: SignalEnvelopeMetadata;
  ciphertext: string;
}

export interface WrappedContentKey {
  recipient_device_id: string;
  key_id: string;
  algorithm: 'signal-envelope-v1' | 'xchacha20poly1305-wrap-v1' | 'aes-256-gcm-wrap-v1';
  nonce: string;
  wrapped_key: string;
  associated_data_hash: string;
}

export interface EncryptedObjectChunk {
  chunk_index: number;
  ciphertext_length: number;
  ciphertext_sha256: string;
  nonce: string;
  randomized_storage_key: string;
}

export interface EncryptedObjectManifest {
  manifest_id: string;
  object_id: string;
  clip_id: string;
  content_cipher_version: 'xchacha20poly1305-chunked-v1' | 'aes-256-gcm-chunked-v1';
  plaintext_length: number;
  ciphertext_length: number;
  chunk_size: number;
  chunks: EncryptedObjectChunk[];
  wrapped_keys: WrappedContentKey[];
  encrypted_metadata: import('./index.js').CipherEnvelope;
  ciphertext_sha256: string;
  created_at: string;
}

export function validateLocalUnlockPolicy(policy: LocalUnlockPolicy): void {
  if (policy.pin_enabled && policy.pin_kdf == null) {
    throw new Error('PIN unlock requires a bounded KDF policy');
  }
  if (policy.pin_kdf != null) {
    const kdf = policy.pin_kdf;
    if (kdf.memory_kib < 8192 || kdf.memory_kib > 1048576 || kdf.iterations < 1 || kdf.iterations > 20) {
      throw new Error('PIN KDF policy is outside supported bounds');
    }
    if (kdf.parallelism < 1 || kdf.parallelism > 8 || kdf.max_attempts < 3 || kdf.max_attempts > 20) {
      throw new Error('PIN throttling policy is outside supported bounds');
    }
  }
}

export function validateSignalEnvelope(envelope: SignalCiphertextEnvelope): void {
  const metadata = envelope.metadata;
  if (metadata.protocol_version !== 1 || !metadata.envelope_id || !metadata.session_id || !envelope.ciphertext) {
    throw new Error('Signal envelope is incomplete');
  }
  if (metadata.sender_device_id === metadata.recipient_device_id) {
    throw new Error('sender and recipient devices must differ');
  }
  if (!Number.isSafeInteger(metadata.message_number) || metadata.message_number < 0) {
    throw new Error('message_number must be a non-negative safe integer');
  }
  if (Date.parse(metadata.expires_at) <= Date.parse(metadata.created_at)) {
    throw new Error('Signal envelope expiry must follow creation');
  }
}

export function validateEncryptedObjectManifest(manifest: EncryptedObjectManifest): void {
  if (manifest.chunks.length === 0 || manifest.wrapped_keys.length === 0) {
    throw new Error('encrypted objects require chunks and wrapped keys');
  }
  if (manifest.chunk_size < 65536 || manifest.chunk_size > 16777216) {
    throw new Error('chunk_size is outside supported bounds');
  }
  const indexes = manifest.chunks.map((chunk) => chunk.chunk_index);
  if (new Set(indexes).size !== indexes.length || indexes.some((index, position) => index !== position)) {
    throw new Error('encrypted object chunks must be unique and contiguous');
  }
  if (new Set(manifest.wrapped_keys.map((key) => key.recipient_device_id)).size !== manifest.wrapped_keys.length) {
    throw new Error('wrapped keys must be unique per recipient device');
  }
}
