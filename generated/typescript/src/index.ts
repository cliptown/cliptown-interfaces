export type ClipKind = 'text' | 'html' | 'rtf' | 'image' | 'file' | 'file_list' | 'url' | 'color' | 'json';
export type SearchPrivacyMode = 'local_only' | 'blind_index' | 'opt_in_vector';
export type CipherAlgorithm = 'xchacha20poly1305-v1' | 'aes-256-gcm-v1';

/** Wire representation. Field names intentionally match the snake_case API contract. */
export interface CipherEnvelope {
  algorithm: CipherAlgorithm;
  nonce: string;
  ciphertext: string;
  associated_data_hash?: string | null;
  key_id: string;
}

/** Ciphertext-only clipboard envelope shared by all ClipTown transports. */
export interface ClipEnvelope {
  clip_id: string;
  kind: ClipKind;
  payload: CipherEnvelope;
  pinned: boolean;
  deleted: boolean;
  blind_terms: string[];
  opt_in_embedding?: number[] | null;
  source_app?: string | null;
  source_device_id: string;
  logical_clock: number;
  created_at: string;
  updated_at: string;
}

export interface SearchRequest {
  privacy_mode: SearchPrivacyMode;
  blind_terms?: string[];
  query_embedding?: number[] | null;
  limit?: number;
  pinned_only?: boolean;
}

export interface SyncCursor {
  cursor: string | null;
  server_sequence: number;
}

export interface SecuritySettings {
  reauth_interval_days: number;
  reauth_max_days: number;
}

export interface UpdateSecuritySettings {
  reauth_interval_days: number;
}

export function validateClipEnvelope(clip: ClipEnvelope): void {
  if (!clip.clip_id || !clip.source_device_id) {
    throw new Error('clip and source device IDs are required');
  }
  if (!Number.isSafeInteger(clip.logical_clock) || clip.logical_clock < 0) {
    throw new Error('logical_clock must be a non-negative safe integer');
  }
  if (Date.parse(clip.updated_at) < Date.parse(clip.created_at)) {
    throw new Error('updated_at cannot be earlier than created_at');
  }
  if (!clip.payload.nonce || !clip.payload.ciphertext || !clip.payload.key_id || clip.payload.key_id.length > 128) {
    throw new Error('cipher envelope fields are incomplete or invalid');
  }
  if ((clip.source_app?.length ?? 0) > 256) {
    throw new Error('source_app may contain at most 256 characters');
  }
  if (clip.blind_terms.length > 256) {
    throw new Error('blind_terms may contain at most 256 entries');
  }
  if (new Set(clip.blind_terms).size !== clip.blind_terms.length) {
    throw new Error('blind_terms must not contain duplicates');
  }
  if (clip.blind_terms.some((term) => term.length < 16 || term.length > 128)) {
    throw new Error('blind terms must contain from 16 through 128 characters');
  }
  if (clip.opt_in_embedding != null) {
    if (clip.opt_in_embedding.length !== 1536) {
      throw new Error('opt_in_embedding must contain exactly 1536 values');
    }
    if (clip.opt_in_embedding.some((value) => !Number.isFinite(value))) {
      throw new Error('opt_in_embedding values must be finite');
    }
  }
}
