/**
 * Ciphertext-only, synchronous cloud retention policy. No decryption, network,
 * clipboard access, or untrusted client-reported byte count.
 *
 * TypeScript does NOT have Rust borrow checking. The caller must not mutate a
 * passed Uint8Array during this synchronous call and must authenticate/verify
 * the envelope before creating this view.
 */
export const MAX_CLOUD_TEXT_ITEMS = 2_000;
export const MAX_CLOUD_LOGICAL_BYTES = 5 * 1024 * 1024;
export const CLOUD_ITEM_RESERVE_BYTES = 512;

export interface CloudCacheEnvelopeView {
  readonly envelope_id: string;
  readonly server_sequence: number;
  readonly kind: string;
  readonly ciphertext: Uint8Array;
}

export interface CloudCacheRetention {
  readonly retained_ids: readonly string[];
  readonly evicted_ids: readonly string[];
  readonly logical_bytes: number;
}

export class CloudCachePolicyError extends Error {
  constructor(readonly code: 'invalid_cloud_cache' | 'invalid_ciphertext' | 'size_limit_exceeded') {
    super(code);
    this.name = 'CloudCachePolicyError';
  }
}

export function measured_text_charge(ciphertext: Uint8Array): number {
  if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength === 0) {
    throw new CloudCachePolicyError('invalid_ciphertext');
  }
  const charge = ciphertext.byteLength + CLOUD_ITEM_RESERVE_BYTES;
  if (!Number.isSafeInteger(charge) || charge > MAX_CLOUD_LOGICAL_BYTES) {
    throw new CloudCachePolicyError('size_limit_exceeded');
  }
  return charge;
}

/** Newest prefix exactly matching the D1 window function and Rust core. */
export function plan_text_cache(rows: readonly CloudCacheEnvelopeView[]): CloudCacheRetention {
  const seen = new Set<string>();
  const charged = rows.map((row) => {
    if (!row || row.kind !== 'text'
        || !/^[A-Za-z0-9_-]{1,128}$/.test(row.envelope_id)
        || !Number.isSafeInteger(row.server_sequence) || row.server_sequence <= 0
        || seen.has(row.envelope_id)) {
      throw new CloudCachePolicyError('invalid_cloud_cache');
    }
    seen.add(row.envelope_id);
    return {id: row.envelope_id, sequence: row.server_sequence, charge: measured_text_charge(row.ciphertext)};
  });

  charged.sort((a, b) => b.sequence - a.sequence ||
    (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
  const retained: string[] = [];
  const evicted: string[] = [];
  let cumulative = 0;
  let retainedBytes = 0;

  for (const [index, row] of charged.entries()) {
    cumulative += row.charge;
    if (index < MAX_CLOUD_TEXT_ITEMS && cumulative <= MAX_CLOUD_LOGICAL_BYTES) {
      retained.push(row.id);
      retainedBytes = cumulative;
    } else {
      evicted.push(row.id);
    }
  }

  return {
    retained_ids: Object.freeze(retained),
    evicted_ids: Object.freeze(evicted),
    logical_bytes: retainedBytes,
  };
}
