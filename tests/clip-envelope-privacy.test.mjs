import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const schema = JSON.parse(
  await readFile(new URL('../json-schema/clip-envelope.schema.json', import.meta.url), 'utf8'),
);

test('clip envelopes remain closed and require ciphertext metadata', () => {
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.payload.additionalProperties, false);
  for (const field of ['clip_id', 'payload', 'source_device_id', 'logical_clock']) {
    assert(schema.required.includes(field), `required encrypted envelope field: ${field}`);
  }
  for (const field of ['algorithm', 'nonce', 'ciphertext', 'key_id']) {
    assert(schema.properties.payload.required.includes(field));
  }
  for (const key of ['plaintext', 'master_key', 'private_key', 'access_token', 'refresh_token']) {
    assert.equal(key in schema.properties, false, `plaintext field: ${key}`);
    assert.equal(key in schema.properties.payload.properties, false, `secret payload field: ${key}`);
  }
});

test('blind index and opt-in vector metadata have strict wire bounds', () => {
  const terms = schema.properties.blind_terms;
  assert.equal(terms.maxItems, 256);
  assert.equal(terms.uniqueItems, true);
  assert.equal(terms.items.minLength, 16);
  assert.equal(terms.items.maxLength, 128);
  const vector = schema.properties.opt_in_embedding;
  assert.equal(vector.minItems, 1536);
  assert.equal(vector.maxItems, 1536);
  assert.deepEqual(vector.type, ['array', 'null']);
  assert(!schema.required.includes('opt_in_embedding'));
});
