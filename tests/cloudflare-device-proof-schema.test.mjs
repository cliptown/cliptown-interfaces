import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';

const schema = JSON.parse(await readFile(
  new URL('../json-schema/cloudflare-device-proof-v1.schema.json', import.meta.url),
  'utf8',
));

test('device proof is closed, scope-bound and contains no secrets or claimed account', () => {
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.protocol.const, 'cliptown.device_auth.v1');
  for (const field of [
    'purpose','device_id','envelope_id','ciphertext_digest','media_kind',
    'device_sequence','key_epoch','revocation_epoch','issued_at_ms',
    'expires_at_ms','nonce','signature'
  ]) assert(schema.required.includes(field), field);
  for (const forbidden of [
    'account_id','tenant_id','application_id','access_token','password',
    'private_key','session_token','plaintext','ciphertext','oauth_code',
  ]) {
    assert.equal(forbidden in schema.properties, false, forbidden);
  }
  assert.equal(schema.properties.device_sequence.maximum, 9007199254740990);
  assert.equal(schema.properties.signature.pattern, '^[A-Za-z0-9_-]{86}$');
});

test('strictly disjoint read and write proof purpose constraints', () => {
  assert.equal(schema.properties.purpose.enum.length, 2);
  const write = schema.allOf.find((node) =>
    node.if?.properties?.purpose?.const === 'text_cache.write').then;
  const read = schema.allOf.find((node) =>
    node.if?.properties?.purpose?.const === 'text_cache.read').then;
  assert.equal(write.properties.media_kind.const, 'text');
  assert.equal(write.properties.device_sequence.minimum, 1);
  assert.equal(read.properties.media_kind.const, 'none');
  assert.equal(read.properties.device_sequence.const, 0);
  assert.equal(read.properties.envelope_id.const, '');
  assert.equal(read.properties.ciphertext_digest.const, '');
});
