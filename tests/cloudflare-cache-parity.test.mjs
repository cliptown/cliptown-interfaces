import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import {
  CloudCachePolicyError, MAX_CLOUD_TEXT_ITEMS, MAX_CLOUD_DEVICE_SEQUENCE,
  plan_text_cache, checked_device_sequence,
} from '../generated/typescript/dist/cloudflare_cache.js';

const fixture = JSON.parse(await readFile(
  new URL('../fixtures/cloudflare-text-cache-v1.json', import.meta.url), 'utf8',
));
const toView = (row) => ({
  envelope_id: row.envelope_id,
  server_sequence: row.server_sequence,
  kind: row.kind,
  ciphertext: new Uint8Array(row.ciphertext_bytes),
});

test('Rust/Dart/TypeScript shared quota fixtures', async (t) => {
  assert.equal(fixture.protocol_version, 1);
  assert.equal(fixture.limits.max_items, MAX_CLOUD_TEXT_ITEMS);
  for (const entry of fixture.cases) {
    await t.test(entry.name, () => {
      const views = entry.rows.map(toView);
      if (entry.error) {
        assert.throws(() => plan_text_cache(views),
          (error) => error instanceof CloudCachePolicyError && error.code === entry.error);
      } else {
        const plan = plan_text_cache(views);
        assert.deepEqual(plan.retained_ids, entry.retained_ids);
        assert.deepEqual(plan.evicted_ids, entry.evicted_ids);
        assert.equal(plan.logical_bytes, entry.logical_bytes);
      }
    });
  }
});

test('2,001 clips evict only oldest, and input order does not matter', () => {
  const items = Array.from({length: 2001}, (_, n) => ({
    envelope_id: 'clip_' + n, server_sequence: n + 1,
    kind: 'text', ciphertext: new Uint8Array(1),
  }));
  const planned = plan_text_cache(items);
  assert.equal(planned.retained_ids.length, 2000);
  assert.deepEqual(planned.evicted_ids, ['clip_0']);
  assert.deepEqual(plan_text_cache([...items].reverse()), planned);
});

test('caller supplied stored_bytes cannot bypass measured quota', () => {
  const v = [{...toView({envelope_id: 'x', server_sequence: 1,
    kind: 'text', ciphertext_bytes: 100}), stored_bytes: 1}];
  assert.equal(plan_text_cache(v).logical_bytes, 612);
});

const replayFixtures = JSON.parse(await readFile(
  new URL('../fixtures/cloudflare-device-replay-v1.json', import.meta.url), 'utf8',
));

test('Rust/Dart/TypeScript signed device watermark fixtures', async (t) => {
  assert.equal(replayFixtures.protocol_version, 1);
  assert.equal(replayFixtures.max_device_sequence, MAX_CLOUD_DEVICE_SEQUENCE);
  for (const vector of replayFixtures.cases) {
    await t.test(vector.name, () => {
      if (vector.error) {
        assert.throws(
          () => checked_device_sequence(vector.incoming, vector.previous),
          (error) => error instanceof CloudCachePolicyError &&
            error.code === vector.error,
        );
      } else {
        assert.equal(
          checked_device_sequence(vector.incoming, vector.previous),
          vector.accepted,
        );
      }
    });
  }
});

test('floating-point, NaN and unsafe signed metadata are rejected', () => {
  for (const bad of [NaN, Infinity, -Infinity, 1.5,
      Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => checked_device_sequence(bad, null),
      (error) => error.code === 'invalid_device_sequence');
  }
});
