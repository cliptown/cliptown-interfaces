import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const schema = JSON.parse(readFileSync(new URL("../json-schema/atto-local-source-v1.schema.json", import.meta.url), "utf8"));
const source = readFileSync(new URL("../examples/atto/local_source_boundary.atto", import.meta.url), "utf8");

function accepts(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return false;
  const props = schema.properties;
  if (Object.keys(record).some((key) => !Object.hasOwn(props, key))) return false;
  if (schema.required.some((key) => !Object.hasOwn(record, key))) return false;
  return Object.entries(props).every(([key, rule]) => {
    const value = record[key];
    if (Object.hasOwn(rule, "const") && value !== rule.const) return false;
    if (rule.type === "integer" && (!Number.isSafeInteger(value) || value < rule.minimum || value > rule.maximum)) return false;
    return true;
  });
}

const record = (byteLength) => ({
  schemaVersion: 1, scope: "local-pre-encryption",
  language: "atto", extension: ".atto", encoding: "utf-8", byteLength,
});

test("closed local-only Atto source contract", () => {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(Object.keys(schema.properties).sort(), [...schema.required].sort());
  for (const length of [0, 1, 1048575, 1048576]) assert.equal(accepts(record(length)), true);
  for (const length of [-1, 1048577, 1.5, Number.MAX_SAFE_INTEGER + 1, "123", null]) {
    assert.equal(accepts(record(length)), false);
  }
});

test("negative canaries fail closed for unknown files and escaped metadata", () => {
  for (const change of [
    { extension: ".txt" }, { extension: ".ATTO" }, { scope: "remote" },
    { encoding: "binary" }, { language: "javascript" },
    { plaintext: "secret" }, { filename: "private.atto" },
  ]) assert.equal(accepts({ ...record(14), ...change }), false);
  const missing = record(14);
  delete missing.scope;
  assert.equal(accepts(missing), false);
});

test(".atto reference has bounded, pure size predicates", () => {
  assert.match(source, /fnc nonnegative_source_size\(int byte_length\) -> bool/);
  assert.match(source, /return byte_length >= 0;/);
  assert.match(source, /fnc within_source_size_limit\(int byte_length\) -> bool/);
  assert.match(source, /return byte_length <= 1048576;/);
  assert.doesNotMatch(source, /\b(?:fetch|http|socket|bearer_token|private_key)\b/i);
});
