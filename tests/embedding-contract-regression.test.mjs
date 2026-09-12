import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const config = JSON.parse(await read("embedding-contract/generation.json"));
const schema = JSON.parse(await read(config.codeFirst.jsonSchema));
const typeSpec = await read(config.codeFirst.typeSpec);
const defs = schema.$defs;
const stored = defs.StoredEmbedding;
const input = defs.EmbeddingInput;

const allowsNull = (property) =>
  Array.isArray(property.anyOf) && property.anyOf.some((branch) => branch?.type === "null");

test("stored and source dimensions cannot drift or become ambiguous", () => {
  assert.equal(config.dimensions.storage, 4100);
  assert.equal(config.dimensions.maximumSource, 4096);
  assert.equal(config.dimensions.padding, "trailing-zero");
  assert.equal(schema.$ref, "StoredEmbedding.json");
  assert.equal(stored.additionalProperties, false);
  assert.equal(stored.properties.storageDimensions.const, 4100);
  assert.equal(stored.properties.values.minItems, 4100);
  assert.equal(stored.properties.values.maxItems, 4100);
  assert.equal(stored.properties.originalDimensions.minimum, 1);
  assert.equal(stored.properties.originalDimensions.maximum, 4096);
  assert.equal(input.additionalProperties, false);
  assert.equal(input.properties.values.minItems, 1);
  assert.equal(input.properties.values.maxItems, 4096);
});

test("embedding and generation provider roles remain distinct and nullability is explicit", () => {
  const embeddingProviders = defs.EmbeddingProvider.enum;
  const generationProviders = defs.GenerationProvider.enum;
  assert.equal(new Set(embeddingProviders).size, embeddingProviders.length);
  assert.equal(new Set(generationProviders).size, generationProviders.length);
  assert(!embeddingProviders.includes("anthropic"));
  assert(generationProviders.includes("anthropic"));
  assert(
    embeddingProviders.some((provider) => !generationProviders.includes(provider)),
    "an embedding-only provider must remain distinguishable",
  );
  assert(
    generationProviders.some((provider) => !embeddingProviders.includes(provider)),
    "a generation-only provider must remain distinguishable",
  );
  assert(allowsNull(stored.properties.generationProvider));
  assert(allowsNull(input.properties.generationProvider));
  assert(allowsNull(stored.properties.searchText));
});

test("identity, provenance, and integrity fields stay mandatory and bounded", () => {
  const required = new Set(stored.required);
  for (const field of [
    "tenantId",
    "entityKind",
    "entityId",
    "purpose",
    "embeddingProvider",
    "model",
    "originalDimensions",
    "embeddingSpace",
    "storageDimensions",
    "values",
    "normalization",
    "contentHash",
  ]) {
    assert(required.has(field), `missing required field: ${field}`);
  }
  assert.equal(stored.properties.embeddingSpace.minLength, 8);
  assert.equal(stored.properties.entityKind.pattern, "^[a-z][a-z0-9_]*$");
  assert.equal(stored.properties.contentHash.minLength, 64);
  assert.equal(stored.properties.contentHash.maxLength, 64);
  assert.equal(stored.properties.contentHash.pattern, "^[0-9a-f]{64}$");
  assert.equal(stored.properties.searchText.maxLength, 200000);
  assert.equal(stored.properties.tenantId.format, "uuid");
});

test("all seven named embedding declarations have independently authored JSON Schema peers", () => {
  assert.deepEqual(
    Object.keys(defs).sort(),
    [
      "EmbeddingInput",
      "EmbeddingMetadata",
      "EmbeddingNormalization",
      "EmbeddingProvider",
      "EmbeddingPurpose",
      "GenerationProvider",
      "StoredEmbedding",
    ].sort(),
  );
  assert.deepEqual(defs.EmbeddingMetadata.properties, {});
  assert.deepEqual(defs.EmbeddingMetadata.unevaluatedProperties, {});
  assert.equal("additionalProperties" in defs.EmbeddingMetadata, false);
});

test("code-first paths are local and application startup cannot own migrations", () => {
  assert.deepEqual(config.externalSqlAuthorities, []);
  assert.equal(config.databaseFirst.migrationsAreAppliedAtStartup, false);
  for (const path of Object.values(config.codeFirst).filter(
    (value) => typeof value === "string",
  )) {
    assert(!path.startsWith("/"), `absolute contract path: ${path}`);
    assert(!path.split("/").includes(".."), `escaping contract path: ${path}`);
  }
  assert.match(typeSpec, /const storageDimensions = 4100/);
  assert.match(typeSpec, /const maximumSourceDimensions = 4096/);
  assert.match(typeSpec, /enum EmbeddingProvider/);
  assert.match(typeSpec, /enum GenerationProvider/);
  assert.match(typeSpec, /Anthropic: "anthropic"/);
  assert.match(typeSpec, /@extension\("additionalProperties", false\)/);
  assert.match(typeSpec, /generationProvider\?: GenerationProvider \| null/);
});
