import fs from 'node:fs';

const schema = JSON.parse(
  fs.readFileSync('embedding-contract/model-space-v3.schema.json', 'utf8'),
);
const typeSpec = fs.readFileSync(
  'embedding-contract/model-space-v3.tsp',
  'utf8',
);

if (schema.properties.product.const !== 'cliptown') {
  throw new Error('product identity drift');
}
if (schema.properties.contractVersion.const !== '3.1.0') {
  throw new Error('contract-version drift');
}
for (const token of [
  'Voyage: "voyage"',
  'Anthropic: "anthropic"',
  'storageDimensions: 4100',
  'sourceDimensions: int32',
  'queryProfile: EmbeddingProfileV3',
  'documentProfile: EmbeddingProfileV3',
  'queryEmbedding: float32[]',
]) {
  if (!typeSpec.includes(token)) {
    throw new Error(`TypeSpec missing ${token}`);
  }
}
for (const purpose of ['clip_search', 'clip_deduplication', 'discovery']) {
  if (!typeSpec.includes(`"${purpose}"`)) {
    throw new Error(`TypeSpec missing purpose ${purpose}`);
  }
}

const providerSchema = schema.properties.providers.properties;
if (providerSchema.anthropic.const !== 'generation-provenance-only') {
  throw new Error('Anthropic provenance drift');
}
if (schema.properties.database.properties.globalFilteredAnnIndex.const !== false) {
  throw new Error('global filtered ANN index must remain disabled');
}
if (schema.properties.database.properties.fusion.const !== 'reciprocal-rank-fusion') {
  throw new Error('hybrid fusion drift');
}

console.log('ClipTown interface model-space v3 verified');
