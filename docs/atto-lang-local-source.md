# AttoLang (`.atto`) local-source contract

ClipTown may classify a user-selected AttoLang source file **locally**, before encrypting it. The closed JSON Schema at `json-schema/atto-local-source-v1.schema.json` accepts only UTF-8 `.atto` source metadata, with a byte count from 0 through 1 MiB. It rejects unknown fields, case variants, negative sizes and out-of-range integers.

This is **not a new server API** or a permission to store plaintext source, file names, source hashes or code-derived search terms in ClipTown server metadata. The local record must never cross the server/storage boundary unencrypted. The canonical ciphertext envelopes, vault isolation and delegated authorization remain unchanged. Never infer a trusted MIME type or an authorization grant solely from a filename extension.

`examples/atto/local_source_boundary.atto` illustrates only pure preflight predicates. Both conditions must hold before local processing. This repository does not claim that these helpers compile across every AttoLang backend or implement the SDK transport. The Rust browser compiler currently supports a limited AttoLang subset; cross-backend executable coverage is a separate release gate.

Run `node --test tests/atto-local-source-contract.test.mjs` for positive boundaries and negative mutation canaries. The main CI also compiles every `json-schema/*.schema.json` with Ajv Draft 2020-12.
