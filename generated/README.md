<!-- generated-policy: frozen -->

# `generated/` — committed output, not hand-editable

Generated **artifacts** in this directory are machine-written and committed to
version control. This policy README is maintained by people, not generated.
Do not edit generated artifacts by hand: change their primary source and rerun
the generator.

Typical producers include:

- [`flags-2-env`](https://github.com/flags-2-env/flags-2-env), for example
  `generated/dart/env.dart`;
- [`oresoftware/api-docs`](https://github.com/oresoftware/api-docs) for route
  maps and clients; and
- JSON Schema, OpenAPI, and route-map generators in this repository.

## Local read-only files

After generation, `chmod a-w` freezes generated artifacts. An editor can then
detect accidental writes immediately. Directories and this README remain
writable so generators can replace files and the policy can be updated.

**Git does not preserve ordinary file write bits.** It tracks the executable
bit, not the local read-only setting. A fresh checkout is writable until a
hook or a manual freeze reapplies the policy. This is a local convenience,
**not** proof that generated files match their sources.

## What enforces the policy

| Guard | What it actually verifies |
| --- | --- |
| `scripts/check-generated-contract.py --freeze --require-readonly` | Policy README, frozen file modes, and runtime JSON Schema/fixture contract checks |
| `generated-contract` CI regeneration step | Diff against fresh generated output **only if** `.generated-regen.sh` is provided; otherwise the workflow explicitly skips that step |
| `.githooks` | Local pre-commit and checkout/merge assistance **only when enabled** |

Enable local hooks once per clone:

```sh
git config core.hooksPath .githooks
```

Re-freeze at any time (safe and idempotent):

```sh
python3 scripts/check-generated-contract.py --freeze --require-readonly
```

Equivalent manual fallback:

```sh
find generated -type f ! -name 'README.md' ! -name 'readme.md' -exec chmod a-w {} +
```

## Regenerating

Edit the **primary source** — for example `.cli-flags.toml`, a route map,
OpenAPI, or `*.schema.json` — and rerun the relevant generator. Preferred
generators thaw their own outputs, regenerate, and re-freeze. When the local
pre-commit guard requires explicit regeneration intent, use:

```sh
REGEN=1 git commit -m "Regenerate clients from the updated route map"
```

Do not treat passing CI as regenerated-output equivalence if this repository
has not supplied `.generated-regen.sh`.

## Runtime contract (not just compile-time)

JSON Schema is a **cross-check**, not necessarily the primary generator input.
Unit tests should validate fixtures and examples against Draft 2020-12 at
runtime: valid fixtures must pass, invalid fixtures must fail, and schema keys
should be compared with `.cli-flags.toml` environment names or route-map keys
whenever those sources exist.
