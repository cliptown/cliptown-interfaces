<!-- generated-policy: frozen -->

# `generated/` — committed, machine-written, and not hand-editable

Everything in this directory except its policy README is machine-written and
**committed to version control**. Do not edit generated artifacts by hand. Change
the primary source they come from and re-run the generator.

Typical producers include:

- [`flags-2-env`](https://github.com/flags-2-env/flags-2-env), for example
  `generated/dart/env.dart`;
- [`oresoftware/api-docs`](https://github.com/oresoftware/api-docs), for route maps
  and clients; and
- JSON Schema, OpenAPI, and route-map generators in this repository.

## Disk permissions

After generation, generated artifacts are frozen with `chmod a-w`. This is a local
ergonomic guard: an editor that tries to modify the wrong file fails immediately.
Directories and this `README.md` stay writable so generators can replace files and
the policy can be maintained.

**Git does not store the write bit.** Git tracks only the executable bit, so files
are mode `100644` in the object database and a fresh clone comes back writable until
the repository hooks re-freeze it.

## What enforces the policy

CI, not the filesystem, is authoritative:

| Guard | Where | What it catches |
| --- | --- | --- |
| `check-generated-contract.py` | CI + pre-commit | a hand-edited or thawed file |
| regenerate-and-diff | CI | committed output that no longer matches its source |
| `post-checkout` / `post-merge` hooks | your clone | files that need to be re-frozen |

Enable the hooks once per clone:

```sh
git config core.hooksPath .githooks
```

Re-freeze at any time (safe and idempotent):

```sh
python3 scripts/check-generated-contract.py --freeze --require-readonly
```

The equivalent manual fallback is:

```sh
find generated -type f ! -name 'README.md' ! -name 'readme.md' -exec chmod a-w {} +
```

## Regenerating

Edit the **primary source** — such as `.cli-flags.toml`, a route map, OpenAPI, or
`*.schema.json` — then run the generator. Preferred generators thaw, write, and
re-freeze their outputs. If a regeneration is being committed, the pre-commit guard
must be told explicitly:

```sh
REGEN=1 git commit -m "Regenerate clients from the updated route map"
```

If `generated/` is intentionally in `.gitignore`, keep this policy visible by
tracking the README through an exception:

```
generated/**
!generated/README.md
```

## Runtime contract (not just compile-time)

JSON Schema is a **cross-check**, not always the primary generator input. Unit tests
should validate fixtures and examples against Draft 2020-12 at runtime: valid
fixtures must pass, invalid fixtures must fail, and schema keys should be compared
with `.cli-flags.toml` environment names or route-map keys whenever those sources
exist.

# `generated/` — committed, and not hand-editable

Everything in this directory is machine-written and **committed to version
control**. Do not edit these files by hand. Change the source they come from
and re-run the generator.

Typical producers:

- [`flags-2-env`](https://github.com/flags-2-env) — e.g. `generated/dart/env.dart`
- [`oresoftware/api-docs`](https://github.com/oresoftware/api-docs) — route maps and clients
- JSON Schema / OpenAPI generators in this repository

## Why the files are read-only on disk

After generation they are frozen with `chmod a-w`. Your editor will refuse the
write, which is the point — it turns "I edited the wrong file" into an error you
see immediately rather than a diff you notice in review.

**Git does not store this.** Git tracks only the executable bit, so every file
here is mode `100644` in the object database and a fresh clone comes back
writable. The read-only bit is a local ergonomic guard; it is *not* what
enforces the policy.

## What actually enforces the policy

CI, not the filesystem:

| Guard | Where | What it catches |
| --- | --- | --- |
| `check-generated-contract.py` | CI + pre-commit | a hand-edited or thawed file |
| regenerate-and-diff | CI | committed output that no longer matches its source |
| `post-checkout` / `post-merge` hooks | your clone | re-freezes after every checkout |

Enable the hooks once per clone:

```sh
git config core.hooksPath .githooks
```

Re-freeze at any time (safe, idempotent):

```sh
python3 scripts/check-generated-contract.py --freeze --require-readonly
```

# Generated files — read-only

Do **not** hand-edit files in this directory. They are produced by tooling such as:

- https://github.com/flags-2-env/flags-2-env (typical Dart path: `generated/dart/env.dart`)
- https://github.com/oresoftware/api-docs
- JSON Schema / OpenAPI / route-map generators in this repository

