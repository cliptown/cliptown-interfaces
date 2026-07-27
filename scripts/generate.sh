#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
command -v buf >/dev/null || { echo 'buf is required' >&2; exit 1; }
buf lint
buf generate
printf 'Generated contracts. Review generated/ changes before committing.\n'
