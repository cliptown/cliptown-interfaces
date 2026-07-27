#!/usr/bin/env python3
"""Fast dependency-free guard for the canonical snake_case wire contract."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "json-schema/clip-envelope.schema.json").read_text())
REQUIRED = {
    "clip_id",
    "kind",
    "payload",
    "pinned",
    "deleted",
    "blind_terms",
    "source_device_id",
    "logical_clock",
    "created_at",
    "updated_at",
}

required = set(SCHEMA["required"])
if required != REQUIRED:
    raise SystemExit(f"JSON Schema required fields drifted: {sorted(required ^ REQUIRED)}")

properties = set(SCHEMA["properties"])
camel_case = sorted(name for name in properties if any(character.isupper() for character in name))
if camel_case:
    raise SystemExit(f"camelCase wire fields are forbidden: {camel_case}")

checks = {
    ROOT / "openapi/cliptown.openapi.yaml": ["clip_id:", "source_device_id:", "logical_clock:"],
    ROOT / "generated/typescript/src/index.ts": ["clip_id:", "source_device_id:", "logical_clock:"],
    ROOT / "generated/rust/src/lib.rs": ["pub clip_id:", "pub source_device_id:", "pub logical_clock:"],
    ROOT / "generated/dart/lib/cliptown_interfaces.dart": ["'clip_id'", "'source_device_id'", "'logical_clock'"],
}
for path, needles in checks.items():
    text = path.read_text()
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path.relative_to(ROOT)} is missing canonical fields: {missing}")

print("ClipTown wire contract is consistently snake_case")
