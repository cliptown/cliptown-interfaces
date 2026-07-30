#!/usr/bin/env python3
"""Fast dependency-free guards for canonical ClipTown wire boundaries."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "json-schema" / name).read_text())


def assert_required_fields(
    schema_name: str,
    schema: dict[str, object],
    expected: set[str],
) -> None:
    required = set(schema["required"])
    if required != expected:
        raise SystemExit(
            f"{schema_name} required fields drifted: {sorted(required ^ expected)}"
        )


def assert_snake_case(schema_name: str, schema: dict[str, object]) -> None:
    properties = set(schema["properties"])
    camel_case = sorted(
        name for name in properties if any(character.isupper() for character in name)
    )
    if camel_case:
        raise SystemExit(f"{schema_name} contains camelCase wire fields: {camel_case}")


clip_schema = load_schema("clip-envelope.schema.json")
assert_required_fields(
    "clip-envelope.schema.json",
    clip_schema,
    {
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
    },
)
assert_snake_case("clip-envelope.schema.json", clip_schema)

app_vault_schema = load_schema("app-vault-mutation.schema.json")
assert_required_fields(
    "app-vault-mutation.schema.json",
    app_vault_schema,
    {
        "protocol_version",
        "mutation_id",
        "app_id",
        "namespace",
        "opaque_record_id",
        "deleted",
        "source_device_id",
        "logical_clock",
        "created_at",
        "updated_at",
        "device_signature",
    },
)
assert_snake_case("app-vault-mutation.schema.json", app_vault_schema)

app_vault_properties = set(app_vault_schema["properties"])
forbidden_app_vault_fields = {
    "kind",
    "pinned",
    "blind_terms",
    "opt_in_embedding",
    "source_app",
    "title",
    "preview",
    "provider",
    "account_label",
    "otp_seed",
    "otp_code",
    "access_token",
    "refresh_token",
    "sync_token",
}
leaked_app_vault_fields = sorted(app_vault_properties & forbidden_app_vault_fields)
if leaked_app_vault_fields:
    raise SystemExit(
        "application-vault records entered clipboard/authentication semantics: "
        f"{leaked_app_vault_fields}"
    )

step_up_schema = load_schema("external-step-up-proof.schema.json")
assert_required_fields(
    "external-step-up-proof.schema.json",
    step_up_schema,
    {
        "protocol_version",
        "proof_id",
        "issuer",
        "subject",
        "audience",
        "device_id",
        "challenge_id",
        "action",
        "issued_at",
        "expires_at",
        "signing_key_id",
        "signature",
    },
)
assert_snake_case("external-step-up-proof.schema.json", step_up_schema)

step_up_properties = set(step_up_schema["properties"])
forbidden_step_up_fields = {
    "access_token",
    "refresh_token",
    "sync_token",
    "cookie",
    "password",
    "pin",
    "otp_seed",
    "otp_code",
    "vault_key",
}
leaked_step_up_fields = sorted(step_up_properties & forbidden_step_up_fields)
if leaked_step_up_fields:
    raise SystemExit(
        "external step-up proof became a credential or secret container: "
        f"{leaked_step_up_fields}"
    )

checks = {
    ROOT / "openapi/cliptown.openapi.yaml": [
        "clip_id:",
        "source_device_id:",
        "logical_clock:",
        "/v1/app-vault/{appId}/sync/push:",
        "/v1/app-vault/{appId}/sync/pull:",
        "X-ClipTown-Device-Token",
        "X-3FA-Step-Up",
        "opaque_record_id:",
    ],
    ROOT / "proto/cliptown/v1/app_vault.proto": [
        "message AppVaultMutation",
        "string opaque_record_id",
        "bytes device_signature",
    ],
    ROOT / "proto/cliptown/v1/security.proto": [
        "SIGNAL_ENVELOPE_PURPOSE_APP_VAULT_KEY",
        "message ExternalStepUpProof",
    ],
    ROOT / "generated/typescript/src/index.ts": [
        "clip_id:",
        "source_device_id:",
        "logical_clock:",
        "export * from './app_vault.js';",
        "export * from './step_up.js';",
    ],
    ROOT / "generated/typescript/src/app_vault.ts": [
        "opaque_record_id:",
        "device_signature:",
    ],
    ROOT / "generated/rust/src/lib.rs": [
        "pub clip_id:",
        "pub source_device_id:",
        "pub logical_clock:",
        "pub use app_vault::*;",
        "pub use step_up::*;",
    ],
    ROOT / "generated/rust/src/app_vault.rs": [
        "pub opaque_record_id:",
        "pub device_signature:",
    ],
    ROOT / "generated/dart/lib/cliptown_interfaces.dart": [
        "'clip_id'",
        "'source_device_id'",
        "'logical_clock'",
        "export 'src/app_vault.dart';",
        "export 'src/step_up.dart';",
    ],
    ROOT / "generated/dart/lib/src/app_vault.dart": [
        "'opaque_record_id'",
        "'device_signature'",
    ],
}
for path, needles in checks.items():
    text = path.read_text()
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path.relative_to(ROOT)} is missing canonical fields: {missing}")

print("ClipTown clipboard, app-vault, and step-up wire boundaries are isolated")
