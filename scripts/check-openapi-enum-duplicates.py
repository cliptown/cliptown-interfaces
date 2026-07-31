#!/usr/bin/env python3
"""Reject duplicate OpenAPI enum entries without depending on Spectral's broken rule.

Spectral's `duplicated-entry-in-enum` rule currently dereferences null nodes while
walking OpenAPI documents (upstream stoplightio/spectral#2959/#2963). Keep the
rest of `spectral:oas` enabled and use this narrow, dependency-free guard until
the upstream fix is released and pinned.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

INLINE_ENUM = re.compile(r"\benum\s*:\s*\[([^\]]*)\]")
BLOCK_ENUM = re.compile(r"^(?P<indent>\s*)enum\s*:\s*$")
BLOCK_ITEM = re.compile(r"^(?P<indent>\s*)-\s*(?P<value>.+?)\s*$")


def strip_yaml_comment(line: str) -> str:
    """Strip a YAML comment while preserving # inside quoted scalars."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None:
            return line[:index]
    return line


def split_inline_values(raw: str) -> list[str]:
    values: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "," and quote is None:
            values.append(raw[start:index].strip())
            start = index + 1
    values.append(raw[start:].strip())
    return values


def normalize_scalar(raw: str) -> str:
    value = strip_yaml_comment(raw).strip()
    if not value:
        raise ValueError("empty enum entry")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            parsed = value[1:-1]
        return str(parsed)
    return value


def reject_duplicates(path: Path, line_number: int, values: list[str]) -> None:
    normalized = [normalize_scalar(value) for value in values]
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in normalized:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        rendered = ", ".join(repr(value) for value in duplicates)
        raise SystemExit(
            f"{path}:{line_number}: duplicate OpenAPI enum entries: {rendered}"
        )


def check_file(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    checked = 0
    while index < len(lines):
        uncommented = strip_yaml_comment(lines[index])

        for match in INLINE_ENUM.finditer(uncommented):
            values = split_inline_values(match.group(1))
            reject_duplicates(path, index + 1, values)
            checked += 1

        block = BLOCK_ENUM.match(uncommented)
        if block is None:
            index += 1
            continue

        base_indent = len(block.group("indent"))
        values: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            candidate = strip_yaml_comment(lines[cursor])
            if not candidate.strip():
                cursor += 1
                continue
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate_indent <= base_indent:
                break
            item = BLOCK_ITEM.match(candidate)
            if item is None:
                raise SystemExit(
                    f"{path}:{cursor + 1}: malformed block-style enum entry"
                )
            values.append(item.group("value"))
            cursor += 1

        if not values:
            raise SystemExit(f"{path}:{index + 1}: enum must contain at least one entry")
        reject_duplicates(path, index + 1, values)
        checked += 1
        index = cursor

    if checked == 0:
        raise SystemExit(f"{path}: no enum definitions found; guard may be misconfigured")
    print(f"{path}: {checked} enum definitions contain no duplicate entries")


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("usage: check-openapi-enum-duplicates.py OPENAPI.yaml [...]")
    for argument in argv[1:]:
        path = Path(argument)
        if not path.is_file():
            raise SystemExit(f"OpenAPI file not found: {path}")
        check_file(path)


if __name__ == "__main__":
    main(sys.argv)
