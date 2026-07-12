#!/usr/bin/env python3
"""README の Schema 節が lake.py のテーブル定義と同期しているか検証する。"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
README = ROOT / "README.md"
LAKE = ROOT / "src" / "vlake" / "lake.py"

TABLE_RE = re.compile(r"CREATE TABLE IF NOT EXISTS \{self\.ALIAS\}\.(\w+) \(")
COLUMN_RE = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s+(.+?)(,)?\s*$")
HISTORY_TO_SECTION = {
    "epss": "epss",
    "cve_history": "cve",
    "ghsa_history": "ghsa",
    "exploitdb_history": "exploitdb",
    "nuclei_history": "nuclei",
    "cwe_history": "cwe",
    "kev_history": "kev",
}
DATASETS_COLUMNS = [
    ("name", "VARCHAR"),
    ("source_url", "VARCHAR"),
    ("license_name", "VARCHAR"),
    ("license_text", "VARCHAR"),
    ("attribution", "VARCHAR"),
    ("disclaimer", "VARCHAR"),
]


def normalize_struct_fields(fields: str) -> str:
    """STRUCT(...) 内をREADMEの簡略表記に合わせてフィールド名だけに正規化する。"""
    names = re.findall(
        r"\b([a-z_][a-z0-9_]*)\s+(?:VARCHAR|DOUBLE|DATE|TIMESTAMP|INTEGER|BOOLEAN|STRUCT\b)",
        fields,
    )
    if names:
        return ", ".join(names)
    return ", ".join(
        field.strip().split()[0] for field in fields.split(",") if field.strip()
    )


def normalize_type(type_text: str) -> str:
    """README と SQL 定義の型表記を比較用に正規化する。"""
    text = type_text.strip().rstrip(",")
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*,\s*", ", ", text)
    struct_match = re.fullmatch(r"STRUCT\((.*)\)\[\]", text)
    if struct_match:
        return f"STRUCT({normalize_struct_fields(struct_match.group(1))})[]"
    return text


def parse_lake_tables() -> dict[str, list[tuple[str, str]]]:
    """lake.py の CREATE TABLE ブロックから top-level カラムを取り出す。"""
    tables: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    columns: list[tuple[str, str]] = []
    pending_name: str | None = None
    pending_type_parts: list[str] = []

    for line in LAKE.read_text().splitlines():
        if current is None:
            match = TABLE_RE.search(line)
            if match:
                current = match.group(1)
                columns = []
            continue

        if line.strip().startswith(')"""'):
            if pending_name is not None:
                columns.append(
                    (pending_name, normalize_type(" ".join(pending_type_parts)))
                )
                pending_name = None
                pending_type_parts = []
            tables[current] = columns
            current = None
            continue

        if pending_name is not None:
            pending_type_parts.append(line.strip().rstrip(","))
            if line.strip().endswith("[],") or line.strip().endswith(")[]"):
                columns.append(
                    (pending_name, normalize_type(" ".join(pending_type_parts)))
                )
                pending_name = None
                pending_type_parts = []
            continue

        stripped = line.strip()
        if not stripped or stripped == ")":
            continue
        match = COLUMN_RE.match(line)
        if not match:
            continue
        name, type_text, _ = match.groups()
        type_text = type_text.strip()
        if type_text.startswith("STRUCT(") and not type_text.endswith("[]"):
            pending_name = name
            pending_type_parts = [type_text.rstrip(",")]
            continue
        columns.append((name, normalize_type(type_text)))

    return tables


def parse_readme_tables() -> dict[str, list[tuple[str, str]]]:
    """README Schema 節のカラム表からカラム名・型を取り出す。"""
    text = README.read_text()
    try:
        schema = text.split("## Schema", 1)[1].split("## Build your own lake", 1)[0]
    except IndexError as exc:
        raise SystemExit(
            "README.md に ## Schema / ## Build your own lake 節が見つかりません"
        ) from exc

    tables: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    in_columns = False

    for line in schema.splitlines():
        if line.startswith("### "):
            match = re.match(r"### `([^`]+)`", line)
            current = match.group(1) if match else None
            in_columns = False
            continue
        if line == "| Column | Type | Description |":
            in_columns = True
            if current is not None:
                tables[current] = []
            continue
        if in_columns and line.startswith("|---"):
            continue
        if in_columns and line.startswith("| "):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 2 or current is None:
                continue
            name = cells[0].strip("`")
            type_text = normalize_type(cells[1])
            tables[current].append((name, type_text))
            continue
        if in_columns and not line.startswith("|"):
            in_columns = False

    return tables


def main() -> int:
    expected = {
        HISTORY_TO_SECTION[table]: columns
        for table, columns in parse_lake_tables().items()
        if table in HISTORY_TO_SECTION
    }
    expected["datasets"] = DATASETS_COLUMNS
    actual = parse_readme_tables()

    ok = True
    for section, columns in expected.items():
        if section not in actual:
            print(f"MISSING README section/table: {section}", file=sys.stderr)
            ok = False
            continue
        if actual[section] != columns:
            print(f"SCHEMA MISMATCH: {section}", file=sys.stderr)
            print(f"  expected: {columns}", file=sys.stderr)
            print(f"  actual:   {actual[section]}", file=sys.stderr)
            ok = False

    extra = sorted(set(actual) - set(expected))
    if extra:
        print(f"EXTRA README schema tables: {', '.join(extra)}", file=sys.stderr)
        ok = False

    if ok:
        for section, columns in expected.items():
            print(f"OK {section}: {len(columns)} columns")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
