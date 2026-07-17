#!/usr/bin/env python3
"""スキーマ参照ドキュメントが lake.py のテーブル定義と同期しているか検証する。"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCHEMA_DOC = ROOT / "docs" / "schema.md"
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
    "attack_history": "attack",
    "attack_relationship_history": "attack_relationship",
    "capec_history": "capec",
    "kev_history": "kev",
    "cloudflare_waf_history": "cloudflare_waf",
}
DATASETS_COLUMNS = [
    ("name", "VARCHAR"),
    ("source_url", "VARCHAR"),
    ("license_name", "VARCHAR"),
    ("license_text", "VARCHAR"),
    ("attribution", "VARCHAR"),
    ("disclaimer", "VARCHAR"),
]
CVE_SOURCES_COLUMNS = [
    ("cve", "VARCHAR"),
    ("has_epss", "BOOLEAN"),
    ("has_cve", "BOOLEAN"),
    ("has_ghsa", "BOOLEAN"),
    ("has_exploitdb", "BOOLEAN"),
    ("has_nuclei", "BOOLEAN"),
    ("has_kev", "BOOLEAN"),
    ("has_cloudflare_waf", "BOOLEAN"),
    ("epss_days", "BIGINT"),
    ("ghsa_count", "BIGINT"),
    ("exploitdb_count", "BIGINT"),
    ("nuclei_count", "BIGINT"),
    ("cloudflare_waf_count", "BIGINT"),
]
CVE_SSVC_COLUMNS = [
    ("cve", "VARCHAR"),
    ("date_updated", "TIMESTAMP"),
    ("ssvc_version", "VARCHAR"),
    ("ssvc_role", "VARCHAR"),
    ("ssvc_timestamp", "TIMESTAMP"),
    ("ssvc_provider", "VARCHAR"),
    ("exploitation", "VARCHAR"),
    ("automatable", "VARCHAR"),
    ("technical_impact", "VARCHAR"),
    ("mission_impact", "VARCHAR"),
    ("recorded_decision", "VARCHAR"),
    ("ssvc_raw", "VARCHAR"),
]
SSVC_DECISION_COLUMNS = [
    ("ssvc_version", "VARCHAR"),
    ("ssvc_role", "VARCHAR"),
    ("exploitation", "VARCHAR"),
    ("automatable", "VARCHAR"),
    ("technical_impact", "VARCHAR"),
    ("mission_impact", "VARCHAR"),
    ("decision", "VARCHAR"),
    ("decision_label", "VARCHAR"),
    ("decision_rank", "INTEGER"),
]
CVE_SSVC_CANDIDATES_COLUMNS = [
    ("cve", "VARCHAR"),
    ("date_updated", "TIMESTAMP"),
    ("ssvc_version", "VARCHAR"),
    ("ssvc_role", "VARCHAR"),
    ("ssvc_timestamp", "TIMESTAMP"),
    ("ssvc_provider", "VARCHAR"),
    ("exploitation", "VARCHAR"),
    ("automatable", "VARCHAR"),
    ("technical_impact", "VARCHAR"),
    ("mission_impact", "VARCHAR"),
    ("recorded_exploitation", "VARCHAR"),
    ("recorded_automatable", "VARCHAR"),
    ("recorded_technical_impact", "VARCHAR"),
    ("recorded_mission_impact", "VARCHAR"),
    ("recorded_decision", "VARCHAR"),
    ("computed_decision", "VARCHAR"),
    ("decision_matches", "BOOLEAN"),
    ("decision_label", "VARCHAR"),
    ("decision_rank", "INTEGER"),
    ("ssvc_raw", "VARCHAR"),
]
CWE_ATTACK_PATTERNS_COLUMNS = [
    ("cwe", "VARCHAR"),
    ("capec_id", "VARCHAR"),
    ("capec_name", "VARCHAR"),
    ("attack_id", "VARCHAR"),
    ("attack_name", "VARCHAR"),
    ("attack_object_type", "VARCHAR"),
    ("kill_chain_phases", "STRUCT(kill_chain_name, phase_name)[]"),
]


def normalize_struct_fields(fields: str) -> str:
    """STRUCT(...) 内をドキュメントの簡略表記に合わせてフィールド名だけに正規化する。"""
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
    """ドキュメントと SQL 定義の型表記を比較用に正規化する。"""
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


def parse_schema_doc_tables() -> dict[str, list[tuple[str, str]]]:
    """docs/schema.md のカラム表からカラム名・型を取り出す。"""
    if not SCHEMA_DOC.exists():
        raise SystemExit("docs/schema.md が見つかりません")
    schema = SCHEMA_DOC.read_text()

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
    expected["cve_sources"] = CVE_SOURCES_COLUMNS
    expected["cve_ssvc"] = CVE_SSVC_COLUMNS
    expected["ssvc_decision"] = SSVC_DECISION_COLUMNS
    expected["cve_ssvc_candidates"] = CVE_SSVC_CANDIDATES_COLUMNS
    expected["cwe_attack_patterns"] = CWE_ATTACK_PATTERNS_COLUMNS
    actual = parse_schema_doc_tables()

    ok = True
    for section, columns in expected.items():
        if section not in actual:
            print(f"MISSING schema doc section/table: {section}", file=sys.stderr)
            ok = False
            continue
        if actual[section] != columns:
            print(f"SCHEMA DOC MISMATCH: {section}", file=sys.stderr)
            print(f"  expected: {columns}", file=sys.stderr)
            print(f"  actual:   {actual[section]}", file=sys.stderr)
            ok = False

    extra = sorted(set(actual) - set(expected))
    if extra:
        print(f"EXTRA schema doc tables: {', '.join(extra)}", file=sys.stderr)
        ok = False

    if ok:
        for section, columns in expected.items():
            print(f"OK {section}: {len(columns)} columns")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
