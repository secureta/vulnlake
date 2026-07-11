"""GHSA (GitHub Advisory Database) データセット。

データ提供: GitHub Advisory Database (https://github.com/github/advisory-database)。
© GitHub, Inc. CC-BY 4.0 で提供されるデータを OSV 形式 JSON から
Parquet に変換して再配布する (変更あり)。
本プロジェクトは GitHub, Inc. の公認・認証を受けたものではない。
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

from .cvelist import _ts

NAME = "ghsa"

AFFECTED_STRUCT = pa.struct(
    [
        ("ecosystem", pa.string()),
        ("package", pa.string()),
        ("introduced", pa.string()),
        ("fixed", pa.string()),
        ("last_affected", pa.string()),
    ]
)

SCHEMA = pa.schema(
    [
        ("ghsa", pa.string()),
        ("cve", pa.string()),
        ("summary", pa.string()),
        ("severity", pa.string()),
        ("cvss", pa.float64()),
        ("cvss_version", pa.string()),
        ("cvss_vector", pa.string()),
        ("cwe", pa.list_(pa.string())),
        ("affected", pa.list_(AFFECTED_STRUCT)),
        ("published", pa.timestamp("us")),
        ("modified", pa.timestamp("us")),
        ("withdrawn", pa.timestamp("us")),
        ("raw", pa.string()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://github.com/github/advisory-database",
    "license_name": "CC-BY 4.0",
    "license_text": (
        "Creative Commons Attribution 4.0 International "
        "(https://creativecommons.org/licenses/by/4.0/). "
        "This dataset is a modified form of the GitHub Advisory Database: "
        "OSV-format JSON records converted to Parquet with extracted columns."
    ),
    "attribution": (
        "GitHub Advisory Database — © GitHub, Inc. "
        "(https://github.com/github/advisory-database), licensed under CC-BY 4.0."
    ),
    "disclaimer": (
        "This project redistributes GitHub Advisory Database records but is "
        "not endorsed or certified by GitHub, Inc."
    ),
}

# CVSS 採択優先順位。GitHub の severity 配列は CVSS_V3 / CVSS_V4 のみ
_CVSS_TYPES = ("CVSS_V4", "CVSS_V3")


def _score_from_vector(vector: str) -> tuple[float | None, str | None]:
    """CVSS ベクタ文字列から (baseScore, version) を算出する。パース不能なら None。"""
    version = vector.split("/", 1)[0].removeprefix("CVSS:")
    try:
        if vector.startswith("CVSS:4."):
            return float(CVSS4(vector).base_score), version
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).scores()[0]), version
    except CVSSError:
        return None, None
    return None, None


def _best_cvss(severity: list) -> tuple[str | None, float | None, str | None]:
    """severity 配列から CVSS_V4 > CVSS_V3 の優先で (vector, score, version) を採択。"""
    for kind in _CVSS_TYPES:
        for entry in severity:
            vector = entry.get("score")
            if entry.get("type") == kind and vector and isinstance(vector, str):
                score, version = _score_from_vector(vector)
                return vector, score, version
    return None, None, None


def _affected_entries(affected: list) -> list[dict]:
    """OSV affected[] を range ごとの struct 行に展開する。

    events を順に見て introduced が現れるたびに新しい struct を開始し、
    後続の fixed / last_affected を現在の struct に付ける。
    ranges の無いエントリは ecosystem / package のみの struct を1つ出す。
    """
    entries: list[dict] = []
    for a in affected:
        pkg = a.get("package") or {}
        base = {"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name")}
        found = False
        for rng in a.get("ranges") or []:
            current = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    current = {
                        **base,
                        "introduced": ev["introduced"],
                        "fixed": None,
                        "last_affected": None,
                    }
                    entries.append(current)
                    found = True
                elif current is not None and "fixed" in ev:
                    current["fixed"] = ev["fixed"]
                elif current is not None and "last_affected" in ev:
                    current["last_affected"] = ev["last_affected"]
        if not found:
            entries.append(
                {**base, "introduced": None, "fixed": None, "last_affected": None}
            )
    return entries


def parse_record(raw: bytes) -> dict | None:
    """OSV レコード1件を SCHEMA の行 dict にする。壊れていれば None。"""
    try:
        rec = json.loads(raw)
        ghsa_id = rec["id"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(ghsa_id, str) or not ghsa_id.startswith("GHSA-"):
        return None
    modified = _ts(rec.get("modified")) or _ts(rec.get("published"))
    if modified is None:
        return None  # view の順序付けに使う日時が無いレコードは扱えない
    aliases = rec.get("aliases") or []
    cve = next(
        (a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), None
    )
    vector, score, version = _best_cvss(rec.get("severity") or [])
    db = rec.get("database_specific") or {}
    return {
        "ghsa": ghsa_id,
        "cve": cve,
        "summary": rec.get("summary"),
        "severity": db.get("severity"),
        "cvss": score,
        "cvss_version": version,
        "cvss_vector": vector,
        "cwe": list(db.get("cwe_ids") or []),
        "affected": _affected_entries(rec.get("affected") or []),
        "published": _ts(rec.get("published")),
        "modified": modified,
        "withdrawn": _ts(rec.get("withdrawn")),
        "raw": raw.decode("utf-8", errors="replace"),
    }


def rows_to_table(rows: list[dict]) -> pa.Table:
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("ghsa", "ascending"), ("modified", "ascending")])


def key_for_year(year: int) -> str:
    """backfill 断面を published 年ごとに集約したファイルのキー。"""
    return f"ghsa/year={year}/ghsa-{year}.parquet"


def key_for_update(d: date) -> str:
    """実行日 d の日次差分ファイルのキー。"""
    return f"ghsa/updates/year={d.year}/ghsa-updates-{d.isoformat()}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    pq.write_table(table, path, compression="zstd")
