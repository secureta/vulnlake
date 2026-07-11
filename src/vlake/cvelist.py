"""CVE List V5 (cvelistV5) データセット。

データ提供: CVE Program (https://github.com/CVEProject/cvelistV5)。
CVE® is a registered trademark of The MITRE Corporation.
本プロジェクトは CVE Records を再配布するが、MITRE / CVE Program の
公認・認証を受けたものではない。
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

NAME = "cve"

SCHEMA = pa.schema(
    [
        ("cve", pa.string()),
        ("state", pa.string()),
        ("assigner", pa.string()),
        ("title", pa.string()),
        ("description", pa.string()),
        ("cvss", pa.float64()),
        ("cvss_version", pa.string()),
        ("cvss_severity", pa.string()),
        ("cvss_vector", pa.string()),
        ("cwe", pa.list_(pa.string())),
        ("date_published", pa.timestamp("us")),
        ("date_reserved", pa.timestamp("us")),
        ("date_updated", pa.timestamp("us")),
        ("raw", pa.string()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://github.com/CVEProject/cvelistV5",
    "license_name": "CVE Terms of Use (cve-tou)",
    "license_text": (
        '"CVE Usage: MITRE hereby grants you a perpetual, worldwide, '
        "non-exclusive, no-charge, royalty-free, irrevocable copyright license "
        "to reproduce, prepare derivative works of, publicly display, publicly "
        "perform, sublicense, and distribute Common Vulnerabilities and "
        "Exposures (CVE®). Any copy you make for such purposes is authorized "
        "provided that you reproduce MITRE's copyright designation and this "
        'license in any such copy." — https://www.cve.org/Legal/TermsOfUse'
    ),
    "attribution": (
        "CVE® is a registered trademark of The MITRE Corporation. "
        "CVE Records: Copyright © 1999-2026 The MITRE Corporation."
    ),
    "disclaimer": (
        "This project redistributes CVE Records but is not endorsed or "
        "certified by MITRE or the CVE Program."
    ),
}

# CVSS 採択優先順位 (コンテナ内)。コンテナは CNA → ADP の順に見る
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _ts(value) -> datetime | None:
    """ISO 8601 (Z / +00:00 / ナイーブ混在) を UTC ナイーブ datetime にする。"""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _first_en(entries) -> str | None:
    """descriptions/rejectedReasons から英語エントリ優先で value を取る。"""
    if not entries:
        return None
    for e in entries:
        if str(e.get("lang", "")).lower().startswith("en") and e.get("value"):
            return e["value"]
    return entries[0].get("value")


def _best_cvss(containers: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """CNA 優先・バージョン降順で最良の CVSS を1つ採択する。"""
    for container in (containers.get("cna") or {},) + tuple(containers.get("adp") or ()):
        for key in _CVSS_KEYS:
            for metric in container.get("metrics") or []:
                m = metric.get(key)
                if isinstance(m, dict) and m.get("baseScore") is not None:
                    version = m.get("version") or key[5:].replace("_", ".")
                    return (
                        float(m["baseScore"]),
                        version,
                        m.get("baseSeverity"),
                        m.get("vectorString"),
                    )
    return (None, None, None, None)


def parse_record(raw: bytes) -> dict | None:
    """CVE JSON 5.x レコード1件を SCHEMA の行 dict にする。壊れていれば None。"""
    try:
        rec = json.loads(raw)
        meta = rec["cveMetadata"]
        cve_id = meta["cveId"]
        containers = rec.get("containers") or {}
        cna = containers.get("cna") or {}
    except (ValueError, KeyError, TypeError):
        return None
    date_updated = (
        _ts(meta.get("dateUpdated"))
        or _ts(meta.get("datePublished"))
        or _ts(meta.get("dateReserved"))
    )
    if date_updated is None:
        return None  # view の順序付けに使う日時が無いレコードは扱えない
    if meta.get("state") == "REJECTED":
        description = _first_en(cna.get("rejectedReasons"))
    else:
        description = _first_en(cna.get("descriptions"))
    cwes: list[str] = []
    for container in (cna, *(containers.get("adp") or ())):
        for pt in container.get("problemTypes") or []:
            for desc in pt.get("descriptions") or []:
                cwe_id = desc.get("cweId")
                if cwe_id and cwe_id not in cwes:
                    cwes.append(cwe_id)
    cvss, cvss_version, cvss_severity, cvss_vector = _best_cvss(containers)
    return {
        "cve": cve_id,
        "state": meta.get("state"),
        "assigner": meta.get("assignerShortName"),
        "title": cna.get("title"),
        "description": description,
        "cvss": cvss,
        "cvss_version": cvss_version,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwe": cwes,
        "date_published": _ts(meta.get("datePublished")),
        "date_reserved": _ts(meta.get("dateReserved")),
        "date_updated": date_updated,
        "raw": raw.decode("utf-8", errors="replace"),
    }


def rows_to_table(rows: list[dict]) -> pa.Table:
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("cve", "ascending"), ("date_updated", "ascending")])


def key_for_year(year: int) -> str:
    """backfill 断面を CVE-ID 年ごとに集約したファイルのキー。"""
    return f"cve/year={year}/cve-{year}.parquet"


def key_for_update(d: date) -> str:
    """baseline 日付 d の日次差分ファイルのキー。"""
    return f"cve/updates/year={d.year}/cve-updates-{d.isoformat()}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    pq.write_table(table, path, compression="zstd")
