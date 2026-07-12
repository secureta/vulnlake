"""KEV (Known Exploited Vulnerabilities) データセット。

データ提供: CISA (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)。
CC0 1.0 Universal で提供されるカタログ JSON を Parquet に変換して再配布する
(変更あり)。本プロジェクトは CISA / DHS の公認・推奨を受けたものではなく、
CISA ロゴ・DHS シールは使用しない。notes 等の第三者リンク先は各サイトの
ポリシー・ライセンスに従う。
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

NAME = "kev"

SCHEMA = pa.schema(
    [
        ("cve", pa.string()),
        ("vendor_project", pa.string()),
        ("product", pa.string()),
        ("vulnerability_name", pa.string()),
        ("short_description", pa.string()),
        ("required_action", pa.string()),
        ("known_ransomware_campaign_use", pa.string()),
        ("notes", pa.string()),
        ("cwe", pa.list_(pa.string())),
        ("date_added", pa.date32()),
        ("due_date", pa.date32()),
        ("fetched_date", pa.date32()),
        ("removed", pa.bool_()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "license_name": "CC0-1.0",
    "license_text": (
        "Creative Commons Zero 1.0 Universal "
        "(https://creativecommons.org/publicdomain/zero/1.0/). "
        "The KEV database is distributed by CISA under CC0 1.0 "
        "(https://www.cisa.gov/sites/default/files/licenses/kev/license.txt). "
        "This dataset is a modified form of the KEV catalog JSON converted to "
        "Parquet. Information at third-party links included in the KEV data "
        "is bound by the policies and licenses of those third-party websites."
    ),
    "attribution": (
        "Known Exploited Vulnerabilities Catalog — CISA "
        "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog), "
        "distributed under CC0 1.0 Universal."
    ),
    "disclaimer": (
        "This project redistributes KEV catalog data but is not endorsed by "
        "CISA or DHS, and does not use the CISA Logo or DHS Seal."
    ),
}

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _str(value) -> str | None:
    """空でない文字列のみ通す (数値等は文字列化しない)。"""
    return value if isinstance(value, str) and value else None


def _date(value) -> date | None:
    """ISO 日付文字列を date にする。欠落・パース不能は None。"""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _cwes(value) -> list[str]:
    """cwes 配列を大文字化した文字列リストに正規化する。"""
    if not isinstance(value, list):
        return []
    return [s.upper() for v in value if isinstance(v, str) and (s := v.strip())]


def parse_record(rec: dict) -> dict | None:
    """vulnerabilities 配列の 1 レコードを SCHEMA の行 dict にする。

    fetched_date / removed は含まない (pipeline が実行日で付与する)。
    cveID が欠落・不正なレコードは None (上流異常の観測点)。
    """
    cve = rec.get("cveID")
    if not isinstance(cve, str) or not _CVE_RE.fullmatch(cve):
        return None
    return {
        "cve": cve,
        "vendor_project": _str(rec.get("vendorProject")),
        "product": _str(rec.get("product")),
        "vulnerability_name": _str(rec.get("vulnerabilityName")),
        "short_description": _str(rec.get("shortDescription")),
        "required_action": _str(rec.get("requiredAction")),
        "known_ransomware_campaign_use": _str(rec.get("knownRansomwareCampaignUse")),
        "notes": _str(rec.get("notes")),
        "cwe": _cwes(rec.get("cwes")),
        "date_added": _date(rec.get("dateAdded")),
        "due_date": _date(rec.get("dueDate")),
    }


def parse_catalog(raw: bytes) -> tuple[list[dict], int]:
    """フィード JSON 全体を (行リスト, bad 件数) にする。

    vulnerabilities 配列が無い・配列でない場合は上流フォーマットの破壊と
    みなして ValueError (差分処理に進ませない)。
    """
    doc = json.loads(raw)
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("KEV feed has no vulnerabilities array")
    rows, bad = [], 0
    for rec in vulns:
        row = parse_record(rec) if isinstance(rec, dict) else None
        if row is None:
            bad += 1
        else:
            rows.append(row)
    return rows, bad


def rows_to_table(rows: list[dict]) -> pa.Table:
    """行リストを SCHEMA に従う PyArrow Table に変換し、cve で昇順ソートする。"""
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("cve", "ascending")])


def key_for_update(d: date) -> str:
    """実行日 d の日次差分ファイルのキー (初回は全量が載る)。"""
    return f"kev/updates/year={d.year}/kev-updates-{d.isoformat()}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    """PyArrow Table を Parquet ファイルに書き出す (zstd 圧縮)。"""
    pq.write_table(table, path, compression="zstd")


def download(url: str, dest: Path) -> None:
    """フィード JSON をダウンロードする。"""
    with httpx.stream("GET", url, follow_redirects=True, timeout=600) as resp:
        resp.raise_for_status()
        with dest.open("wb") as f:
            for chunk in resp.iter_bytes():
                f.write(chunk)
