# Cloudflare WAF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cloudflare WAF ChangeLog から脆弱性識別子を抽出し、`vlake.cloudflare_waf` と `vlake.cve_sources` で WAF 対応シグナルを問い合わせ可能にする。

**Architecture:** `cloudflare_waf.py` が Cloudflare Docs GitHub リポジトリ上の MDX を取得・パースし、`cloudflare_waf_history` に append-only で差分を追記する。`cloudflare_waf` view は `identifier + source_url` ごとの latest を返し、CVE は `cve_sources` に `has_cloudflare_waf` / `cloudflare_waf_count` として集約する。

**Tech Stack:** Python 3.14.6+, Click, httpx, PyArrow, DuckDB/DuckLake, pytest, ruff, zizmor/actionlint.

## Global Constraints

- コード内コメント・docstring・コミットメッセージは日本語。
- 正式名は **vulnlake**、CLI / `VLAKE_*` / `src/vlake/` / カタログ名は **vlake** のまま維持する。
- 公開順序の不変条件を崩さない: Parquet を先にアップロードし、カタログ (`vlake.ducklake`) の差し替えは必ず最後。
- `cloudflare_waf` は backfill なし。初回 `update` が現行断面の全量投入になる。
- Cloudflare Docs のライセンスは CC-BY-4.0 として扱い、`LICENSE_INFO` / `DATA_LICENSES.md` / `datasets` view に帰属・変更・免責を明記する。
- ChangeLog 内で脆弱性 ID が言及されていれば WAF 対応シグナルとして扱う。防御文脈の自然言語判定はしない。
- CVE 以外の識別子も `cloudflare_waf.identifier` で拾う。`cve_sources` は CVE のみ集計する。
- ネットワーク越しの git 操作 (`git push` / `git fetch` / `git pull`) は実行しない。
- スキーマ・README・`docs/schema.md` を変更するタスクでは `readme-schema-sync` skill を使う。
- 完了・コミット前には `mise run pre-commit` を実行する。

---

## File Structure

- Create `src/vlake/cloudflare_waf.py`
  - Cloudflare Docs GitHub MDX 取得、frontmatter / historical table パース、脆弱性識別子抽出、Parquet 書き出しを担当する。
- Modify `src/vlake/lake.py`
  - `cloudflare_waf_history` DDL、latest rows helper、`cloudflare_waf` view、`cve_sources` 集計列を追加する。
- Modify `src/vlake/pipeline.py`
  - `update_cloudflare_waf()`、publish/rebuild/verify 配線を追加する。
- Modify `src/vlake/cli.py`
  - `vlake update cloudflare_waf` を追加し、backfill には追加しない。
- Create `tests/test_cloudflare_waf.py`
  - module-level parser / extractor / parquet tests。
- Create `tests/test_pipeline_cloudflare_waf.py`
  - update 差分・tombstone・verify・rebuild integration tests。
- Modify `tests/test_lake.py`, `tests/test_cli.py`, existing dataset-count tests
  - latest view / `cve_sources` / CLI / `datasets` 件数を更新する。
- Modify `README.md`, `docs/schema.md`, `DATA_LICENSES.md`
  - 公開スキーマ・クエリ例・ライセンスを同期する。
- Modify `.github/workflows/publish.yml`
  - daily publish に `uv run vlake update cloudflare_waf` を追加する。

---

### Task 1: `cloudflare_waf.py` データセットモジュール

**Files:**
- Create: `src/vlake/cloudflare_waf.py`
- Create: `tests/test_cloudflare_waf.py`

**Interfaces:**
- Produces:
  - `NAME: str = "cloudflare_waf"`
  - `SCHEMA: pyarrow.Schema`
  - `LICENSE_INFO: dict[str, str]`
  - `download(dest_dir: Path) -> list[Path]`
  - `parse_dir(source_dir: Path) -> list[dict]`
  - `parse_markdown(source_path: str, raw: bytes) -> list[dict]`
  - `extract_identifiers(text: str) -> list[tuple[str, str]]`
  - `rows_to_table(rows: list[dict]) -> pa.Table`
  - `key_for_update(d: date) -> str`
  - `write_parquet(table: pa.Table, path: Path) -> None`
- Consumed by later tasks:
  - `pipeline.update_cloudflare_waf()` calls `download()`, `parse_dir()`, `key_for_update()`, `rows_to_table()`, `write_parquet()`.
  - `_publish_catalog()` reads `LICENSE_INFO`.

- [ ] **Step 1: Write failing parser/extractor tests**

Create `tests/test_cloudflare_waf.py` with:

```python
from datetime import date

import pyarrow.parquet as pq

from vlake import cloudflare_waf


def test_extract_identifiers_supports_multiple_vulnerability_id_types():
    text = (
        "CVE:CVE-2026-1281 and cve-2026-1340, "
        "GHSA-abcd-1234-wxyz, GO-2024-1234, PYSEC-2023-45, "
        "RUSTSEC-2024-0001 are mentioned. CVE-2026-1281 repeats."
    )

    assert cloudflare_waf.extract_identifiers(text) == [
        ("CVE-2026-1281", "CVE"),
        ("CVE-2026-1340", "CVE"),
        ("GHSA-ABCD-1234-WXYZ", "GHSA"),
        ("GO-2024-1234", "GO"),
        ("PYSEC-2023-45", "PYSEC"),
        ("RUSTSEC-2024-0001", "RUSTSEC"),
    ]


def test_parse_current_changelog_mdx_extracts_frontmatter_and_context():
    raw = b'''---
title: "WAF Release - 2026-03-12 - Emergency"
description: Cloudflare WAF managed rulesets emergency release
date: 2026-03-12
---

import { RuleID } from "~/components";

This release adds detections for Ivanti EPMM (CVE-2026-1281 and CVE-2026-1340).

<td>Ivanti EPMM - Code Injection - CVE:CVE-2026-1281 CVE:CVE-2026-1340</td>
'''

    rows = cloudflare_waf.parse_markdown(
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx", raw
    )

    assert [(r["identifier"], r["identifier_type"]) for r in rows] == [
        ("CVE-2026-1281", "CVE"),
        ("CVE-2026-1340", "CVE"),
    ]
    assert rows[0]["cve"] == "CVE-2026-1281"
    assert rows[0]["source_title"] == "WAF Release - 2026-03-12 - Emergency"
    assert rows[0]["source_date"] == date(2026, 3, 12)
    assert rows[0]["source_url"] == (
        "https://developers.cloudflare.com/changelog/"
        "2026-03-12-emergency-waf-release/"
    )
    assert "CVE-2026-1281" in rows[0]["matched_text"]


def test_parse_historical_table_uses_row_description_and_change_date():
    raw = b'''---
title: "Historical (2024)"
---
<table><tbody>
<tr>
<td>Cloudflare Specials</td>
<td><RuleID id="fc7338307e484b9f8d460aca6bc398e9" /></td>
<td>100675</td>
<td>Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205</td>
<td>2024-10-21</td>
<td>Log</td>
<td>Block</td>
</tr>
</tbody></table>
'''

    rows = cloudflare_waf.parse_markdown(
        "src/content/docs/waf/change-log/historical-2024.mdx", raw
    )

    assert rows == [
        {
            "identifier": "CVE-2023-38205",
            "identifier_type": "CVE",
            "cve": "CVE-2023-38205",
            "source_title": "Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205",
            "source_url": "https://developers.cloudflare.com/waf/change-log/historical-2024/",
            "source_date": date(2024, 10, 21),
            "matched_text": "Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205",
        }
    ]


def test_parse_dir_deduplicates_identifier_per_source_url(tmp_path):
    p = tmp_path / "src" / "content" / "changelog" / "waf" / "2026-01-01-waf-release.mdx"
    p.parent.mkdir(parents=True)
    p.write_text(
        '''---
title: WAF Release
date: 2026-01-01
---
CVE-2026-0001 appears twice: CVE:CVE-2026-0001.
'''
    )

    rows = cloudflare_waf.parse_dir(tmp_path)

    assert len(rows) == 1
    assert rows[0]["identifier"] == "CVE-2026-0001"


def test_rows_to_table_key_and_parquet_roundtrip(tmp_path):
    rows = [
        {
            "identifier": "GHSA-ABCD-1234-WXYZ",
            "identifier_type": "GHSA",
            "cve": None,
            "source_title": "sample",
            "source_url": "https://developers.cloudflare.com/changelog/sample/",
            "source_date": date(2026, 1, 2),
            "matched_text": "GHSA-abcd-1234-wxyz",
            "fetched_date": date(2026, 7, 16),
            "removed": False,
        },
        {
            "identifier": "CVE-2026-0001",
            "identifier_type": "CVE",
            "cve": "CVE-2026-0001",
            "source_title": "sample",
            "source_url": "https://developers.cloudflare.com/changelog/sample/",
            "source_date": date(2026, 1, 1),
            "matched_text": "CVE-2026-0001",
            "fetched_date": date(2026, 7, 16),
            "removed": False,
        },
    ]

    table = cloudflare_waf.rows_to_table(rows)
    assert table.column_names == [
        "identifier",
        "identifier_type",
        "cve",
        "source_title",
        "source_url",
        "source_date",
        "matched_text",
        "fetched_date",
        "removed",
    ]
    assert table.column("identifier").to_pylist() == [
        "CVE-2026-0001",
        "GHSA-ABCD-1234-WXYZ",
    ]
    assert cloudflare_waf.key_for_update(date(2026, 7, 16)) == (
        "cloudflare_waf/updates/year=2026/"
        "cloudflare-waf-updates-2026-07-16.parquet"
    )

    out = tmp_path / "rows.parquet"
    cloudflare_waf.write_parquet(table, out)
    assert pq.read_table(out).schema == cloudflare_waf.SCHEMA
```

- [ ] **Step 2: Run module tests and verify they fail**

Run:

```bash
uv run pytest tests/test_cloudflare_waf.py -v
```

Expected: FAIL during import with `ImportError: cannot import name 'cloudflare_waf' from 'vlake'` or `ModuleNotFoundError` because `src/vlake/cloudflare_waf.py` does not exist yet.

- [ ] **Step 3: Implement `src/vlake/cloudflare_waf.py`**

Create `src/vlake/cloudflare_waf.py`:

```python
"""Cloudflare WAF ChangeLog データセット。

データ提供: Cloudflare Docs (https://github.com/cloudflare/cloudflare-docs)。
CC-BY-4.0 で提供される WAF ChangeLog の MDX から脆弱性識別子を抽出し、
Parquet に変換して再配布する (変更あり)。本プロジェクトは Cloudflare の
公認・推奨を受けたものではない。
"""

from __future__ import annotations

import html
import json
import re
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

NAME = "cloudflare_waf"

SCHEMA = pa.schema(
    [
        ("identifier", pa.string()),
        ("identifier_type", pa.string()),
        ("cve", pa.string()),
        ("source_title", pa.string()),
        ("source_url", pa.string()),
        ("source_date", pa.date32()),
        ("matched_text", pa.string()),
        ("fetched_date", pa.date32()),
        ("removed", pa.bool_()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://github.com/cloudflare/cloudflare-docs",
    "license_name": "CC-BY-4.0",
    "license_text": (
        "Creative Commons Attribution 4.0 International "
        "(https://creativecommons.org/licenses/by/4.0/). "
        "This dataset is a modified form of Cloudflare Docs WAF ChangeLog MDX: "
        "vulnerability identifiers are extracted and converted to Parquet."
    ),
    "attribution": (
        "Cloudflare Docs WAF ChangeLog — Cloudflare "
        "(https://developers.cloudflare.com/waf/change-log/), "
        "licensed under CC-BY 4.0."
    ),
    "disclaimer": (
        "This project redistributes derived Cloudflare Docs metadata but is not "
        "endorsed or certified by Cloudflare."
    ),
}

_REPO = "cloudflare/cloudflare-docs"
_BRANCH = "production"
_API_DIR_URL = (
    f"https://api.github.com/repos/{_REPO}/contents/src/content/changelog/waf"
    f"?ref={_BRANCH}"
)
_RAW_BASE = f"https://raw.githubusercontent.com/{_REPO}/{_BRANCH}/{{}}"
_DOC_BASE = "https://developers.cloudflare.com"
_HISTORICAL_PATHS = [
    "src/content/docs/waf/change-log/historical-2022.mdx",
    "src/content/docs/waf/change-log/historical-2023.mdx",
    "src/content/docs/waf/change-log/historical-2024.mdx",
]
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_TR_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.DOTALL | re.IGNORECASE)
_TD_RE = re.compile(r"<td\b[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_PATTERNS = [
    ("CVE", re.compile(r"(?i)\bCVE-\d{4}-\d{4,}\b")),
    ("GHSA", re.compile(r"(?i)\bGHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b")),
    ("GO", re.compile(r"(?i)\bGO-\d{4}-\d+\b")),
    ("PYSEC", re.compile(r"(?i)\bPYSEC-\d{4}-\d+\b")),
    ("RUSTSEC", re.compile(r"(?i)\bRUSTSEC-\d{4}-\d+\b")),
]


def _frontmatter(raw: str) -> tuple[dict[str, str], str]:
    """単純な YAML frontmatter から文字列値だけを取り出す。"""
    m = _FRONTMATTER_RE.match(raw)
    if not m:
        return {}, raw
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            meta[key.strip()] = value
    return meta, raw[m.end() :]


def _parse_date(value: str | None) -> date | None:
    """文字列中の ISO 日付を date にする。見つからなければ None。"""
    if not value:
        return None
    m = _DATE_RE.search(value)
    if not m:
        return None
    try:
        return date.fromisoformat(m.group(1))
    except ValueError:
        return None


def _text(value: str) -> str:
    """MDX/HTML 断片を検索・表示用の平文に近づける。"""
    value = re.sub(r"<RuleID\b[^>]*/>", " ", value)
    value = _TAG_RE.sub(" ", value)
    value = html.unescape(value)
    return _WS_RE.sub(" ", value).strip()


def _doc_url(source_path: str) -> str:
    """GitHub 内パスから developers.cloudflare.com の公開 URL を作る。"""
    name = Path(source_path).name.removesuffix(".mdx")
    if source_path.startswith("src/content/changelog/waf/"):
        return f"{_DOC_BASE}/changelog/{name}/"
    if source_path.startswith("src/content/docs/waf/change-log/"):
        return f"{_DOC_BASE}/waf/change-log/{name}/"
    return f"https://github.com/{_REPO}/blob/{_BRANCH}/{source_path}"


def extract_identifiers(text: str) -> list[tuple[str, str]]:
    """本文から脆弱性識別子を出現順・重複なしで抽出する。"""
    matches = []
    for ident_type, pat in _PATTERNS:
        for m in pat.finditer(text):
            matches.append((m.start(), m.group(0).upper(), ident_type))
    matches.sort(key=lambda x: x[0])
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for _, ident, ident_type in matches:
        if ident not in seen:
            seen.add(ident)
            out.append((ident, ident_type))
    return out


def _context(text: str, identifier: str, size: int = 120) -> str:
    """識別子周辺の短い文脈を返す。"""
    pos = text.upper().find(identifier)
    if pos < 0:
        return text[:size]
    start = max(0, pos - size // 2)
    end = min(len(text), pos + len(identifier) + size // 2)
    return text[start:end].strip()


def _rows_from_text(
    *,
    text: str,
    source_title: str,
    source_url: str,
    source_date: date | None,
) -> list[dict]:
    """1つの出典テキストから identifier 行を作る。"""
    rows = []
    for identifier, ident_type in extract_identifiers(text):
        rows.append(
            {
                "identifier": identifier,
                "identifier_type": ident_type,
                "cve": identifier if ident_type == "CVE" else None,
                "source_title": source_title,
                "source_url": source_url,
                "source_date": source_date,
                "matched_text": _context(text, identifier),
            }
        )
    return rows


def _historical_rows(source_path: str, body: str, page_title: str) -> list[dict]:
    """historical-YYYY.mdx の HTML table を行単位にパースする。"""
    source_url = _doc_url(source_path)
    rows = []
    for tr in _TR_RE.findall(body):
        cells = [_text(c) for c in _TD_RE.findall(tr)]
        if len(cells) < 5:
            continue
        description = cells[3]
        if not extract_identifiers(description):
            continue
        rows.extend(
            _rows_from_text(
                text=description,
                source_title=description or page_title,
                source_url=source_url,
                source_date=_parse_date(cells[4]),
            )
        )
    return rows


def parse_markdown(source_path: str, raw: bytes) -> list[dict]:
    """Cloudflare Docs の WAF ChangeLog MDX 1ファイルから行 dict を抽出する。"""
    text = raw.decode("utf-8", errors="replace")
    meta, body = _frontmatter(text)
    title = meta.get("title") or Path(source_path).stem
    if source_path.startswith("src/content/docs/waf/change-log/historical-"):
        rows = _historical_rows(source_path, body, title)
    else:
        plain = _text(body)
        rows = _rows_from_text(
            text=plain,
            source_title=title,
            source_url=_doc_url(source_path),
            source_date=_parse_date(meta.get("date")),
        )
    dedup: dict[tuple[str, str], dict] = {}
    for row in rows:
        dedup.setdefault((row["identifier"], row["source_url"]), row)
    return list(dedup.values())


def parse_dir(source_dir: Path) -> list[dict]:
    """download() が保存した MDX 群を全て読み、identifier+source_url で重複排除する。"""
    rows: list[dict] = []
    for path in sorted(source_dir.rglob("*.mdx")):
        source_path = path.relative_to(source_dir).as_posix()
        rows.extend(parse_markdown(source_path, path.read_bytes()))
    dedup: dict[tuple[str, str], dict] = {}
    for row in rows:
        dedup.setdefault((row["identifier"], row["source_url"]), row)
    return list(dedup.values())


def _write_source(dest_dir: Path, source_path: str, raw: bytes) -> Path:
    """GitHub 内パスを保って MDX を保存する。"""
    out = dest_dir / source_path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(raw)
    return out


def download(dest_dir: Path) -> list[Path]:
    """Cloudflare Docs GitHub リポジトリから WAF ChangeLog MDX を取得する。"""
    dest_dir.mkdir(parents=True, exist_ok=True)
    paths: list[str] = list(_HISTORICAL_PATHS)
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        resp = client.get(_API_DIR_URL)
        resp.raise_for_status()
        listing = json.loads(resp.text)
        if not isinstance(listing, list):
            raise ValueError("Cloudflare Docs API response is not a directory listing")
        for item in listing:
            if isinstance(item, dict) and item.get("type") == "file":
                path = item.get("path")
                if isinstance(path, str) and path.endswith(".mdx"):
                    paths.append(path)
        written = []
        for source_path in sorted(set(paths)):
            raw = client.get(_RAW_BASE.format(source_path))
            raw.raise_for_status()
            written.append(_write_source(dest_dir, source_path, raw.content))
    return written


def rows_to_table(rows: list[dict]) -> pa.Table:
    """行リストを SCHEMA に従う PyArrow Table に変換し、identifier/source_url でソートする。"""
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("identifier", "ascending"), ("source_url", "ascending")])


def key_for_update(d: date) -> str:
    """実行日 d の日次差分ファイルのキー (初回は全量が載る)。"""
    return (
        f"cloudflare_waf/updates/year={d.year}/"
        f"cloudflare-waf-updates-{d.isoformat()}.parquet"
    )


def write_parquet(table: pa.Table, path: Path) -> None:
    """PyArrow Table を Parquet ファイルに書き出す (zstd 圧縮)。"""
    pq.write_table(table, path, compression="zstd")
```

- [ ] **Step 4: Run module tests and verify they pass**

Run:

```bash
uv run pytest tests/test_cloudflare_waf.py -v
```

Expected: PASS for all tests in `tests/test_cloudflare_waf.py`.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/vlake/cloudflare_waf.py tests/test_cloudflare_waf.py
git commit -m "feat: Cloudflare WAFデータセットモジュールを追加"
```

---

### Task 2: DuckLake table/view と `cve_sources` 集計

**Files:**
- Modify: `src/vlake/lake.py`
- Modify: `tests/test_lake.py`

**Interfaces:**
- Consumes: `cloudflare_waf.SCHEMA` column names from Task 1.
- Produces:
  - `Lake.cloudflare_waf_latest_rows() -> list[dict]`
  - `Lake.refresh_cloudflare_waf_view() -> None`
  - `Lake.refresh_cve_sources_view()` includes `has_cloudflare_waf`, `cloudflare_waf_count`.

- [ ] **Step 1: Write failing lake tests**

In `tests/test_lake.py`, add this test after `test_kev_latest_rows_and_view`:

```python

def test_cloudflare_waf_latest_rows_and_view(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        assert lake.cloudflare_waf_latest_rows() == []
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cloudflare_waf_history "  # noqa: S608
            "(identifier, identifier_type, cve, source_title, source_url, "
            "source_date, matched_text, fetched_date, removed) VALUES "
            "('CVE-2026-0001', 'CVE', 'CVE-2026-0001', 'old', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'old text', DATE '2026-07-10', false), "
            "('CVE-2026-0001', 'CVE', 'CVE-2026-0001', 'new', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'new text', DATE '2026-07-12', false), "
            "('GHSA-ABCD-1234-WXYZ', 'GHSA', NULL, 'removed', "
            " 'https://developers.cloudflare.com/changelog/b/', "
            " DATE '2026-01-02', 'ghsa text', DATE '2026-07-12', true)"
        )
        rows = {
            (r["identifier"], r["source_url"]): r
            for r in lake.cloudflare_waf_latest_rows()
        }
        assert rows[("CVE-2026-0001", "https://developers.cloudflare.com/changelog/a/")][
            "source_title"
        ] == "new"
        assert rows[("GHSA-ABCD-1234-WXYZ", "https://developers.cloudflare.com/changelog/b/")][
            "removed"
        ] is True

        lake.refresh_cloudflare_waf_view()
        got = lake.query(
            "SELECT identifier, source_title, removed FROM lake.cloudflare_waf "
            "ORDER BY identifier"
        )
        assert got == [
            ("CVE-2026-0001", "new", False),
            ("GHSA-ABCD-1234-WXYZ", "removed", True),
        ]
    finally:
        lake.close()
```

Then update `test_cve_sources_view_summarizes_dataset_presence`:

1. Insert Cloudflare WAF rows after the KEV insert:

```python
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cloudflare_waf_history "  # noqa: S608
            "(identifier, identifier_type, cve, source_title, source_url, "
            "source_date, matched_text, fetched_date, removed) VALUES "
            "('CVE-2024-0001', 'CVE', 'CVE-2024-0001', 'waf-a', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'CVE-2024-0001', DATE '2026-07-10', false), "
            "('CVE-2024-0001', 'CVE', 'CVE-2024-0001', 'waf-b', "
            " 'https://developers.cloudflare.com/changelog/b/', "
            " DATE '2026-01-02', 'CVE-2024-0001', DATE '2026-07-10', false), "
            "('CVE-2024-0006', 'CVE', 'CVE-2024-0006', 'removed', "
            " 'https://developers.cloudflare.com/changelog/c/', "
            " DATE '2026-01-03', 'CVE-2024-0006', DATE '2026-07-10', true)"
        )
```

2. Add `lake.refresh_cloudflare_waf_view()` before `lake.refresh_cve_sources_view()`:

```python
        lake.refresh_cloudflare_waf_view()
        lake.refresh_cve_sources_view()
```

3. Change the SELECT to include Cloudflare WAF columns:

```python
        got = lake.query(
            "SELECT cve, has_epss, has_cve, has_ghsa, has_exploitdb, "
            "has_nuclei, has_kev, has_cloudflare_waf, epss_days, ghsa_count, "
            "exploitdb_count, nuclei_count, cloudflare_waf_count "
            "FROM lake.cve_sources ORDER BY cve"
        )
```

4. Change expected tuples to include `has_cloudflare_waf` and `cloudflare_waf_count`:

```python
        assert got == [
            (
                "CVE-2024-0001",
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                2,
                2,
                1,
                1,
                2,
            ),
            (
                "CVE-2024-0002",
                True,
                False,
                False,
                False,
                False,
                False,
                False,
                1,
                0,
                0,
                0,
                0,
            ),
            (
                "CVE-2024-0003",
                False,
                False,
                False,
                True,
                False,
                False,
                False,
                0,
                0,
                2,
                0,
                0,
            ),
        ]
```

- [ ] **Step 2: Run lake tests and verify they fail**

Run:

```bash
uv run pytest tests/test_lake.py -k 'cloudflare_waf or cve_sources' -v
```

Expected: FAIL because `cloudflare_waf_history` and `Lake.cloudflare_waf_latest_rows` do not exist yet.

- [ ] **Step 3: Add table and latest view methods to `lake.py`**

In `Lake.ensure_tables()`, add this DDL after the `kev_history` block and before `cwe_history`:

```python
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.cloudflare_waf_history (
                identifier VARCHAR,
                identifier_type VARCHAR,
                cve VARCHAR,
                source_title VARCHAR,
                source_url VARCHAR,
                source_date DATE,
                matched_text VARCHAR,
                fetched_date DATE,
                removed BOOLEAN
            )"""
        )
```

After `refresh_kev_view()`, add:

```python
    def cloudflare_waf_latest_rows(self) -> list[dict]:
        """identifier + source_url ごと fetched_date 最新の1行を列名付き dict で返す。"""
        cur = self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT * FROM {self.ALIAS}.cloudflare_waf_history "  # noqa: S608
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY identifier, source_url ORDER BY fetched_date DESC) = 1"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def refresh_cloudflare_waf_view(self) -> None:
        """identifier + source_url ごとに fetched_date 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.cloudflare_waf AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.cloudflare_waf_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY identifier, source_url ORDER BY fetched_date DESC) = 1"
        )
```

- [ ] **Step 4: Update `refresh_cve_sources_view()`**

In the SQL CTE list, after `kev_src AS (...)`, add:

```sql
            cloudflare_waf_src AS (
                SELECT cve, count(*) AS cloudflare_waf_count
                FROM {self.ALIAS}.cloudflare_waf
                WHERE cve IS NOT NULL AND NOT removed
                GROUP BY cve
            ),
```

In `all_cves`, add:

```sql
                UNION
                SELECT cve FROM cloudflare_waf_src
```

In the final SELECT, add after `kev_src.cve IS NOT NULL AS has_kev,`:

```sql
                cloudflare_waf_src.cve IS NOT NULL AS has_cloudflare_waf,
```

Add after `COALESCE(nuclei_src.nuclei_count, 0) AS nuclei_count`:

```sql
                COALESCE(cloudflare_waf_src.cloudflare_waf_count, 0) AS cloudflare_waf_count
```

If the previous line needs a comma, make the final count section:

```sql
                COALESCE(epss_src.epss_days, 0) AS epss_days,
                COALESCE(ghsa_src.ghsa_count, 0) AS ghsa_count,
                COALESCE(exploitdb_src.exploitdb_count, 0) AS exploitdb_count,
                COALESCE(nuclei_src.nuclei_count, 0) AS nuclei_count,
                COALESCE(cloudflare_waf_src.cloudflare_waf_count, 0) AS cloudflare_waf_count
```

Add the final join:

```sql
            LEFT JOIN cloudflare_waf_src ON all_cves.cve = cloudflare_waf_src.cve
```

- [ ] **Step 5: Run lake tests and verify they pass**

Run:

```bash
uv run pytest tests/test_lake.py -k 'cloudflare_waf or cve_sources' -v
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/vlake/lake.py tests/test_lake.py
git commit -m "feat: Cloudflare WAFのDuckLakeビューを追加"
```

---

### Task 3: Pipeline update / rebuild / verify

**Files:**
- Modify: `src/vlake/pipeline.py`
- Create: `tests/test_pipeline_cloudflare_waf.py`
- Modify: existing tests with exact `datasets` count/name assertions (`tests/test_pipeline.py` and any `rg 'datasets' tests` hits)

**Interfaces:**
- Consumes:
  - `cloudflare_waf.download(dest_dir: Path) -> list[Path]`
  - `cloudflare_waf.parse_dir(source_dir: Path) -> list[dict]`
  - `Lake.cloudflare_waf_latest_rows()`
  - `Lake.refresh_cloudflare_waf_view()`
- Produces:
  - `pipeline.update_cloudflare_waf(cfg: Config, today: date | None = None) -> str`
  - `verify(cfg)["datasets"]["cloudflare_waf"]`
  - `rebuild_catalog()` routes `cloudflare_waf/` files to `cloudflare_waf_history`.

- [ ] **Step 1: Write failing pipeline integration tests**

Create `tests/test_pipeline_cloudflare_waf.py`:

```python
from datetime import date
from pathlib import Path

import duckdb
import pytest

from vlake import cloudflare_waf, pipeline
from vlake.config import Config


@pytest.fixture
def cfg(tmp_path):
    return Config(
        s3_endpoint=None,
        s3_bucket=None,
        public_url=None,
        local_dir=tmp_path / "bucket",
    )


def _attach(cfg):
    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(
        f"ATTACH 'ducklake:{cfg.local_dir / 'vlake.ducklake'}' AS frozen (READ_ONLY)"
    )
    return con


def _write_current(root: Path, slug: str, title: str, d: str, body: str) -> None:
    path = root / "src" / "content" / "changelog" / "waf" / f"{slug}.mdx"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'''---
title: "{title}"
date: {d}
---

{body}
'''
    )


def _patch_download(monkeypatch, files: dict[str, str]):
    def fake_download(dest_dir: Path):
        written = []
        for rel, text in files.items():
            p = dest_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
            written.append(p)
        return written

    monkeypatch.setattr(cloudflare_waf, "download", fake_download)


def _initial_files():
    return {
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": '''---
title: "WAF Release - 2026-03-12 - Emergency"
date: 2026-03-12
---
This release adds detections for CVE-2026-1281 and CVE-2026-1340.
''',
        "src/content/changelog/waf/2026-04-01-waf-release.mdx": '''---
title: "WAF Release - 2026-04-01"
date: 2026-04-01
---
This release mentions GHSA-abcd-1234-wxyz.
''',
    }


def test_update_cloudflare_waf_initial_full_load(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())

    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    assert msg == "published 2026-07-16 (3 records)"
    assert (
        cfg.local_dir
        / "cloudflare_waf"
        / "updates"
        / "year=2026"
        / "cloudflare-waf-updates-2026-07-16.parquet"
    ).exists()
    con = _attach(cfg)
    assert (
        con.execute("SELECT count(*) FROM frozen.cloudflare_waf_history").fetchone()[0]
        == 3
    )
    assert (
        con.execute(
            "SELECT count(*) FROM frozen.cloudflare_waf WHERE NOT removed"
        ).fetchone()[0]
        == 3
    )
    assert con.execute(
        "SELECT source_title FROM frozen.cloudflare_waf "
        "WHERE identifier = 'CVE-2026-1281' AND NOT removed"
    ).fetchone()[0] == "WAF Release - 2026-03-12 - Emergency"
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {
        "epss",
        "cve",
        "ghsa",
        "exploitdb",
        "nuclei",
        "cwe",
        "kev",
        "cloudflare_waf",
    }

    assert (
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))
        == "already-registered 2026-07-16"
    )
    assert (
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))
        == "no-new-records 2026-07-17"
    )


def test_update_cloudflare_waf_diff_tombstone_and_revival(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    changed = {
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": '''---
title: "WAF Release - 2026-03-12 - Emergency Updated"
date: 2026-03-12
---
Updated context for CVE-2026-1281 only.
''',
        "src/content/changelog/waf/2026-05-01-waf-release.mdx": '''---
title: "WAF Release - 2026-05-01"
date: 2026-05-01
---
New detection for CVE-2026-9999.
''',
    }
    _patch_download(monkeypatch, changed)

    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))
    assert msg == "published 2026-07-17 (4 records)"  # 変更+追加+削除2件

    con = _attach(cfg)
    removed = con.execute(
        "SELECT removed FROM frozen.cloudflare_waf "
        "WHERE identifier = 'CVE-2026-1340'"
    ).fetchone()[0]
    assert removed is True
    assert con.execute(
        "SELECT source_title FROM frozen.cloudflare_waf "
        "WHERE identifier = 'CVE-2026-1281'"
    ).fetchone()[0] == "WAF Release - 2026-03-12 - Emergency Updated"

    _patch_download(monkeypatch, _initial_files())
    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 18))
    assert msg == "published 2026-07-18 (4 records)"
    assert con.execute(
        "SELECT removed FROM frozen.cloudflare_waf "
        "WHERE identifier = 'CVE-2026-1340'"
    ).fetchone()[0] is False


def test_update_cloudflare_waf_refuses_empty_snapshot(cfg, monkeypatch):
    _patch_download(monkeypatch, {})

    with pytest.raises(RuntimeError, match="no vulnerability identifiers"):
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))


def test_update_cloudflare_waf_refuses_shrunken_snapshot(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    _patch_download(
        monkeypatch,
        {
            "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": '''---
title: "WAF Release"
date: 2026-03-12
---
Only CVE-2026-1281 remains.
'''
        },
    )
    with pytest.raises(RuntimeError, match="less than half"):
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))

    con = _attach(cfg)
    assert (
        con.execute("SELECT count(*) FROM frozen.cloudflare_waf_history").fetchone()[0]
        == 3
    )


def test_cve_sources_covers_cloudflare_waf(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    con = _attach(cfg)
    got = con.execute(
        "SELECT cve, has_cloudflare_waf, cloudflare_waf_count "
        "FROM frozen.cve_sources WHERE cve IN ('CVE-2026-1281', 'CVE-2026-1340') "
        "ORDER BY cve"
    ).fetchall()
    assert got == [
        ("CVE-2026-1281", True, 1),
        ("CVE-2026-1340", True, 1),
    ]


def test_verify_and_rebuild_cover_cloudflare_waf(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    rep = report["datasets"]["cloudflare_waf"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 3
    assert rep["max_date"] == date(2026, 7, 16)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cloudflare_waf").fetchone()[0] == 3
```

- [ ] **Step 2: Run pipeline tests and verify they fail**

Run:

```bash
uv run pytest tests/test_pipeline_cloudflare_waf.py -v
```

Expected: FAIL because `pipeline.update_cloudflare_waf` does not exist yet.

- [ ] **Step 3: Wire imports, publish, rebuild, verify in `pipeline.py`**

Change the import line near the top from:

```python
from . import cvelist, cwe, epss, exploitdb, ghsa, kev, nuclei
```

to:

```python
from . import cloudflare_waf, cvelist, cwe, epss, exploitdb, ghsa, kev, nuclei
```

In `_publish_catalog()`, add `cloudflare_waf.LICENSE_INFO` to the list and call `lake.refresh_cloudflare_waf_view()` before `lake.refresh_cve_sources_view()`:

```python
            kev.LICENSE_INFO,
            cloudflare_waf.LICENSE_INFO,
        ]
    )
```

```python
    lake.refresh_kev_view()
    lake.refresh_cloudflare_waf_view()
    lake.refresh_cve_sources_view()
```

In `rebuild_catalog()`, add the route:

```python
        "cloudflare_waf/": "cloudflare_waf_history",
```

Near the existing update-key regexes, add:

```python
_CLOUDFLARE_WAF_UPDATE_KEY_DATE = re.compile(
    r"cloudflare-waf-updates-(\d{4}-\d{2}-\d{2})\.parquet$"
)
```

In `verify()`, add this report entry after `kev`:

```python
                "cloudflare_waf": _verify_history(
                    storage,
                    lake,
                    max_age_days,
                    prefix="cloudflare_waf/",
                    table="cloudflare_waf_history",
                    ts_column="fetched_date",
                    update_key_re=_CLOUDFLARE_WAF_UPDATE_KEY_DATE,
                ),
```

- [ ] **Step 4: Implement `update_cloudflare_waf()` in `pipeline.py`**

Add this function after `update_kev()` and before `update_cwe()`:

```python
def update_cloudflare_waf(cfg: Config, today: date | None = None) -> str:
    """Cloudflare WAF ChangeLog 断面とカタログ latest の差分だけを追記する。

    ChangeLog の更新履歴ではなく、identifier + source_url ごとの現行断面を
    latest と比較する。カタログが空なら初回 update が全量投入になる。
    上流から消えた識別子言及は最終値を引き継いだ removed=true の
    トゥームストーン行として追記する。
    """
    storage = make_storage(cfg)
    run_date = today or datetime.now(UTC).date()
    key = cloudflare_waf.key_for_update(run_date)
    compare_cols = (
        "identifier_type",
        "cve",
        "source_title",
        "source_date",
        "matched_text",
    )
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        lake, catalog = _open_lake(storage, workdir)
        try:
            if storage.url(key) in lake.registered_paths():
                return f"already-registered {run_date}"
            source_dir = workdir / "cloudflare-waf-sources"
            cloudflare_waf.download(source_dir)
            parsed = cloudflare_waf.parse_dir(source_dir)
            current: dict[tuple[str, str], dict] = {}
            for row in parsed:
                current.setdefault((row["identifier"], row["source_url"]), row)
            if not current:
                raise RuntimeError(
                    "refusing to ingest: no vulnerability identifiers extracted "
                    "from Cloudflare WAF changelog"
                )
            latest = {
                (r["identifier"], r["source_url"]): r
                for r in lake.cloudflare_waf_latest_rows()
            }
            active = sum(1 for r in latest.values() if not r["removed"])
            if latest and len(current) * 2 < active:
                raise RuntimeError(
                    f"refusing to ingest: snapshot has {len(current)} records, "
                    f"less than half of {active} active in catalog"
                )
            rows = []
            for row_key, row in current.items():
                prev = latest.get(row_key)
                if (
                    prev is None
                    or prev["removed"]
                    or any(prev[col] != row[col] for col in compare_cols)
                ):
                    rows.append({**row, "fetched_date": run_date, "removed": False})
            for row_key, prev in latest.items():
                if row_key not in current and not prev["removed"]:
                    rows.append({**prev, "fetched_date": run_date, "removed": True})
            if not rows:
                return f"no-new-records {run_date}"
            parquet = workdir / "updates.parquet"
            cloudflare_waf.write_parquet(cloudflare_waf.rows_to_table(rows), parquet)
            storage.put(parquet, key)
            lake.set_message(f"cloudflare_waf updates {run_date} ({len(rows)} records)")
            lake.add_file("cloudflare_waf_history", storage.url(key))
            _publish_catalog(storage, lake, catalog)
        finally:
            lake.close()
    return f"published {run_date} ({len(rows)} records)"
```

- [ ] **Step 5: Run pipeline Cloudflare WAF tests and fix dataset-count assertions**

Run:

```bash
uv run pytest tests/test_pipeline_cloudflare_waf.py -v
```

Expected: PASS after implementation.

Then find existing exact dataset-count/name assertions:

```bash
rg -n "datasets|count\(\*\).*frozen\.datasets|\{\"epss\"" tests
```

Apply these concrete updates where applicable:

- Change `assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 7` to `== 8`.
- Change exact dataset name sets from:

```python
{"epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe", "kev"}
```

to:

```python
{
    "epss",
    "cve",
    "ghsa",
    "exploitdb",
    "nuclei",
    "cwe",
    "kev",
    "cloudflare_waf",
}
```

Run the pipeline-related tests:

```bash
uv run pytest tests/test_pipeline.py tests/test_pipeline_cloudflare_waf.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/vlake/pipeline.py tests/test_pipeline_cloudflare_waf.py tests/test_pipeline.py
git commit -m "feat: Cloudflare WAF更新パイプラインを追加"
```

If `rg` found other existing tests that needed dataset assertion updates, include those files in `git add`.

---

### Task 4: CLI と publish workflow

**Files:**
- Modify: `src/vlake/cli.py`
- Modify: `tests/test_cli.py`
- Modify: `.github/workflows/publish.yml`

**Interfaces:**
- Consumes: `pipeline.update_cloudflare_waf(cfg)` from Task 3.
- Produces: `vlake update cloudflare_waf` command.

- [ ] **Step 1: Write failing CLI test**

Append to `tests/test_cli.py` near the other update CLI tests:

```python

def test_update_cloudflare_waf_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline,
        "update_cloudflare_waf",
        lambda cfg: "published 2026-07-16 (3 records)",
    )
    result = CliRunner().invoke(main, ["update", "cloudflare_waf"])
    assert result.exit_code == 0, result.output
    assert "published 2026-07-16" in result.output


def test_update_cloudflare_waf_rejects_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(
        main, ["update", "cloudflare_waf", "--date", "2026-07-01"]
    )
    assert result.exit_code != 0
    assert "--date" in result.output


def test_backfill_cloudflare_waf_is_not_supported(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["backfill", "cloudflare_waf"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output
```

- [ ] **Step 2: Run CLI tests and verify they fail**

Run:

```bash
uv run pytest tests/test_cli.py -k cloudflare_waf -v
```

Expected: FAIL because `click.Choice` rejects `cloudflare_waf` for update.

- [ ] **Step 3: Update `src/vlake/cli.py`**

Change the update `click.Choice` list to include `cloudflare_waf`:

```python
    type=click.Choice(
        ["epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe", "kev", "cloudflare_waf"]
    ),
```

Change the update docstring to mention Cloudflare WAF:

```python
    """日次更新 (冪等)。nuclei / cwe / kev / cloudflare_waf は backfill 不要 (初回 update が全量投入)。"""
```

Add the updater entry:

```python
        "cloudflare_waf": pipeline.update_cloudflare_waf,
```

Do not change the `backfill` choice list; `cloudflare_waf` must remain unsupported there.

- [ ] **Step 4: Update publish workflow**

In `.github/workflows/publish.yml`, add a dataset step after `kev` and before `verify`:

```yaml
      - id: cloudflare_waf
        continue-on-error: true
        run: uv run vlake update cloudflare_waf
```

Do not add Cloudflare WAF to `.github/workflows/backfill.yml` because it has no backfill.

- [ ] **Step 5: Run CLI tests**

Run:

```bash
uv run pytest tests/test_cli.py -k cloudflare_waf -v
```

Expected: PASS.

- [ ] **Step 6: Run actionlint for workflow syntax**

Run:

```bash
actionlint
```

Expected: no output and exit code 0.

- [ ] **Step 7: Commit Task 4**

```bash
git add src/vlake/cli.py tests/test_cli.py .github/workflows/publish.yml
git commit -m "feat: Cloudflare WAF更新CLIを追加"
```

---

### Task 5: README / schema / license documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/schema.md`
- Modify: `DATA_LICENSES.md`

**Interfaces:**
- Consumes: schema and behavior from Tasks 1-4.
- Produces: public documentation consistent with DuckLake schema.

- [ ] **Step 1: Invoke schema-doc sync skill**

Use the `readme-schema-sync` skill before editing docs because this task changes schema docs, README schema summary, `datasets` docs, and `cve_sources` columns.

Expected skill-specific checks: README schema summary and `docs/schema.md` stay consistent with `lake.py` DDL/views and storage keys.

- [ ] **Step 2: Update README dataset overview and examples**

In `README.md`, add Cloudflare WAF to the dataset table near other detection/exploitation signal datasets:

```markdown
| Cloudflare WAF ChangeLog | Vulnerability IDs mentioned in Cloudflare WAF managed-rules updates | `vlake.cloudflare_waf WHERE NOT removed` |
```

Update the “Most datasets are modeled as” latest-view list from:

```markdown
- a latest view (`cve`, `ghsa`, `exploitdb`, `nuclei`, `cwe`, `kev`) for normal queries
```

to:

```markdown
- a latest view (`cve`, `ghsa`, `exploitdb`, `nuclei`, `cwe`, `kev`, `cloudflare_waf`) for normal queries
```

Add a query example after the KEV/nuclei examples:

```markdown
### Check whether Cloudflare WAF ChangeLog mentions a vulnerability

```sql
SELECT identifier, source_title, source_url, source_date
FROM vlake.cloudflare_waf
WHERE identifier = 'CVE-2025-53770' AND NOT removed;
```
```

Update any `cve_sources` query columns to include:

```sql
  s.has_cloudflare_waf,
```

Add `uv run vlake update cloudflare_waf` to the update command list; do not add it to backfill examples.

Add the license summary row:

```markdown
| cloudflare_waf | [Cloudflare WAF ChangeLog](https://developers.cloudflare.com/waf/change-log/) | CC-BY-4.0; vulnerability identifiers extracted from Cloudflare Docs MDX and converted to Parquet |
```

- [ ] **Step 3: Update `docs/schema.md`**

In the top table, add:

```markdown
| `cloudflare_waf` | `cloudflare_waf_history` | vulnerability identifier × source URL | Vulnerability IDs mentioned in Cloudflare WAF ChangeLog entries |
```

In the `cve_sources` section, update the derived-from sentence:

```markdown
It is derived from `epss`, `cve`, `ghsa`, `exploitdb`, `nuclei`, `kev`, and `cloudflare_waf`.
```

Add columns:

```markdown
| `has_cloudflare_waf` | BOOLEAN | Whether `cloudflare_waf` has at least one currently-live WAF ChangeLog mention for the CVE |
| `cloudflare_waf_count` | BIGINT | Number of linked currently-live Cloudflare WAF ChangeLog mentions |
```

Add a new section before `datasets`:

```markdown
### `cloudflare_waf` / `cloudflare_waf_history` — Cloudflare WAF ChangeLog vulnerability mentions

Append-only history of vulnerability identifiers extracted from Cloudflare WAF ChangeLog MDX.
The `cloudflare_waf` view returns the latest row per `identifier + source_url`;
mentions that disappear upstream become **tombstones** (`removed = true`).

| Column | Type | Description |
|---|---|---|
| `identifier` | VARCHAR | Vulnerability identifier extracted from the ChangeLog, such as CVE or GHSA |
| `identifier_type` | VARCHAR | Identifier family (`CVE`, `GHSA`, `GO`, `PYSEC`, `RUSTSEC`) |
| `cve` | VARCHAR | Same as `identifier` for CVE rows, otherwise NULL |
| `source_title` | VARCHAR | ChangeLog entry title or historical table description |
| `source_url` | VARCHAR | Public Cloudflare Docs URL for the source ChangeLog entry/page |
| `source_date` | DATE | ChangeLog entry or historical table date, if available |
| `matched_text` | VARCHAR | Short text excerpt containing the identifier |
| `fetched_date` | DATE | Fetch date (also the view's latest-row key) |
| `removed` | BOOLEAN | Tombstone flag (`true` = mention disappeared upstream) |
```

In the Parquet storage layout table, add:

```markdown
| `cloudflare_waf` | *(none)* | `cloudflare_waf/updates/year=YYYY/cloudflare-waf-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full current ChangeLog identifier snapshot |
```

- [ ] **Step 4: Update `DATA_LICENSES.md`**

Append after KEV or near other CC-BY datasets:

```markdown
## Cloudflare WAF ChangeLog

- **Source:** https://developers.cloudflare.com/waf/change-log/
  (source MDX: https://github.com/cloudflare/cloudflare-docs)
- **License:** Creative Commons Attribution 4.0 International (SPDX: `CC-BY-4.0`)
  — https://creativecommons.org/licenses/by/4.0/
- **Modifications:** Cloudflare Docs WAF ChangeLog MDX files are parsed to extract
  vulnerability identifiers (CVE / GHSA / GO / PYSEC / RUSTSEC), source titles,
  source URLs, source dates, and short matched text excerpts, then converted to Parquet.
- **Attribution:** Cloudflare Docs WAF ChangeLog — Cloudflare
  (https://developers.cloudflare.com/waf/change-log/), licensed under CC-BY 4.0.
- **Disclaimer:** This project redistributes derived Cloudflare Docs metadata but is
  not endorsed or certified by Cloudflare.
```

- [ ] **Step 5: Run documentation consistency checks**

Run:

```bash
uv run pytest tests/test_llms_doc.py -v
```

Expected: PASS.

Run the check script if provided by `readme-schema-sync` skill. If the skill points to `.pi/skills/readme-schema-sync/scripts/check_readme_schema.py`, run:

```bash
python .pi/skills/readme-schema-sync/scripts/check_readme_schema.py
```

Expected: PASS or no mismatch output. If the script interface differs, follow the skill instructions exactly.

- [ ] **Step 6: Commit Task 5**

```bash
git add README.md docs/schema.md DATA_LICENSES.md
git commit -m "docs: Cloudflare WAFデータセットを公開ドキュメントに追加"
```

If the schema sync skill required updating other docs/tests, include those files in `git add`.

---

### Task 6: Full verification and final polish

**Files:**
- Potentially modify any file flagged by tests/lint.

**Interfaces:**
- Consumes all previous tasks.
- Produces a verified branch ready for review/PR.

- [ ] **Step 1: Run the full test suite**

Run:

```bash
uv run pytest -v
```

Expected: all tests PASS.

- [ ] **Step 2: Run lint and SAST gate**

Run:

```bash
mise run pre-commit
```

Expected:

```text
All checks passed!
35 files already formatted
No findings to report. Good job!
```

The exact formatted file count may differ after adding files; success exit code is required.

- [ ] **Step 3: If checks fail, fix and rerun the same command**

For a ruff formatting failure, run:

```bash
uv run ruff format .
mise run pre-commit
```

For a ruff lint failure, edit the flagged file, then run:

```bash
mise run pre-commit
```

For an actionlint/zizmor failure in `.github/workflows/publish.yml`, fix the YAML and rerun:

```bash
actionlint
uv run zizmor --no-progress .github/workflows/
mise run pre-commit
```

Do not report completion until `mise run pre-commit` succeeds.

- [ ] **Step 4: Commit final fixes if any**

If Step 3 changed files, commit them:

```bash
git add <changed-files>
git commit -m "chore: Cloudflare WAF追加の検証指摘を修正"
```

If no files changed, skip this commit.

- [ ] **Step 5: Summarize final state**

Run:

```bash
git status --short
git log --oneline -6
```

Expected: only unrelated pre-existing working-tree changes remain, and recent commits include the Cloudflare WAF task commits. Do not push; network git operations are restricted in this environment.

---

## Self-Review

**Spec coverage:**
- 脆弱性 ID 中心の `cloudflare_waf` view: Task 1 + Task 2.
- CVE/GHSA/GO/PYSEC/RUSTSEC 抽出: Task 1 tests and implementation.
- GitHub MDX 第一候補、historical/current 両対応: Task 1.
- backfill なし、初回 update 全量、差分・tombstone: Task 3.
- `cve_sources` の `has_cloudflare_waf` / `cloudflare_waf_count`: Task 2 + Task 3 tests + Task 5 docs.
- verify/rebuild/CLI/publish workflow: Tasks 3 and 4.
- README / `docs/schema.md` / `DATA_LICENSES.md`: Task 5.
- 公開順序の不変条件: Task 3 implementation calls `storage.put()` before `lake.add_file()` and `_publish_catalog()`.

**Placeholder scan:** No `TBD`, `TODO`, “implement later”, or unspecified “add tests” steps remain. Each code-changing step includes concrete code or exact edit instructions.

**Type consistency:** `cloudflare_waf_history`, `cloudflare_waf`, `cloudflare_waf_latest_rows()`, `refresh_cloudflare_waf_view()`, `update_cloudflare_waf()`, `has_cloudflare_waf`, and `cloudflare_waf_count` are used consistently across tasks.
