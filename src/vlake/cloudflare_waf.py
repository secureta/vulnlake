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
