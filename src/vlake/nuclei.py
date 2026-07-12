"""nuclei-templates データセット。

データ提供: ProjectDiscovery, Inc.
(https://github.com/projectdiscovery/nuclei-templates)。MIT License で提供される
テンプレート YAML の info ブロックのメタデータを Parquet に変換して再配布する
(変更あり)。テンプレート本文 (マッチャー・ペイロード) は再配布せず、各行は
template_url でテンプレートを参照する。本プロジェクトは ProjectDiscovery の
公認・認証を受けたものではない。
"""

from __future__ import annotations

import hashlib
import re
import tarfile
from collections.abc import Iterator
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

NAME = "nuclei"

SCHEMA = pa.schema(
    [
        ("template_id", pa.string()),
        ("name", pa.string()),
        ("severity", pa.string()),
        ("description", pa.string()),
        ("author", pa.list_(pa.string())),
        ("tags", pa.list_(pa.string())),
        ("reference", pa.list_(pa.string())),
        ("cve", pa.list_(pa.string())),
        ("cwe", pa.list_(pa.string())),
        ("cvss_score", pa.float64()),
        ("cvss_metrics", pa.string()),
        ("epss_score", pa.float64()),
        ("epss_percentile", pa.float64()),
        ("cpe", pa.string()),
        ("vendor", pa.string()),
        ("product", pa.string()),
        ("verified", pa.bool_()),
        ("type", pa.string()),
        ("file", pa.string()),
        ("template_url", pa.string()),
        ("digest", pa.string()),
        ("fetched_date", pa.date32()),
        ("removed", pa.bool_()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://github.com/projectdiscovery/nuclei-templates",
    "license_name": "MIT",
    "license_text": (
        "MIT License (https://opensource.org/license/mit). "
        "This dataset is a modified form of the nuclei-templates repository: "
        "template info-block metadata extracted from YAML and converted to "
        "Parquet. Template bodies (matchers/payloads) are not redistributed; "
        "each row links to the template via template_url."
    ),
    "attribution": (
        "nuclei-templates — © ProjectDiscovery, Inc. "
        "(https://github.com/projectdiscovery/nuclei-templates), "
        "licensed under the MIT License."
    ),
    "disclaimer": (
        "This project redistributes nuclei-templates metadata but is not "
        "endorsed or certified by ProjectDiscovery, Inc."
    ),
}

TARBALL_URL = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/main"
_BLOB_URL = "https://github.com/projectdiscovery/nuclei-templates/blob/main/{}"
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
# libyaml があれば C 実装の safe ローダを使う (フォールバックは pure-Python)
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
# ProjectDiscovery の署名行。再署名だけの変更を差分にしないため digest 計算から除く
_SIGNATURE_RE = re.compile(rb"^# digest:.*\n?", re.MULTILINE)
# テンプレートを含まないディレクトリ (リポジトリ相対)
_EXCLUDE_PREFIXES = (".github/", "helpers/", "profiles/")
# YAML トップレベルキー → type の正規化 (先勝ち)。requests/tcp は旧形式の別名
_TYPE_KEYS = (
    ("http", "http"),
    ("requests", "http"),
    ("network", "network"),
    ("tcp", "network"),
    ("dns", "dns"),
    ("file", "file"),
    ("headless", "headless"),
    ("ssl", "ssl"),
    ("websocket", "websocket"),
    ("whois", "whois"),
    ("code", "code"),
    ("javascript", "javascript"),
    ("workflows", "workflows"),
)


def content_digest(raw: bytes) -> str:
    """署名行 (# digest: ...) を除いた内容の SHA-256 (hex)。"""
    return hashlib.sha256(_SIGNATURE_RE.sub(b"", raw)).hexdigest()


def _strlist(value) -> list[str]:
    """カンマ区切り文字列 / リスト / None を文字列リストに正規化する。"""
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = [str(v) for v in value]
    else:
        return []
    return [s for v in items if (s := v.strip())]


def _float(value) -> float | None:
    """数値または数値文字列を float にする。それ以外は None。"""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _str(value) -> str | None:
    """空でない文字列のみ通す (数値等は文字列化しない)。"""
    return value if isinstance(value, str) and value else None


def _template_type(doc: dict) -> str | None:
    """トップレベルキーからプロトコル種別を判定する。不明なら None。"""
    for key, name in _TYPE_KEYS:
        if key in doc:
            return name
    return None


def parse_template(relpath: str, raw: bytes) -> dict | None:
    """テンプレート YAML 1件を SCHEMA の行 dict にする。

    fetched_date / removed は含まない (pipeline が実行日で付与する)。
    パース不能・トップレベル id / info 欠落は None (非テンプレート YAML)。
    """
    try:
        # safe 系ローダのみ使用 (libyaml があれば C 実装で ~1.2万ファイル/日を高速化)
        doc = yaml.load(raw, Loader=_LOADER)  # noqa: S506
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    template_id = doc.get("id")
    info = doc.get("info")
    if (
        not isinstance(template_id, str)
        or not template_id
        or not isinstance(info, dict)
    ):
        return None
    cls = info.get("classification")
    if not isinstance(cls, dict):
        cls = {}
    meta = info.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    cve = [c for v in _strlist(cls.get("cve-id")) if _CVE_RE.fullmatch(c := v.upper())]
    return {
        "template_id": template_id,
        "name": _str(info.get("name")),
        "severity": _str(info.get("severity")),
        "description": _str(info.get("description")),
        "author": _strlist(info.get("author")),
        "tags": _strlist(info.get("tags")),
        "reference": _strlist(info.get("reference")),
        "cve": cve,
        "cwe": [c.upper() for c in _strlist(cls.get("cwe-id"))],
        "cvss_score": _float(cls.get("cvss-score")),
        "cvss_metrics": _str(cls.get("cvss-metrics")),
        "epss_score": _float(cls.get("epss-score")),
        "epss_percentile": _float(cls.get("epss-percentile")),
        "cpe": _str(cls.get("cpe")),
        "vendor": _str(meta.get("vendor")),
        "product": _str(meta.get("product")),
        "verified": meta.get("verified") is True,
        "type": _template_type(doc),
        "file": relpath,
        "template_url": _BLOB_URL.format(relpath),
        "digest": content_digest(raw),
    }


def iter_templates(tar_path: Path) -> Iterator[tuple[str, bytes]]:
    """tarball 内のテンプレート候補 YAML を (相対パス, 内容) で逐次 yield する。

    ストリーミングモード ("r|gz") で逐次読みし、top dir を除いた相対パスで
    _EXCLUDE_PREFIXES 配下と非 YAML はエントリ名だけ見て読み飛ばす (展開しない)。
    """
    with tarfile.open(tar_path, "r|gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            _, _, relpath = member.name.partition("/")
            if not relpath or relpath.startswith(_EXCLUDE_PREFIXES):
                continue
            if not relpath.endswith((".yaml", ".yml")):
                continue
            f = tf.extractfile(member)
            if f is not None:
                yield relpath, f.read()


def rows_to_table(rows: list[dict]) -> pa.Table:
    """行リストを SCHEMA に従う PyArrow Table に変換し、template_id で昇順ソートする。"""
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("template_id", "ascending")])


def key_for_update(d: date) -> str:
    """実行日 d の日次差分ファイルのキー (初回は全量が載る)。"""
    return f"nuclei/updates/year={d.year}/nuclei-updates-{d.isoformat()}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    """PyArrow Table を Parquet ファイルに書き出す (zstd 圧縮)。"""
    pq.write_table(table, path, compression="zstd")


def download(url: str, dest: Path) -> None:
    """リポジトリ tarball をストリーミングでダウンロードする。"""
    with httpx.stream("GET", url, follow_redirects=True, timeout=600) as resp:
        resp.raise_for_status()
        with dest.open("wb") as f:
            for chunk in resp.iter_bytes():
                f.write(chunk)
