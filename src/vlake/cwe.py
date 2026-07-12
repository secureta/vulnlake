"""CWE (Common Weakness Enumeration) データセット。

データ提供: The MITRE Corporation (https://cwe.mitre.org/)。CWE Terms of Use
(https://cwe.mitre.org/about/termsofuse.html) に基づき、帰属表示を条件に
複製・再配布が許諾される。cwec XML カタログの弱点・カテゴリ・ビューから
主要フィールドを抽出して Parquet に変換する (変更あり)。本プロジェクトは
MITRE の公認・認証を受けたものではない。
"""

from __future__ import annotations

import io
import zipfile
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
from defusedxml import ElementTree as DET

NAME = "cwe"

SCHEMA = pa.schema(
    [
        ("cwe_id", pa.string()),
        ("entry_type", pa.string()),
        ("name", pa.string()),
        ("abstraction", pa.string()),
        ("status", pa.string()),
        ("description", pa.string()),
        ("likelihood_of_exploit", pa.string()),
        (
            "relations",
            pa.list_(pa.struct([("nature", pa.string()), ("target_id", pa.string())])),
        ),
        ("cwe_version", pa.string()),
        ("release_date", pa.date32()),
    ]
)

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://cwe.mitre.org/data/downloads.html",
    "license_name": "CWE Terms of Use",
    "license_text": (
        "CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). "
        "Free to use, copy and redistribute with attribution. This dataset "
        "is a modified form of the cwec XML catalog: weaknesses, categories "
        "and views converted to Parquet with selected fields."
    ),
    "attribution": (
        "CWE — Common Weakness Enumeration, © The MITRE Corporation "
        "(https://cwe.mitre.org/)."
    ),
    "disclaimer": (
        "This project redistributes CWE content but is not endorsed or "
        "certified by The MITRE Corporation."
    ),
}

ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
LAST_MODIFIED_KEY = "cwe/last-modified.txt"

_NS = "{http://cwe.mitre.org/cwe-7}"


def fetch(prev_last_modified: str | None = None) -> tuple[bytes, str | None] | None:
    """cwec zip を条件付き GET で取得する。

    prev_last_modified があれば If-Modified-Since を付け、304 なら None を返す。
    条件付き GET は帯域最適化にすぎず、正しさは呼び出し側のバージョン判定が
    担保する。それ以外は (zip バイト列, Last-Modified ヘッダ値 or None)。
    """
    headers = {}
    if prev_last_modified:
        headers["If-Modified-Since"] = prev_last_modified
    resp = httpx.get(ZIP_URL, headers=headers, follow_redirects=True, timeout=600)
    if resp.status_code == 304:
        return None
    resp.raise_for_status()
    return resp.content, resp.headers.get("Last-Modified")


def _text(elem, tag: str) -> str | None:
    """直下の tag 要素の全テキスト (xhtml 含む) を空白正規化して返す。無ければ None。"""
    child = elem.find(f"{_NS}{tag}")
    if child is None:
        return None
    text = " ".join("".join(child.itertext()).split())
    return text or None


def _relations(container, member_tag: str, nature: str | None = None) -> list[dict]:
    """関係要素を {nature, target_id} のリストにする。

    同一 (Nature, CWE_ID) が View_ID 違いで重複するため出現順を保って畳む。
    nature を指定すると属性より優先する (Has_Member には Nature 属性が無い)。
    """
    if container is None:
        return []
    rels: list[dict] = []
    for el in container.iterfind(f"{_NS}{member_tag}"):
        rel = {
            "nature": nature or el.get("Nature"),
            "target_id": f"CWE-{el.get('CWE_ID')}",
        }
        if rel not in rels:
            rels.append(rel)
    return rels


def parse_catalog(zip_bytes: bytes) -> tuple[str, date, list[dict]]:
    """cwec zip をパースし (バージョン, リリース日, 全エントリ行) を返す。

    弱点・カテゴリ・ビューを entry_type で区別した行にする。Deprecated も
    status 付きでそのまま収録する (削除は status で表現され、行は消えない)。
    """
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".xml"))
        root = DET.fromstring(zf.read(name))
    version = root.get("Version")
    release = root.get("Date")
    if not version or not release:
        raise ValueError("Weakness_Catalog に Version / Date 属性がありません")
    release_date = date.fromisoformat(release)
    rows = []
    for w in root.iterfind(f"{_NS}Weaknesses/{_NS}Weakness"):
        rows.append(
            {
                "cwe_id": f"CWE-{w.get('ID')}",
                "entry_type": "weakness",
                "name": w.get("Name"),
                "abstraction": w.get("Abstraction"),
                "status": w.get("Status"),
                "description": _text(w, "Description"),
                "likelihood_of_exploit": _text(w, "Likelihood_Of_Exploit"),
                "relations": _relations(
                    w.find(f"{_NS}Related_Weaknesses"), "Related_Weakness"
                ),
            }
        )
    for c in root.iterfind(f"{_NS}Categories/{_NS}Category"):
        rows.append(
            {
                "cwe_id": f"CWE-{c.get('ID')}",
                "entry_type": "category",
                "name": c.get("Name"),
                "abstraction": None,
                "status": c.get("Status"),
                "description": _text(c, "Summary"),
                "likelihood_of_exploit": None,
                "relations": _relations(
                    c.find(f"{_NS}Relationships"), "Has_Member", nature="HasMember"
                ),
            }
        )
    for v in root.iterfind(f"{_NS}Views/{_NS}View"):
        rows.append(
            {
                "cwe_id": f"CWE-{v.get('ID')}",
                "entry_type": "view",
                "name": v.get("Name"),
                "abstraction": None,
                "status": v.get("Status"),
                "description": _text(v, "Objective"),
                "likelihood_of_exploit": None,
                "relations": _relations(
                    v.find(f"{_NS}Members"), "Has_Member", nature="HasMember"
                ),
            }
        )
    for row in rows:
        row["cwe_version"] = version
        row["release_date"] = release_date
    return version, release_date, rows


def key_for_version(version: str) -> str:
    """バージョン断面スナップショットのキー。"""
    return f"cwe/version={version}/cwe-{version}.parquet"


def rows_to_table(rows: list[dict]) -> pa.Table:
    """行リストを SCHEMA に従う PyArrow Table に変換し、entry_type, cwe_id 順にソートする。"""
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    return table.sort_by([("entry_type", "ascending"), ("cwe_id", "ascending")])


def write_parquet(table: pa.Table, path: Path) -> None:
    """PyArrow Table を Parquet ファイルに書き出す (zstd 圧縮)。"""
    pq.write_table(table, path, compression="zstd")
