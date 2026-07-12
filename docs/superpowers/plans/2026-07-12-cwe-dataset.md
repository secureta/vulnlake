# CWE データセット追加 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** MITRE の cwec XML カタログをバージョン断面スナップショットとして DuckLake に追加し、CVE / GHSA / nuclei の `cwe VARCHAR[]` 列をレイク内で解決できるようにする。

**Architecture:** 既存の「1 データセット = 1 モジュール + history テーブル + latest ビュー」パターンに従う。弱点・カテゴリ・ビューを 1 テーブル (`cwe_history`) に `entry_type` で区別して収め、`cwe` ビューは `release_date` 最大の断面を返す。update は前回成功時の `Last-Modified` による条件付き GET (304 → 即終了) → XML の `Version` でバージョン断面キーを決定 → 登録済みなら skip → 新バージョンのみ全件追記。backfill は提供しない (初回 update が全量投入)。

**Tech Stack:** Python >= 3.14, httpx, defusedxml (新規依存), PyArrow, DuckDB/DuckLake, click, pytest

**Spec:** `docs/superpowers/specs/2026-07-12-cwe-design.md`

## Global Constraints

- コード内のコメント・docstring・コミットメッセージは日本語
- 公開順序の不変条件: Parquet アップロード → カタログ登録 → カタログ公開が最後。この順序を崩さない
- `cwe/last-modified.txt` の更新は **カタログ公開成功後のみ** (途中失敗時は次回が無条件 GET からやり直す冪等回復)
- ruff (bandit 有効): stdlib `xml.etree` での**パースは** B31x で弾かれるため defusedxml を使う。動的 SQL には既存同様 `# noqa: S608` + 理由コメント
- defusedxml はレジストリ最新安定版を使う (`uv add defusedxml` が解決する。バージョン手書き禁止)
- 名称: パッケージ/CLI/env は `vlake`。「vulnlake との不統一」としてリネームしない
- テストはネットワークに出ない (`cwe.fetch` を monkeypatch / httpx を偽装)
- 検証コマンド: `uv run pytest -v`, `uv run ruff check .`, `uv run ruff format .`

## 実 XML の検証済み事実 (2026-07-12 に cwec_v4.20 で確認)

- ルート: `<Weakness_Catalog Name="CWE" Version="4.20" Date="2026-04-30" xmlns="http://cwe.mitre.org/cwe-7" ...>`
- 子: `Weaknesses` (969 件) / `Categories` (422 件) / `Views` (59 件)
- Weakness 属性: `ID`, `Name`, `Abstraction` (Pillar/Class/Base/Variant等), `Structure`, `Status` (Stable/Draft/Incomplete/Deprecated)。子に `Description`, `Related_Weaknesses/Related_Weakness[@Nature,@CWE_ID,@View_ID]`, `Likelihood_Of_Exploit` (テキスト、省略可)
- **同一 (Nature, CWE_ID) が View_ID 違いで重複する** (例: CWE-79 は ChildOf 74 が view 1000/1003 の 2 回) → dedupe 必須
- Nature の値域: CanAlsoBe, CanPrecede, ChildOf, PeerOf, Requires, StartsWith
- Category 属性: `ID`, `Name`, `Status`。子に `Summary`, `Relationships/Has_Member[@CWE_ID,@View_ID]`
- View 属性: `ID`, `Name`, `Type`, `Status`。子に `Objective`, `Members/Has_Member[@CWE_ID,@View_ID]`
- Deprecated エントリは Weakness/Category 双方に存在し `Status="Deprecated"` で残る
- HTTP: サーバーは ETag を返さない。`Last-Modified` を返し、`If-Modified-Since` に 304 で応答する

---

### Task 1: cwe.py モジュール (fetch / parse / キー命名) + conftest フィクスチャ

**Files:**
- Create: `src/vlake/cwe.py`
- Create: `tests/test_cwe.py`
- Modify: `tests/conftest.py` (末尾に追記)
- Modify: `pyproject.toml` (`uv add defusedxml` 経由)

**Interfaces:**
- Produces: `cwe.NAME = "cwe"`, `cwe.SCHEMA` (PyArrow schema), `cwe.LICENSE_INFO` (dict), `cwe.ZIP_URL`, `cwe.LAST_MODIFIED_KEY = "cwe/last-modified.txt"`, `cwe.fetch(prev_last_modified: str | None) -> tuple[bytes, str | None] | None`, `cwe.parse_catalog(zip_bytes: bytes) -> tuple[str, date, list[dict]]`, `cwe.key_for_version(version: str) -> str`, `cwe.rows_to_table(rows: list[dict]) -> pa.Table`, `cwe.write_parquet(table, path) -> None`
- conftest: `make_cwe_xml_zip(*, version="4.20", date_str="2026-04-30", weaknesses=None, categories=None, views=None) -> bytes` (デフォルトで弱点 3 件 [CWE-79, CWE-74, Deprecated の CWE-1187] + カテゴリ 1 件 [CWE-137] + ビュー 1 件 [CWE-1000] = 5 行)

- [ ] **Step 1: defusedxml を依存に追加**

```bash
uv add defusedxml
```

Expected: pyproject.toml の dependencies に defusedxml が追加される (バージョンはレジストリ解決)。

- [ ] **Step 2: conftest.py にフィクスチャ生成関数を追記**

`tests/conftest.py` の import に `from xml.sax.saxutils import escape` を追加し、末尾に追記:

```python
def _cwe_attr(value: str) -> str:
    """XML 属性値用エスケープ (ダブルクォート含む)。"""
    return escape(value, {'"': "&quot;"})


def _cwe_weakness_xml(w: dict) -> str:
    rels = "".join(
        f'<Related_Weakness Nature="{n}" CWE_ID="{cid}" View_ID="{vid}"/>'
        for n, cid, vid in w.get("relations", ())
    )
    related = f"<Related_Weaknesses>{rels}</Related_Weaknesses>" if rels else ""
    likelihood = (
        f"<Likelihood_Of_Exploit>{w['likelihood']}</Likelihood_Of_Exploit>"
        if w.get("likelihood")
        else ""
    )
    return (
        f'<Weakness ID="{w["id"]}" Name="{_cwe_attr(w.get("name", "Weakness"))}" '
        f'Abstraction="{w.get("abstraction", "Base")}" Structure="Simple" '
        f'Status="{w.get("status", "Stable")}">'
        f"<Description>{escape(w.get('description', 'A sample weakness.'))}</Description>"
        f"{related}{likelihood}</Weakness>"
    )


def _cwe_category_xml(c: dict) -> str:
    members = "".join(
        f'<Has_Member CWE_ID="{cid}" View_ID="{c["id"]}"/>'
        for cid in c.get("members", ())
    )
    relationships = f"<Relationships>{members}</Relationships>" if members else ""
    return (
        f'<Category ID="{c["id"]}" Name="{_cwe_attr(c.get("name", "Category"))}" '
        f'Status="{c.get("status", "Draft")}">'
        f"<Summary>{escape(c.get('summary', 'A sample category.'))}</Summary>"
        f"{relationships}</Category>"
    )


def _cwe_view_xml(v: dict) -> str:
    members = "".join(
        f'<Has_Member CWE_ID="{cid}" View_ID="{v["id"]}"/>'
        for cid in v.get("members", ())
    )
    members_block = f"<Members>{members}</Members>" if members else ""
    return (
        f'<View ID="{v["id"]}" Name="{_cwe_attr(v.get("name", "View"))}" '
        f'Type="Graph" Status="{v.get("status", "Draft")}">'
        f"<Objective>{escape(v.get('objective', 'A sample view.'))}</Objective>"
        f"{members_block}</View>"
    )


def make_cwe_xml_zip(
    *,
    version: str = "4.20",
    date_str: str = "2026-04-30",
    weaknesses: list[dict] | None = None,
    categories: list[dict] | None = None,
    views: list[dict] | None = None,
) -> bytes:
    """実フォーマットを模した cwec XML zip を作る。

    デフォルトは弱点3件 (CWE-79 / CWE-74 / Deprecated の CWE-1187) +
    カテゴリ1件 (CWE-137) + ビュー1件 (CWE-1000) = 5 エントリ。
    CWE-79 の ChildOf 74 は実データ同様 View_ID 違いで重複させてある
    (パーサの dedupe を検証するため)。
    """
    if weaknesses is None:
        weaknesses = [
            {
                "id": "79",
                "name": (
                    "Improper Neutralization of Input During Web Page "
                    "Generation ('Cross-site Scripting')"
                ),
                "abstraction": "Base",
                "status": "Stable",
                "description": (
                    "The product does not neutralize user-controllable input "
                    "before it is placed in output used as a web page."
                ),
                "likelihood": "High",
                "relations": [
                    ("ChildOf", "74", "1000"),
                    ("ChildOf", "74", "1003"),
                    ("PeerOf", "352", "1000"),
                ],
            },
            {
                "id": "74",
                "name": (
                    "Improper Neutralization of Special Elements in Output "
                    "Used by a Downstream Component ('Injection')"
                ),
                "abstraction": "Class",
                "status": "Draft",
                "description": "A sample injection class weakness.",
                "relations": [("ChildOf", "707", "1000")],
            },
            {
                "id": "1187",
                "name": "DEPRECATED: Use of Uninitialized Resource",
                "abstraction": "Base",
                "status": "Deprecated",
                "description": (
                    "This entry has been deprecated because it was a "
                    "duplicate of CWE-908."
                ),
            },
        ]
    if categories is None:
        categories = [
            {
                "id": "137",
                "name": "Data Neutralization Issues",
                "status": "Draft",
                "summary": (
                    "Weaknesses in this category are related to the creation "
                    "or neutralization of data using an incorrect format."
                ),
                "members": ["74", "79"],
            }
        ]
    if views is None:
        views = [
            {
                "id": "1000",
                "name": "Research Concepts",
                "status": "Draft",
                "objective": (
                    "This view is intended to facilitate research into "
                    "weaknesses."
                ),
                "members": ["74"],
            }
        ]
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Weakness_Catalog Name="CWE" Version="{version}" Date="{date_str}" '
        'xmlns="http://cwe.mitre.org/cwe-7" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">'
        f"<Weaknesses>{''.join(_cwe_weakness_xml(w) for w in weaknesses)}</Weaknesses>"
        f"<Categories>{''.join(_cwe_category_xml(c) for c in categories)}</Categories>"
        f"<Views>{''.join(_cwe_view_xml(v) for v in views)}</Views>"
        "</Weakness_Catalog>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"cwec_v{version}.xml", xml)
    return buf.getvalue()
```

- [ ] **Step 3: 失敗するテストを書く**

`tests/test_cwe.py` を新規作成:

```python
from datetime import date

from tests.conftest import make_cwe_xml_zip
from vlake import cwe


def test_parse_catalog_weakness():
    version, release_date, rows = cwe.parse_catalog(make_cwe_xml_zip())
    assert version == "4.20"
    assert release_date == date(2026, 4, 30)
    assert len(rows) == 5
    by_id = {r["cwe_id"]: r for r in rows}
    w = by_id["CWE-79"]
    assert w["entry_type"] == "weakness"
    assert w["name"].startswith("Improper Neutralization of Input")
    assert w["abstraction"] == "Base"
    assert w["status"] == "Stable"
    assert w["likelihood_of_exploit"] == "High"
    assert w["description"].startswith("The product does not neutralize")
    # View_ID 違いの重複 (ChildOf 74 が view 1000/1003) は1件に畳む
    assert w["relations"] == [
        {"nature": "ChildOf", "target_id": "CWE-74"},
        {"nature": "PeerOf", "target_id": "CWE-352"},
    ]
    assert w["cwe_version"] == "4.20"
    assert w["release_date"] == date(2026, 4, 30)


def test_parse_catalog_category_and_view():
    _, _, rows = cwe.parse_catalog(make_cwe_xml_zip())
    by_id = {r["cwe_id"]: r for r in rows}
    cat = by_id["CWE-137"]
    assert cat["entry_type"] == "category"
    assert cat["abstraction"] is None
    assert cat["description"].startswith("Weaknesses in this category")
    assert cat["relations"] == [
        {"nature": "HasMember", "target_id": "CWE-74"},
        {"nature": "HasMember", "target_id": "CWE-79"},
    ]
    view = by_id["CWE-1000"]
    assert view["entry_type"] == "view"
    assert view["name"] == "Research Concepts"
    assert view["description"].startswith("This view is intended")
    assert view["relations"] == [{"nature": "HasMember", "target_id": "CWE-74"}]


def test_parse_catalog_keeps_deprecated():
    # 削除は行の消滅ではなく Status="Deprecated" で表現される (トゥームストーン不要の根拠)
    _, _, rows = cwe.parse_catalog(make_cwe_xml_zip())
    dep = next(r for r in rows if r["cwe_id"] == "CWE-1187")
    assert dep["status"] == "Deprecated"
    assert dep["relations"] == []


def test_key_for_version():
    assert cwe.key_for_version("4.20") == "cwe/version=4.20/cwe-4.20.parquet"


def test_rows_to_table_matches_schema():
    _, _, rows = cwe.parse_catalog(make_cwe_xml_zip())
    table = cwe.rows_to_table(rows)
    assert table.num_rows == 5
    assert table.schema.equals(cwe.SCHEMA)


class _FakeResponse:
    def __init__(self, status_code, content=b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    def raise_for_status(self):
        assert self.status_code < 400


def test_fetch_returns_none_on_304(monkeypatch):
    seen = {}

    def fake_get(url, headers=None, **kwargs):
        seen["headers"] = headers
        return _FakeResponse(304)

    monkeypatch.setattr(cwe.httpx, "get", fake_get)
    assert cwe.fetch("Thu, 30 Apr 2026 09:15:04 GMT") is None
    assert seen["headers"]["If-Modified-Since"] == "Thu, 30 Apr 2026 09:15:04 GMT"


def test_fetch_unconditional_without_previous(monkeypatch):
    def fake_get(url, headers=None, **kwargs):
        assert "If-Modified-Since" not in (headers or {})
        return _FakeResponse(
            200, b"zipbytes", {"Last-Modified": "Fri, 01 May 2026 00:00:00 GMT"}
        )

    monkeypatch.setattr(cwe.httpx, "get", fake_get)
    assert cwe.fetch(None) == (b"zipbytes", "Fri, 01 May 2026 00:00:00 GMT")
```

- [ ] **Step 4: テストが失敗することを確認**

Run: `uv run pytest tests/test_cwe.py -v`
Expected: FAIL — `ImportError: cannot import name 'cwe'` (または ModuleNotFoundError)

- [ ] **Step 5: src/vlake/cwe.py を実装**

```python
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
```

- [ ] **Step 6: テストが通ることを確認**

Run: `uv run pytest tests/test_cwe.py -v`
Expected: 7 passed

- [ ] **Step 7: lint と全テスト**

Run: `uv run ruff check . && uv run ruff format . && uv run pytest -v`
Expected: エラーなし、既存テストも全通過

- [ ] **Step 8: コミット**

```bash
git add pyproject.toml uv.lock src/vlake/cwe.py tests/test_cwe.py tests/conftest.py
git commit -m "feat: cwe モジュールを追加 (cwec XML のパースと条件付き GET)"
```

---

### Task 2: lake.py — cwe_history テーブルと latest ビュー

**Files:**
- Modify: `src/vlake/lake.py` (`ensure_tables` 末尾にテーブル追加、`refresh_nuclei_view` の後にメソッド追加)
- Modify: `tests/test_lake.py` (末尾に追記)

**Interfaces:**
- Consumes: Task 1 の SCHEMA と同構造 (列名・型を一致させる)
- Produces: `Lake.ensure_tables()` が `cwe_history` を作る。`Lake.refresh_cwe_view() -> None`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_lake.py` の末尾に追記:

```python
def test_cwe_view_returns_latest_snapshot(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cwe_history "  # noqa: S608
            "(cwe_id, entry_type, cwe_version, release_date) VALUES "
            "('CWE-79', 'weakness', '4.9', DATE '2025-11-19'), "
            "('CWE-79', 'weakness', '4.20', DATE '2026-04-30'), "
            "('CWE-9999', 'weakness', '4.9', DATE '2025-11-19')"
        )
        lake.refresh_cwe_view()
        # 文字列比較では '4.9' > '4.20' になるが、release_date 最大の断面が返る
        got = lake.query("SELECT cwe_id, cwe_version FROM lake.cwe")
        assert got == [("CWE-79", "4.20")]
    finally:
        lake.close()
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_lake.py::test_cwe_view_returns_latest_snapshot -v`
Expected: FAIL — cwe_history テーブルが存在しない (Catalog Error)

- [ ] **Step 3: lake.py を実装**

`ensure_tables()` の nuclei_history 定義の直後に追加:

```python
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.cwe_history (
                cwe_id VARCHAR,
                entry_type VARCHAR,
                name VARCHAR,
                abstraction VARCHAR,
                status VARCHAR,
                description VARCHAR,
                likelihood_of_exploit VARCHAR,
                relations STRUCT(nature VARCHAR, target_id VARCHAR)[],
                cwe_version VARCHAR,
                release_date DATE
            )"""
        )
```

`refresh_nuclei_view()` の直後にメソッド追加:

```python
    def refresh_cwe_view(self) -> None:
        """release_date 最大のバージョン断面 (全エントリ) を返す view。

        cwe_version の文字列比較は '4.9' > '4.20' となるため使わない。
        """
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.cwe AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.cwe_history WHERE release_date = "
            f"(SELECT max(release_date) FROM {self.ALIAS}.cwe_history)"
        )
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_lake.py -v`
Expected: 全 passed

- [ ] **Step 5: lint とコミット**

```bash
uv run ruff check . && uv run ruff format .
git add src/vlake/lake.py tests/test_lake.py
git commit -m "feat: lake に cwe_history テーブルと latest 断面ビューを追加"
```

---

### Task 3: pipeline.update_cwe (条件付き GET + バージョン断面 append)

**Files:**
- Modify: `src/vlake/pipeline.py` (import、`_publish_catalog`、`update_nuclei` の後に `update_cwe` 追加)
- Create: `tests/test_pipeline_cwe.py`
- Modify: `tests/test_pipeline_nuclei.py:82` (datasets ビューの期待集合に "cwe" を追加)

**Interfaces:**
- Consumes: Task 1 の `cwe.fetch` / `cwe.parse_catalog` / `cwe.key_for_version` / `cwe.rows_to_table` / `cwe.write_parquet` / `cwe.LAST_MODIFIED_KEY` / `cwe.LICENSE_INFO`、Task 2 の `lake.refresh_cwe_view`
- Produces: `pipeline.update_cwe(cfg: Config) -> str`。戻り値は `"not-modified"` / `"already-registered <ver>"` / `"published <ver> (<n> records)"`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_pipeline_cwe.py` を新規作成:

```python
from datetime import date

import duckdb
import pytest

from tests.conftest import make_cwe_xml_zip
from vlake import cwe, pipeline
from vlake.config import Config

LM1 = "Thu, 30 Apr 2026 09:15:04 GMT"
LM2 = "Fri, 30 Oct 2026 09:00:00 GMT"


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


def _patch_fetch(monkeypatch, zip_bytes, last_modified):
    """cwe.fetch を偽装し、渡された prev_last_modified の記録を返す。

    zip_bytes=None は 304 (not-modified) を意味する。
    """
    calls = []

    def fake_fetch(prev_last_modified=None):
        calls.append(prev_last_modified)
        if zip_bytes is None:
            return None
        return zip_bytes, last_modified

    monkeypatch.setattr(cwe, "fetch", fake_fetch)
    return calls


def test_update_cwe_initial_full_load(cfg, monkeypatch):
    # backfill は存在しない: カタログが空でも初回 update が全量投入になる
    calls = _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    msg = pipeline.update_cwe(cfg)
    assert msg == "published 4.20 (5 records)"
    assert calls == [None]  # 初回は Last-Modified 未保存なので無条件 GET
    assert (cfg.local_dir / "cwe" / "version=4.20" / "cwe-4.20.parquet").exists()
    # Last-Modified はカタログ公開成功後に保存される
    assert (cfg.local_dir / "cwe" / "last-modified.txt").read_text().strip() == LM1

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5
    abstraction, status = con.execute(
        "SELECT abstraction, status FROM frozen.cwe WHERE cwe_id = 'CWE-79'"
    ).fetchone()
    assert (abstraction, status) == ("Base", "Stable")
    # 既存テーブルの cwe VARCHAR[] 列との JOIN を想定した relations 構造
    kids = con.execute(
        "SELECT r.target_id FROM frozen.cwe, UNNEST(relations) AS t(r) "
        "WHERE cwe_id = 'CWE-79' AND r.nature = 'ChildOf'"
    ).fetchall()
    assert kids == [("CWE-74",)]
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert "cwe" in names


def test_update_cwe_not_modified_short_circuits(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    calls = _patch_fetch(monkeypatch, None, None)
    assert pipeline.update_cwe(cfg) == "not-modified"
    assert calls == [LM1]  # 保存済み Last-Modified が条件付き GET に渡る


def test_update_cwe_same_version_already_registered(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    # Last-Modified だけ変わりバージョンが同じ (再アップロード等) 場合は登録済み skip
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM2)
    assert pipeline.update_cwe(cfg) == "already-registered 4.20"
    # 以後の再ダウンロードを避けるため新しい Last-Modified を保存する
    assert (cfg.local_dir / "cwe" / "last-modified.txt").read_text().strip() == LM2

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5


def test_update_cwe_new_version_switches_view(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    _patch_fetch(
        monkeypatch, make_cwe_xml_zip(version="4.21", date_str="2026-10-30"), LM2
    )
    assert pipeline.update_cwe(cfg) == "published 4.21 (5 records)"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 10
    assert con.execute(
        "SELECT DISTINCT cwe_version FROM frozen.cwe"
    ).fetchall() == [("4.21",)]
    assert con.execute(
        "SELECT max(release_date) FROM frozen.cwe"
    ).fetchone()[0] == date(2026, 10, 30)


def test_update_cwe_failure_does_not_save_last_modified(cfg, monkeypatch):
    # 公開前に失敗したら Last-Modified は保存されず、次回は無条件 GET からやり直す
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)

    def boom(table, path):
        raise RuntimeError("boom")

    monkeypatch.setattr(cwe, "write_parquet", boom)
    with pytest.raises(RuntimeError, match="boom"):
        pipeline.update_cwe(cfg)
    assert not (cfg.local_dir / "cwe" / "last-modified.txt").exists()
    assert not (cfg.local_dir / "vlake.ducklake").exists()  # カタログ未公開
```

- [ ] **Step 2: test_pipeline_nuclei.py の datasets 期待集合を更新**

`tests/test_pipeline_nuclei.py` の 82 行目を変更:

```python
    assert names == {"epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe"}
```

- [ ] **Step 3: テストが失敗することを確認**

Run: `uv run pytest tests/test_pipeline_cwe.py tests/test_pipeline_nuclei.py -v`
Expected: test_pipeline_cwe は AttributeError (update_cwe が無い)、test_update_nuclei_initial_full_load は datasets 集合の不一致で FAIL

- [ ] **Step 4: pipeline.py を実装**

import 行を変更:

```python
from . import cvelist, cwe, epss, exploitdb, ghsa, nuclei
```

`_publish_catalog` の infos リスト末尾に `cwe.LICENSE_INFO` を、ビュー再生成に `lake.refresh_cwe_view()` を追加:

```python
def _publish_catalog(storage: Storage, lake: Lake, catalog: Path) -> None:
    lake.refresh_datasets_view(
        [
            epss.LICENSE_INFO,
            cvelist.LICENSE_INFO,
            ghsa.LICENSE_INFO,
            exploitdb.LICENSE_INFO,
            nuclei.LICENSE_INFO,
            cwe.LICENSE_INFO,
        ]
    )
    lake.refresh_cve_view()
    lake.refresh_ghsa_view()
    lake.refresh_exploitdb_view()
    lake.refresh_nuclei_view()
    lake.refresh_cwe_view()
    lake.close()
    storage.put(catalog, CATALOG_KEY)
```

`update_nuclei` の直後に追加:

```python
def update_cwe(cfg: Config) -> str:
    """cwec XML の新バージョン断面を全件スナップショットとして追記する。

    CWE は年数回しか更新されないため、前回成功時の Last-Modified による
    条件付き GET (304 なら即終了、レイクも開かない) で日次実行の無駄な
    ダウンロードを避ける。Last-Modified の保存はカタログ公開成功後のみ
    行い、途中失敗時は次回が無条件 GET からやり直す (冪等回復)。
    カタログが空なら初回 update が全量投入となるため backfill は存在しない。
    削除はカタログ側の Status=Deprecated で表現されるためトゥームストーンも
    不要。
    """
    storage = make_storage(cfg)
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        lm_path = workdir / "last-modified.txt"
        prev_lm = None
        if storage.get(cwe.LAST_MODIFIED_KEY, lm_path):
            prev_lm = lm_path.read_text().strip() or None
        fetched = cwe.fetch(prev_lm)
        if fetched is None:
            return "not-modified"
        raw_zip, last_modified = fetched
        version, _, rows = cwe.parse_catalog(raw_zip)
        key = cwe.key_for_version(version)
        lake, catalog = _open_lake(storage, workdir)
        try:
            if storage.url(key) in lake.registered_paths():
                result = f"already-registered {version}"
            else:
                parquet = workdir / "snapshot.parquet"
                cwe.write_parquet(cwe.rows_to_table(rows), parquet)
                storage.put(parquet, key)
                lake.set_message(f"cwe {version} ({len(rows)} records)")
                lake.add_file("cwe_history", storage.url(key))
                _publish_catalog(storage, lake, catalog)
                result = f"published {version} ({len(rows)} records)"
        finally:
            lake.close()
        if last_modified:
            lm_path.write_text(last_modified + "\n")
            storage.put(lm_path, cwe.LAST_MODIFIED_KEY)
    return result
```

- [ ] **Step 5: テストが通ることを確認**

Run: `uv run pytest tests/test_pipeline_cwe.py tests/test_pipeline_nuclei.py -v`
Expected: 全 passed

- [ ] **Step 6: 全テストと lint**

Run: `uv run pytest -v && uv run ruff check . && uv run ruff format .`
Expected: 全 passed、lint エラーなし

- [ ] **Step 7: コミット**

```bash
git add src/vlake/pipeline.py tests/test_pipeline_cwe.py tests/test_pipeline_nuclei.py
git commit -m "feat: pipeline に update_cwe を追加 (Last-Modified 条件付き GET・バージョン断面 append)"
```

---

### Task 4: verify / rebuild-catalog の CWE 対応 (鮮度チェック除外)

**Files:**
- Modify: `src/vlake/pipeline.py` (`rebuild_catalog` の tables、`verify` の reports、正規表現定数)
- Modify: `tests/test_pipeline_cwe.py` (末尾に追記)

**Interfaces:**
- Consumes: 既存 `_verify_history` (シグネチャ変更なし)
- Produces: `verify()` の戻り値 `datasets` に `"cwe"` キーが加わる。CWE は `stale` が常に False

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_pipeline_cwe.py` の末尾に追記:

```python
def test_verify_covers_cwe_and_excludes_from_staleness(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)  # release_date 2026-04-30
    pipeline.update_cwe(cfg)

    # release_date が数ヶ月前でも CWE は鮮度チェックの対象外 (更新が無いのが正常)
    report = pipeline.verify(cfg, max_age_days=3)
    assert report["ok"] is True
    assert report["stale"] is False
    rep = report["datasets"]["cwe"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 5
    assert rep["max_date"] == date(2026, 4, 30)
    assert rep["stale"] is False


def test_verify_detects_cwe_stray_file(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    stray = cfg.local_dir / "cwe" / "version=9.99" / "cwe-9.99.parquet"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["cwe"]["ok"] is False


def test_verify_ignores_last_modified_marker(cfg, monkeypatch):
    # cwe/last-modified.txt は Parquet ではないので整合検査の対象にならない
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    assert (cfg.local_dir / "cwe" / "last-modified.txt").exists()
    assert pipeline.verify(cfg)["ok"] is True


def test_rebuild_catalog_covers_cwe(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5
    assert con.execute("SELECT count(*) FROM frozen.cwe").fetchone()[0] == 5
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_pipeline_cwe.py -v -k "verify or rebuild"`
Expected: FAIL — `report["datasets"]["cwe"]` が KeyError / rebuild は cwe/ をルーティングできず "refused: no parquet files in storage" を返す

- [ ] **Step 3: pipeline.py を実装**

`rebuild_catalog` の tables に追加:

```python
    tables = {
        "epss/": "epss",
        "cve/": "cve_history",
        "ghsa/": "ghsa_history",
        "exploitdb/": "exploitdb_history",
        "nuclei/": "nuclei_history",
        "cwe/": "cwe_history",
    }
```

`_NUCLEI_UPDATE_KEY_DATE` の直後に定数追加:

```python
# cwe のキーはバージョン断面 (cwe/version=<ver>/) で日付を含まないため常に不一致。
# _verify_history の「max(ts) が日次キーに追随」検査は自然にスキップされる
_CWE_UPDATE_KEY_DATE = re.compile(r"cwe-updates-(\d{4}-\d{2}-\d{2})\.parquet$")
```

`verify()` の reports に nuclei の後で追加:

```python
                "cwe": _verify_history(
                    storage,
                    lake,
                    None,  # CWE は数ヶ月更新なしが正常のため鮮度チェック対象外
                    prefix="cwe/",
                    table="cwe_history",
                    ts_column="release_date",
                    update_key_re=_CWE_UPDATE_KEY_DATE,
                ),
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_pipeline_cwe.py -v`
Expected: 全 passed

- [ ] **Step 5: 全テスト・lint・コミット**

```bash
uv run pytest -v && uv run ruff check . && uv run ruff format .
git add src/vlake/pipeline.py tests/test_pipeline_cwe.py
git commit -m "feat: verify と rebuild-catalog を cwe に対応 (鮮度チェックは対象外)"
```

---

### Task 5: CLI — update に cwe を追加

**Files:**
- Modify: `src/vlake/cli.py` (update の Choice と updaters。backfill には追加しない)
- Modify: `tests/test_cli.py` (末尾に追記)

**Interfaces:**
- Consumes: Task 3 の `pipeline.update_cwe`
- Produces: `vlake update cwe` コマンド

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_cli.py` の末尾に追記:

```python
def test_update_cwe_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline, "update_cwe", lambda cfg: "published 4.20 (1450 records)"
    )
    result = CliRunner().invoke(main, ["update", "cwe"])
    assert result.exit_code == 0, result.output
    assert "published 4.20" in result.output


def test_update_cwe_rejects_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["update", "cwe", "--date", "2026-07-01"])
    assert result.exit_code != 0
    assert "--date" in result.output


def test_backfill_cwe_not_available(monkeypatch, tmp_path):
    # cwe に backfill は無い (初回 update が全量投入)
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["backfill", "cwe"])
    assert result.exit_code != 0
    assert "cwe" in result.output  # Choice 外の invalid choice エラー
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_cli.py -v -k cwe`
Expected: test_update_cwe_via_cli と test_update_cwe_rejects_date_option が FAIL (invalid choice)、test_backfill_cwe_not_available は PASS (元から Choice 外)

- [ ] **Step 3: cli.py を実装**

update コマンドの Choice・docstring・updaters を変更:

```python
@main.command()
@click.argument(
    "dataset", type=click.Choice(["epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe"])
)
@click.option(
    "--date",
    "target",
    type=click.DateTime(["%Y-%m-%d"]),
    default=None,
    help="取得する日付 (epss のみ。省略時は最新)",
)
def update(dataset: str, target) -> None:
    """日次更新 (冪等)。nuclei / cwe は backfill 不要 (初回 update が全量投入)。"""
    cfg = Config.from_env()
    if dataset == "epss":
        click.echo(pipeline.update_epss(cfg, target.date() if target else None))
        return
    if target is not None:
        raise click.UsageError(
            f"{dataset} は常に最新スナップショットを取得します (--date 非対応)"
        )
    updaters = {
        "cve": pipeline.update_cve,
        "ghsa": pipeline.update_ghsa,
        "exploitdb": pipeline.update_exploitdb,
        "nuclei": pipeline.update_nuclei,
        "cwe": pipeline.update_cwe,
    }
    result = updaters[dataset](cfg)
    click.echo(result)
    if result.startswith("refused"):
        # backfill 未実施のまま日次更新だけが緑になるサイレント失敗を防ぐ
        raise SystemExit(1)
```

(backfill コマンドの Choice は変更しない)

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_cli.py -v`
Expected: 全 passed

- [ ] **Step 5: lint とコミット**

```bash
uv run ruff check . && uv run ruff format .
git add src/vlake/cli.py tests/test_cli.py
git commit -m "feat: cli の update に cwe を追加 (backfill は提供しない)"
```

---

### Task 6: ドキュメントと CI (README / DATA_LICENSES / publish.yml)

**Files:**
- Modify: `README.md` (Schema 節の末尾と「Build your own lake」の daily ブロック)
- Modify: `DATA_LICENSES.md` (末尾に節追加)
- Modify: `.github/workflows/publish.yml` (`update exploitdb` ステップの後に追加)

**Interfaces:** なし (ドキュメントのみ)

- [ ] **Step 1: README.md の Schema 節末尾 (exploitdb の Layout 段落の後) に追記**

```markdown
`cwe_history(cwe_id, entry_type, name, abstraction, status, description,
likelihood_of_exploit, relations STRUCT(nature, target_id)[], cwe_version,
release_date DATE)` — versioned snapshots of the CWE catalog (weaknesses,
categories and views, told apart by `entry_type`). The `cwe` view returns the
snapshot with the latest `release_date`; join it against the `cwe` array
columns of `cve` / `ghsa`. Deprecated entries remain with
`status = 'Deprecated'`.

Layout: `cwe/version=<ver>/cwe-<ver>.parquet` — one full snapshot per CWE
release (a few per year). No backfill: the first `update cwe` loads the whole
current catalog. `cwe/last-modified.txt` stores the upstream `Last-Modified`
value used for conditional GETs.
```

- [ ] **Step 2: README.md の「Build your own lake」daily ブロックに `uv run vlake update cwe` の行を追記** (既存の `uv run vlake update ...` 群の末尾)

- [ ] **Step 3: DATA_LICENSES.md の末尾に節追加**

```markdown
## CWE (Common Weakness Enumeration)

- **Source:** https://cwe.mitre.org/data/downloads.html
  (cwec XML カタログ: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)
- **License:** CWE Terms of Use — https://cwe.mitre.org/about/termsofuse.html
  (帰属表示を条件に複製・改変・再配布を許諾)
- **Attribution:** CWE — Common Weakness Enumeration, © The MITRE Corporation
  (https://cwe.mitre.org/).
- **Modifications:** cwec XML の弱点・カテゴリ・ビューから主要フィールドを抽出して
  Parquet に変換している (全フィールドは収録しない。関係は nature/target_id に平坦化)。
- **Disclaimer:** This project redistributes CWE content but is not endorsed
  or certified by The MITRE Corporation.
```

- [ ] **Step 4: publish.yml の `uv run vlake update exploitdb` ステップの後 (verify の前) に追加**

```yaml
      - run: uv run vlake update cwe
        env:
          VLAKE_S3_ENDPOINT: ${{ secrets.VLAKE_S3_ENDPOINT }}
          VLAKE_S3_BUCKET: ${{ secrets.VLAKE_S3_BUCKET }}
          VLAKE_PUBLIC_URL: ${{ vars.VLAKE_PUBLIC_URL }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: auto
```

(backfill.yml は変更しない — cwe に backfill は無い)

- [ ] **Step 5: 検証**

Run: `uv run pytest -v && uv run ruff check . && uv run ruff format . && uv run zizmor .github/workflows/`
Expected: 全 passed、lint / zizmor エラーなし

- [ ] **Step 6: コミット**

```bash
git add README.md DATA_LICENSES.md .github/workflows/publish.yml
git commit -m "docs: cwe データセットのスキーマ・ライセンス記載と日次 publish への追加"
```

---

## 補足 (実装者向け)

- **公開順序の不変条件**: `update_cwe` 内で `storage.put(parquet)` → `lake.add_file` → `_publish_catalog` の順序は既存 `update_nuclei` と同じ。順序を変えない。
- **Last-Modified の保存タイミング**: `lake.close()` 後 (`finally` の外)。例外時には到達しないので、失敗した実行の Last-Modified が残ることはない。`already-registered` のときも保存する (サーバー側の再アップロードで永久に再ダウンロードし続けるのを防ぐ)。
- **`cwe/last-modified.txt` と verify/rebuild**: どちらも `.parquet` フィルタで自然に無視される。追加の除外処理は書かない。
- **defusedxml の import**: `from defusedxml import ElementTree as DET` とし、`DET.fromstring` のみ使う。stdlib の `xml.etree` を直接 import しない (bandit)。
