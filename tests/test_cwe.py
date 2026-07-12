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
