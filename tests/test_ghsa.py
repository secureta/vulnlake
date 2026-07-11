import json
from datetime import date, datetime

from tests.conftest import make_ghsa_record
from vlake import ghsa


def test_parse_record_basic():
    rec = make_ghsa_record("GHSA-jfh8-c2jp-5v3q")
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["ghsa"] == "GHSA-jfh8-c2jp-5v3q"
    assert row["cve"] == "CVE-2021-44228"
    assert row["summary"] == "Sample advisory summary"
    assert row["severity"] == "CRITICAL"
    assert row["cvss"] == 10.0  # ベクタから算出
    assert row["cvss_version"] == "3.1"
    assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert row["cwe"] == ["CWE-502"]
    assert row["affected"] == [
        {
            "ecosystem": "Maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "introduced": "2.0-beta9",
            "fixed": "2.3.1",
            "last_affected": None,
        }
    ]
    assert row["published"] == datetime(2021, 12, 10, 0, 40, 56)
    assert row["modified"] == datetime(2026, 7, 10, 12, 0, 0)
    assert row["withdrawn"] is None
    assert json.loads(row["raw"])["id"] == "GHSA-jfh8-c2jp-5v3q"


def test_parse_record_prefers_cvss_v4():
    rec = make_ghsa_record(
        "GHSA-aaaa-bbbb-cccc",
        severity=[
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
        ],
    )
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["cvss_version"] == "4.0"
    assert row["cvss_vector"].startswith("CVSS:4.0/")
    assert row["cvss"] is not None and 0.0 < row["cvss"] <= 10.0


def test_parse_record_no_severity():
    rec = make_ghsa_record("GHSA-aaaa-bbbb-cccc", severity=[], severity_label=None)
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert (row["cvss"], row["cvss_version"], row["cvss_vector"]) == (None, None, None)
    assert row["severity"] is None


def test_parse_record_broken_vector_keeps_vector_string():
    rec = make_ghsa_record(
        "GHSA-aaaa-bbbb-cccc",
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/broken"}],
    )
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["cvss"] is None
    assert row["cvss_version"] is None
    assert row["cvss_vector"] == "CVSS:3.1/broken"


def test_parse_record_non_string_score_is_skipped():
    # score が文字列でないエントリは採択しない (vector も格納しない)
    rec = make_ghsa_record(
        "GHSA-aaaa-bbbb-cccc",
        severity=[{"type": "CVSS_V3", "score": 12345}],
    )
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row is not None
    assert (row["cvss"], row["cvss_version"], row["cvss_vector"]) == (None, None, None)


def test_parse_record_multiple_ranges_and_no_ranges():
    rec = make_ghsa_record(
        "GHSA-aaaa-bbbb-cccc",
        affected=[
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.0.0"},
                            {"introduced": "2.0.0"},
                            {"last_affected": "2.1.0"},
                        ],
                    }
                ],
            },
            {"package": {"ecosystem": "pip", "name": "leftpad"}},
        ],
    )
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["affected"] == [
        {
            "ecosystem": "npm",
            "package": "left-pad",
            "introduced": "0",
            "fixed": "1.0.0",
            "last_affected": None,
        },
        {
            "ecosystem": "npm",
            "package": "left-pad",
            "introduced": "2.0.0",
            "fixed": None,
            "last_affected": "2.1.0",
        },
        {
            "ecosystem": "pip",
            "package": "leftpad",
            "introduced": None,
            "fixed": None,
            "last_affected": None,
        },
    ]


def test_parse_record_withdrawn():
    rec = make_ghsa_record("GHSA-aaaa-bbbb-cccc", withdrawn="2024-05-01T00:00:00Z")
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["withdrawn"] == datetime(2024, 5, 1, 0, 0, 0)


def test_parse_record_no_cve_alias():
    rec = make_ghsa_record("GHSA-aaaa-bbbb-cccc", aliases=())
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["cve"] is None


def test_modified_falls_back_to_published():
    rec = make_ghsa_record("GHSA-aaaa-bbbb-cccc", modified=None)
    row = ghsa.parse_record(json.dumps(rec).encode())
    assert row["modified"] == datetime(2021, 12, 10, 0, 40, 56)


def test_parse_record_returns_none_for_garbage():
    assert ghsa.parse_record(b"not json") is None
    assert ghsa.parse_record(b"{}") is None
    # id が GHSA 形式でない
    rec = make_ghsa_record("CVE-2021-44228")
    assert ghsa.parse_record(json.dumps(rec).encode()) is None
    # 日時が一切ないレコードは view の順序付けができないため skip
    rec = make_ghsa_record("GHSA-aaaa-bbbb-cccc", modified=None, published=None)
    assert ghsa.parse_record(json.dumps(rec).encode()) is None


def test_rows_to_table_sorts_and_casts():
    rows = [
        ghsa.parse_record(json.dumps(make_ghsa_record(g)).encode())
        for g in ("GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-bbbb-cccc")
    ]
    table = ghsa.rows_to_table(rows)
    assert table.schema.equals(ghsa.SCHEMA)
    assert table.column("ghsa").to_pylist() == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-zzzz-zzzz-zzzz",
    ]


def test_keys():
    assert ghsa.key_for_year(2021) == "ghsa/year=2021/ghsa-2021.parquet"
    assert ghsa.key_for_update(date(2026, 7, 12)) == (
        "ghsa/updates/year=2026/ghsa-updates-2026-07-12.parquet"
    )


def test_iter_reviewed_skips_unreviewed(tmp_path):
    from tests.conftest import make_ghsa_tarball

    tp = tmp_path / "advisory-database.tar.gz"
    make_ghsa_tarball(
        tp,
        [
            make_ghsa_record("GHSA-aaaa-bbbb-cccc", published="2021-12-10T00:40:56Z"),
            make_ghsa_record("GHSA-dddd-eeee-ffff", published="2024-03-01T00:00:00Z"),
        ],
        unreviewed=[
            make_ghsa_record("GHSA-uuuu-uuuu-uuuu", published="2024-03-01T00:00:00Z")
        ],
    )
    ids = []
    for raw in ghsa.iter_reviewed(tp):
        ids.append(json.loads(raw)["id"])
    assert sorted(ids) == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]


def test_download_streams_to_dest(tmp_path, monkeypatch):
    # cvelist.download と同型の httpx ストリーミング。互換の smoke テストのみ
    import httpx

    class FakeStream:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        def iter_bytes(self):
            yield b"tar"
            yield b"ball"

    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: FakeStream())
    dest = tmp_path / "out.tar.gz"
    ghsa.download("https://x/tarball", dest)
    assert dest.read_bytes() == b"tarball"
