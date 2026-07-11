import json
from datetime import date, datetime

from tests.conftest import make_baseline_zip, make_cve_record
from vlake import cvelist


def _v31(score=9.8, severity="CRITICAL", vector="CVSS:3.1/AV:N/AC:L"):
    return {
        "cvssV3_1": {
            "version": "3.1",
            "baseScore": score,
            "baseSeverity": severity,
            "vectorString": vector,
        }
    }


def test_parse_record_published():
    rec = make_cve_record(
        "CVE-2021-44228",
        cna_metrics=[_v31()],
        cwes=["CWE-502", "CWE-400"],
    )
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert row["cve"] == "CVE-2021-44228"
    assert row["state"] == "PUBLISHED"
    assert row["assigner"] == "sample"
    assert row["title"] == "Sample vulnerability title"
    assert row["description"] == "A sample vulnerability."
    assert row["cvss"] == 9.8
    assert row["cvss_version"] == "3.1"
    assert row["cvss_severity"] == "CRITICAL"
    assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L"
    assert row["cwe"] == ["CWE-502", "CWE-400"]
    assert row["date_updated"] == datetime(2026, 7, 10, 12, 0, 0)
    assert row["date_published"] == datetime(2021, 12, 10, 0, 0, 0)
    assert json.loads(row["raw"])["cveMetadata"]["cveId"] == "CVE-2021-44228"


def test_parse_record_rejected_uses_rejected_reasons():
    rec = make_cve_record(
        "CVE-2024-0001",
        state="REJECTED",
        description=None,
        rejected_reasons=["Not a security issue."],
    )
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert row["state"] == "REJECTED"
    assert row["description"] == "Not a security issue."
    assert row["cvss"] is None


def test_cvss_priority_cna_v2_beats_adp_v31():
    """コンテナ優先 (CNA > ADP)、コンテナ内はバージョン優先。"""
    rec = make_cve_record(
        "CVE-2020-0001",
        cna_metrics=[
            {
                "cvssV2_0": {
                    "version": "2.0",
                    "baseScore": 5.0,
                    "vectorString": "AV:N/AC:L",
                }
            }
        ],
        adp_metrics=[_v31(9.8)],
    )
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert (row["cvss"], row["cvss_version"]) == (5.0, "2.0")
    assert row["cvss_severity"] is None  # v2 に baseSeverity は無い


def test_cvss_adp_fallback_when_cna_has_none():
    rec = make_cve_record("CVE-2020-0002", adp_metrics=[_v31(7.5, "HIGH")])
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert (row["cvss"], row["cvss_version"], row["cvss_severity"]) == (
        7.5,
        "3.1",
        "HIGH",
    )


def test_date_updated_falls_back_to_published_then_reserved():
    rec = make_cve_record("CVE-1999-0001", date_updated=None)
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert row["date_updated"] == datetime(2021, 12, 10, 0, 0, 0)

    rec = make_cve_record(
        "CVE-1999-0002",
        date_updated=None,
        date_published=None,
        date_reserved="2021-11-26T00:00:00+00:00",
    )
    row = cvelist.parse_record(json.dumps(rec).encode())
    assert row["date_updated"] == datetime(2021, 11, 26, 0, 0, 0)


def test_parse_record_returns_none_for_garbage():
    assert cvelist.parse_record(b"not json") is None
    assert cvelist.parse_record(b"{}") is None
    # 日時が一切ないレコードは view の順序付けができないため skip
    rec = make_cve_record(
        "CVE-1999-0003", date_updated=None, date_published=None, date_reserved=None
    )
    assert cvelist.parse_record(json.dumps(rec).encode()) is None


def test_rows_to_table_sorts_and_casts():
    rows = [
        cvelist.parse_record(json.dumps(make_cve_record(f"CVE-2021-{n}")).encode())
        for n in ("44228", "0001")
    ]
    table = cvelist.rows_to_table(rows)
    assert table.schema.equals(cvelist.SCHEMA)
    assert table.column("cve").to_pylist() == ["CVE-2021-0001", "CVE-2021-44228"]


def test_keys():
    assert cvelist.key_for_year(2021) == "cve/year=2021/cve-2021.parquet"
    assert cvelist.key_for_update(date(2026, 7, 11)) == (
        "cve/updates/year=2026/cve-updates-2026-07-11.parquet"
    )


def _sample_records():
    return [
        make_cve_record("CVE-2021-44228"),
        make_cve_record("CVE-2021-0001"),
        make_cve_record("CVE-2024-1234"),
    ]


def test_open_baseline_nested_and_flat(tmp_path):
    for nested in (True, False):
        zp = tmp_path / f"baseline-{nested}.zip"
        make_baseline_zip(zp, _sample_records(), nested=nested)
        zf = cvelist.open_baseline(zp, tmp_path / f"work-{nested}")
        try:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            assert len(names) == 3
        finally:
            zf.close()


def test_iter_names_by_year_groups_by_cve_id(tmp_path):
    zp = tmp_path / "baseline.zip"
    make_baseline_zip(zp, _sample_records())
    workdir = tmp_path / "work"
    workdir.mkdir()
    zf = cvelist.open_baseline(zp, workdir)
    try:
        groups = list(cvelist.iter_names_by_year(zf))
        years = [y for y, _ in groups]
        assert years == [2021, 2024]
        assert len(groups[0][1]) == 2
        # グループ内のファイルを読んでパースできる
        row = cvelist.parse_record(zf.read(groups[1][1][0]))
        assert row["cve"] == "CVE-2024-1234"
    finally:
        zf.close()


def test_latest_baseline_parses_release_assets(monkeypatch):
    import httpx

    payload = {
        "assets": [
            {"name": "release_notes.md", "browser_download_url": "https://x/notes"},
            {
                "name": "2026-07-11_delta_CVEs_at_1200Z.zip",
                "browser_download_url": "https://x/delta",
            },
            {
                "name": "2026-07-11_all_CVEs_at_midnight.zip.zip",
                "browser_download_url": "https://x/baseline",
            },
        ]
    }

    def fake_get(url, **kw):
        return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    d, url = cvelist.latest_baseline()
    assert d == date(2026, 7, 11)
    assert url == "https://x/baseline"
