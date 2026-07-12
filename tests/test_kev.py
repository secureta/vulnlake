from datetime import date

import pyarrow.parquet as pq

from tests.conftest import make_kev_json, make_kev_record
from vlake import kev


def test_parse_record_full():
    row = kev.parse_record(make_kev_record())
    assert row == {
        "cve": "CVE-2021-44228",
        "vendor_project": "Apache",
        "product": "Log4j2",
        "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
        "short_description": "Log4j2 contains a JNDI injection vulnerability.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_campaign_use": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "cwe": ["CWE-917"],
        "date_added": date(2021, 12, 10),
        "due_date": date(2021, 12, 24),
    }


def test_parse_record_rejects_bad_cve():
    assert kev.parse_record({}) is None
    assert kev.parse_record(make_kev_record("not-a-cve")) is None
    assert kev.parse_record(make_kev_record("")) is None


def test_parse_record_tolerates_missing_optional_fields():
    row = kev.parse_record({"cveID": "CVE-2024-0001"})
    assert row["cve"] == "CVE-2024-0001"
    assert row["vendor_project"] is None
    assert row["cwe"] == []
    assert row["date_added"] is None
    assert row["due_date"] is None


def test_parse_record_normalizes_dates_and_cwes():
    rec = make_kev_record(
        date_added="unknown", due_date="", cwes=["cwe-79", " CWE-89 ", ""]
    )
    row = kev.parse_record(rec)
    assert row["date_added"] is None
    assert row["due_date"] is None
    assert row["cwe"] == ["CWE-79", "CWE-89"]


def test_parse_catalog_counts_bad_records():
    raw = make_kev_json(
        [
            make_kev_record("CVE-2024-0002"),
            make_kev_record("bogus"),
            make_kev_record("CVE-2024-0001"),
        ]
    )
    rows, bad = kev.parse_catalog(raw)
    assert [r["cve"] for r in rows] == ["CVE-2024-0002", "CVE-2024-0001"]
    assert bad == 1


def test_rows_to_table_sorts_by_cve(tmp_path):
    rows, _ = kev.parse_catalog(
        make_kev_json(
            [make_kev_record("CVE-2024-0002"), make_kev_record("CVE-2024-0001")]
        )
    )
    table = kev.rows_to_table(
        [{**r, "fetched_date": date(2026, 7, 12), "removed": False} for r in rows]
    )
    assert table.column("cve").to_pylist() == ["CVE-2024-0001", "CVE-2024-0002"]
    out = tmp_path / "kev.parquet"
    kev.write_parquet(table, out)
    assert pq.read_table(out).num_rows == 2


def test_key_for_update():
    assert (
        kev.key_for_update(date(2026, 7, 12))
        == "kev/updates/year=2026/kev-updates-2026-07-12.parquet"
    )
