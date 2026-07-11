import json
from datetime import date, datetime
from pathlib import Path

import duckdb

from tests.conftest import make_cve_record, make_epss_csv_gz
from vlake import cvelist, epss
from vlake.lake import Lake


def _make_parquet(tmp_path: Path, d: date) -> Path:
    raw = make_epss_csv_gz(
        d, [("CVE-1999-0001", 0.1, 0.5), ("CVE-1999-0002", 0.2, 0.6)]
    )
    table, _, _ = epss.parse(raw, fallback_date=d)
    out = tmp_path / f"epss-{d.isoformat()}.parquet"
    epss.write_parquet(table, out)
    return out


def test_create_register_and_read_back(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    pq2 = _make_parquet(tmp_path, date(2026, 7, 10))

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.registered_paths() == set()
    assert lake.add_file("epss", str(pq1)) is True
    assert lake.add_file("epss", str(pq1)) is False  # 冪等
    assert lake.add_file("epss", str(pq2)) is True
    assert lake.registered_paths() == {str(pq1), str(pq2)}
    lake.set_message("epss 2026-07-10")
    lake.close()

    # 消費者と同じ経路: 素の duckdb で ATTACH して読む
    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    n, days = con.execute(
        "SELECT count(*), count(DISTINCT date) FROM frozen.epss"
    ).fetchone()
    assert (n, days) == (4, 2)
    top = con.execute(
        "SELECT cve FROM frozen.epss WHERE date = DATE '2026-07-10' ORDER BY epss DESC LIMIT 1"
    ).fetchone()[0]
    assert top == "CVE-1999-0002"


def _make_cve_parquet(tmp_path: Path, cve_id: str, updated: str, name: str) -> Path:
    rec = make_cve_record(cve_id, date_updated=updated)
    row = cvelist.parse_record(json.dumps(rec).encode())
    out = tmp_path / name
    cvelist.write_parquet(cvelist.rows_to_table([row]), out)
    return out


def test_cve_history_and_latest_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    old = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2025-01-01T00:00:00Z", "a.parquet"
    )
    new = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2026-01-01T00:00:00Z", "b.parquet"
    )

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.max_cve_date_updated() is None
    lake.add_file("cve_history", str(old))
    lake.add_file("cve_history", str(new))
    assert lake.max_cve_date_updated() == datetime(2026, 1, 1)
    lake.refresh_cve_view()
    lake.refresh_cve_view()  # 再実行しても壊れない
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 2
    rows = con.execute("SELECT cve, date_updated FROM frozen.cve").fetchall()
    assert rows == [("CVE-2021-0001", datetime(2026, 1, 1))]


def test_registered_paths_scoped_by_table(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    epss_pq = _make_parquet(tmp_path, date(2026, 7, 10))
    cve_pq = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2026-01-01T00:00:00Z", "c.parquet"
    )

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.add_file("epss", str(epss_pq))
    lake.add_file("cve_history", str(cve_pq))
    assert lake.registered_paths() == {str(epss_pq), str(cve_pq)}
    assert lake.registered_paths("epss") == {str(epss_pq)}
    assert lake.registered_paths("cve_history") == {str(cve_pq)}
    lake.close()


def test_reopen_existing_catalog_without_data_path(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.add_file("epss", str(pq1))
    lake.close()

    # 既存カタログは data_path なしで再オープンできる
    lake2 = Lake(catalog)
    assert lake2.registered_paths() == {str(pq1)}
    assert lake2.add_file("epss", str(pq1)) is False
    lake2.close()


def test_datasets_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.refresh_datasets_view([epss.LICENSE_INFO])
    lake.refresh_datasets_view([epss.LICENSE_INFO])  # 再実行しても壊れない
    rows = lake.query("SELECT name, attribution FROM lake.datasets")
    assert rows[0][0] == "epss"
    assert rows[0][1] == epss.LICENSE_INFO["attribution"]
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 1
