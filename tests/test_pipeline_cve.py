from datetime import datetime
from pathlib import Path

import duckdb
import pytest

from tests.conftest import make_baseline_zip, make_cve_record
from vlake import cvelist, pipeline
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
    con.execute(f"ATTACH 'ducklake:{cfg.local_dir / 'vlake.ducklake'}' AS frozen (READ_ONLY)")
    return con


def _records():
    return [
        make_cve_record("CVE-2021-44228", date_updated="2025-10-21T23:25:23.121Z"),
        make_cve_record("CVE-2021-0001", date_updated="2024-01-01T00:00:00Z"),
        make_cve_record("CVE-2024-1234", date_updated="2026-07-01T00:00:00Z"),
    ]


def test_backfill_cve_from_local_zip(cfg, tmp_path):
    zp = tmp_path / "baseline.zip"
    make_baseline_zip(zp, _records())

    msg = pipeline.backfill_cve(cfg, source_zip=zp)
    assert msg == "backfilled 2 year files (skipped 0 years, 0 bad records)"

    assert (cfg.local_dir / "cve" / "year=2021" / "cve-2021.parquet").exists()
    assert (cfg.local_dir / "cve" / "year=2024" / "cve-2024.parquet").exists()

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.cve").fetchone()[0] == 3
    # 年ファイル内は cve ソート
    rows = con.execute(
        f"SELECT cve FROM read_parquet('{cfg.local_dir / 'cve' / 'year=2021' / 'cve-2021.parquet'}')"
    ).fetchall()
    assert [r[0] for r in rows] == ["CVE-2021-0001", "CVE-2021-44228"]
    # datasets view に cve のライセンスが載る
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {"epss", "cve"}

    # 冪等: 再実行は全年 skip
    msg = pipeline.backfill_cve(cfg, source_zip=zp)
    assert msg == "backfilled 0 year files (skipped 2 years, 0 bad records)"


def test_backfill_cve_counts_bad_records(cfg, tmp_path):
    import io
    import json
    import zipfile

    zp = tmp_path / "baseline.zip"
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        rec = make_cve_record("CVE-2021-0001")
        zf.writestr("cves/2021/CVE-2021-0001.json", json.dumps(rec))
        zf.writestr("cves/2021/CVE-2021-9999.json", "broken{")
        zf.writestr("cves/notes.txt", "ignored")
    with zipfile.ZipFile(zp, "w") as outer:
        outer.writestr("cves.zip", inner.getvalue())

    msg = pipeline.backfill_cve(cfg, source_zip=zp)
    assert msg == "backfilled 1 year files (skipped 0 years, 1 bad records)"


def test_backfill_cve_downloads_when_no_source(cfg, tmp_path, monkeypatch):
    from datetime import date

    zp = tmp_path / "fetched.zip"
    make_baseline_zip(zp, [make_cve_record("CVE-2021-0001")])

    monkeypatch.setattr(
        cvelist, "latest_baseline", lambda: (date(2026, 7, 11), "https://x/baseline")
    )

    def fake_download(url, dest):
        assert url == "https://x/baseline"
        dest.write_bytes(zp.read_bytes())

    monkeypatch.setattr(cvelist, "download", fake_download)
    msg = pipeline.backfill_cve(cfg)
    assert msg == "backfilled 1 year files (skipped 0 years, 0 bad records)"
