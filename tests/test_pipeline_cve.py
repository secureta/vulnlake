from datetime import datetime

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
    con.execute(
        f"ATTACH 'ducklake:{cfg.local_dir / 'vlake.ducklake'}' AS frozen (READ_ONLY)"
    )
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
        "SELECT cve FROM read_parquet(?)",
        [str(cfg.local_dir / "cve" / "year=2021" / "cve-2021.parquet")],
    ).fetchall()
    assert [r[0] for r in rows] == ["CVE-2021-0001", "CVE-2021-44228"]
    # datasets view に cve のライセンスが載る
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {"epss", "cve", "ghsa"}

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


def _patch_fetch(monkeypatch, tmp_path, records, baseline_date):
    zp = tmp_path / f"baseline-{baseline_date}.zip"
    make_baseline_zip(zp, records)
    monkeypatch.setattr(
        cvelist, "latest_baseline", lambda: (baseline_date, "https://x/baseline")
    )
    monkeypatch.setattr(
        cvelist, "download", lambda url, dest: dest.write_bytes(zp.read_bytes())
    )


def test_update_cve_appends_only_newer_records(cfg, tmp_path, monkeypatch):
    from datetime import date

    zp = tmp_path / "initial.zip"
    make_baseline_zip(zp, _records())  # max date_updated = 2026-07-01
    pipeline.backfill_cve(cfg, source_zip=zp)

    updated = [
        make_cve_record(
            "CVE-2021-44228",
            date_updated="2026-07-10T03:00:00Z",
            description="Updated description.",
        ),
        make_cve_record("CVE-2021-0001", date_updated="2024-01-01T00:00:00Z"),
        make_cve_record("CVE-2024-1234", date_updated="2026-07-01T00:00:00Z"),
    ]
    _patch_fetch(monkeypatch, tmp_path, updated, date(2026, 7, 11))

    msg = pipeline.update_cve(cfg)
    assert msg == "published 2026-07-11 (1 records, 0 bad)"
    assert (
        cfg.local_dir
        / "cve"
        / "updates"
        / "year=2026"
        / "cve-updates-2026-07-11.parquet"
    ).exists()

    # 同日 baseline の再実行は skip
    assert pipeline.update_cve(cfg) == "already-registered 2026-07-11"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 4
    # view は最新版を返す
    desc, updated_ts = con.execute(
        "SELECT description, date_updated FROM frozen.cve WHERE cve = 'CVE-2021-44228'"
    ).fetchone()
    assert desc == "Updated description."
    assert updated_ts == datetime(2026, 7, 10, 3, 0, 0)
    assert con.execute("SELECT count(*) FROM frozen.cve").fetchone()[0] == 3


def test_update_cve_no_new_records(cfg, tmp_path, monkeypatch):
    from datetime import date

    zp = tmp_path / "initial.zip"
    make_baseline_zip(zp, _records())
    pipeline.backfill_cve(cfg, source_zip=zp)

    _patch_fetch(monkeypatch, tmp_path, _records(), date(2026, 7, 12))
    assert pipeline.update_cve(cfg) == "no-new-records 2026-07-12"
    # 空ファイルは登録しない
    assert not (cfg.local_dir / "cve" / "updates").exists()


def test_update_cve_refuses_on_empty_table(cfg, tmp_path, monkeypatch):
    from datetime import date

    _patch_fetch(monkeypatch, tmp_path, _records(), date(2026, 7, 11))
    msg = pipeline.update_cve(cfg)
    assert msg == "refused: cve_history is empty; run backfill cve first"


def test_verify_covers_cve(cfg, tmp_path, monkeypatch):
    from datetime import date

    zp = tmp_path / "initial.zip"
    make_baseline_zip(zp, _records())
    pipeline.backfill_cve(cfg, source_zip=zp)

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["stale"] is False
    cve_rep = report["datasets"]["cve"]
    assert cve_rep["files_in_storage"] == cve_rep["files_in_catalog"] == 2
    assert cve_rep["row_count"] == 3
    assert cve_rep["max_date"] == date(2026, 7, 1)
    # epss 側は空でも ok
    assert report["datasets"]["epss"]["ok"] is True
    assert report["datasets"]["epss"]["files_in_storage"] == 0


def test_verify_detects_cve_stray_file(cfg, tmp_path):
    zp = tmp_path / "initial.zip"
    make_baseline_zip(zp, [make_cve_record("CVE-2021-0001")])
    pipeline.backfill_cve(cfg, source_zip=zp)

    stray = cfg.local_dir / "cve" / "year=2099" / "cve-2099.parquet"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["cve"]["ok"] is False
    assert report["datasets"]["epss"]["ok"] is True


def test_verify_cve_staleness(cfg, tmp_path):
    zp = tmp_path / "initial.zip"
    make_baseline_zip(
        zp, [make_cve_record("CVE-2021-0001", date_updated="2024-01-01T00:00:00Z")]
    )
    pipeline.backfill_cve(cfg, source_zip=zp)

    report = pipeline.verify(cfg, max_age_days=3)
    assert report["datasets"]["cve"]["stale"] is True
    assert report["stale"] is True
    assert report["ok"] is True


def test_rebuild_catalog_covers_both_datasets(cfg, tmp_path, monkeypatch):
    from datetime import date

    from tests.conftest import make_epss_csv_gz
    from vlake import epss

    zp = tmp_path / "initial.zip"
    make_baseline_zip(zp, _records())
    pipeline.backfill_cve(cfg, source_zip=zp)
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    pipeline.update_epss(cfg)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 3 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.cve").fetchone()[0] == 3
