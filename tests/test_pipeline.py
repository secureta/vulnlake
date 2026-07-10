from datetime import date
from pathlib import Path

import duckdb
import pytest

from tests.conftest import make_epss_csv_gz
from vlake import epss, pipeline
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


def test_update_publish_and_idempotency(cfg, monkeypatch):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)

    assert pipeline.update_epss(cfg) == "published 2026-07-10"
    assert pipeline.update_epss(cfg) == "already-registered 2026-07-10"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 1


def test_update_not_published_yet(cfg, monkeypatch):
    monkeypatch.setattr(epss, "fetch", lambda target=None: None)
    assert pipeline.update_epss(cfg) == "not-published-yet"


def test_backfill_then_update_then_verify(cfg, monkeypatch, tmp_path):
    # ミラー clone を模した source dir (年ディレクトリ + beta_scores は無視)
    src = tmp_path / "mirror"
    (src / "2021").mkdir(parents=True)
    (src / "beta_scores").mkdir()
    (src / "2021" / "epss_scores-2021-04-14.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 14),
            [("CVE-2020-5902", 0.65117)],
            with_comment=False,
            with_percentile=False,
        )
    )
    (src / "2021" / "epss_scores-2021-04-15.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 15),
            [("CVE-2020-5902", 0.66, 0.99)],
            model_version="v1",
            date_suffix="T00:00:00+0000",
        )
    )
    (src / "beta_scores" / "epss_scores-2099-01-01.csv.gz").write_bytes(b"ignored")

    assert pipeline.backfill_epss(cfg, src) == "backfilled 2 files (skipped 0)"
    assert pipeline.backfill_epss(cfg, src) == "backfilled 0 files (skipped 2)"

    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["files_in_storage"] == report["files_in_catalog"] == 3
    assert report["row_count"] == 3
    assert report["min_date"] == date(2021, 4, 14)
    assert report["max_date"] == date(2026, 7, 10)


def test_verify_without_catalog(cfg, monkeypatch):
    # ストレージに Parquet はあるがカタログだけ失われているケース
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"
    (cfg.local_dir / "vlake.ducklake").unlink()

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["stale"] is False
    assert report["files_in_storage"] == 1
    assert report["files_in_catalog"] is None
    assert report["row_count"] is None
    assert report["min_date"] is None
    assert report["max_date"] is None
    assert report["error"] == "catalog not found"


def test_verify_detects_untracked_file(cfg, monkeypatch):
    """件数一致だけでは見逃す差し替え/混入をパス集合比較で検出できること。"""
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"

    stray = cfg.local_dir / "epss" / "year=2099" / "epss-2099-01-01.parquet"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not a real parquet file")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["files_in_storage"] == 2
    assert report["files_in_catalog"] == 1


def test_verify_staleness_flags_old_max_date(cfg, monkeypatch):
    raw = make_epss_csv_gz(
        date(2021, 4, 14),
        [("CVE-2020-5902", 0.65117)],
        with_comment=False,
        with_percentile=False,
    )
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg, date(2021, 4, 14)) == "published 2021-04-14"

    report = pipeline.verify(cfg, max_age_days=3)
    assert report["ok"] is True
    assert report["stale"] is True


def test_verify_staleness_default_false_for_recent_day(cfg, monkeypatch):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"

    report = pipeline.verify(cfg)
    assert report["stale"] is False


def test_rebuild_catalog(cfg, monkeypatch):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    pipeline.update_epss(cfg)

    # カタログを消して再構築
    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1


def test_rebuild_catalog_refuses_when_empty(cfg):
    assert pipeline.rebuild_catalog(cfg) == "refused: no parquet files in storage"
    assert not (cfg.local_dir / "vlake.ducklake").exists()
