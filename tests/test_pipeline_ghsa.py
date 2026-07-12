from datetime import date, datetime

import duckdb
import pytest

from tests.conftest import make_ghsa_record, make_ghsa_tarball
from vlake import ghsa, pipeline
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
        make_ghsa_record(
            "GHSA-jfh8-c2jp-5v3q",
            published="2021-12-10T00:40:56Z",
            modified="2025-10-22T19:13:24Z",
        ),
        make_ghsa_record(
            "GHSA-aaaa-bbbb-cccc",
            published="2021-01-01T00:00:00Z",
            modified="2024-01-01T00:00:00Z",
        ),
        make_ghsa_record(
            "GHSA-dddd-eeee-ffff",
            published="2024-03-01T00:00:00Z",
            modified="2026-07-01T00:00:00Z",
        ),
    ]


def test_backfill_ghsa_from_local_tarball(cfg, tmp_path):
    tp = tmp_path / "advisory-database.tar.gz"
    make_ghsa_tarball(
        tp,
        _records(),
        unreviewed=[
            make_ghsa_record("GHSA-uuuu-uuuu-uuuu", published="2024-03-01T00:00:00Z")
        ],
    )

    msg = pipeline.backfill_ghsa(cfg, source_tar=tp)
    assert msg == "backfilled 2 year files (skipped 0 years, 0 bad records)"

    assert (cfg.local_dir / "ghsa" / "year=2021" / "ghsa-2021.parquet").exists()
    assert (cfg.local_dir / "ghsa" / "year=2024" / "ghsa-2024.parquet").exists()

    con = _attach(cfg)
    # unreviewed は収録されない
    assert con.execute("SELECT count(*) FROM frozen.ghsa_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.ghsa").fetchone()[0] == 3
    # published 年ファイル内は ghsa ソート
    rows = con.execute(
        "SELECT ghsa FROM read_parquet(?)",
        [str(cfg.local_dir / "ghsa" / "year=2021" / "ghsa-2021.parquet")],
    ).fetchall()
    assert [r[0] for r in rows] == ["GHSA-aaaa-bbbb-cccc", "GHSA-jfh8-c2jp-5v3q"]
    # datasets view に ghsa のライセンスが載る
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {"epss", "cve", "ghsa", "exploitdb", "nuclei"}

    # 冪等: 再実行は全年 skip
    msg = pipeline.backfill_ghsa(cfg, source_tar=tp)
    assert msg == "backfilled 0 year files (skipped 2 years, 0 bad records)"


def test_backfill_ghsa_counts_bad_records(cfg, tmp_path):
    import io
    import json
    import tarfile

    tp = tmp_path / "advisory-database.tar.gz"
    with tarfile.open(tp, "w:gz") as tf:
        for name, data in [
            (
                "advisory-database-main/advisories/github-reviewed/2021/01/"
                "GHSA-aaaa-bbbb-cccc/GHSA-aaaa-bbbb-cccc.json",
                json.dumps(
                    make_ghsa_record(
                        "GHSA-aaaa-bbbb-cccc", published="2021-01-01T00:00:00Z"
                    )
                ).encode(),
            ),
            (
                "advisory-database-main/advisories/github-reviewed/2021/02/"
                "GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json",
                b"broken{",
            ),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    msg = pipeline.backfill_ghsa(cfg, source_tar=tp)
    assert msg == "backfilled 1 year files (skipped 0 years, 1 bad records)"


def test_backfill_ghsa_downloads_when_no_source(cfg, tmp_path, monkeypatch):
    tp = tmp_path / "fetched.tar.gz"
    make_ghsa_tarball(
        tp, [make_ghsa_record("GHSA-aaaa-bbbb-cccc", published="2021-01-01T00:00:00Z")]
    )

    def fake_download(url, dest):
        assert url == ghsa.TARBALL_URL
        dest.write_bytes(tp.read_bytes())

    monkeypatch.setattr(ghsa, "download", fake_download)
    msg = pipeline.backfill_ghsa(cfg)
    assert msg == "backfilled 1 year files (skipped 0 years, 0 bad records)"


def _patch_fetch(monkeypatch, tmp_path, records, tag):
    tp = tmp_path / f"tarball-{tag}.tar.gz"
    make_ghsa_tarball(tp, records)
    monkeypatch.setattr(
        ghsa, "download", lambda url, dest: dest.write_bytes(tp.read_bytes())
    )


def test_update_ghsa_appends_only_newer_records(cfg, tmp_path, monkeypatch):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(tp, _records())  # max modified = 2026-07-01
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    updated = _records()
    updated[0] = make_ghsa_record(
        "GHSA-jfh8-c2jp-5v3q",
        published="2021-12-10T00:40:56Z",
        modified="2026-07-11T03:00:00Z",
        summary="Updated summary",
    )
    _patch_fetch(monkeypatch, tmp_path, updated, "second")

    msg = pipeline.update_ghsa(cfg, today=date(2026, 7, 12))
    assert msg == "published 2026-07-12 (1 records, 0 bad)"
    assert (
        cfg.local_dir
        / "ghsa"
        / "updates"
        / "year=2026"
        / "ghsa-updates-2026-07-12.parquet"
    ).exists()

    # 同日の再実行は skip
    assert (
        pipeline.update_ghsa(cfg, today=date(2026, 7, 12))
        == "already-registered 2026-07-12"
    )

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.ghsa_history").fetchone()[0] == 4
    # view は最新版を返す
    summary, modified = con.execute(
        "SELECT summary, modified FROM frozen.ghsa WHERE ghsa = 'GHSA-jfh8-c2jp-5v3q'"
    ).fetchone()
    assert summary == "Updated summary"
    assert modified == datetime(2026, 7, 11, 3, 0, 0)
    assert con.execute("SELECT count(*) FROM frozen.ghsa").fetchone()[0] == 3


def test_update_ghsa_no_new_records(cfg, tmp_path, monkeypatch):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(tp, _records())
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    _patch_fetch(monkeypatch, tmp_path, _records(), "same")
    assert (
        pipeline.update_ghsa(cfg, today=date(2026, 7, 13))
        == "no-new-records 2026-07-13"
    )
    # 空ファイルは登録しない
    assert not (cfg.local_dir / "ghsa" / "updates").exists()


def test_update_ghsa_refuses_on_empty_table(cfg, tmp_path, monkeypatch):
    _patch_fetch(monkeypatch, tmp_path, _records(), "initial")
    msg = pipeline.update_ghsa(cfg, today=date(2026, 7, 12))
    assert msg == "refused: ghsa_history is empty; run backfill ghsa first"


def test_verify_covers_ghsa(cfg, tmp_path):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(tp, _records())
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["stale"] is False
    rep = report["datasets"]["ghsa"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 2
    assert rep["row_count"] == 3
    assert rep["max_date"] == date(2026, 7, 1)
    # 他データセットは空でも ok
    assert report["datasets"]["epss"]["ok"] is True
    assert report["datasets"]["cve"]["ok"] is True


def test_verify_detects_ghsa_stray_file(cfg, tmp_path):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(
        tp, [make_ghsa_record("GHSA-aaaa-bbbb-cccc", published="2021-01-01T00:00:00Z")]
    )
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    stray = cfg.local_dir / "ghsa" / "year=2099" / "ghsa-2099.parquet"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["ghsa"]["ok"] is False


def test_verify_ghsa_staleness(cfg, tmp_path):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(
        tp,
        [
            make_ghsa_record(
                "GHSA-aaaa-bbbb-cccc",
                published="2021-01-01T00:00:00Z",
                modified="2024-01-01T00:00:00Z",
            )
        ],
    )
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    report = pipeline.verify(cfg, max_age_days=3)
    assert report["datasets"]["ghsa"]["stale"] is True
    assert report["stale"] is True
    assert report["ok"] is True


def test_rebuild_catalog_covers_ghsa(cfg, tmp_path):
    tp = tmp_path / "initial.tar.gz"
    make_ghsa_tarball(tp, _records())
    pipeline.backfill_ghsa(cfg, source_tar=tp)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 2 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.ghsa_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.ghsa").fetchone()[0] == 3
