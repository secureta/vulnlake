from datetime import date

import duckdb
import pytest

from tests.conftest import make_kev_json, make_kev_record
from vlake import kev, pipeline
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


def _patch_download(monkeypatch, records):
    payload = make_kev_json(records)
    monkeypatch.setattr(kev, "download", lambda url, dest: dest.write_bytes(payload))


def _initial_records():
    return [
        make_kev_record("CVE-2021-44228"),
        make_kev_record(
            "CVE-2020-29583",
            vendor_project="Zyxel",
            product="Multiple Products",
            known_ransomware_campaign_use="Unknown",
            cwes=["CWE-522"],
        ),
        make_kev_record(
            "CVE-2024-0001",
            vendor_project="Example",
            date_added="2024-01-10",
            due_date="2024-01-31",
        ),
    ]


def test_update_kev_initial_full_load(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())

    # backfill は存在しない: カタログが空でも初回 update が全量投入になる
    msg = pipeline.update_kev(cfg, today=date(2026, 7, 12))
    assert msg == "published 2026-07-12 (3 records, 0 bad)"
    assert (
        cfg.local_dir
        / "kev"
        / "updates"
        / "year=2026"
        / "kev-updates-2026-07-12.parquet"
    ).exists()

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.kev_history").fetchone()[0] == 3
    hit = con.execute(
        "SELECT vendor_project, known_ransomware_campaign_use, date_added, cwe "
        "FROM frozen.kev WHERE cve = 'CVE-2021-44228' AND NOT removed"
    ).fetchone()
    assert hit == ("Apache", "Known", date(2021, 12, 10), ["CWE-917"])
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {"epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe", "kev"}

    # 同日の再実行は skip、翌日は差分なし
    assert (
        pipeline.update_kev(cfg, today=date(2026, 7, 12))
        == "already-registered 2026-07-12"
    )
    assert (
        pipeline.update_kev(cfg, today=date(2026, 7, 13)) == "no-new-records 2026-07-13"
    )


def test_update_kev_diff_tombstone_and_revival(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())
    pipeline.update_kev(cfg, today=date(2026, 7, 12))

    changed = _initial_records()
    # 変更: ransomware 判定の更新 (dateAdded は変わらないのが KEV の実挙動)
    changed[1] = make_kev_record(
        "CVE-2020-29583",
        vendor_project="Zyxel",
        product="Multiple Products",
        known_ransomware_campaign_use="Known",
        cwes=["CWE-522"],
    )
    del changed[2]  # 削除 (CISA が撤回したエントリ)
    changed.append(make_kev_record("CVE-2025-0002", date_added="2025-02-01"))  # 追加

    _patch_download(monkeypatch, changed)
    msg = pipeline.update_kev(cfg, today=date(2026, 7, 13))
    assert msg == "published 2026-07-13 (3 records, 0 bad)"  # 変更+追加+削除

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.kev_history").fetchone()[0] == 6
    removed, vendor = con.execute(
        "SELECT removed, vendor_project FROM frozen.kev WHERE cve = 'CVE-2024-0001'"
    ).fetchone()
    assert removed is True
    assert vendor == "Example"  # トゥームストーンは最終値を引き継ぐ
    assert (
        con.execute(
            "SELECT known_ransomware_campaign_use FROM frozen.kev "
            "WHERE cve = 'CVE-2020-29583'"
        ).fetchone()[0]
        == "Known"
    )
    assert (
        con.execute("SELECT count(*) FROM frozen.kev WHERE NOT removed").fetchone()[0]
        == 3
    )
    con.close()

    # 復活: 消えた cve が再出現したら removed=false で追記される
    _patch_download(monkeypatch, _initial_records())
    msg = pipeline.update_kev(cfg, today=date(2026, 7, 14))
    # CVE-2024-0001 復活 + CVE-2020-29583 の戻し + CVE-2025-0002 の削除
    assert msg == "published 2026-07-14 (3 records, 0 bad)"
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT removed FROM frozen.kev WHERE cve = 'CVE-2024-0001'"
        ).fetchone()[0]
        is False
    )


def test_update_kev_refuses_shrunken_snapshot(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())  # 3件
    pipeline.update_kev(cfg, today=date(2026, 7, 12))

    # 1件 (< 3/2) に縮んだ断面は上流異常とみなして中断
    _patch_download(monkeypatch, [make_kev_record("CVE-2021-44228")])
    with pytest.raises(RuntimeError, match="less than half"):
        pipeline.update_kev(cfg, today=date(2026, 7, 13))

    # カタログは未更新のまま (トゥームストーンは生成されない)
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.kev_history").fetchone()[0] == 3


def test_update_kev_duplicate_cve_first_wins(cfg, monkeypatch):
    _patch_download(
        monkeypatch,
        [
            make_kev_record("CVE-2024-0001", vendor_project="First"),
            make_kev_record("CVE-2024-0001", vendor_project="Second"),
        ],
    )
    msg = pipeline.update_kev(cfg, today=date(2026, 7, 12))
    assert msg == "published 2026-07-12 (1 records, 0 bad)"
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT vendor_project FROM frozen.kev WHERE cve = 'CVE-2024-0001'"
        ).fetchone()[0]
        == "First"
    )


def test_update_kev_counts_bad_records(cfg, monkeypatch):
    _patch_download(
        monkeypatch,
        [make_kev_record("CVE-2024-0001"), make_kev_record("bogus")],
    )
    assert (
        pipeline.update_kev(cfg, today=date(2026, 7, 12))
        == "published 2026-07-12 (1 records, 1 bad)"
    )


def test_update_kev_rejects_broken_feed(cfg, monkeypatch):
    payload = b'{"title": "broken feed"}'
    monkeypatch.setattr(kev, "download", lambda url, dest: dest.write_bytes(payload))
    with pytest.raises(ValueError, match="vulnerabilities"):
        pipeline.update_kev(cfg, today=date(2026, 7, 12))


def test_verify_covers_kev(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())
    pipeline.update_kev(cfg, today=date(2026, 7, 12))

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    rep = report["datasets"]["kev"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 3
    assert rep["max_date"] == date(2026, 7, 12)


def test_verify_detects_kev_stray_file(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())
    pipeline.update_kev(cfg, today=date(2026, 7, 12))

    stray = (
        cfg.local_dir
        / "kev"
        / "updates"
        / "year=2099"
        / "kev-updates-2099-01-01.parquet"
    )
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["kev"]["ok"] is False


def test_rebuild_catalog_covers_kev(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_records())
    pipeline.update_kev(cfg, today=date(2026, 7, 12))

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.kev_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.kev").fetchone()[0] == 3
