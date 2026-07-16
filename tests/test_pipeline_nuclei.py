from datetime import date

import duckdb
import pytest

from tests.conftest import make_nuclei_tarball, make_nuclei_yaml
from vlake import nuclei, pipeline
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


def _patch_download(monkeypatch, tmp_path, files):
    tar = tmp_path / "src.tar.gz"
    make_nuclei_tarball(tar, files)
    payload = tar.read_bytes()
    monkeypatch.setattr(nuclei, "download", lambda url, dest: dest.write_bytes(payload))


def _initial_files():
    return {
        "http/cves/2024/CVE-2024-0001.yaml": make_nuclei_yaml(
            "CVE-2024-0001", cve_id="CVE-2024-0001"
        ),
        "http/cves/2024/CVE-2024-0002.yaml": make_nuclei_yaml(
            "CVE-2024-0002", cve_id="CVE-2024-0002"
        ),
        "network/misc/sample-service.yaml": make_nuclei_yaml(
            "sample-service",
            cve_id=None,
            tags="network,detect",
            protocol_key="network",
        ),
    }


def test_update_nuclei_initial_full_load(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())

    # backfill は存在しない: カタログが空でも初回 update が全量投入になる
    msg = pipeline.update_nuclei(cfg, today=date(2026, 7, 12))
    assert msg == "published 2026-07-12 (3 records, 0 bad)"
    assert (
        cfg.local_dir
        / "nuclei"
        / "updates"
        / "year=2026"
        / "nuclei-updates-2026-07-12.parquet"
    ).exists()

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.nuclei_history").fetchone()[0] == 3
    hit = con.execute(
        "SELECT template_id, severity, type, template_url FROM frozen.nuclei "
        "WHERE list_contains(cve, 'CVE-2024-0001') AND NOT removed"
    ).fetchone()
    assert hit == (
        "CVE-2024-0001",
        "critical",
        "http",
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
        "http/cves/2024/CVE-2024-0001.yaml",
    )
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert names == {
        "epss",
        "cve",
        "ghsa",
        "exploitdb",
        "nuclei",
        "cwe",
        "kev",
        "cloudflare_waf",
    }

    # 同日の再実行は skip、翌日は差分なし
    assert (
        pipeline.update_nuclei(cfg, today=date(2026, 7, 12))
        == "already-registered 2026-07-12"
    )
    assert (
        pipeline.update_nuclei(cfg, today=date(2026, 7, 13))
        == "no-new-records 2026-07-13"
    )


def test_update_nuclei_diff_tombstone_and_revival(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    changed = _initial_files()
    changed["http/cves/2024/CVE-2024-0001.yaml"] = make_nuclei_yaml(
        "CVE-2024-0001", cve_id="CVE-2024-0001", body_marker="v2"
    )  # 変更
    del changed["network/misc/sample-service.yaml"]  # 削除
    changed["http/cves/2025/CVE-2025-0003.yaml"] = make_nuclei_yaml(
        "CVE-2025-0003", cve_id="CVE-2025-0003"
    )  # 追加
    _patch_download(monkeypatch, tmp_path, changed)

    msg = pipeline.update_nuclei(cfg, today=date(2026, 7, 13))
    assert msg == "published 2026-07-13 (3 records, 0 bad)"  # 変更+追加+削除

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.nuclei_history").fetchone()[0] == 6
    removed, sev = con.execute(
        "SELECT removed, severity FROM frozen.nuclei "
        "WHERE template_id = 'sample-service'"
    ).fetchone()
    assert removed is True
    assert sev == "critical"  # トゥームストーンは最終値を引き継ぐ
    assert (
        con.execute("SELECT count(*) FROM frozen.nuclei WHERE NOT removed").fetchone()[
            0
        ]
        == 3
    )
    con.close()

    # 復活: 消えたテンプレートが再出現したら removed=false で追記される
    _patch_download(monkeypatch, tmp_path, _initial_files())
    msg = pipeline.update_nuclei(cfg, today=date(2026, 7, 14))
    # sample-service 復活 + CVE-2024-0001 の v1 戻し + CVE-2025-0003 の削除
    assert msg == "published 2026-07-14 (3 records, 0 bad)"
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT removed FROM frozen.nuclei WHERE template_id = 'sample-service'"
        ).fetchone()[0]
        is False
    )


def test_update_nuclei_ignores_resign_only_changes(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, {"http/a.yaml": make_nuclei_yaml("tpl-a")})
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    resigned = (
        make_nuclei_yaml("tpl-a", with_signature=False)
        + b"# digest: ffff0000newsignature\n"
    )
    _patch_download(monkeypatch, tmp_path, {"http/a.yaml": resigned})
    assert (
        pipeline.update_nuclei(cfg, today=date(2026, 7, 13))
        == "no-new-records 2026-07-13"
    )


def test_update_nuclei_detects_path_move(cfg, tmp_path, monkeypatch):
    _patch_download(
        monkeypatch, tmp_path, {"http/old/tpl-a.yaml": make_nuclei_yaml("tpl-a")}
    )
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    _patch_download(
        monkeypatch, tmp_path, {"http/new/tpl-a.yaml": make_nuclei_yaml("tpl-a")}
    )
    assert (
        pipeline.update_nuclei(cfg, today=date(2026, 7, 13))
        == "published 2026-07-13 (1 records, 0 bad)"
    )
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT file FROM frozen.nuclei WHERE template_id = 'tpl-a'"
        ).fetchone()[0]
        == "http/new/tpl-a.yaml"
    )


def test_update_nuclei_refuses_shrunken_snapshot(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())  # 3件
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    # 1件 (< 3/2) に縮んだ断面は上流異常とみなして中断
    _patch_download(monkeypatch, tmp_path, {"http/a.yaml": make_nuclei_yaml("tpl-a")})
    with pytest.raises(RuntimeError, match="less than half"):
        pipeline.update_nuclei(cfg, today=date(2026, 7, 13))

    # カタログは未更新のまま (トゥームストーンは生成されない)
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.nuclei_history").fetchone()[0] == 3


def test_update_nuclei_duplicate_id_first_path_wins(cfg, tmp_path, monkeypatch):
    files = {
        "http/a/dup.yaml": make_nuclei_yaml("dup", body_marker="a"),
        "http/b/dup.yaml": make_nuclei_yaml("dup", body_marker="b"),
    }
    _patch_download(monkeypatch, tmp_path, files)
    msg = pipeline.update_nuclei(cfg, today=date(2026, 7, 12))
    assert msg == "published 2026-07-12 (1 records, 0 bad)"
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT file FROM frozen.nuclei WHERE template_id = 'dup'"
        ).fetchone()[0]
        == "http/a/dup.yaml"
    )


def test_update_nuclei_counts_bad_yaml(cfg, tmp_path, monkeypatch):
    files = {
        "http/a.yaml": make_nuclei_yaml("tpl-a"),
        "http/broken.yaml": b"id: [unclosed\n",
        "top-config.yaml": b"just: config\n",  # id/info 無しの非テンプレート
    }
    _patch_download(monkeypatch, tmp_path, files)
    assert (
        pipeline.update_nuclei(cfg, today=date(2026, 7, 12))
        == "published 2026-07-12 (1 records, 2 bad)"
    )


def test_verify_covers_nuclei(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    rep = report["datasets"]["nuclei"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 3
    assert rep["max_date"] == date(2026, 7, 12)


def test_verify_detects_nuclei_stray_file(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    stray = (
        cfg.local_dir
        / "nuclei"
        / "updates"
        / "year=2099"
        / "nuclei-updates-2099-01-01.parquet"
    )
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["nuclei"]["ok"] is False


def test_rebuild_catalog_covers_nuclei(cfg, tmp_path, monkeypatch):
    _patch_download(monkeypatch, tmp_path, _initial_files())
    pipeline.update_nuclei(cfg, today=date(2026, 7, 12))

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.nuclei_history").fetchone()[0] == 3
    assert con.execute("SELECT count(*) FROM frozen.nuclei").fetchone()[0] == 3
