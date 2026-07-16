from datetime import date
from pathlib import Path

import duckdb
import pytest

from vlake import cloudflare_waf, pipeline
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


def _patch_download(monkeypatch, files: dict[str, str]):
    def fake_download(dest_dir: Path):
        written = []
        for rel, text in files.items():
            p = dest_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
            written.append(p)
        return written

    monkeypatch.setattr(cloudflare_waf, "download", fake_download)


def _initial_files():
    return {
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": """---
title: "WAF Release - 2026-03-12 - Emergency"
date: 2026-03-12
---
This release adds detections for CVE-2026-1281 and CVE-2026-1340.
""",
        "src/content/changelog/waf/2026-04-01-waf-release.mdx": """---
title: "WAF Release - 2026-04-01"
date: 2026-04-01
---
This release mentions GHSA-abcd-1234-wxyz.
""",
    }


def test_update_cloudflare_waf_initial_full_load(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())

    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    assert msg == "published 2026-07-16 (3 records)"
    assert (
        cfg.local_dir
        / "cloudflare_waf"
        / "updates"
        / "year=2026"
        / "cloudflare-waf-updates-2026-07-16.parquet"
    ).exists()
    con = _attach(cfg)
    assert (
        con.execute("SELECT count(*) FROM frozen.cloudflare_waf_history").fetchone()[0]
        == 3
    )
    assert (
        con.execute(
            "SELECT count(*) FROM frozen.cloudflare_waf WHERE NOT removed"
        ).fetchone()[0]
        == 3
    )
    assert (
        con.execute(
            "SELECT source_title FROM frozen.cloudflare_waf "
            "WHERE identifier = 'CVE-2026-1281' AND NOT removed"
        ).fetchone()[0]
        == "WAF Release - 2026-03-12 - Emergency"
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
    con.close()

    assert (
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))
        == "already-registered 2026-07-16"
    )
    assert (
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))
        == "no-new-records 2026-07-17"
    )


def test_update_cloudflare_waf_diff_tombstone_and_revival(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    changed = {
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": """---
title: "WAF Release - 2026-03-12 - Emergency Updated"
date: 2026-03-12
---
Updated context for CVE-2026-1281 only.
""",
        "src/content/changelog/waf/2026-05-01-waf-release.mdx": """---
title: "WAF Release - 2026-05-01"
date: 2026-05-01
---
New detection for CVE-2026-9999.
""",
    }
    _patch_download(monkeypatch, changed)

    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))
    assert msg == "published 2026-07-17 (4 records)"  # 変更+追加+削除2件

    con = _attach(cfg)
    removed = con.execute(
        "SELECT removed FROM frozen.cloudflare_waf WHERE identifier = 'CVE-2026-1340'"
    ).fetchone()[0]
    assert removed is True
    assert (
        con.execute(
            "SELECT source_title FROM frozen.cloudflare_waf "
            "WHERE identifier = 'CVE-2026-1281'"
        ).fetchone()[0]
        == "WAF Release - 2026-03-12 - Emergency Updated"
    )
    con.close()

    _patch_download(monkeypatch, _initial_files())
    msg = pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 18))
    assert msg == "published 2026-07-18 (4 records)"
    con = _attach(cfg)
    assert (
        con.execute(
            "SELECT removed FROM frozen.cloudflare_waf "
            "WHERE identifier = 'CVE-2026-1340'"
        ).fetchone()[0]
        is False
    )
    con.close()


def test_update_cloudflare_waf_refuses_empty_snapshot(cfg, monkeypatch):
    _patch_download(monkeypatch, {})

    with pytest.raises(RuntimeError, match="no vulnerability identifiers"):
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))


def test_update_cloudflare_waf_refuses_shrunken_snapshot(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    _patch_download(
        monkeypatch,
        {
            "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx": """---
title: "WAF Release"
date: 2026-03-12
---
Only CVE-2026-1281 remains.
"""
        },
    )
    with pytest.raises(RuntimeError, match="less than half"):
        pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 17))

    con = _attach(cfg)
    assert (
        con.execute("SELECT count(*) FROM frozen.cloudflare_waf_history").fetchone()[0]
        == 3
    )
    con.close()


def test_cve_sources_covers_cloudflare_waf(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    con = _attach(cfg)
    got = con.execute(
        "SELECT cve, has_cloudflare_waf, cloudflare_waf_count "
        "FROM frozen.cve_sources WHERE cve IN ('CVE-2026-1281', 'CVE-2026-1340') "
        "ORDER BY cve"
    ).fetchall()
    assert got == [
        ("CVE-2026-1281", True, 1),
        ("CVE-2026-1340", True, 1),
    ]
    con.close()


def test_verify_and_rebuild_cover_cloudflare_waf(cfg, monkeypatch):
    _patch_download(monkeypatch, _initial_files())
    pipeline.update_cloudflare_waf(cfg, today=date(2026, 7, 16))

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    rep = report["datasets"]["cloudflare_waf"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 3
    assert rep["max_date"] == date(2026, 7, 16)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cloudflare_waf").fetchone()[0] == 3
    con.close()
