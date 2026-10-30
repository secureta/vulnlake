import io
import zipfile
from datetime import date

import duckdb
import pytest

from tests.conftest import make_cwe_xml_zip
from vlake import cwe, pipeline
from vlake.config import Config
from vlake.lake import Lake

LM1 = "Thu, 30 Apr 2026 09:15:04 GMT"
LM2 = "Fri, 30 Oct 2026 09:00:00 GMT"


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


def _patch_fetch(monkeypatch, zip_bytes, last_modified, *, conditional=False):
    """cwe.fetch を偽装し、渡された prev_last_modified の記録を返す。

    zip_bytes=None は 304 (not-modified) を意味する。
    """
    calls = []

    def fake_fetch(prev_last_modified=None):
        calls.append(prev_last_modified)
        if zip_bytes is None or (conditional and prev_last_modified == last_modified):
            return None
        return zip_bytes, last_modified

    monkeypatch.setattr(cwe, "fetch", fake_fetch)
    return calls


def test_update_cwe_initial_full_load(cfg, monkeypatch):
    # backfill は存在しない: カタログが空でも初回 update が全量投入になる
    calls = _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    msg = pipeline.update_cwe(cfg)
    assert msg == "published 4.20 (5 records)"
    assert calls == [None]  # 初回は Last-Modified 未保存なので無条件 GET
    assert (cfg.local_dir / "cwe" / "version=4.20" / "cwe-4.20.parquet").exists()
    # Last-Modified はカタログ公開成功後に保存される
    assert (cfg.local_dir / "cwe" / "last-modified.txt").read_text().strip() == LM1

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5
    abstraction, status = con.execute(
        "SELECT abstraction, status FROM frozen.cwe WHERE cwe_id = 'CWE-79'"
    ).fetchone()
    assert (abstraction, status) == ("Base", "Stable")
    # 既存テーブルの cwe VARCHAR[] 列との JOIN を想定した relations 構造
    kids = con.execute(
        "SELECT r.target_id FROM frozen.cwe, UNNEST(relations) AS t(r) "
        "WHERE cwe_id = 'CWE-79' AND r.nature = 'ChildOf'"
    ).fetchall()
    assert kids == [("CWE-74",)]
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert "cwe" in names


def test_update_cwe_not_modified_short_circuits(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    calls = _patch_fetch(monkeypatch, None, None)
    assert pipeline.update_cwe(cfg) == "not-modified"
    assert calls == [LM1]  # 保存済み Last-Modified が条件付き GET に渡る


def test_update_cwe_recovers_empty_unregistered_snapshot(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    pending = cfg.local_dir / cwe.key_for_version("5.0")
    pending.parent.mkdir(parents=True)
    cwe.write_parquet(cwe.rows_to_table([]), pending)
    marker = cfg.local_dir / cwe.LAST_MODIFIED_KEY
    marker.write_text(LM2 + "\n")
    assert pipeline.verify(cfg)["ok"] is False

    calls = _patch_fetch(
        monkeypatch,
        make_cwe_xml_zip(
            namespace="http://cwe.mitre.org/cwe-8",
            version="5.0",
            date_str="2026-10-28",
        ),
        LM2,
        conditional=True,
    )
    assert pipeline.update_cwe(cfg) == "published 5.0 (5 records)"
    assert calls == [None]
    assert marker.read_text().strip() == LM2
    with _attach(cfg) as con:
        assert (
            con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 10
        )
        assert con.execute(
            "SELECT DISTINCT cwe_version FROM frozen.cwe"
        ).fetchall() == [("5.0",)]
    assert pipeline.verify(cfg)["ok"] is True

    calls = _patch_fetch(monkeypatch, None, None)
    assert pipeline.update_cwe(cfg) == "not-modified"
    assert calls == [LM2]


@pytest.mark.parametrize("missing_catalog", [False, True])
@pytest.mark.parametrize("missing_data", [False, True])
def test_update_cwe_marker_without_registered_snapshot(
    cfg, monkeypatch, missing_catalog, missing_data
):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    catalog = cfg.local_dir / pipeline.CATALOG_KEY
    catalog.unlink()
    if missing_data:
        (cfg.local_dir / cwe.key_for_version("4.20")).unlink()
    if not missing_catalog:
        lake = Lake(catalog)
        try:
            lake.ensure_tables()
        finally:
            lake.close()
    calls = _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1, conditional=True)
    assert pipeline.update_cwe(cfg) == "published 4.20 (5 records)"
    assert calls == [None]
    assert pipeline.verify(cfg)["ok"] is True


def test_update_cwe_recovery_publish_failure_is_retryable(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    pending = cfg.local_dir / cwe.key_for_version("5.0")
    pending.parent.mkdir(parents=True)
    cwe.write_parquet(cwe.rows_to_table([]), pending)
    catalog = cfg.local_dir / pipeline.CATALOG_KEY
    before = catalog.read_bytes()
    marker = cfg.local_dir / cwe.LAST_MODIFIED_KEY
    marker.write_text(LM2 + "\n")
    calls = _patch_fetch(
        monkeypatch,
        make_cwe_xml_zip(
            namespace="http://cwe.mitre.org/cwe-8",
            version="5.0",
            date_str="2026-10-28",
        ),
        LM2,
        conditional=True,
    )

    def fail_publish(*args):
        raise RuntimeError("publish failed")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline, "_publish_catalog", fail_publish)
        with pytest.raises(RuntimeError, match="publish failed"):
            pipeline.update_cwe(cfg)
    assert catalog.read_bytes() == before
    assert marker.read_text() == LM2 + "\n"
    assert pipeline.update_cwe(cfg) == "published 5.0 (5 records)"
    assert calls == [None, None]
    assert pipeline.verify(cfg)["ok"] is True


def test_update_cwe_same_version_already_registered(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    # Last-Modified だけ変わりバージョンが同じ (再アップロード等) 場合は登録済み skip
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM2)
    assert pipeline.update_cwe(cfg) == "already-registered 4.20"
    # 以後の再ダウンロードを避けるため新しい Last-Modified を保存する
    assert (cfg.local_dir / "cwe" / "last-modified.txt").read_text().strip() == LM2

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5


def test_update_cwe_new_version_switches_view(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    _patch_fetch(
        monkeypatch, make_cwe_xml_zip(version="4.21", date_str="2026-10-30"), LM2
    )
    assert pipeline.update_cwe(cfg) == "published 4.21 (5 records)"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 10
    assert con.execute("SELECT DISTINCT cwe_version FROM frozen.cwe").fetchall() == [
        ("4.21",)
    ]
    assert con.execute("SELECT max(release_date) FROM frozen.cwe").fetchone()[
        0
    ] == date(2026, 10, 30)


def test_update_cwe_failure_does_not_save_last_modified(cfg, monkeypatch):
    # 公開前に失敗したら Last-Modified は保存されず、次回は無条件 GET からやり直す
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)

    def boom(table, path):
        raise RuntimeError("boom")

    monkeypatch.setattr(cwe, "write_parquet", boom)
    with pytest.raises(RuntimeError, match="boom"):
        pipeline.update_cwe(cfg)
    assert not (cfg.local_dir / "cwe" / "last-modified.txt").exists()
    assert not (cfg.local_dir / "vlake.ducklake").exists()  # カタログ未公開


def test_verify_covers_cwe_and_excludes_from_staleness(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)  # release_date 2026-04-30
    pipeline.update_cwe(cfg)

    # release_date が数ヶ月前でも CWE は鮮度チェックの対象外 (更新が無いのが正常)
    report = pipeline.verify(cfg, max_age_days=3)
    assert report["ok"] is True
    assert report["stale"] is False
    rep = report["datasets"]["cwe"]
    assert rep["files_in_storage"] == rep["files_in_catalog"] == 1
    assert rep["row_count"] == 5
    assert rep["max_date"] == date(2026, 4, 30)
    assert rep["stale"] is False


def test_verify_detects_cwe_stray_file(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    stray = cfg.local_dir / "cwe" / "version=9.99" / "cwe-9.99.parquet"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"not parquet")

    report = pipeline.verify(cfg)
    assert report["ok"] is False
    assert report["datasets"]["cwe"]["ok"] is False


def test_verify_ignores_last_modified_marker(cfg, monkeypatch):
    # cwe/last-modified.txt は Parquet ではないので整合検査の対象にならない
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    assert (cfg.local_dir / "cwe" / "last-modified.txt").exists()
    assert pipeline.verify(cfg)["ok"] is True


def test_rebuild_catalog_covers_cwe(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.cwe_history").fetchone()[0] == 5
    assert con.execute("SELECT count(*) FROM frozen.cwe").fetchone()[0] == 5


def test_update_cwe_schema_8_and_verify(cfg, monkeypatch):
    _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
    pipeline.update_cwe(cfg)
    _patch_fetch(
        monkeypatch,
        make_cwe_xml_zip(
            namespace="http://cwe.mitre.org/cwe-8",
            version="5.0",
            date_str="2026-10-28",
        ),
        LM2,
    )
    assert pipeline.update_cwe(cfg) == "published 5.0 (5 records)"
    with _attach(cfg) as con:
        assert con.execute(
            "SELECT DISTINCT cwe_version FROM frozen.cwe"
        ).fetchall() == [("5.0",)]
        assert con.execute(
            "SELECT entry_type FROM frozen.cwe WHERE cwe_id = 'CWE-137'"
        ).fetchone() == ("category",)
    assert pipeline.verify(cfg)["ok"] is True


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "invalid",
    ["unknown", "empty", "empty_parser", "duplicate", "child_namespace", "xhtml"],
)
def test_update_cwe_invalid_input_never_writes(cfg, monkeypatch, existing, invalid):
    if existing:
        _patch_fetch(monkeypatch, make_cwe_xml_zip(), LM1)
        pipeline.update_cwe(cfg)
    before = {
        p.relative_to(cfg.local_dir): p.read_bytes()
        for p in cfg.local_dir.rglob("*")
        if p.is_file()
    }
    kwargs = (
        {"namespace": "http://cwe.mitre.org/cwe-9"}
        if invalid == "unknown"
        else {"weaknesses": [], "categories": [], "views": []}
    )
    raw = make_cwe_xml_zip(**kwargs)
    if invalid in {"duplicate", "child_namespace", "xhtml"}:
        raw = make_cwe_xml_zip(namespace="http://cwe.mitre.org/cwe-8", version="5.0")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            xml = archive.read(archive.namelist()[0])
        if invalid == "duplicate":
            xml = xml.replace(b"<Groupings>", b"<Groupings/><Groupings>")
        else:
            namespace = (
                "http://www.w3.org/1999/xhtml"
                if invalid == "xhtml"
                else "http://cwe.mitre.org/cwe-7"
            )
            xml = xml.replace(
                b"<Summary>", f'<Summary xmlns="{namespace}">'.encode()
            ).replace(
                b"<Relationships>", f'<Relationships xmlns="{namespace}">'.encode()
            )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("catalog.xml", xml)
        raw = buf.getvalue()
    _patch_fetch(monkeypatch, raw, LM2)
    if invalid == "empty_parser":
        monkeypatch.setattr(
            cwe, "parse_catalog", lambda _: ("5.0", date(2026, 10, 28), [])
        )

    def forbidden(*args, **kwargs):
        pytest.fail("不正な入力で公開処理に到達しました")

    monkeypatch.setattr(pipeline, "_publish_catalog", forbidden)
    monkeypatch.setattr(cwe, "write_parquet", forbidden)
    with pytest.raises(ValueError):
        pipeline.update_cwe(cfg)
    after = {
        p.relative_to(cfg.local_dir): p.read_bytes()
        for p in cfg.local_dir.rglob("*")
        if p.is_file()
    }
    assert after == before
