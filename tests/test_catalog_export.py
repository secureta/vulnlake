from datetime import date

import duckdb
import pytest

from tests.conftest import make_epss_csv_gz
from vlake import epss, pipeline
from vlake.config import Config
from vlake.lake import Lake, _sql_literal, export_compatible_catalog


def _catalog(path):
    lake = Lake(path, data_path=str(path.parent / "unused"))
    try:
        lake.ensure_tables()
        assert lake.query(
            "SELECT value FROM lake.options() WHERE option_name = 'version'"
        ) == [("1.0",)]
    finally:
        lake.close()


@pytest.mark.parametrize(
    "name",
    ["working's catalog.ducklake", "catalog'; CREATE TABLE injected(i INT); --"],
)
def test_export_preserves_source_and_uses_legacy_storage(tmp_path, name):
    source = tmp_path / name
    destination = tmp_path / "public's catalog.ducklake"
    _catalog(source)
    before = source.read_bytes()
    export_compatible_catalog(source, destination)
    assert source.read_bytes() == before
    with duckdb.connect(str(destination), read_only=True) as con:
        assert con.execute(
            "SELECT tags['storage_version'] FROM duckdb_databases() WHERE path = ?",
            [str(destination)],
        ).fetchone() == ("v1.5.0+",)
        assert con.execute(
            "SELECT value FROM ducklake_metadata WHERE key = 'version'"
        ).fetchall() == [("1.0",)]
        assert con.execute(
            "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'injected'"
        ).fetchone() == (0,)
    assert set(tmp_path.iterdir()) == {source, destination}


def test_export_rejects_same_path(tmp_path):
    source = tmp_path / "catalog.ducklake"
    _catalog(source)
    before = source.read_bytes()
    with pytest.raises(ValueError, match="別ファイル"):
        export_compatible_catalog(source, source)
    assert source.read_bytes() == before


def test_export_rejects_newer_ducklake_format(tmp_path):
    source = tmp_path / "new.ducklake"
    destination = tmp_path / "public.ducklake"
    with duckdb.connect() as con:
        con.execute("INSTALL ducklake; LOAD ducklake")
        con.execute(
            f"ATTACH {_sql_literal('ducklake:' + str(source))} AS lake "
            "(DUCKLAKE_VERSION '1.1')"
        )
    before = source.read_bytes()
    destination.write_bytes(b"previous public catalog")
    with pytest.raises(ValueError, match="1.0"):
        export_compatible_catalog(source, destination)
    assert source.read_bytes() == before
    assert destination.read_bytes() == b"previous public catalog"
    assert set(tmp_path.iterdir()) == {source, destination}


def test_export_copy_failure_leaves_destination_untouched(tmp_path, monkeypatch):
    source = tmp_path / "working.ducklake"
    destination = tmp_path / "public.ducklake"
    _catalog(source)
    before = source.read_bytes()
    destination.write_bytes(b"previous public catalog")
    connect = duckdb.connect

    class FailingConnection:
        def __enter__(self):
            self.con = connect()
            return self

        def __exit__(self, *args):
            self.con.close()

        def execute(self, query, parameters=None):
            if query == "COPY FROM DATABASE src TO dst":
                raise duckdb.IOException("injected copy failure")
            return self.con.execute(query, parameters)

    monkeypatch.setattr(duckdb, "connect", FailingConnection)
    with pytest.raises(duckdb.IOException, match="injected copy failure"):
        export_compatible_catalog(source, destination)
    assert source.read_bytes() == before
    assert destination.read_bytes() == b"previous public catalog"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("operation", ["update", "rebuild"])
def test_conversion_failure_prevents_publication_and_recovers(
    tmp_path, monkeypatch, existing, operation
):
    cfg = Config(
        s3_endpoint=None,
        s3_bucket=None,
        public_url=None,
        local_dir=tmp_path / "bucket",
    )
    catalog = cfg.local_dir / pipeline.CATALOG_KEY
    old = make_epss_csv_gz(date(2026, 7, 9), [("CVE-2026-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: old)
    if existing:
        pipeline.update_epss(cfg)
    before = catalog.read_bytes() if existing else None
    day = date(2026, 7, 10)
    raw = make_epss_csv_gz(day, [("CVE-2026-0001", 0.2, 0.6)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    if operation == "rebuild":
        table, _, _ = epss.parse(raw, fallback_date=day)
        parquet = cfg.local_dir / epss.key_for(day)
        parquet.parent.mkdir(parents=True, exist_ok=True)
        epss.write_parquet(table, parquet)
    run = pipeline.update_epss if operation == "update" else pipeline.rebuild_catalog

    def fail_export(source, destination):
        with duckdb.connect(str(source), read_only=True) as con:
            assert con.execute("SELECT count(*) FROM ducklake_data_file").fetchone()[
                0
            ] == (2 if existing else 1)
        raise OSError("injected conversion failure")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline, "export_compatible_catalog", fail_export)
        with pytest.raises(OSError, match="injected conversion failure"):
            run(cfg)
    assert catalog.exists() == existing
    if existing:
        assert catalog.read_bytes() == before
    assert (cfg.local_dir / epss.key_for(day)).exists()
    run(cfg)
    assert pipeline.verify(cfg)["datasets"]["epss"]["row_count"] == (
        2 if existing else 1
    )
    assert list(cfg.local_dir.glob("*.ducklake")) == [catalog]


def test_export_rejects_unexpected_storage_version(tmp_path, monkeypatch):
    source = tmp_path / "working.ducklake"
    destination = tmp_path / "public.ducklake"
    _catalog(source)
    destination.write_bytes(b"previous public catalog")
    connect = duckdb.connect

    class InvalidStorageConnection:
        def __enter__(self):
            self.con = connect()
            return self

        def __exit__(self, *args):
            self.con.close()

        def execute(self, query, parameters=None):
            if query.startswith("SELECT tags['storage_version']"):
                return self.con.execute("SELECT 'v2.0.0+'")
            return self.con.execute(query, parameters)

    monkeypatch.setattr(duckdb, "connect", InvalidStorageConnection)
    with pytest.raises(ValueError, match="ストレージ形式"):
        export_compatible_catalog(source, destination)
    assert destination.read_bytes() == b"previous public catalog"
    assert set(tmp_path.iterdir()) == {source, destination}
