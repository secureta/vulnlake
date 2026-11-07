import json
import os
import subprocess
from datetime import date, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from tests.catalog_reader import PUBLIC_TABLES, PUBLIC_VIEWS, read_metadata
from tests.conftest import make_cve_record, make_epss_csv_gz
from vlake import (
    cloudflare_waf,
    cvelist,
    cwe,
    epss,
    exploitdb,
    ghsa,
    kev,
    mitre,
    nuclei,
    pipeline,
)
from vlake.config import Config
from vlake.lake import Lake
from vlake.storage import LocalStorage


@pytest.fixture
def reader_python():
    value = os.environ.get("VLAKE_COMPAT_PYTHON")
    if not value:
        pytest.skip("VLAKE_COMPAT_PYTHON is not set")
    path = Path(value)
    assert path.is_absolute() and path.is_file()
    return path


@pytest.fixture
def cfg(tmp_path, reader_python):
    return Config(
        s3_endpoint=None,
        s3_bucket=None,
        public_url=None,
        local_dir=tmp_path / "bucket's data",
    )


def _reader(reader_python, catalog, **kwargs):
    try:
        result = subprocess.run(
            args=[str(reader_python), "-I", "tests/catalog_reader.py"],
            cwd=Path(__file__).resolve().parent.parent,
            input=json.dumps({"catalog": str(catalog), **kwargs}),
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )
    except subprocess.CalledProcessError as exc:
        pytest.fail(exc.stderr)
    return json.loads(result.stdout)


def _published(reader_python, cfg):
    result = _reader(reader_python, cfg.local_dir / pipeline.CATALOG_KEY)
    assert result["reader_version"].startswith("1.5.")
    assert set(result["tables"]) == set(PUBLIC_TABLES)
    assert set(result["views"]) == set(PUBLIC_VIEWS)
    assert len(result["views"]["datasets"]) == 10
    assert len(result["views"]["ssvc_decision"]) == 36
    version = [
        row["value"]
        for row in result["metadata"]["ducklake_metadata"]
        if row["key"] == "version"
    ]
    assert version == ["1.0"]
    registered = {
        row["path"]
        for row in result["metadata"]["ducklake_data_file"]
        if row["end_snapshot"] is None
    }
    storage = LocalStorage(cfg.local_dir)
    assert registered == {
        storage.url(key) for key in storage.list("") if key.endswith(".parquet")
    }
    return result


def test_published_catalog_lifecycle(reader_python, cfg, monkeypatch, tmp_path):
    def update(day, score):
        raw = make_epss_csv_gz(day, [("CVE-2021-44228", score, 0.9)])
        monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
        return pipeline.update_epss(cfg)

    assert update(date(2026, 7, 9), 0.1) == "published 2026-07-09"
    first = _published(reader_python, cfg)
    assert first["tables"]["epss"][0]["epss"] == 0.1
    assert update(date(2026, 7, 10), 0.2) == "published 2026-07-10"
    updated = _published(reader_python, cfg)
    assert [row["epss"] for row in updated["tables"]["epss"]] == [0.1, 0.2]
    assert update(date(2026, 7, 10), 0.2) == "already-registered 2026-07-10"
    assert _published(reader_python, cfg) == updated

    source = tmp_path / "mirror" / "2021"
    source.mkdir(parents=True)
    (source / "epss_scores-2021-04-14.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 14),
            [("CVE-2021-44228", 0.3)],
            with_comment=False,
            with_percentile=False,
        )
    )
    assert pipeline.backfill_epss(cfg, source.parent, today=date(2026, 7, 10)) == (
        "backfilled 1 year files, 0 daily files (skipped 0 years, 0 daily)"
    )
    backfilled = _published(reader_python, cfg)
    assert len(backfilled["tables"]["epss"]) == 3
    assert backfilled["tables"]["epss"][0]["date"] == "2021-04-14"
    assert backfilled["tables"]["epss"][0]["percentile"] is None
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 3 files"
    rebuilt = _published(reader_python, cfg)
    assert rebuilt["tables"] == backfilled["tables"]
    assert rebuilt["views"] == backfilled["views"]


def _representative_tables():
    day = date(2026, 7, 10)
    timestamp = datetime(2026, 7, 10, 12, 34, 56, 123456)
    cve_id = "CVE-2021-44228"
    metric = {
        "other": {
            "type": "ssvc",
            "content": {
                "version": "2.0.3",
                "role": "CISA Coordinator",
                "timestamp": "2026-07-10T12:34:56.123456Z",
                "decision": "act",
                "options": [
                    {"Exploitation": "active"},
                    {"Automatable": "yes"},
                    {"Technical Impact": "total"},
                    {"Mission and Well-Being Impact": "high"},
                ],
            },
        }
    }
    cve_row = cvelist.parse_record(
        json.dumps(
            make_cve_record(cve_id, cwes=["CWE-502"], adp_metrics=[metric])
        ).encode()
    )
    definitions = [
        (
            "epss",
            epss.key_for(day),
            epss.SCHEMA,
            {
                "cve": cve_id,
                "epss": 0.5,
                "percentile": None,
                "date": day,
                "model_version": "v2026.06.15",
            },
        ),
        ("cve_history", cvelist.key_for_update(day), cvelist.SCHEMA, cve_row),
        (
            "ghsa_history",
            ghsa.key_for_update(day),
            ghsa.SCHEMA,
            {
                "ghsa": "GHSA-aaaa-bbbb-cccc",
                "cve": cve_id,
                "cwe": ["CWE-502"],
                "affected": [
                    {
                        "ecosystem": "Maven",
                        "package": "log4j-core",
                        "introduced": "0",
                        "fixed": "2.17.1",
                        "last_affected": None,
                    }
                ],
                "published": timestamp,
                "modified": timestamp,
                "raw": "{}",
            },
        ),
        (
            "exploitdb_history",
            exploitdb.key_for_update(day),
            exploitdb.SCHEMA,
            {
                "edb_id": 123,
                "cve": [cve_id],
                "port": None,
                "verified": True,
                "date_published": day,
                "date_added": day,
                "date_updated": day,
            },
        ),
        (
            "nuclei_history",
            nuclei.key_for_update(day),
            nuclei.SCHEMA,
            {
                "template_id": "log4j",
                "name": "Removed template",
                "cve": [cve_id],
                "author": ["author's name"],
                "tags": [],
                "reference": None,
                "fetched_date": day,
                "removed": True,
            },
        ),
        (
            "kev_history",
            kev.key_for_update(day),
            kev.SCHEMA,
            {
                "cve": cve_id,
                "cwe": ["CWE-502"],
                "date_added": day,
                "due_date": date(2026, 7, 31),
                "fetched_date": day,
                "removed": False,
            },
        ),
        (
            "cloudflare_waf_history",
            cloudflare_waf.key_for_update(day),
            cloudflare_waf.SCHEMA,
            {
                "identifier": "rule-1",
                "identifier_type": "rule",
                "cve": cve_id,
                "source_url": "https://example.com/waf",
                "source_date": None,
                "fetched_date": day,
                "removed": True,
            },
        ),
        (
            "cwe_history",
            cwe.key_for_version("4.20"),
            cwe.SCHEMA,
            {
                "cwe_id": "CWE-502",
                "entry_type": "weakness",
                "name": "Deserialization",
                "relations": [{"nature": "ChildOf", "target_id": "CWE-20"}],
                "cwe_version": "4.20",
                "release_date": day,
            },
        ),
        (
            "attack_history",
            mitre.attack_key_for_update(day),
            mitre.ATTACK_SCHEMA,
            {
                "matrix": "enterprise",
                "attack_id": "T1190",
                "object_id": "attack-1",
                "object_type": "attack-pattern",
                "name": "Exploit Public-Facing Application",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "revoked": False,
                "deprecated": False,
                "modified": timestamp,
                "raw": "{}",
            },
        ),
        (
            "attack_relationship_history",
            mitre.attack_relationship_key_for_update(day),
            mitre.ATTACK_RELATIONSHIP_SCHEMA,
            {
                "matrix": "enterprise",
                "relationship_id": "relationship-1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set-1",
                "target_ref": "attack-1",
                "target_attack_id": "T1190",
                "revoked": False,
                "deprecated": False,
                "modified": timestamp,
                "raw": "{}",
            },
        ),
        (
            "capec_history",
            mitre.capec_key_for_update(day),
            mitre.CAPEC_SCHEMA,
            {
                "capec_id": "CAPEC-1",
                "object_id": "capec-1",
                "name": "Sample pattern",
                "cwe": ["CWE-502"],
                "attack": ["T1190"],
                "revoked": False,
                "deprecated": False,
                "modified": timestamp,
                "raw": "{}",
            },
        ),
    ]
    return [
        (name, key, pa.Table.from_pylist([row], schema=schema))
        for name, key, schema, row in definitions
    ]


def test_all_tables_views_and_exported_history(reader_python, cfg, tmp_path):
    storage = LocalStorage(cfg.local_dir)
    workdir = tmp_path / "writer"
    workdir.mkdir()
    lake, catalog = pipeline._open_lake(storage, workdir)
    expected = {}
    try:
        for name, key, table in _representative_tables():
            parquet = workdir / "data.parquet"
            pq.write_table(table, parquet)
            storage.put(parquet, key)
            lake.con.execute("BEGIN")
            lake.set_message("compat seed " + name)
            assert lake.add_file(name, storage.url(key))
            lake.con.execute("COMMIT")
            expected[name] = json.loads(json.dumps(table.to_pylist(), default=str))
        pipeline._publish_catalog(storage, lake, catalog)
    finally:
        lake.close()

    published = _published(reader_python, cfg)
    assert published["tables"] == expected
    assert all(published["views"].values())
    assert published["views"]["cve_ssvc"][0]["recorded_decision"] == "act"
    assert published["views"]["ghsa"][0]["affected"][0]["last_affected"] is None
    assert published["views"]["cwe_attack_patterns"][0]["attack_id"] == "T1190"
    metadata = read_metadata(catalog)
    assert published["metadata"] == metadata
    snapshots = metadata["ducklake_snapshot"]
    assert len(snapshots) > len(PUBLIC_TABLES)
    assert len(metadata["ducklake_snapshot_changes"]) > len(PUBLIC_TABLES)
    messages = {row["commit_message"] for row in metadata["ducklake_snapshot_changes"]}
    assert {"compat seed " + name for name in PUBLIC_TABLES} <= messages

    from vlake.lake import export_compatible_catalog

    destination = tmp_path / "exported's catalog.ducklake"
    export_compatible_catalog(catalog, destination)
    exported = _reader(reader_python, destination)
    assert exported == published
    assert read_metadata(catalog) == metadata
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 11 files"
    rebuilt = _published(reader_python, cfg)
    assert rebuilt["tables"] == published["tables"]
    assert rebuilt["views"] == published["views"]


def test_legacy_catalog_updated_by_current_writer(
    reader_python, cfg, tmp_path, monkeypatch
):
    storage = LocalStorage(cfg.local_dir)
    day = date(2026, 7, 9)
    table, _, _ = epss.parse(
        make_epss_csv_gz(day, [("CVE-2021-44228", 0.1, 0.9)]), fallback_date=day
    )
    parquet = tmp_path / "legacy.parquet"
    epss.write_parquet(table, parquet)
    key = epss.key_for(day)
    storage.put(parquet, key)
    catalog = tmp_path / "legacy.ducklake"
    legacy_metadata = _reader(
        reader_python, catalog, mode="create", parquet=storage.url(key)
    )
    lake = Lake(catalog)
    try:
        lake.ensure_tables()
        pipeline._publish_catalog(storage, lake, catalog)
    finally:
        lake.close()
    initial = _published(reader_python, cfg)
    assert initial["tables"]["epss"][0]["epss"] == 0.1
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-2021-44228", 0.2, 0.95)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"
    updated = _published(reader_python, cfg)
    assert [row["epss"] for row in updated["tables"]["epss"]] == [0.1, 0.2]
    for name in ("ducklake_snapshot", "ducklake_snapshot_changes"):
        assert all(row in updated["metadata"][name] for row in legacy_metadata[name])
    assert any(
        row["commit_message"] == "legacy seed" and row["author"] == "compat-reader"
        for row in updated["metadata"]["ducklake_snapshot_changes"]
    )
