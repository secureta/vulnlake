from datetime import date

from click.testing import CliRunner

from tests.conftest import make_epss_csv_gz
from vlake import epss
from vlake.cli import main


def test_update_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)

    result = CliRunner().invoke(main, ["update", "epss"])
    assert result.exit_code == 0, result.output
    assert "published 2026-07-10" in result.output

    result = CliRunner().invoke(main, ["verify"])
    assert result.exit_code == 0, result.output
    assert "'ok': True" in result.output


def test_verify_exit_1_when_stale(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    raw = make_epss_csv_gz(
        date(2021, 4, 14),
        [("CVE-2020-5902", 0.65117)],
        with_comment=False,
        with_percentile=False,
    )
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)

    result = CliRunner().invoke(main, ["update", "epss", "--date", "2021-04-14"])
    assert result.exit_code == 0, result.output

    result = CliRunner().invoke(main, ["verify", "--max-age-days", "3"])
    assert result.exit_code == 1
    assert "'ok': True" in result.output
    assert "'stale': True" in result.output


def test_update_with_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    seen = {}

    def fake_fetch(target=None):
        seen["target"] = target
        return None

    monkeypatch.setattr(epss, "fetch", fake_fetch)
    result = CliRunner().invoke(main, ["update", "epss", "--date", "2026-07-01"])
    assert result.exit_code == 0
    assert seen["target"] == date(2026, 7, 1)
    assert "not-published-yet" in result.output


def test_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    for cmd in ("update", "backfill", "rebuild-catalog", "verify"):
        assert cmd in result.output


def test_update_cve_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline, "update_cve", lambda cfg: "published 2026-07-11 (5 records, 0 bad)"
    )
    result = CliRunner().invoke(main, ["update", "cve"])
    assert result.exit_code == 0, result.output
    assert "published 2026-07-11" in result.output


def test_update_cve_refused_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline,
        "update_cve",
        lambda cfg: "refused: cve_history is empty; run backfill cve first",
    )
    result = CliRunner().invoke(main, ["update", "cve"])
    assert result.exit_code == 1
    assert "refused" in result.output


def test_update_cve_rejects_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["update", "cve", "--date", "2026-07-01"])
    assert result.exit_code != 0
    assert "--date" in result.output


def test_backfill_cve_via_cli_with_source(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path / "bucket"))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from tests.conftest import make_baseline_zip, make_cve_record

    zp = tmp_path / "baseline.zip"
    make_baseline_zip(zp, [make_cve_record("CVE-2021-0001")])
    result = CliRunner().invoke(main, ["backfill", "cve", "--source", str(zp)])
    assert result.exit_code == 0, result.output
    assert "backfilled 1 year files" in result.output


def test_backfill_epss_requires_source(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["backfill", "epss"])
    assert result.exit_code != 0


def test_update_ghsa_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline, "update_ghsa", lambda cfg: "published 2026-07-12 (5 records, 0 bad)"
    )
    result = CliRunner().invoke(main, ["update", "ghsa"])
    assert result.exit_code == 0, result.output
    assert "published 2026-07-12" in result.output


def test_update_ghsa_refused_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline,
        "update_ghsa",
        lambda cfg: "refused: ghsa_history is empty; run backfill ghsa first",
    )
    result = CliRunner().invoke(main, ["update", "ghsa"])
    assert result.exit_code == 1
    assert "refused" in result.output


def test_update_ghsa_rejects_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["update", "ghsa", "--date", "2026-07-01"])
    assert result.exit_code != 0
    assert "--date" in result.output


def test_backfill_ghsa_via_cli_with_source(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path / "bucket"))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from tests.conftest import make_ghsa_record, make_ghsa_tarball

    tp = tmp_path / "advisory-database.tar.gz"
    make_ghsa_tarball(
        tp, [make_ghsa_record("GHSA-aaaa-bbbb-cccc", published="2021-01-01T00:00:00Z")]
    )
    result = CliRunner().invoke(main, ["backfill", "ghsa", "--source", str(tp)])
    assert result.exit_code == 0, result.output
    assert "backfilled 1 year files" in result.output


def test_update_exploitdb_via_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline,
        "update_exploitdb",
        lambda cfg: "published 2026-07-12 (1 records, 0 bad)",
    )
    result = CliRunner().invoke(main, ["update", "exploitdb"])
    assert result.exit_code == 0, result.output
    assert "published 2026-07-12" in result.output


def test_update_exploitdb_refused_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    monkeypatch.setattr(
        pipeline,
        "update_exploitdb",
        lambda cfg: "refused: exploitdb_history is empty; run backfill exploitdb first",
    )
    result = CliRunner().invoke(main, ["update", "exploitdb"])
    assert result.exit_code == 1
    assert "refused" in result.output


def test_update_exploitdb_rejects_date_option(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    result = CliRunner().invoke(main, ["update", "exploitdb", "--date", "2026-07-01"])
    assert result.exit_code != 0
    assert "--date" in result.output


def test_backfill_exploitdb_via_cli_with_source(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path / "bucket"))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    csv_path = tmp_path / "files_exploits.csv"
    csv_path.write_text("id,file,description,date,author,type,platform,port\n")

    called = {}

    def fake_backfill(cfg, source):
        called["source"] = source
        return "backfilled 1 year files (skipped 0 years, 0 bad records)"

    monkeypatch.setattr(pipeline, "backfill_exploitdb", fake_backfill)
    result = CliRunner().invoke(
        main, ["backfill", "exploitdb", "--source", str(csv_path)]
    )
    assert result.exit_code == 0, result.output
    assert "backfilled 1 year files" in result.output
    assert called["source"] == csv_path


def test_backfill_exploitdb_via_cli_without_source(monkeypatch, tmp_path):
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path / "bucket"))
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    from vlake import pipeline

    called = {}

    def fake_backfill(cfg, source):
        called["source"] = source
        return "backfilled 1 year files (skipped 0 years, 0 bad records)"

    monkeypatch.setattr(pipeline, "backfill_exploitdb", fake_backfill)
    result = CliRunner().invoke(main, ["backfill", "exploitdb"])
    assert result.exit_code == 0, result.output
    assert "backfilled 1 year files" in result.output
    assert called["source"] is None
