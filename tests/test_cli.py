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
