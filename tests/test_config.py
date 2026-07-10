import vlake

from pathlib import Path

import pytest

from vlake.config import Config


def test_import():
    assert vlake.__version__


def test_from_env_local(monkeypatch, tmp_path):
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    cfg = Config.from_env()
    assert cfg.local_dir == tmp_path
    assert cfg.s3_bucket is None


def test_from_env_s3(monkeypatch):
    monkeypatch.setenv("VLAKE_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("VLAKE_S3_ENDPOINT", "https://acc.r2.cloudflarestorage.com")
    monkeypatch.setenv("VLAKE_PUBLIC_URL", "https://data.example.com/")
    monkeypatch.delenv("VLAKE_LOCAL_DIR", raising=False)
    cfg = Config.from_env()
    assert cfg.s3_bucket == "my-bucket"
    assert cfg.public_url == "https://data.example.com"  # 末尾スラッシュ除去


def test_from_env_missing(monkeypatch):
    for var in ("VLAKE_S3_BUCKET", "VLAKE_LOCAL_DIR", "VLAKE_PUBLIC_URL", "VLAKE_S3_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SystemExit):
        Config.from_env()


def test_from_env_s3_requires_public_url(monkeypatch):
    monkeypatch.setenv("VLAKE_S3_BUCKET", "my-bucket")
    monkeypatch.delenv("VLAKE_PUBLIC_URL", raising=False)
    monkeypatch.delenv("VLAKE_LOCAL_DIR", raising=False)
    with pytest.raises(SystemExit):
        Config.from_env()
