import pytest

import vlake
from vlake.config import Config


def test_import():
    assert vlake.__version__


def test_from_env_local(monkeypatch, tmp_path):
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    cfg = Config.from_env()
    assert cfg.local_dir == tmp_path
    assert cfg.s3_bucket is None


@pytest.mark.parametrize(
    "public_url",
    [
        "https://data.example.com/",
        "https://data.example.com/datasets/",
        "HTTPS://data.example.com/",
        "https://data.example.com:8443/datasets/",
        "https://[::1]:8443/datasets/",
    ],
)
def test_from_env_s3(monkeypatch, public_url):
    monkeypatch.setenv("VLAKE_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("VLAKE_S3_ENDPOINT", "https://acc.r2.cloudflarestorage.com")
    monkeypatch.setenv("VLAKE_PUBLIC_URL", public_url)
    monkeypatch.delenv("VLAKE_LOCAL_DIR", raising=False)
    cfg = Config.from_env()
    assert cfg.s3_bucket == "my-bucket"
    assert cfg.public_url == public_url.rstrip("/")


def test_from_env_missing(monkeypatch):
    for var in (
        "VLAKE_S3_BUCKET",
        "VLAKE_LOCAL_DIR",
        "VLAKE_PUBLIC_URL",
        "VLAKE_S3_ENDPOINT",
    ):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SystemExit):
        Config.from_env()


@pytest.mark.parametrize("public_url", [None, ""])
def test_from_env_s3_requires_public_url(monkeypatch, public_url):
    monkeypatch.setenv("VLAKE_S3_BUCKET", "my-bucket")
    if public_url is None:
        monkeypatch.delenv("VLAKE_PUBLIC_URL", raising=False)
    else:
        monkeypatch.setenv("VLAKE_PUBLIC_URL", public_url)
    monkeypatch.delenv("VLAKE_LOCAL_DIR", raising=False)
    with pytest.raises(SystemExit, match="VLAKE_PUBLIC_URL.*が必要です"):
        Config.from_env()


@pytest.mark.parametrize(
    "public_url",
    [
        "http://data.example.com",
        "ftp://data.example.com",
        "s3://my-bucket",
        "//data.example.com",
        "data.example.com",
        "https:///datasets",
        "https://:443/datasets",
        "https://[invalid/datasets",
        "https://user:secret@data.example.com",
        "https://user@data.example.com",
        "https://@data.example.com",
        "https://data.example.com:abc",
        "https://data.example.com:65536",
        "https://data.example.com:-1",
        "https://data.example.com:0",
        "https://data.example.com?token=secret",
        "https://data.example.com#data",
        "https://data.example.com?",
        "https://data.example.com#",
    ],
)
@pytest.mark.parametrize("local", [False, True])
def test_from_env_s3_rejects_invalid_public_url(
    monkeypatch, tmp_path, public_url, local
):
    monkeypatch.setenv("VLAKE_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("VLAKE_PUBLIC_URL", public_url)
    if local:
        monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    else:
        monkeypatch.delenv("VLAKE_LOCAL_DIR", raising=False)
    with pytest.raises(SystemExit, match="VLAKE_PUBLIC_URL.*HTTPS"):
        Config.from_env()


@pytest.mark.parametrize("public_url", [None, "http://localhost:8000", "unused"])
def test_from_env_local_does_not_validate_public_url(monkeypatch, tmp_path, public_url):
    monkeypatch.delenv("VLAKE_S3_BUCKET", raising=False)
    monkeypatch.setenv("VLAKE_LOCAL_DIR", str(tmp_path))
    if public_url is None:
        monkeypatch.delenv("VLAKE_PUBLIC_URL", raising=False)
    else:
        monkeypatch.setenv("VLAKE_PUBLIC_URL", public_url)
    cfg = Config.from_env()
    assert cfg.local_dir == tmp_path
    assert cfg.s3_bucket is None
    assert cfg.public_url == public_url
