import boto3
import pytest

from vlake.storage import S3Storage


@pytest.fixture
def s3_storage(monkeypatch, tmp_path):
    pytest.importorskip("moto")
    from moto.server import ThreadedMotoServer

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "moto-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "moto-test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_SECURITY_TOKEN", raising=False)
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)

    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    try:
        host, port = server.get_host_and_port()
        storage = S3Storage(
            "vlake-test", f"http://{host}:{port}", "https://example.test"
        )
        storage.client.create_bucket(Bucket=storage.bucket)
        yield storage
    finally:
        server.stop()


@pytest.mark.parametrize("size", [1024, 9 * 1024**2], ids=["single-part", "multipart"])
def test_s3_storage_round_trip(s3_storage, tmp_path, size):
    payload = b"vlake-s3" * (size // 8)
    key = "cve/year=2026/test.parquet"
    source = tmp_path / "source.parquet"
    destination = tmp_path / "download" / "test.parquet"
    source.write_bytes(payload)

    s3_storage.put(source, key)

    assert s3_storage.exists(key)
    assert s3_storage.list("cve/") == [key]
    assert s3_storage.list("epss/") == []
    assert s3_storage.get(key, destination)
    assert destination.read_bytes() == payload


def test_s3_storage_missing_object(s3_storage, tmp_path):
    destination = tmp_path / "missing.parquet"

    assert not s3_storage.exists("missing.parquet")
    assert not s3_storage.get("missing.parquet", destination)
    assert not destination.exists()
