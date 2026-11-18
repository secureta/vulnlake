from pathlib import Path

import pytest

from vlake import storage
from vlake.config import Config
from vlake.storage import LocalStorage, S3Storage, make_storage


def test_local_roundtrip(tmp_path):
    root = tmp_path / "bucket"
    work = tmp_path / "work"
    work.mkdir()
    st = LocalStorage(root)

    src = work / "a.txt"
    src.write_text("hello")
    st.put(src, "epss/year=2026/a.txt")
    assert st.exists("epss/year=2026/a.txt")
    assert not st.exists("nope")

    dest = work / "b.txt"
    assert st.get("epss/year=2026/a.txt", dest)
    assert dest.read_text() == "hello"
    assert not st.get("nope", work / "c.txt")


def test_local_list_and_url(tmp_path):
    root = tmp_path / "bucket"
    st = LocalStorage(root)
    f = tmp_path / "x"
    f.write_text("1")
    st.put(f, "epss/year=2021/a.parquet")
    st.put(f, "epss/year=2022/b.parquet")
    st.put(f, "vlake.ducklake")
    assert st.list("epss/") == [
        "epss/year=2021/a.parquet",
        "epss/year=2022/b.parquet",
    ]
    assert st.url("epss/year=2021/a.parquet") == str(
        (root / "epss/year=2021/a.parquet").resolve()
    )


@pytest.mark.parametrize("existing", [False, True])
def test_local_put_copy_failure_preserves_published_file(
    tmp_path, monkeypatch, existing
):
    root = tmp_path / "bucket"
    root.mkdir()
    st = LocalStorage(root)
    destination = root / "vlake.ducklake"
    if existing:
        destination.write_bytes(b"previous catalog")
    source = tmp_path / "source.ducklake"
    source.write_bytes(b"new catalog")

    def fail_copy(src, dest):
        Path(dest).write_bytes(b"partial")
        assert destination.exists() == existing
        if existing:
            assert destination.read_bytes() == b"previous catalog"
        raise OSError("injected upload failure")

    with monkeypatch.context() as patch:
        patch.setattr(storage.shutil, "copyfile", fail_copy)
        with pytest.raises(OSError, match="injected upload failure"):
            st.put(source, "vlake.ducklake")
    assert destination.exists() == existing
    if existing:
        assert destination.read_bytes() == b"previous catalog"
    assert set(root.iterdir()) == ({destination} if existing else set())
    st.put(source, "vlake.ducklake")
    assert destination.read_bytes() == b"new catalog"
    assert list(root.iterdir()) == [destination]


def test_local_put_replaces_only_after_copy_completes(tmp_path, monkeypatch):
    root = tmp_path / "bucket"
    root.mkdir()
    st = LocalStorage(root)
    destination = root / "vlake.ducklake"
    destination.write_bytes(b"previous catalog")
    source = tmp_path / "source.ducklake"
    source.write_bytes(b"new catalog")
    copyfile = storage.shutil.copyfile

    def observe_copy(src, dest):
        assert Path(dest) != destination
        result = copyfile(src, dest)
        assert destination.read_bytes() == b"previous catalog"
        return result

    monkeypatch.setattr(storage.shutil, "copyfile", observe_copy)
    st.put(source, "vlake.ducklake")
    assert destination.read_bytes() == b"new catalog"
    assert list(root.iterdir()) == [destination]


def test_make_storage_local(tmp_path):
    cfg = Config(s3_endpoint=None, s3_bucket=None, public_url=None, local_dir=tmp_path)
    assert isinstance(make_storage(cfg), LocalStorage)


@pytest.mark.parametrize(
    "public_url",
    [
        "http://data.example.com",
        "https://user:secret@data.example.com",
        "https://data.example.com:abc",
        "https://data.example.com:65536",
        "https://data.example.com?token=secret",
        "https://data.example.com#data",
        "https://data example.com",
        "https://data\texample.com",
        "https://data\nexample.com",
    ],
)
@pytest.mark.parametrize("direct", [False, True])
def test_s3_storage_rejects_invalid_public_url(public_url, direct):
    with pytest.raises(ValueError, match="VLAKE_PUBLIC_URL.*HTTPS"):
        if direct:
            S3Storage("bucket", None, public_url)
        else:
            cfg = Config(
                s3_endpoint=None,
                s3_bucket="bucket",
                public_url=public_url,
                local_dir=None,
            )
            make_storage(cfg)


@pytest.mark.parametrize(
    "public_url",
    [
        "https://data.example.com",
        "https://data.example.com:8443/datasets",
        "https://[::1]:8443/datasets",
        "https://data.example.com/data%20sets",
    ],
)
def test_make_storage_s3_public_url(monkeypatch, public_url):
    import boto3

    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: object())
    cfg = Config(
        s3_endpoint=None, s3_bucket="bucket", public_url=public_url, local_dir=None
    )
    st = make_storage(cfg)
    assert isinstance(st, S3Storage)
    assert st.url("epss/year=2026/a.parquet") == (
        f"{public_url}/epss/year=2026/a.parquet"
    )


def test_make_storage_missing_public_url():
    cfg = Config(s3_endpoint=None, s3_bucket="b", public_url=None, local_dir=None)
    with pytest.raises(ValueError):
        make_storage(cfg)


def test_make_storage_missing_local_dir():
    cfg = Config(s3_endpoint=None, s3_bucket=None, public_url=None, local_dir=None)
    with pytest.raises(ValueError):
        make_storage(cfg)
