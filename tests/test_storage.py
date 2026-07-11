import pytest

from vlake.config import Config
from vlake.storage import LocalStorage, make_storage


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


def test_make_storage_local(tmp_path):
    cfg = Config(s3_endpoint=None, s3_bucket=None, public_url=None, local_dir=tmp_path)
    assert isinstance(make_storage(cfg), LocalStorage)


def test_make_storage_missing_public_url():
    cfg = Config(s3_endpoint=None, s3_bucket="b", public_url=None, local_dir=None)
    with pytest.raises(ValueError):
        make_storage(cfg)


def test_make_storage_missing_local_dir():
    cfg = Config(s3_endpoint=None, s3_bucket=None, public_url=None, local_dir=None)
    with pytest.raises(ValueError):
        make_storage(cfg)
