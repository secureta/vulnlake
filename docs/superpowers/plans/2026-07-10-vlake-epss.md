# vlake (EPSS Frozen DuckLake) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** EPSS 全履歴を Parquet 化し、S3 互換ストレージ上の Frozen DuckLake として公開する OSS パイプライン `vlake` を作る。

**Architecture:** Parquet は自前生成して人間可読パス (`epss/year=YYYY/epss-YYYY-MM-DD.parquet`) に置き、カタログ (`vlake.ducklake` = DuckDB ファイル) には `ducklake_add_data_files()` で公開絶対 URL を登録する。公開 = 新 Parquet アップロード後にカタログファイルを差し替え (消費者視点でアトミック)。ストレージ層は Local/S3 の薄い抽象で、テストは全てローカル FS で完結する。

**Tech Stack:** Python 3.12+ / uv / duckdb (+ducklake, httpfs 拡張) / pyarrow / boto3 / httpx / click / pytest

**Spec:** `docs/superpowers/specs/2026-07-10-vlake-design.md`

## Global Constraints

- 依存バージョンは 2026-07-10 に PyPI で確認した最新安定版を下限に: `duckdb>=1.5.4`, `pyarrow>=25.0.0`, `boto3>=1.43.45`, `httpx>=0.28.1`, `click>=8.4.2`, `pytest>=9.1.1`
- コードのライセンスは Apache-2.0。データのライセンスは `DATA_LICENSES.md` とレイク内 `datasets` ビューの両方に原文引用付きで記載
- EPSS 帰属表示 (固定文言): `EPSS scores provided by FIRST.org — https://www.first.org/epss`
- EPSS 非公認ディスクレーマ (固定文言): `This project redistributes EPSS data but is not endorsed or certified by FIRST.`
- Parquet キー命名: `epss/year={YYYY}/epss-{YYYY-MM-DD}.parquet`、圧縮 zstd
- カタログのキーは `vlake.ducklake` (バケット直下)
- DATA_PATH はカタログ**新規作成時のみ**指定し (`<公開URL>/unused`)、以後の ATTACH では指定しない (作成後変更不可のため)
- `ducklake_add_data_files()` は非冪等 → 登録前に必ず `ducklake_data_file` の path を照会
- EPSS CSV は3世代ある (実物確認済み):
  - 2021年初期: コメント行なし、列は `cve,epss` のみ (percentile なし)
  - 〜v3: `#model_version:v2023.03.01,score_date:2023-06-01T00:00:00+0000` + `cve,epss,percentile`
  - 現行: `#model_version:v2026.06.15,score_date:2026-07-10T12:00:34Z` + `cve,epss,percentile`
- テストはネットワーク・S3 に依存しない (fetch はモック、ストレージは LocalStorage)

## File Structure

```
pyproject.toml               # uv / uv_build、依存ピン、console script
LICENSE                      # Apache-2.0
DATA_LICENSES.md             # データセットごとの再配布根拠 (原文引用)
README.md                    # 消費者向けクイックスタート + 運用手順
.gitignore
.github/workflows/test.yml   # PR/push で pytest
.github/workflows/publish.yml# 日次 cron で vlake update epss
src/vlake/__init__.py
src/vlake/config.py          # 環境変数 → Config
src/vlake/storage.py         # Storage Protocol + LocalStorage / S3Storage
src/vlake/epss.py            # EPSS データセット: fetch / parse / parquet / license_info
src/vlake/lake.py            # DuckLake カタログ操作 (Lake クラス)
src/vlake/pipeline.py        # update / backfill / rebuild / verify のオーケストレーション
src/vlake/cli.py             # click CLI
tests/__init__.py            # 空 (tests.conftest を import 可能にする)
tests/conftest.py            # CSV fixture ヘルパ
tests/test_config.py
tests/test_storage.py
tests/test_epss.py
tests/test_lake.py
tests/test_pipeline.py       # LocalStorage でのエンドツーエンド
```

---

### Task 1: プロジェクト骨格

**Files:**
- Create: `pyproject.toml`, `LICENSE`, `.gitignore`, `src/vlake/__init__.py`, `tests/__init__.py` (空。`from tests.conftest import ...` を可能にする), `tests/test_config.py`

**Interfaces:**
- Produces: パッケージ `vlake` (src layout)、`uv run pytest` が動く状態

- [ ] **Step 1: uv の確認・インストール**

Run: `uv --version || curl -LsSf https://astral.sh/uv/install.sh | sh`
インストールした場合は `source $HOME/.local/bin/env` か PATH に `~/.local/bin` を追加して `uv --version` を再確認。

- [ ] **Step 2: pyproject.toml を作成**

```toml
[project]
name = "vlake"
version = "0.1.0"
description = "Security datasets published as a frozen DuckLake on S3-compatible storage"
readme = "README.md"
license = "Apache-2.0"
requires-python = ">=3.12"
dependencies = [
    "duckdb>=1.5.4",
    "pyarrow>=25.0.0",
    "boto3>=1.43.45",
    "httpx>=0.28.1",
    "click>=8.4.2",
]

[project.scripts]
vlake = "vlake.cli:main"

[dependency-groups]
dev = ["pytest>=9.1.1"]

[build-system]
requires = ["uv_build>=0.9,<0.10"]
build-backend = "uv_build"
```

- [ ] **Step 3: LICENSE (Apache-2.0) と .gitignore を作成**

LICENSE は Apache-2.0 全文 (https://www.apache.org/licenses/LICENSE-2.0.txt をそのまま)。冒頭の copyright 行は `Copyright 2026 vlake contributors`。

`.gitignore`:
```
__pycache__/
*.pyc
.venv/
dist/
.pytest_cache/
*.ducklake
*.ducklake.wal
```

- [ ] **Step 4: パッケージ骨格と smoke テスト**

`src/vlake/__init__.py`:
```python
__version__ = "0.1.0"
```

`tests/__init__.py`: 空ファイル (これがないと後続タスクの `from tests.conftest import make_epss_csv_gz` が失敗する)。

`tests/test_config.py` (この時点では import smoke のみ):
```python
import vlake


def test_import():
    assert vlake.__version__
```

- [ ] **Step 5: 依存解決してテスト実行**

Run: `uv sync && uv run pytest -v`
Expected: PASS (1 passed)。`uv.lock` が生成される。

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock LICENSE .gitignore src tests
git commit -m "chore: vlake プロジェクト骨格 (uv, Apache-2.0)"
```

---

### Task 2: Config と Storage 抽象

**Files:**
- Create: `src/vlake/config.py`, `src/vlake/storage.py`
- Modify: `tests/test_config.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- Produces:
  - `Config` (frozen dataclass): `s3_endpoint: str | None`, `s3_bucket: str | None`, `public_url: str | None`, `local_dir: Path | None`; `Config.from_env() -> Config`
  - `Storage` Protocol: `put(local_path: Path, key: str) -> None` / `get(key: str, local_path: Path) -> bool` / `exists(key: str) -> bool` / `list(prefix: str) -> list[str]` / `url(key: str) -> str`
  - `make_storage(cfg: Config) -> Storage`
  - `url(key)` はカタログに焼き込む絶対参照を返す: LocalStorage は絶対パス、S3Storage は `{public_url}/{key}`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_config.py` に追記:
```python
from pathlib import Path

import pytest

from vlake.config import Config


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
```

`tests/test_storage.py`:
```python
from pathlib import Path

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
```

- [ ] **Step 2: 失敗を確認**

Run: `uv run pytest tests/test_config.py tests/test_storage.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'vlake.config'`)

- [ ] **Step 3: 実装**

`src/vlake/config.py`:
```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    s3_endpoint: str | None
    s3_bucket: str | None
    public_url: str | None
    local_dir: Path | None

    @classmethod
    def from_env(cls) -> Config:
        bucket = os.environ.get("VLAKE_S3_BUCKET")
        local = os.environ.get("VLAKE_LOCAL_DIR")
        public = (os.environ.get("VLAKE_PUBLIC_URL") or "").rstrip("/") or None
        if not bucket and not local:
            raise SystemExit(
                "VLAKE_S3_BUCKET (S3互換) または VLAKE_LOCAL_DIR (ローカル) を設定してください"
            )
        if bucket and not public:
            raise SystemExit(
                "VLAKE_PUBLIC_URL (カタログに焼き込む公開HTTPSベースURL) が必要です"
            )
        return cls(
            s3_endpoint=os.environ.get("VLAKE_S3_ENDPOINT"),
            s3_bucket=bucket,
            public_url=public,
            local_dir=Path(local) if local else None,
        )
```

`src/vlake/storage.py`:
```python
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol

from .config import Config


class Storage(Protocol):
    """put/get はストレージとローカルファイルの転送。url() はカタログに登録する絶対参照。"""

    def put(self, local_path: Path, key: str) -> None: ...
    def get(self, key: str, local_path: Path) -> bool: ...
    def exists(self, key: str) -> bool: ...
    def list(self, prefix: str) -> list[str]: ...
    def url(self, key: str) -> str: ...


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, local_path: Path, key: str) -> None:
        dest = self._path(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_path, dest)

    def get(self, key: str, local_path: Path) -> bool:
        src = self._path(key)
        if not src.exists():
            return False
        local_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, local_path)
        return True

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def list(self, prefix: str) -> list[str]:
        if not self.root.exists():
            return []
        keys = (
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
            if p.is_file()
        )
        return sorted(k for k in keys if k.startswith(prefix))

    def url(self, key: str) -> str:
        return str(self._path(key).resolve())


class S3Storage:
    def __init__(self, bucket: str, endpoint: str | None, public_url: str):
        import boto3

        self.client = boto3.client("s3", endpoint_url=endpoint)
        self.bucket = bucket
        self.public_url = public_url

    def put(self, local_path: Path, key: str) -> None:
        self.client.upload_file(str(local_path), self.bucket, key)

    def get(self, key: str, local_path: Path) -> bool:
        import botocore.exceptions

        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.client.download_file(self.bucket, key, str(local_path))
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise
        return True

    def exists(self, key: str) -> bool:
        import botocore.exceptions

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise
        return True

    def list(self, prefix: str) -> list[str]:
        paginator = self.client.get_paginator("list_objects_v2")
        keys: list[str] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            keys.extend(obj["Key"] for obj in page.get("Contents", []))
        return sorted(keys)

    def url(self, key: str) -> str:
        return f"{self.public_url}/{key}"


def make_storage(cfg: Config) -> Storage:
    if cfg.s3_bucket:
        assert cfg.public_url is not None
        return S3Storage(cfg.s3_bucket, cfg.s3_endpoint, cfg.public_url)
    assert cfg.local_dir is not None
    return LocalStorage(cfg.local_dir)
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_config.py tests/test_storage.py -v`
Expected: PASS (全件)

- [ ] **Step 5: Commit**

```bash
git add src/vlake/config.py src/vlake/storage.py tests/test_config.py tests/test_storage.py
git commit -m "feat: Config と Storage 抽象 (Local/S3互換)"
```

---

### Task 3: EPSS データセットモジュール

**Files:**
- Create: `src/vlake/epss.py`, `tests/conftest.py`
- Test: `tests/test_epss.py`

**Interfaces:**
- Consumes: なし (独立モジュール)
- Produces:
  - `epss.NAME = "epss"`, `epss.SCHEMA: pa.schema` (cve string / epss float64 / percentile float64 / date date32 / model_version string)
  - `epss.parse(raw_gz: bytes, fallback_date: datetime.date) -> tuple[pa.Table, datetime.date, str]` — (テーブル, score_date, model_version)。3世代フォーマット対応
  - `epss.key_for(d: datetime.date) -> str` — `epss/year=2021/epss-2021-04-14.parquet`
  - `epss.write_parquet(table: pa.Table, path: Path) -> None` — zstd
  - `epss.fetch(target: datetime.date | None) -> bytes | None` — None = 未公開 (404/403)
  - `epss.LICENSE_INFO: dict` — keys: name, source_url, license_name, license_text, attribution, disclaimer

- [ ] **Step 1: fixture ヘルパと失敗するテストを書く**

`tests/conftest.py`:
```python
import gzip
from datetime import date


def make_epss_csv_gz(
    score_date: date,
    rows: list[tuple],
    *,
    with_comment: bool = True,
    with_percentile: bool = True,
    model_version: str = "v2026.06.15",
    date_suffix: str = "T12:00:34Z",
) -> bytes:
    """実フォーマットを模した EPSS CSV (.gz) を作る。

    rows: with_percentile=True なら (cve, epss, percentile)、False なら (cve, epss)
    """
    lines = []
    if with_comment:
        lines.append(
            f"#model_version:{model_version},score_date:{score_date.isoformat()}{date_suffix}"
        )
    lines.append("cve,epss,percentile" if with_percentile else "cve,epss")
    for row in rows:
        lines.append(",".join(str(v) for v in row))
    return gzip.compress(("\n".join(lines) + "\n").encode())
```

`tests/test_epss.py`:
```python
from datetime import date
from pathlib import Path

import pyarrow.parquet as pq

from tests.conftest import make_epss_csv_gz
from vlake import epss


def test_parse_current_format():
    raw = make_epss_csv_gz(
        date(2026, 7, 10),
        [("CVE-1999-0001", 0.03351, 0.87263), ("CVE-2021-44228", 0.97565, 0.99999)],
    )
    table, score_date, mv = epss.parse(raw, fallback_date=date(2000, 1, 1))
    assert score_date == date(2026, 7, 10)  # コメント行優先、fallback は無視
    assert mv == "v2026.06.15"
    assert table.schema.equals(epss.SCHEMA)
    assert table.num_rows == 2
    d = table.to_pylist()[1]
    assert d == {
        "cve": "CVE-2021-44228",
        "epss": 0.97565,
        "percentile": 0.99999,
        "date": date(2026, 7, 10),
        "model_version": "v2026.06.15",
    }


def test_parse_v3_format_offset_timestamp():
    raw = make_epss_csv_gz(
        date(2023, 6, 1),
        [("CVE-2020-5902", 0.97, 0.999)],
        model_version="v2023.03.01",
        date_suffix="T00:00:00+0000",
    )
    _, score_date, mv = epss.parse(raw, fallback_date=date(2000, 1, 1))
    assert score_date == date(2023, 6, 1)
    assert mv == "v2023.03.01"


def test_parse_v1_no_comment_no_percentile():
    raw = make_epss_csv_gz(
        date(2021, 4, 14),
        [("CVE-2020-5902", 0.65117), ("CVE-2018-19571", 0.04773)],
        with_comment=False,
        with_percentile=False,
    )
    table, score_date, mv = epss.parse(raw, fallback_date=date(2021, 4, 14))
    assert score_date == date(2021, 4, 14)  # fallback (ファイル名由来) を採用
    assert mv == "v1"
    assert table.schema.equals(epss.SCHEMA)
    assert table.column("percentile").null_count == 2


def test_key_for():
    assert epss.key_for(date(2021, 4, 14)) == "epss/year=2021/epss-2021-04-14.parquet"


def test_write_parquet_roundtrip(tmp_path):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    table, _, _ = epss.parse(raw, fallback_date=date(2026, 7, 10))
    out = tmp_path / "day.parquet"
    epss.write_parquet(table, out)
    back = pq.read_table(out)
    assert back.schema.equals(epss.SCHEMA)
    assert back.num_rows == 1


def test_license_info_complete():
    for key in ("name", "source_url", "license_name", "license_text", "attribution", "disclaimer"):
        assert epss.LICENSE_INFO[key]
    assert "not endorsed or certified by FIRST" in epss.LICENSE_INFO["disclaimer"]
```

- [ ] **Step 2: 失敗を確認**

Run: `uv run pytest tests/test_epss.py -v`
Expected: FAIL (`ModuleNotFoundError` / `AttributeError`)

- [ ] **Step 3: 実装**

`src/vlake/epss.py`:
```python
"""EPSS (Exploit Prediction Scoring System) データセット。

データ提供: FIRST.org — https://www.first.org/epss
本プロジェクトは EPSS データを再配布するが、FIRST の公認・認証を受けたものではない。
"""

from __future__ import annotations

import gzip
import io
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

NAME = "epss"

SCHEMA = pa.schema(
    [
        ("cve", pa.string()),
        ("epss", pa.float64()),
        ("percentile", pa.float64()),  # 2021年初期ファイルには存在しない (NULL)
        ("date", pa.date32()),
        ("model_version", pa.string()),
    ]
)

CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DATED_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://www.first.org/epss/data_stats",
    "license_name": "FIRST EPSS Usage Agreement (LicenseRef-scancode-first-epss-usage)",
    "license_text": (
        '"We grant the use of EPSS scores freely to the public, subject to the '
        "following conditions. ... we ask that if you are using EPSS, that you "
        'provide appropriate attribution where possible." '
        "— https://www.first.org/epss/faq"
    ),
    "attribution": (
        "EPSS scores provided by FIRST.org — https://www.first.org/epss. "
        "Citation: Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, "
        "Idris Adjerid (2021), Exploit Prediction Scoring System, "
        "Digital Threats Research and Practice, 2(3)."
    ),
    "disclaimer": (
        "This project redistributes EPSS data but is not endorsed or certified by FIRST."
    ),
}


def parse(raw_gz: bytes, fallback_date: date) -> tuple[pa.Table, date, str]:
    """gzip 圧縮された EPSS 日次 CSV を Arrow テーブルに変換する。

    3世代のフォーマットに対応:
    - コメント行なし + cve,epss (2021年初期) → model_version="v1"、日付は fallback_date
    - #model_version:...,score_date:...+0000 + cve,epss,percentile
    - #model_version:...,score_date:...Z + cve,epss,percentile
    """
    data = gzip.decompress(raw_gz)
    model_version = "v1"
    score_date = fallback_date
    if data.startswith(b"#"):
        line, _, data = data.partition(b"\n")
        meta = dict(
            kv.split(":", 1) for kv in line[1:].decode().split(",") if ":" in kv
        )
        model_version = meta.get("model_version", "v1")
        if "score_date" in meta:
            score_date = date.fromisoformat(meta["score_date"][:10])

    table = pacsv.read_csv(
        io.BytesIO(data),
        convert_options=pacsv.ConvertOptions(
            column_types={
                "cve": pa.string(),
                "epss": pa.float64(),
                "percentile": pa.float64(),
            }
        ),
    )
    n = table.num_rows
    if "percentile" not in table.column_names:
        table = table.append_column("percentile", pa.nulls(n, pa.float64()))
    table = table.append_column("date", pa.array([score_date] * n, pa.date32()))
    table = table.append_column("model_version", pa.array([model_version] * n))
    return table.select(SCHEMA.names).cast(SCHEMA), score_date, model_version


def key_for(d: date) -> str:
    return f"epss/year={d.year}/epss-{d.isoformat()}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    pq.write_table(table, path, compression="zstd")


def fetch(target: date | None = None) -> bytes | None:
    """日次 CSV を取得する。未公開 (404/403) なら None。"""
    url = DATED_URL.format(d=target.isoformat()) if target else CURRENT_URL
    resp = httpx.get(url, follow_redirects=True, timeout=120)
    if resp.status_code in (403, 404):
        return None
    resp.raise_for_status()
    return resp.content
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_epss.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add src/vlake/epss.py tests/conftest.py tests/test_epss.py
git commit -m "feat: EPSS パーサ (3世代フォーマット対応) と Parquet 出力"
```

---

### Task 4: DuckLake カタログ操作 (Lake)

**Files:**
- Create: `src/vlake/lake.py`
- Test: `tests/test_lake.py`

**Interfaces:**
- Consumes: Task 3 の `epss.SCHEMA`, `epss.write_parquet` (テストで使用)
- Produces:
  - `Lake(catalog_path: Path, data_path: str | None = None)` — data_path はカタログ**新規作成時のみ**渡す。内部で `INSTALL/LOAD ducklake, httpfs` 実行
  - `Lake.ensure_epss_table() -> None`
  - `Lake.registered_paths() -> set[str]` — アクティブなデータファイルの path 集合
  - `Lake.add_file(table: str, path: str) -> bool` — 登録したら True、登録済みなら False (冪等)
  - `Lake.set_message(message: str) -> None` — スナップショットへのコミットメッセージ (未対応版では無視)
  - `Lake.refresh_datasets_view(infos: list[dict]) -> None` — `datasets` ビューを作り直す
  - `Lake.query(sql: str) -> list[tuple]` — 検証用
  - `Lake.close() -> None`

**注意 (実装者向け):** DuckDB で ducklake カタログを `lake` として ATTACH すると、メタデータ DB が `__ducklake_metadata_lake` という名前で同時に ATTACH される。もしテストで `Catalog "__ducklake_metadata_lake" does not exist` 系のエラーが出たら、`SELECT database_name FROM duckdb_databases()` を実行して実際の名前を確認し、`Lake.META` 定数を修正すること。

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_lake.py`:
```python
from datetime import date
from pathlib import Path

import duckdb

from tests.conftest import make_epss_csv_gz
from vlake import epss
from vlake.lake import Lake


def _make_parquet(tmp_path: Path, d: date) -> Path:
    raw = make_epss_csv_gz(d, [("CVE-1999-0001", 0.1, 0.5), ("CVE-1999-0002", 0.2, 0.6)])
    table, _, _ = epss.parse(raw, fallback_date=d)
    out = tmp_path / f"epss-{d.isoformat()}.parquet"
    epss.write_parquet(table, out)
    return out


def test_create_register_and_read_back(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    pq2 = _make_parquet(tmp_path, date(2026, 7, 10))

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_epss_table()
    assert lake.registered_paths() == set()
    assert lake.add_file("epss", str(pq1)) is True
    assert lake.add_file("epss", str(pq1)) is False  # 冪等
    assert lake.add_file("epss", str(pq2)) is True
    assert lake.registered_paths() == {str(pq1), str(pq2)}
    lake.set_message("epss 2026-07-10")
    lake.close()

    # 消費者と同じ経路: 素の duckdb で ATTACH して読む
    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    n, days = con.execute(
        "SELECT count(*), count(DISTINCT date) FROM frozen.epss"
    ).fetchone()
    assert (n, days) == (4, 2)
    top = con.execute(
        "SELECT cve FROM frozen.epss WHERE date = DATE '2026-07-10' ORDER BY epss DESC LIMIT 1"
    ).fetchone()[0]
    assert top == "CVE-1999-0002"


def test_reopen_existing_catalog_without_data_path(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_epss_table()
    lake.add_file("epss", str(pq1))
    lake.close()

    # 既存カタログは data_path なしで再オープンできる
    lake2 = Lake(catalog)
    assert lake2.registered_paths() == {str(pq1)}
    assert lake2.add_file("epss", str(pq1)) is False
    lake2.close()


def test_datasets_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_epss_table()
    lake.refresh_datasets_view([epss.LICENSE_INFO])
    lake.refresh_datasets_view([epss.LICENSE_INFO])  # 再実行しても壊れない
    rows = lake.query("SELECT name, attribution FROM lake.datasets")
    assert rows[0][0] == "epss"
    assert "FIRST.org" in rows[0][1]
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 1
```

- [ ] **Step 2: 失敗を確認**

Run: `uv run pytest tests/test_lake.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'vlake.lake'`)

- [ ] **Step 3: 実装**

`src/vlake/lake.py`:
```python
"""DuckLake カタログ (vlake.ducklake) への書き込みセッション。

カタログはローカルファイルとして操作し、呼び出し側が Storage 経由で
ダウンロード/アップロードする。データファイルは ducklake_add_data_files()
で絶対 URL (またはローカル絶対パス) を登録する。
"""

from __future__ import annotations

from pathlib import Path

import duckdb


def _q(s: str) -> str:
    """SQL 文字列リテラル用エスケープ。"""
    return s.replace("'", "''")


class Lake:
    ALIAS = "lake"
    META = "__ducklake_metadata_lake"

    def __init__(self, catalog_path: Path, data_path: str | None = None):
        self.con = duckdb.connect()
        self.con.execute("INSTALL ducklake; LOAD ducklake;")
        self.con.execute("INSTALL httpfs; LOAD httpfs;")
        options = f" (DATA_PATH '{_q(data_path)}')" if data_path else ""
        self.con.execute(f"ATTACH 'ducklake:{catalog_path}' AS {self.ALIAS}{options}")

    def ensure_epss_table(self) -> None:
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.epss (
                cve VARCHAR,
                epss DOUBLE,
                percentile DOUBLE,
                date DATE,
                model_version VARCHAR
            )"""
        )

    def registered_paths(self) -> set[str]:
        rows = self.con.execute(
            f"SELECT path FROM {self.META}.ducklake_data_file WHERE end_snapshot IS NULL"
        ).fetchall()
        return {r[0] for r in rows}

    def add_file(self, table: str, path: str) -> bool:
        if path in self.registered_paths():
            return False
        self.con.execute(
            f"CALL ducklake_add_data_files('{self.ALIAS}', '{_q(table)}', '{_q(path)}')"
        )
        return True

    def set_message(self, message: str) -> None:
        try:
            self.con.execute(
                f"CALL {self.ALIAS}.set_commit_message('vlake', '{_q(message)}')"
            )
        except duckdb.Error:
            pass  # 拡張のバージョンによっては未対応。注記は必須機能ではない

    def refresh_datasets_view(self, infos: list[dict]) -> None:
        cols = ("name", "source_url", "license_name", "license_text", "attribution", "disclaimer")
        values = ", ".join(
            "(" + ", ".join(f"'{_q(str(info[c]))}'" for c in cols) + ")" for info in infos
        )
        self.con.execute(
            f"CREATE OR REPLACE VIEW {self.ALIAS}.datasets AS "
            f"SELECT * FROM (VALUES {values}) AS t({', '.join(cols)})"
        )

    def query(self, sql: str) -> list[tuple]:
        return self.con.execute(sql).fetchall()

    def close(self) -> None:
        self.con.close()
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_lake.py -v`
Expected: PASS (3 passed)。失敗した場合は上の「注意」のメタデータ DB 名を確認。`ducklake_add_data_files` のパスが相対保存されて冪等判定が壊れるケースが出たら、`registered_paths()` の比較を `path.endswith(Path(url).name)` ベースに変えず、まず `SELECT path, path_is_relative FROM ...` で実際の保存値を確認して登録 URL 側を合わせること。

- [ ] **Step 5: Commit**

```bash
git add src/vlake/lake.py tests/test_lake.py
git commit -m "feat: DuckLake カタログ操作 (冪等な add_data_files と datasets ビュー)"
```

---

### Task 5: パイプライン (update / backfill / rebuild / verify)

**Files:**
- Create: `src/vlake/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `Config`, `make_storage`, `Storage`, `Lake`, `epss.*`
- Produces:
  - `CATALOG_KEY = "vlake.ducklake"`
  - `update_epss(cfg: Config, target: date | None = None) -> str` — 戻り値は `"published 2026-07-10"` / `"already-registered 2026-07-10"` / `"not-published-yet"`
  - `backfill_epss(cfg: Config, source_dir: Path) -> str` — `"backfilled N files (skipped M)"`
  - `rebuild_catalog(cfg: Config) -> str` — `"rebuilt catalog with N files"`
  - `verify(cfg: Config) -> dict` — keys: `files_in_storage`, `files_in_catalog`, `row_count`, `min_date`, `max_date`, `ok`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_pipeline.py`:
```python
from datetime import date
from pathlib import Path

import duckdb
import pytest

from tests.conftest import make_epss_csv_gz
from vlake import epss, pipeline
from vlake.config import Config


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
    con.execute(f"ATTACH 'ducklake:{cfg.local_dir / 'vlake.ducklake'}' AS frozen (READ_ONLY)")
    return con


def test_update_publish_and_idempotency(cfg, monkeypatch):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)

    assert pipeline.update_epss(cfg) == "published 2026-07-10"
    assert pipeline.update_epss(cfg) == "already-registered 2026-07-10"

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 1


def test_update_not_published_yet(cfg, monkeypatch):
    monkeypatch.setattr(epss, "fetch", lambda target=None: None)
    assert pipeline.update_epss(cfg) == "not-published-yet"


def test_backfill_then_update_then_verify(cfg, monkeypatch, tmp_path):
    # ミラー clone を模した source dir (年ディレクトリ + beta_scores は無視)
    src = tmp_path / "mirror"
    (src / "2021").mkdir(parents=True)
    (src / "beta_scores").mkdir()
    (src / "2021" / "epss_scores-2021-04-14.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 14),
            [("CVE-2020-5902", 0.65117)],
            with_comment=False,
            with_percentile=False,
        )
    )
    (src / "2021" / "epss_scores-2021-04-15.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 15),
            [("CVE-2020-5902", 0.66, 0.99)],
            model_version="v1",
            date_suffix="T00:00:00+0000",
        )
    )
    (src / "beta_scores" / "epss_scores-2099-01-01.csv.gz").write_bytes(b"ignored")

    assert pipeline.backfill_epss(cfg, src) == "backfilled 2 files (skipped 0)"
    assert pipeline.backfill_epss(cfg, src) == "backfilled 0 files (skipped 2)"

    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg) == "published 2026-07-10"

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["files_in_storage"] == report["files_in_catalog"] == 3
    assert report["row_count"] == 3
    assert report["min_date"] == date(2021, 4, 14)
    assert report["max_date"] == date(2026, 7, 10)


def test_rebuild_catalog(cfg, monkeypatch):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    pipeline.update_epss(cfg)

    # カタログを消して再構築
    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 1 files"
    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1
```

- [ ] **Step 2: 失敗を確認**

Run: `uv run pytest tests/test_pipeline.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'vlake.pipeline'`)

- [ ] **Step 3: 実装**

`src/vlake/pipeline.py`:
```python
"""取得 → Parquet 化 → アップロード → カタログ登録 → カタログ公開 の手順。

公開順序の不変条件: Parquet を先にアップロードし、カタログの差し替えは最後。
途中で失敗してもカタログが未更新なら消費者には影響せず、次回実行が冪等に回復する。
"""

from __future__ import annotations

import re
import tempfile
from datetime import date
from pathlib import Path

from . import epss
from .config import Config
from .lake import Lake
from .storage import Storage, make_storage

CATALOG_KEY = "vlake.ducklake"
_BACKFILL_NAME = re.compile(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")


def _open_lake(storage: Storage, workdir: Path) -> tuple[Lake, Path]:
    """カタログをストレージから取得して開く。無ければ新規作成 (DATA_PATH 焼き込み)。"""
    catalog = workdir / CATALOG_KEY
    existed = storage.get(CATALOG_KEY, catalog)
    lake = Lake(catalog, data_path=None if existed else storage.url("unused"))
    lake.ensure_epss_table()
    return lake, catalog


def _publish_catalog(storage: Storage, lake: Lake, catalog: Path) -> None:
    lake.refresh_datasets_view([epss.LICENSE_INFO])
    lake.close()
    storage.put(catalog, CATALOG_KEY)


def _ingest_day(
    storage: Storage, lake: Lake, raw_gz: bytes, fallback: date, workdir: Path
) -> tuple[bool, date]:
    """1日分を Parquet 化して登録する。戻り値: (新規登録したか, score_date)"""
    table, score_date, model_version = epss.parse(raw_gz, fallback_date=fallback)
    key = epss.key_for(score_date)
    url = storage.url(key)
    if url in lake.registered_paths():
        return False, score_date
    parquet = workdir / "day.parquet"
    epss.write_parquet(table, parquet)
    storage.put(parquet, key)
    lake.set_message(f"epss {score_date} ({model_version})")
    lake.add_file("epss", url)
    return True, score_date


def update_epss(cfg: Config, target: date | None = None) -> str:
    storage = make_storage(cfg)
    raw = epss.fetch(target)
    if raw is None:
        return "not-published-yet"
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        lake, catalog = _open_lake(storage, workdir)
        added, score_date = _ingest_day(
            storage, lake, raw, fallback=target or date.today(), workdir=workdir
        )
        if not added:
            lake.close()
            return f"already-registered {score_date}"
        _publish_catalog(storage, lake, catalog)
    return f"published {score_date}"


def backfill_epss(cfg: Config, source_dir: Path) -> str:
    """empiricalsec/epss_scores の clone (等) から全履歴を取り込む。"""
    storage = make_storage(cfg)
    files = sorted(
        p
        for p in source_dir.rglob("epss_scores-*.csv.gz")
        if "beta_scores" not in p.parts and _BACKFILL_NAME.search(p.name)
    )
    added = skipped = 0
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        lake, catalog = _open_lake(storage, workdir)
        for i, path in enumerate(files, 1):
            file_date = date.fromisoformat(_BACKFILL_NAME.search(path.name).group(1))
            ok, _ = _ingest_day(
                storage, lake, path.read_bytes(), fallback=file_date, workdir=workdir
            )
            added += ok
            skipped += not ok
            if i % 50 == 0:
                print(f"  {i}/{len(files)} 処理済み")
        _publish_catalog(storage, lake, catalog)
    return f"backfilled {added} files (skipped {skipped})"


def rebuild_catalog(cfg: Config) -> str:
    """ストレージ上の Parquet 一覧を真実源としてカタログをゼロから作り直す。"""
    storage = make_storage(cfg)
    keys = [k for k in storage.list("epss/") if k.endswith(".parquet")]
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        catalog = workdir / CATALOG_KEY
        lake = Lake(catalog, data_path=storage.url("unused"))
        lake.ensure_epss_table()
        for key in keys:
            lake.add_file("epss", storage.url(key))
        _publish_catalog(storage, lake, catalog)
    return f"rebuilt catalog with {len(keys)} files"


def verify(cfg: Config) -> dict:
    """カタログとストレージの整合を検証する。

    count(*)/min/max はファイル統計 (メタデータ) で解決されるため、
    リモートでも全 Parquet の読み込みは発生しない。
    """
    storage = make_storage(cfg)
    keys = [k for k in storage.list("epss/") if k.endswith(".parquet")]
    with tempfile.TemporaryDirectory() as td:
        catalog = Path(td) / CATALOG_KEY
        if not storage.get(CATALOG_KEY, catalog):
            return {"ok": False, "error": "catalog not found"}
        lake = Lake(catalog)
        (n_files,) = lake.query(
            f"SELECT count(*) FROM {lake.META}.ducklake_data_file WHERE end_snapshot IS NULL"
        )[0]
        row_count, min_date, max_date = lake.query(
            f"SELECT count(*), min(date), max(date) FROM {lake.ALIAS}.epss"
        )[0]
        lake.close()
    return {
        "files_in_storage": len(keys),
        "files_in_catalog": n_files,
        "row_count": row_count,
        "min_date": min_date,
        "max_date": max_date,
        "ok": len(keys) == n_files,
    }
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_pipeline.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: 全テスト実行**

Run: `uv run pytest -v`
Expected: PASS (全件)

- [ ] **Step 6: Commit**

```bash
git add src/vlake/pipeline.py tests/test_pipeline.py
git commit -m "feat: update/backfill/rebuild/verify パイプライン"
```

---

### Task 6: CLI

**Files:**
- Create: `src/vlake/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Config.from_env()`, `pipeline.*`
- Produces: console script `vlake` — サブコマンド `update` / `backfill` / `rebuild-catalog` / `verify`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_cli.py`:
```python
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
```

- [ ] **Step 2: 失敗を確認**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'vlake.cli'`)

- [ ] **Step 3: 実装**

`src/vlake/cli.py`:
```python
from __future__ import annotations

from pathlib import Path

import click

from . import pipeline
from .config import Config


@click.group()
def main() -> None:
    """vlake — security datasets as a frozen DuckLake."""


@main.command()
@click.argument("dataset", type=click.Choice(["epss"]))
@click.option("--date", "target", type=click.DateTime(["%Y-%m-%d"]), default=None,
              help="取得する日付 (省略時は最新)")
def update(dataset: str, target) -> None:
    """日次更新 (冪等)。"""
    cfg = Config.from_env()
    click.echo(pipeline.update_epss(cfg, target.date() if target else None))


@main.command()
@click.argument("dataset", type=click.Choice(["epss"]))
@click.option("--source", required=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="empiricalsec/epss_scores の clone ディレクトリ")
def backfill(dataset: str, source: Path) -> None:
    """全履歴の一括取り込み (冪等)。"""
    cfg = Config.from_env()
    click.echo(pipeline.backfill_epss(cfg, source))


@main.command("rebuild-catalog")
def rebuild_catalog() -> None:
    """ストレージ上の Parquet 一覧からカタログを再構築する。"""
    cfg = Config.from_env()
    click.echo(pipeline.rebuild_catalog(cfg))


@main.command()
def verify() -> None:
    """カタログとストレージの整合を検証する。"""
    cfg = Config.from_env()
    report = pipeline.verify(cfg)
    click.echo(str(report))
    if not report["ok"]:
        raise SystemExit(1)
```

- [ ] **Step 4: テストが通ることを確認**

Run: `uv run pytest tests/test_cli.py -v && uv run vlake --help`
Expected: PASS (3 passed)、ヘルプに4サブコマンド表示

- [ ] **Step 5: Commit**

```bash
git add src/vlake/cli.py tests/test_cli.py
git commit -m "feat: vlake CLI (update/backfill/rebuild-catalog/verify)"
```

---

### Task 7: ドキュメントと GitHub Actions

**Files:**
- Create: `README.md`, `DATA_LICENSES.md`, `.github/workflows/test.yml`, `.github/workflows/publish.yml`

**Interfaces:**
- Consumes: CLI コマンド名、環境変数名 (Task 2/6 のとおり)

- [ ] **Step 1: DATA_LICENSES.md を作成**

````markdown
# Data Licenses

vlake のコードは Apache-2.0 (LICENSE 参照)。収録データのライセンスはデータセットごとに異なり、
本ファイルとレイク内の `datasets` ビュー (`SELECT * FROM vlake.datasets`) に記載する。

## EPSS

- **Source:** https://www.first.org/epss/data_stats
  (daily CSV: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz,
  full history: https://github.com/empiricalsec/epss_scores)
- **License:** FIRST EPSS Usage Agreement (`LicenseRef-scancode-first-epss-usage`)
- **Grant (verbatim, from https://www.first.org/epss/faq):**
  > We grant the use of EPSS scores freely to the public, subject to the following
  > conditions. We reserve the right to update the model and these webpages
  > periodically, as necessary, though we will make every attempt to provide
  > sufficient notice to users in the event of material changes. While membership
  > in the EPSS SIG is not required to use or implement EPSS, we ask that if you
  > are using EPSS, that you provide appropriate attribution where possible.
- **Attribution:** EPSS scores provided by FIRST.org — https://www.first.org/epss.
  Citation: Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman,
  Idris Adjerid (2021), Exploit Prediction Scoring System, Digital Threats
  Research and Practice, 2(3).
- **Disclaimer:** This project redistributes EPSS data but is not endorsed or
  certified by FIRST.
- **Model version boundaries** (kept in the `model_version` column):
  v1 = 2021-04-14, v2 = 2022-02-04, v3 = 2023-03-07, v4 = 2025-03-17
````

- [ ] **Step 2: README.md を作成**

````markdown
# vlake

Security datasets published as a **frozen DuckLake** on S3-compatible storage.
Currently included: **EPSS** (full daily history since 2021-04-14).

## Query it

```sql
-- DuckDB 1.5.2+
INSTALL ducklake;
ATTACH 'ducklake:https://<your-public-url>/vlake.ducklake' AS vlake;
SELECT * FROM vlake.epss WHERE cve = 'CVE-2021-44228' ORDER BY date;
SELECT * FROM vlake.datasets;  -- data sources & licenses
```

Prefer plain Parquet? The same files are directly readable:

```sql
SELECT * FROM read_parquet('https://<your-public-url>/epss/year=2026/*.parquet');
```

```python
import polars as pl
pl.read_parquet("https://<your-public-url>/epss/year=2026/epss-2026-07-10.parquet")
```

## Schema

`epss(cve VARCHAR, epss DOUBLE, percentile DOUBLE, date DATE, model_version VARCHAR)`
— `percentile` is NULL for early 2021 files (the column did not exist yet).

## Build your own lake

```bash
uv sync
export VLAKE_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com  # or AWS S3 endpoint
export VLAKE_S3_BUCKET=my-vlake
export VLAKE_PUBLIC_URL=https://data.example.com   # public base URL of the bucket
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

# one-time backfill (avoids hammering the official CDN)
git clone --depth 1 https://github.com/empiricalsec/epss_scores /tmp/epss_scores
uv run vlake backfill epss --source /tmp/epss_scores

# daily
uv run vlake update epss
uv run vlake verify
```

Local mode for testing: set `VLAKE_LOCAL_DIR=/some/dir` instead of the S3 variables.

The included GitHub Actions workflow (`.github/workflows/publish.yml`) runs
`vlake update epss` daily at 14:30 UTC (EPSS publishes around 13:30 UTC).
Fork the repo, set the secrets above, and you have your own lake.

## Data licenses

EPSS scores provided by FIRST.org — https://www.first.org/epss.
This project redistributes EPSS data but is not endorsed or certified by FIRST.
See [DATA_LICENSES.md](DATA_LICENSES.md) and the in-lake `datasets` view.

## Code license

Apache-2.0
````

- [ ] **Step 3: GitHub Actions ワークフローを作成**

`.github/workflows/test.yml`:
```yaml
name: test
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uv sync
      - run: uv run pytest -v
```

`.github/workflows/publish.yml`:
```yaml
name: publish
on:
  schedule:
    - cron: "30 14 * * *"  # EPSS 更新 (~13:30 UTC) の後
  workflow_dispatch:
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uv sync
      - run: uv run vlake update epss
        env:
          VLAKE_S3_ENDPOINT: ${{ secrets.VLAKE_S3_ENDPOINT }}
          VLAKE_S3_BUCKET: ${{ secrets.VLAKE_S3_BUCKET }}
          VLAKE_PUBLIC_URL: ${{ secrets.VLAKE_PUBLIC_URL }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: auto
      - run: uv run vlake verify
        env:
          VLAKE_S3_ENDPOINT: ${{ secrets.VLAKE_S3_ENDPOINT }}
          VLAKE_S3_BUCKET: ${{ secrets.VLAKE_S3_BUCKET }}
          VLAKE_PUBLIC_URL: ${{ secrets.VLAKE_PUBLIC_URL }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: auto
```

- [ ] **Step 4: 実データでのスモークテスト (ローカルモード)**

Run:
```bash
export VLAKE_LOCAL_DIR=/tmp/claude-501/-Users-reta-workspace-vlake/f252c94e-0525-44b6-886d-2c181dc565d2/scratchpad/vlake-smoke
uv run vlake update epss
uv run vlake verify
duckdb -c "INSTALL ducklake; ATTACH 'ducklake:$VLAKE_LOCAL_DIR/vlake.ducklake' AS v (READ_ONLY); SELECT count(*), max(date) FROM v.epss; SELECT name FROM v.datasets;"
```
Expected: `published <今日または前日>`、verify で `'ok': True`、count 約34万行。duckdb CLI が無ければ `uv run python -c "import duckdb; ..."` で同等の確認。

- [ ] **Step 5: 全テスト + Commit**

Run: `uv run pytest -v`
Expected: PASS (全件)

```bash
git add README.md DATA_LICENSES.md .github
git commit -m "docs: README / DATA_LICENSES と GitHub Actions (test, daily publish)"
```

---

## 運用手順 (計画外・参考)

初回の本番構築 (コード完成後、ユーザーの R2/S3 バケットで実施):

1. バケット作成、公開アクセス (public bucket / custom domain) を設定
2. `git clone --depth 1 https://github.com/empiricalsec/epss_scores` (数 GB、一度きり)
3. `vlake backfill epss --source ...` (約1900ファイル。中断しても再実行で続きから)
4. `vlake verify`
5. GitHub リポジトリに Secrets を設定して publish.yml を有効化
