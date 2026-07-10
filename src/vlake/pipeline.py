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
        try:
            added, score_date = _ingest_day(
                storage, lake, raw, fallback=target or date.today(), workdir=workdir
            )
            if not added:
                return f"already-registered {score_date}"
            _publish_catalog(storage, lake, catalog)
        finally:
            lake.close()
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
        try:
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
        finally:
            lake.close()
    return f"backfilled {added} files (skipped {skipped})"


def rebuild_catalog(cfg: Config) -> str:
    """ストレージ上の Parquet 一覧を真実源としてカタログをゼロから作り直す。"""
    storage = make_storage(cfg)
    keys = [k for k in storage.list("epss/") if k.endswith(".parquet")]
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        catalog = workdir / CATALOG_KEY
        lake = Lake(catalog, data_path=storage.url("unused"))
        try:
            lake.ensure_epss_table()
            for key in keys:
                lake.add_file("epss", storage.url(key))
            _publish_catalog(storage, lake, catalog)
        finally:
            lake.close()
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
            return {
                "files_in_storage": len(keys),
                "files_in_catalog": 0,
                "row_count": 0,
                "min_date": None,
                "max_date": None,
                "ok": False,
                "error": "catalog not found",
            }
        lake = Lake(catalog)
        try:
            (n_files,) = lake.query(
                f"SELECT count(*) FROM {lake.META}.ducklake_data_file WHERE end_snapshot IS NULL"
            )[0]
            row_count, min_date, max_date = lake.query(
                f"SELECT count(*), min(date), max(date) FROM {lake.ALIAS}.epss"
            )[0]
        finally:
            lake.close()
    return {
        "files_in_storage": len(keys),
        "files_in_catalog": n_files,
        "row_count": row_count,
        "min_date": min_date,
        "max_date": max_date,
        "ok": len(keys) == n_files,
    }
