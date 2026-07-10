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
_KEY_DATE = re.compile(r"epss-(\d{4}-\d{2}-\d{2})\.parquet$")


def _dates_from_keys(keys: list[str]) -> list[date]:
    """ストレージキー (epss.key_for の出力) からファイル名由来の日付を抽出する。"""
    dates = []
    for key in keys:
        m = _KEY_DATE.search(key)
        if m:
            dates.append(date.fromisoformat(m.group(1)))
    return dates


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
    if not keys:
        return "refused: no parquet files in storage"
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


def verify(cfg: Config, max_age_days: int | None = None) -> dict:
    """カタログとストレージの整合を検証する。

    件数一致だけでは「同数だが中身が違う」差し替えを見逃すため、
    登録パスの集合 (Lake.registered_paths()) をストレージの実キー集合と突き合わせ、
    さらにファイル名由来の日付 (epss-YYYY-MM-DD.parquet) の min/max をカタログの
    min(date)/max(date) と突き合わせる。row_count/min_date/max_date 自体は
    count(*)/min/max のファイル統計 (メタデータ) で解決されるため、
    リモートでも全 Parquet の読み込みは発生しない。

    max_age_days を指定すると、カタログの max_date が古すぎる場合に
    report["stale"] = True を立てる (ok には影響しない、上流の恒常的な
    403/404 で更新が止まっていても ok=True のまま緑になり続ける問題への対処)。
    """
    storage = make_storage(cfg)
    keys = [k for k in storage.list("epss/") if k.endswith(".parquet")]
    storage_paths = {storage.url(k) for k in keys}
    key_dates = _dates_from_keys(keys)
    with tempfile.TemporaryDirectory() as td:
        catalog = Path(td) / CATALOG_KEY
        if not storage.get(CATALOG_KEY, catalog):
            return {
                "files_in_storage": len(keys),
                "files_in_catalog": None,
                "row_count": None,
                "min_date": None,
                "max_date": None,
                "ok": False,
                "stale": False,
                "error": "catalog not found",
            }
        lake = Lake(catalog)
        try:
            catalog_paths = lake.registered_paths()
            row_count, min_date, max_date = lake.query(
                f"SELECT count(*), min(date), max(date) FROM {lake.ALIAS}.epss"
            )[0]
        finally:
            lake.close()
    ok = storage_paths == catalog_paths
    if key_dates:
        ok = ok and min_date == min(key_dates) and max_date == max(key_dates)
    stale = (
        max_age_days is not None
        and max_date is not None
        and (date.today() - max_date).days > max_age_days
    )
    return {
        "files_in_storage": len(keys),
        "files_in_catalog": len(catalog_paths),
        "row_count": row_count,
        "min_date": min_date,
        "max_date": max_date,
        "ok": ok,
        "stale": stale,
    }
