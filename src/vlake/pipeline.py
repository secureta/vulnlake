"""取得 → Parquet 化 → アップロード → カタログ登録 → カタログ公開 の手順。

公開順序の不変条件: Parquet を先にアップロードし、カタログの差し替えは最後。
途中で失敗してもカタログが未更新なら消費者には影響せず、次回実行が冪等に回復する。
"""

from __future__ import annotations

import re
import shutil
import tempfile
from datetime import date
from pathlib import Path

import duckdb

from . import cvelist, epss
from .config import Config
from .lake import Lake
from .storage import Storage, make_storage

CATALOG_KEY = "vlake.ducklake"
_BACKFILL_NAME = re.compile(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")
_KEY_DATE = re.compile(r"epss-(\d{4}-\d{2}-\d{2})\.parquet$")
_KEY_YEAR = re.compile(r"epss-(\d{4})\.parquet$")


def _dates_from_keys(keys: list[str]) -> list[date]:
    """ストレージキー (epss.key_for の出力) からファイル名由来の日付を抽出する。"""
    dates = []
    for key in keys:
        m = _KEY_DATE.search(key)
        if m:
            dates.append(date.fromisoformat(m.group(1)))
    return dates


def _years_from_keys(keys: list[str]) -> set[int]:
    """ストレージキーから対象年を抽出する (日次ファイル・年ファイル両対応)。"""
    years = set()
    for key in keys:
        m = _KEY_DATE.search(key)
        if m:
            years.add(date.fromisoformat(m.group(1)).year)
            continue
        m = _KEY_YEAR.search(key)
        if m:
            years.add(int(m.group(1)))
    return years


def _daily_registered(paths: set[str], year: int) -> bool:
    """指定年の日次ファイルがカタログに登録済みかどうか。"""
    pat = re.compile(rf"epss-{year}-\d{{2}}-\d{{2}}\.parquet$")
    return any(pat.search(p) for p in paths)


def _open_lake(storage: Storage, workdir: Path) -> tuple[Lake, Path]:
    """カタログをストレージから取得して開く。無ければ新規作成 (DATA_PATH 焼き込み)。"""
    catalog = workdir / CATALOG_KEY
    existed = storage.get(CATALOG_KEY, catalog)
    lake = Lake(catalog, data_path=None if existed else storage.url("unused"))
    lake.ensure_tables()
    return lake, catalog


def _publish_catalog(storage: Storage, lake: Lake, catalog: Path) -> None:
    lake.refresh_datasets_view([epss.LICENSE_INFO, cvelist.LICENSE_INFO])
    lake.refresh_cve_view()
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


def _sort_merge(day_dir: Path, out: Path, workdir: Path) -> None:
    """日次 Parquet 群を (cve, date) ソートの単一 Parquet に集約する。

    DuckDB の外部ソート (temp_directory へのスピル) を使うため、
    1年分 (最大1億行規模) をメモリに載せない。
    """
    con = duckdb.connect()
    try:
        tmp = str(workdir / "duckdb_tmp").replace("'", "''")
        src = str(day_dir / "*.parquet").replace("'", "''")
        dst = str(out).replace("'", "''")
        con.execute(f"SET temp_directory='{tmp}'")
        con.execute(
            # src/dst は内部生成パスのみ。COPY はパラメータ化非対応
            f"COPY (SELECT * FROM read_parquet('{src}') ORDER BY cve, date) "  # noqa: S608
            f"TO '{dst}' (FORMAT parquet, COMPRESSION zstd)"
        )
    finally:
        con.close()


def _ingest_year(
    storage: Storage,
    lake: Lake,
    year: int,
    days: list[tuple[date, Path]],
    workdir: Path,
) -> None:
    """確定年の全日次 CSV を年1ファイルに集約して登録する。"""
    day_dir = workdir / f"days-{year}"
    day_dir.mkdir()
    model_versions = set()
    for d, path in days:
        table, _, model_version = epss.parse(path.read_bytes(), fallback_date=d)
        epss.write_parquet(table, day_dir / f"{d.isoformat()}.parquet")
        model_versions.add(model_version)
    year_parquet = workdir / f"epss-{year}.parquet"
    _sort_merge(day_dir, year_parquet, workdir)
    key = epss.year_key_for(year)
    storage.put(year_parquet, key)
    lake.set_message(f"epss {year} backfill ({', '.join(sorted(model_versions))})")
    lake.add_file("epss", storage.url(key))
    shutil.rmtree(day_dir)
    year_parquet.unlink()


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


def backfill_epss(cfg: Config, source_dir: Path, today: date | None = None) -> str:
    """empiricalsec/epss_scores の clone (等) から全履歴を取り込む。

    確定した過去年 (today の年より前) は年1ファイル (cve, date ソート) に集約し、
    進行中の年は日次のまま登録する。today はテスト用の注入点 (省略時は実日付)。
    """
    storage = make_storage(cfg)
    current_year = (today or date.today()).year
    files = sorted(
        p
        for p in source_dir.rglob("epss_scores-*.csv.gz")
        if "beta_scores" not in p.parts and _BACKFILL_NAME.search(p.name)
    )
    by_year: dict[int, list[tuple[date, Path]]] = {}
    for path in files:
        d = date.fromisoformat(_BACKFILL_NAME.search(path.name).group(1))
        by_year.setdefault(d.year, []).append((d, path))

    added_years = skipped_years = added_days = skipped_days = 0
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        lake, catalog = _open_lake(storage, workdir)
        try:
            registered = lake.registered_paths()
            for year in sorted(by_year):
                days = by_year[year]
                if year < current_year:
                    if storage.url(epss.year_key_for(year)) in registered:
                        skipped_years += 1
                        continue
                    if _daily_registered(registered, year):
                        print(
                            f"  {year}: 日次ファイルが登録済みのため skip (年集約は行わない)"
                        )
                        skipped_years += 1
                        continue
                    _ingest_year(storage, lake, year, days, workdir)
                    added_years += 1
                    print(f"  {year}: 年ファイル登録 ({len(days)}日分)")
                else:
                    for d, path in days:
                        ok, _ = _ingest_day(
                            storage,
                            lake,
                            path.read_bytes(),
                            fallback=d,
                            workdir=workdir,
                        )
                        added_days += ok
                        skipped_days += not ok
                    print(f"  {year}: 日次 {len(days)}日分 (新規 {added_days})")
            _publish_catalog(storage, lake, catalog)
        finally:
            lake.close()
    return (
        f"backfilled {added_years} year files, {added_days} daily files "
        f"(skipped {skipped_years} years, {skipped_days} daily)"
    )


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
            lake.ensure_tables()
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
    さらにファイル名由来の日付を検証する。min は年ファイル (epss-YYYY.parquet) が
    日付を持たないため年単位の比較に緩和し、max は進行中の年が常に日次であることを
    利用して日次キーの max と厳密比較する。row_count/min_date/max_date 自体は
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
    key_years = _years_from_keys(keys)
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
                # ALIAS はクラス定数の固定識別子
                f"SELECT count(*), min(date), max(date) FROM {lake.ALIAS}.epss"  # noqa: S608
            )[0]
        finally:
            lake.close()
    ok = storage_paths == catalog_paths
    if key_dates:
        ok = ok and max_date == max(key_dates)
    if key_years:
        ok = ok and min_date is not None and min_date.year == min(key_years)
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
