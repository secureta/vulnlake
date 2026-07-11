# バックフィルの GitHub Actions 実行 + 年単位コンパクション Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** バックフィルを GitHub Actions (`workflow_dispatch`) で実行可能にし、その際に確定した過去年を年1ファイル (cve, date ソート) の Parquet に集約する。

**Architecture:** `backfill_epss` がソースを年ごとにグループ化し、確定年 (実行時点の年より前) は DuckDB の `COPY ... ORDER BY cve, date` で年1ファイルに集約、進行中の年は従来どおり日次登録する。`verify` の日付検証を混在レイアウト対応に緩和する。日次 update パイプライン (`update_epss`, `publish.yml`) は一切変更しない。カタログ公開は最後に1回、という不変条件を維持する。

**Tech Stack:** Python 3.12+ / uv / pytest / DuckDB (ducklake 拡張) / pyarrow / GitHub Actions

**Spec:** `docs/superpowers/specs/2026-07-11-backfill-workflow-design.md`

## Global Constraints

- テストは `uv run pytest` で実行する (dev グループに pytest あり)
- コミットメッセージは既存スタイルに合わせ日本語 + conventional prefix (`feat:`, `fix:`, `docs:`)
- docstring・コメントは既存コードに合わせ日本語
- 公開順序の不変条件: Parquet を先にアップロードし、カタログ差し替えは最後 (pipeline.py 冒頭 docstring)
- 年ファイルのキーは `epss/year=YYYY/epss-YYYY.parquet`、日次は従来どおり `epss/year=YYYY/epss-YYYY-MM-DD.parquet`
- `update_epss` と `.github/workflows/publish.yml` には手を入れない

---

### Task 1: 年ファイル命名と verify の混在レイアウト対応

`epss.year_key_for()` を追加し、`verify` の日付検証を「max は日次キーから / min は年単位比較」に緩和する。この緩和は現行の日次オンリーのレイアウトでもそのまま成立するため、後続タスクでレイアウトが変わってもテストが緑のまま進められる。

**Files:**
- Modify: `src/vlake/epss.py` (`key_for` の直後に追加)
- Modify: `src/vlake/pipeline.py` (`_KEY_DATE` 付近と `verify`)
- Test: `tests/test_epss.py`, `tests/test_pipeline.py`

**Interfaces:**
- Produces: `epss.year_key_for(year: int) -> str` — 年ファイルのストレージキー。Task 2 が使用。
- Produces: `pipeline._years_from_keys(keys: list[str]) -> set[int]` — 日次・年ファイル両対応の年抽出。

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_epss.py` に追加 (既存の import はそのまま使える想定。`from vlake import epss` が無ければ追加):

```python
def test_year_key_for():
    assert epss.year_key_for(2021) == "epss/year=2021/epss-2021.parquet"
```

`tests/test_pipeline.py` に追加:

```python
def test_years_from_keys():
    keys = [
        "epss/year=2021/epss-2021.parquet",
        "epss/year=2026/epss-2026-07-10.parquet",
        "epss/other.txt",
    ]
    assert pipeline._years_from_keys(keys) == {2021, 2026}
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_epss.py::test_year_key_for tests/test_pipeline.py::test_years_from_keys -v`
Expected: FAIL (`AttributeError: ... has no attribute 'year_key_for'` / `'_years_from_keys'`)

- [ ] **Step 3: 実装**

`src/vlake/epss.py` の `key_for` の直後に追加:

```python
def year_key_for(year: int) -> str:
    """確定した過去年を集約した年ファイルのキー。"""
    return f"epss/year={year}/epss-{year}.parquet"
```

`src/vlake/pipeline.py` の `_KEY_DATE` の直後に追加:

```python
_KEY_YEAR = re.compile(r"epss-(\d{4})\.parquet$")
```

`_dates_from_keys` の直後に追加:

```python
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
```

`verify` 内の日付チェックを変更。現行:

```python
    ok = storage_paths == catalog_paths
    if key_dates:
        ok = ok and min_date == min(key_dates) and max_date == max(key_dates)
```

を以下に置き換える (`key_dates = _dates_from_keys(keys)` の直後に `key_years = _years_from_keys(keys)` を追加):

```python
    ok = storage_paths == catalog_paths
    if key_dates:
        ok = ok and max_date == max(key_dates)
    if key_years:
        ok = ok and min_date is not None and min_date.year == min(key_years)
```

あわせて `verify` の docstring の min/max 説明を1文更新する: 「min は年ファイル
(epss-YYYY.parquet) が日付を持たないため年単位の比較に緩和し、max は進行中の年が
常に日次であることを利用して日次キーの max と厳密比較する。」

- [ ] **Step 4: 全テストが通ることを確認**

Run: `uv run pytest -v`
Expected: 全 PASS (既存の verify 系テストは日次オンリーのままでも年単位 min チェックを満たす)

- [ ] **Step 5: Commit**

```bash
git add src/vlake/epss.py src/vlake/pipeline.py tests/test_epss.py tests/test_pipeline.py
git commit -m "feat: 年ファイル命名を追加、verify を年単位 min 比較に緩和"
```

---

### Task 2: backfill の年単位コンパクション

`backfill_epss` を「確定年は年1ファイルに集約、進行中の年は日次」に書き換える。既存の backfill テストは新レイアウト前提に更新する。

**Files:**
- Modify: `src/vlake/pipeline.py` (import 部、`backfill_epss`、ヘルパー追加)
- Test: `tests/test_pipeline.py` (`test_backfill_then_update_then_verify` 更新、新テスト追加)

**Interfaces:**
- Consumes: `epss.year_key_for(year)` (Task 1)、既存の `_ingest_day` / `_open_lake` / `_publish_catalog`
- Produces: `backfill_epss(cfg: Config, source_dir: Path, today: date | None = None) -> str`。
  戻り値の形式は `"backfilled {N} year files, {M} daily files (skipped {X} years, {Y} daily)"`。
  Task 3 がこの関数に skip 分岐を追加する。

- [ ] **Step 1: 既存テストを新仕様に更新し、新テストを書く**

`tests/test_pipeline.py` の `test_backfill_then_update_then_verify` の assert 3 行を更新
(2021 年は確定年になったので年ファイル1個に集約される):

```python
    assert pipeline.backfill_epss(cfg, src) == (
        "backfilled 1 year files, 0 daily files (skipped 0 years, 0 daily)"
    )
    assert pipeline.backfill_epss(cfg, src) == (
        "backfilled 0 year files, 0 daily files (skipped 1 years, 0 daily)"
    )
```

同テストの verify 部分の期待値を更新 (storage は 年ファイル + 2026 日次の 2 件):

```python
    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["files_in_storage"] == report["files_in_catalog"] == 2
    assert report["row_count"] == 3
    assert report["min_date"] == date(2021, 4, 14)
    assert report["max_date"] == date(2026, 7, 10)
```

新テストを追加:

```python
def test_backfill_consolidates_closed_years(cfg, tmp_path):
    src = tmp_path / "mirror"
    days = [
        (date(2021, 4, 14), [("CVE-2020-5902", 0.65117)],
         dict(with_comment=False, with_percentile=False)),
        (date(2021, 4, 15), [("CVE-2020-5902", 0.66, 0.99), ("CVE-2020-0001", 0.01, 0.1)],
         dict(model_version="v1")),
        (date(2022, 1, 1), [("CVE-2020-5902", 0.7, 0.99)], dict(model_version="v2")),
        (date(2023, 1, 5), [("CVE-2020-5902", 0.8, 0.99)], dict(model_version="v3")),
        (date(2023, 1, 6), [("CVE-2020-5902", 0.81, 0.99)], dict(model_version="v3")),
    ]
    for d, rows, kw in days:
        p = src / str(d.year) / f"epss_scores-{d.isoformat()}.csv.gz"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(make_epss_csv_gz(d, rows, **kw))

    # today を注入: 2023 が「進行中の年」
    msg = pipeline.backfill_epss(cfg, src, today=date(2023, 6, 1))
    assert msg == "backfilled 2 year files, 2 daily files (skipped 0 years, 0 daily)"

    epss_dir = cfg.local_dir / "epss"
    assert (epss_dir / "year=2021" / "epss-2021.parquet").exists()
    assert (epss_dir / "year=2022" / "epss-2022.parquet").exists()
    assert (epss_dir / "year=2023" / "epss-2023-01-05.parquet").exists()
    assert (epss_dir / "year=2023" / "epss-2023-01-06.parquet").exists()

    # 年ファイル内は (cve, date) ソート
    con = duckdb.connect()
    rows = con.execute(
        f"SELECT cve, date FROM read_parquet('{epss_dir / 'year=2021' / 'epss-2021.parquet'}')"
    ).fetchall()
    assert len(rows) == 3
    assert rows == sorted(rows)

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["files_in_storage"] == report["files_in_catalog"] == 4
    assert report["row_count"] == 6
    assert report["min_date"] == date(2021, 4, 14)
    assert report["max_date"] == date(2023, 1, 6)

    # 冪等: 再実行はすべて skip
    msg = pipeline.backfill_epss(cfg, src, today=date(2023, 6, 1))
    assert msg == "backfilled 0 year files, 0 daily files (skipped 2 years, 2 daily)"
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_pipeline.py -v -k backfill`
Expected: FAIL (`backfill_epss() got an unexpected keyword argument 'today'` および戻り値形式の不一致)

- [ ] **Step 3: 実装**

`src/vlake/pipeline.py` の import 部に追加:

```python
import shutil

import duckdb
```

(`import re` / `import tempfile` は既存。標準ライブラリの `shutil` は `re` の隣、
`duckdb` はサードパーティとして空行区切りで配置する。)

`_ingest_day` の直後にヘルパー2つを追加:

```python
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
            f"COPY (SELECT * FROM read_parquet('{src}') ORDER BY cve, date) "
            f"TO '{dst}' (FORMAT parquet, COMPRESSION zstd)"
        )
    finally:
        con.close()


def _ingest_year(
    storage: Storage, lake: Lake, year: int, days: list[tuple[date, Path]], workdir: Path
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
```

`backfill_epss` を以下に置き換える:

```python
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
                    _ingest_year(storage, lake, year, days, workdir)
                    added_years += 1
                    print(f"  {year}: 年ファイル登録 ({len(days)}日分)")
                else:
                    for d, path in days:
                        ok, _ = _ingest_day(
                            storage, lake, path.read_bytes(), fallback=d, workdir=workdir
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
```

注意点:
- `_ingest_day` が `workdir / "day.parquet"` を使い回すのは従来どおり (上書きされる)。
- カタログ公開 (`_publish_catalog`) は従来と同じく無条件で最後に1回。
- `registered` はループ前のスナップショットで足りる (1回の実行内で同じ年を
  二度処理することはない)。

- [ ] **Step 4: 全テストが通ることを確認**

Run: `uv run pytest -v`
Expected: 全 PASS

- [ ] **Step 5: Commit**

```bash
git add src/vlake/pipeline.py tests/test_pipeline.py
git commit -m "feat: backfill が確定年を年1ファイル (cve, date ソート) に集約するように"
```

---

### Task 3: 日次登録済みの確定年を skip して二重登録を防ぐ

過去に日次で取り込んだ年 (例: 年またぎ後の前年) に対して年ファイルを追加登録すると、同じデータがカタログに二重に載る。これを構造的に防ぐ。

**Files:**
- Modify: `src/vlake/pipeline.py` (`backfill_epss` に分岐追加、ヘルパー追加)
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: Task 2 の `backfill_epss(cfg, source_dir, today=None)` と戻り値形式
- Produces: `pipeline._daily_registered(paths: set[str], year: int) -> bool`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_pipeline.py` に追加:

```python
def test_backfill_skips_closed_year_with_daily_files(cfg, monkeypatch, tmp_path):
    """日次で登録済みの確定年は skip され、年ファイルによる二重登録が起きないこと。"""
    raw = make_epss_csv_gz(
        date(2021, 4, 14),
        [("CVE-2020-5902", 0.65117)],
        with_comment=False,
        with_percentile=False,
    )
    monkeypatch.setattr(epss, "fetch", lambda target=None: raw)
    assert pipeline.update_epss(cfg, date(2021, 4, 14)) == "published 2021-04-14"

    src = tmp_path / "mirror"
    (src / "2021").mkdir(parents=True)
    (src / "2021" / "epss_scores-2021-04-14.csv.gz").write_bytes(raw)
    (src / "2021" / "epss_scores-2021-04-15.csv.gz").write_bytes(
        make_epss_csv_gz(
            date(2021, 4, 15), [("CVE-2020-5902", 0.66, 0.99)], model_version="v1"
        )
    )

    msg = pipeline.backfill_epss(cfg, src, today=date(2026, 7, 11))
    assert msg == "backfilled 0 year files, 0 daily files (skipped 1 years, 0 daily)"
    assert not (cfg.local_dir / "epss" / "year=2021" / "epss-2021.parquet").exists()

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["row_count"] == 1
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `uv run pytest tests/test_pipeline.py::test_backfill_skips_closed_year_with_daily_files -v`
Expected: FAIL (skip されず年ファイルが作られ、戻り値が `backfilled 1 year files, ...` になる)

- [ ] **Step 3: 実装**

`src/vlake/pipeline.py` の `_years_from_keys` の直後に追加:

```python
def _daily_registered(paths: set[str], year: int) -> bool:
    """指定年の日次ファイルがカタログに登録済みかどうか。"""
    pat = re.compile(rf"epss-{year}-\d{{2}}-\d{{2}}\.parquet$")
    return any(pat.search(p) for p in paths)
```

`backfill_epss` の確定年分岐に skip を追加。現行:

```python
                if year < current_year:
                    if storage.url(epss.year_key_for(year)) in registered:
                        skipped_years += 1
                        continue
                    _ingest_year(storage, lake, year, days, workdir)
```

を以下に置き換える:

```python
                if year < current_year:
                    if storage.url(epss.year_key_for(year)) in registered:
                        skipped_years += 1
                        continue
                    if _daily_registered(registered, year):
                        print(f"  {year}: 日次ファイルが登録済みのため skip (年集約は行わない)")
                        skipped_years += 1
                        continue
                    _ingest_year(storage, lake, year, days, workdir)
```

- [ ] **Step 4: 全テストが通ることを確認**

Run: `uv run pytest -v`
Expected: 全 PASS

- [ ] **Step 5: Commit**

```bash
git add src/vlake/pipeline.py tests/test_pipeline.py
git commit -m "fix: 日次登録済みの確定年は backfill で skip し二重登録を防止"
```

---

### Task 4: GitHub Actions ワークフロー backfill.yml

**Files:**
- Create: `.github/workflows/backfill.yml`

**Interfaces:**
- Consumes: `vlake backfill epss --source <dir>` CLI (既存)、`publish` Environment の Secrets/Variables (設定済み)
- Produces: `workflow_dispatch` で起動できる `backfill` ワークフロー

- [ ] **Step 1: ワークフローを書く**

`.github/workflows/backfill.yml` を作成:

```yaml
name: backfill
on:
  workflow_dispatch:
concurrency:
  group: publish  # publish.yml と同一グループ: 日次 update とのカタログ差し替え競合を直列化
  cancel-in-progress: false
jobs:
  backfill:
    runs-on: ubuntu-latest
    timeout-minutes: 360
    environment: publish  # Secrets/Variables は publish Environment を再利用
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uv sync
      - run: git clone --depth 1 https://github.com/empiricalsec/epss_scores "$RUNNER_TEMP/epss_scores"
      - run: uv run vlake backfill epss --source "$RUNNER_TEMP/epss_scores"
        env:
          VLAKE_S3_ENDPOINT: ${{ secrets.VLAKE_S3_ENDPOINT }}
          VLAKE_S3_BUCKET: ${{ secrets.VLAKE_S3_BUCKET }}
          VLAKE_PUBLIC_URL: ${{ vars.VLAKE_PUBLIC_URL }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: auto
      - run: uv run vlake verify
        env:
          VLAKE_S3_ENDPOINT: ${{ secrets.VLAKE_S3_ENDPOINT }}
          VLAKE_S3_BUCKET: ${{ secrets.VLAKE_S3_BUCKET }}
          VLAKE_PUBLIC_URL: ${{ vars.VLAKE_PUBLIC_URL }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: auto
```

`vlake verify` に `--max-age-days` を付けないのは仕様どおり (鮮度監視は日次 publish 側の責務)。

- [ ] **Step 2: 静的検証**

actionlint が入っていれば実行、無ければ YAML パースだけ確認:

```bash
if command -v actionlint >/dev/null; then
  actionlint .github/workflows/backfill.yml
else
  uv run --with pyyaml python -c "import yaml; yaml.safe_load(open('.github/workflows/backfill.yml'))"
fi
```

Expected: エラーなし (actionlint なら指摘 0 件)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/backfill.yml
git commit -m "feat: backfill を workflow_dispatch で実行する GitHub Actions を追加"
```

---

### Task 5: README 更新

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 4 の `backfill` ワークフロー名

- [ ] **Step 1: レイアウト説明を追記**

`## Schema` セクションの本文 (percentile の注記の後) に以下を追加:

```markdown
Layout: closed years are consolidated into one Parquet per year
(`epss/year=2021/epss-2021.parquet`, sorted by `cve, date` so per-CVE history
queries prune well); only the current year has per-day files
(`epss-YYYY-MM-DD.parquet`). Day-level direct URLs therefore exist only for
the current year — year-level globs (`year=2021/*.parquet`) work for all years.
```

- [ ] **Step 2: Actions からのバックフィル手順を追記**

`## Build your own lake` のコードブロック (「# one-time backfill ...」を含む) の直後に
以下の段落を追加:

```markdown
No local machine needed for the backfill: after configuring the `publish`
Environment (below), open the **Actions** tab → **backfill** → **Run
workflow**. The job clones the mirror on the runner, consolidates closed
years into per-year Parquet files, and ingests the current year day by day
(roughly an hour). It is idempotent — already-registered years/days are
skipped — so re-running after a failure is safe. It shares the `publish`
concurrency group with the daily job, so the two never touch the catalog
concurrently.
```

- [ ] **Step 3: 内容確認**

Run: `grep -n "backfill" README.md`
Expected: ローカル手順と Actions 手順の両方が存在する

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README に Actions バックフィル手順と年単位レイアウトを追記"
```
