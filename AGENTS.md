# AGENTS.md

このファイルは、このリポジトリで作業するコーディングエージェント向けの汎用ガイダンスです。

## プロジェクト概要

セキュリティデータセット (EPSS / CVE / GHSA / ExploitDB / nuclei-templates / KEV) を frozen DuckLake として
S3 互換ストレージに公開するツール。正式名は **vulnlake**(README タイトル・対外的な呼称)、
略称は **vlake**(CLI コマンド、`VLAKE_*` 環境変数、`src/vlake/` パッケージ、
ドメイン・カタログ名)。URL・CLI・コード内識別子の `vlake` を「不統一」としてリネーム提案しない。

コード内のコメント・docstring・コミットメッセージは日本語。

## コマンド

```bash
uv sync                          # 依存インストール (Python >= 3.14)
uv run pytest -v                 # テスト全実行
uv run pytest tests/test_pipeline.py -k backfill   # 単一ファイル / キーワード指定
uv run ruff check .              # lint (isort/bugbear/pyupgrade/bandit 有効)
uv run ruff format .             # フォーマット (CI では --check)
uv run zizmor .github/workflows/ # GitHub Actions の SAST
```

CLI の動作確認はローカルモードで行う (S3 不要):

```bash
export VLAKE_LOCAL_DIR=/tmp/vlake-test
uv run vlake update epss         # dataset は epss|cve|ghsa|exploitdb|nuclei|kev
uv run vlake backfill epss --source <dir>
uv run vlake verify [--max-age-days N]
uv run vlake rebuild-catalog     # VLAKE_PUBLIC_URL 変更後にカタログのパスを焼き直す
```

S3 モードは `VLAKE_S3_BUCKET` + `VLAKE_PUBLIC_URL`(+ `VLAKE_S3_ENDPOINT`, AWS 認証情報)。

## アーキテクチャ

レイヤ構造 (`src/vlake/`):

- **cli.py** — click のサブコマンド (`update` / `backfill` / `verify` / `rebuild-catalog`)。薄いラッパで、実体は pipeline へ委譲。
- **pipeline.py** — オーケストレーション層。「取得 → Parquet 化 → アップロード → カタログ登録 → カタログ公開」の手順をデータセットごとに `update_*` / `backfill_*` として実装。`verify` はストレージとカタログの整合性を検査する。
- **データセットモジュール** (epss.py / cvelist.py / ghsa.py / exploitdb.py / nuclei.py / kev.py) — 各ソースの fetch / parse / PyArrow Table 化 / Parquet 書き出しと、ストレージキー命名 (`key_for` 等)。pipeline から呼ばれる純粋な変換ロジック。
- **lake.py** — DuckLake カタログ (`vlake.ducklake`) への書き込みセッション。カタログはローカルファイルとして操作し、データファイルは `ducklake_add_data_files()` で絶対 URL を登録する。テーブル定義・latest ビュー (`cve` / `ghsa` / `exploitdb` / `nuclei` / `kev`) の再生成もここ。
- **storage.py** — `Storage` Protocol と `LocalStorage` / `S3Storage` の 2 実装。`put/get` は転送、`url()` がカタログに焼き込まれる絶対参照を返す。
- **config.py** — 環境変数から `Config` を構築。`VLAKE_LOCAL_DIR` でローカルモード。

### 公開順序の不変条件 (最重要)

Parquet データファイルを先にアップロードし、カタログ (`vlake.ducklake`) の差し替えは
必ず最後。途中で失敗してもカタログが未更新なら消費者には影響せず、次回実行が冪等に
回復する。登録済みの年/日はスキップされるので再実行は常に安全。この順序を崩す変更をしないこと。

### データセットの共通パターン

各データセットは「append-only の history テーブル + 最新行を返すビュー」で構成:

- **backfill**: 年パーティションのスナップショット Parquet (`<ds>/year=YYYY/<ds>-YYYY.parquet`)
- **update**: 日次デルタ (`<ds>/updates/year=YYYY/<ds>-updates-YYYY-MM-DD.parquet`)。カタログ内の最大更新日時 (`max_*` メソッド) を超えたレコードだけを追記
- EPSS のみ例外で、履歴そのものがデータ (日次スコア)。閉じた年は年単位 1 ファイルに統合、当年のみ日次ファイル
- nuclei も例外で backfill が無い。YAML に更新日時が無いため内容ハッシュ (digest 列) で差分検出し、初回 update が全量投入。削除は removed=true のトゥームストーン行
- kev も backfill が無い (過去断面の公式アーカイブが無い)。レコード更新日時が無いためカタログ latest との全フィールド比較で差分検出。削除・復活の扱いは nuclei と同じ

### 新データセットを追加するときに触るファイル

データセットモジュール新規作成、lake.py (テーブル定義・max_* / refresh_*_view)、
pipeline.py (update_* / backfill_* / verify)、cli.py (Choice に追加)、
tests (conftest.py に実フォーマットを模したフィクスチャ生成関数 + test_<ds>.py + test_pipeline_<ds>.py)、
README のスキーマ節、DATA_LICENSES.md、`.github/workflows/publish.yml` / `backfill.yml`。
過去の追加例: git log の ghsa / exploitdb 追加コミット群、および
`docs/superpowers/plans/` と `docs/superpowers/specs/` の設計文書。

## テスト

テストは `VLAKE_LOCAL_DIR` + tmp_path でローカルストレージに対して pipeline を実際に
走らせる統合スタイル。ネットワークには出ない — `tests/conftest.py` の
`make_epss_csv_gz` / `make_baseline_zip` / `make_ghsa_tarball` / `make_exploitdb_csv` 等が
実フォーマットを忠実に模したソースデータを生成する。ソースのフォーマット処理を変えたら
conftest のフィクスチャも実データと一致しているか確認すること。

## CI

- **test.yml** (push/PR): pytest、ruff check、ruff format --check、zizmor、actionlint。actions は SHA ピン留め + `persist-credentials: false`。
- **publish.yml**: 毎日 14:30 UTC に全データセットの `update` を実行 (`publish` Environment の Secrets を使用)。
- **backfill.yml**: 手動ディスパッチ (dataset 選択)。publish と concurrency group を共有し、カタログへの同時書き込みを防ぐ。

## ライセンス上の注意

コードは Apache-2.0 だがデータは各ソースのライセンスに従う (DATA_LICENSES.md と
in-lake `datasets` ビュー)。ExploitDB はエクスプロイトコード本体を再配布しない —
索引メタデータのみ Parquet 化し `code_url` で参照する設計。
nuclei-templates も同様にテンプレート本文は再配布せず、info メタデータのみ Parquet 化し
template_url で参照する。データセット追加・変更時は
DATA_LICENSES.md と各モジュール docstring の帰属表示を維持すること。
