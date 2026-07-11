# GHSA (GitHub Advisory Database) データセット追加 設計

2026-07-12。EPSS・CVE に続く3つ目のデータセットとして GitHub Advisory Database
(https://github.com/github/advisory-database) の github-reviewed advisory を
vlake に収録する。

## ライセンス (収録可否の根拠)

GitHub Advisory Database は **CC-BY 4.0** (リポジトリの LICENSE.md、および
GitHub の repo メタデータで SPDX: `CC-BY-4.0` と明示)。再配布・翻案 (Parquet
への変換) は明示的に許諾されており、条件は:

1. 帰属表示 (作成者・著作権表示の保持)
2. ライセンスへの参照 (CC-BY 4.0 へのリンク)
3. 変更を加えたことの明示

いずれも既存方式 (`DATA_LICENSES.md` + カタログの `datasets` ビュー) への記載で
満たす。**収録に問題なし。**

- **Attribution:** GitHub Advisory Database — © GitHub, Inc. Licensed under
  CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
- **変更の明示:** OSV 形式 JSON から Parquet への変換・列抽出を行っている旨を
  datasets ビューと DATA_LICENSES.md に記載する。

## 収録範囲

`advisories/github-reviewed/` のみ (約3万件)。GHSA の価値の本体である
ecosystem / package / バージョン範囲情報を持つのはこちら。
`advisories/unreviewed/` (約28万件) は CVE からの自動生成スタブで内容が既存の
`cve` データセットとほぼ重複するため収録しない。

## データソース

リポジトリの main ブランチ tarball スナップショット:
`https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main`
(API の `/tarball/main` のリダイレクト先と同一。認証・トークン不要、API レート
制限も受けない)。

- workdir にダウンロード後、`tarfile` の逐次読みで
  `*/advisories/github-reviewed/**/*.json` だけを処理する
  (unreviewed 配下はエントリ名で skip し、メモリ・時間を使わない)。
- backfill も日次更新も**同じ tarball** を使う。取得機構は1つ。
- cvelistV5 と同じ「スナップショット + `modified` 差分」モデル。日次更新は
  「カタログの max(modified) より新しいレコードだけ」を追記する差分抽出なので、
  何日停止しても次の1回で完全回復する。
- tarball にはリリース資産のような日付ラベルが無いため、日次差分ファイル名には
  **実行日 (UTC)** を使う。

## スキーマ

テーブル `ghsa_history` (append-only):

| 列 | 型 | 内容 |
|---|---|---|
| ghsa | VARCHAR | OSV `id` (GHSA-xxxx-xxxx-xxxx) |
| cve | VARCHAR | `aliases` 内で `CVE-` から始まる最初の ID (無ければ NULL) |
| summary | VARCHAR | OSV `summary` |
| severity | VARCHAR | `database_specific.severity` (CRITICAL / HIGH / MODERATE / LOW) |
| cvss | DOUBLE | 採択した CVSS ベクタから算出した baseScore (下記) |
| cvss_version | VARCHAR | 採択した CVSS のバージョン (例 "3.1") |
| cvss_vector | VARCHAR | vectorString |
| cwe | VARCHAR[] | `database_specific.cwe_ids` (出現順) |
| affected | STRUCT(ecosystem, package, introduced, fixed, last_affected)[] | 下記の展開規則 |
| published | TIMESTAMP | OSV `published` |
| modified | TIMESTAMP | OSV `modified` (欠損時は published にフォールバック。それも無ければ skip) |
| withdrawn | TIMESTAMP | OSV `withdrawn` (取下げ済みなら非 NULL) |
| raw | VARCHAR | OSV JSON 全体 (details 等はここから掘れる) |

**CVSS 採択規則:** OSV `severity[]` の `score` は数値ではなく**ベクタ文字列**。
`CVSS_V4` > `CVSS_V3` の優先順で1つ採択し、数値スコアは PyPI の `cvss`
ライブラリ (純 Python、執筆時最新 3.6) でベクタから算出する。バージョンは
ベクタ先頭の `CVSS:x.y/` から取る。ベクタがパース不能なら cvss / cvss_version
は NULL でベクタ文字列だけ残す。severity 配列が無ければ全て NULL。

**affected の展開規則:** OSV `affected[]` の各エントリ (package.ecosystem,
package.name) について `ranges[]` を走査し、range 内の `events` を順に見て
`introduced` が現れるたびに新しい struct を開始、後続の `fixed` /
`last_affected` を現在の struct に付ける (GitHub の実データはほぼ 1 range =
introduced 1つ + fixed/last_affected 0-1つ)。ranges が無いエントリは
ecosystem / package のみの struct を1つ出す。

ビュー `ghsa` (カタログ内 view): GHSA ごとに modified 最新の1行。

```sql
SELECT * FROM ghsa_history
QUALIFY row_number() OVER (PARTITION BY ghsa ORDER BY modified DESC) = 1
```

使い方例:

```sql
SELECT ghsa, a.package, a.introduced, a.fixed
FROM vlake.ghsa, UNNEST(affected) AS t(a)
WHERE a.ecosystem = 'npm';
```

## ストレージレイアウト

```
ghsa/year=2021/ghsa-2021.parquet                          # backfill: published 年ごと、ghsa ソート
ghsa/updates/year=2026/ghsa-updates-2026-07-12.parquet    # 日次差分 (modified > カタログ max)、実行日 UTC
```

- backfill の年ファイルは「スナップショット断面での各レコード最新版」を
  **published の年**で分割 (GHSA ID は年を含まないため)。ソートは
  (ghsa, modified) 昇順。
- 日次差分は1日数十〜数百レコード。閉じた年の updates 集約は cve 同様やらない。

## パイプライン

- `vlake update ghsa`: tarball を取得 → github-reviewed 全件を走査し
  `modified > カタログの max(modified)` のものだけ Arrow 化 →
  `ghsa-updates-<実行日UTC>.parquet` を put → add_file → カタログ公開。
  当日キーが登録済みなら skip (冪等)。テーブルが空なら refuse して backfill を促す。
- `vlake backfill ghsa [--source tarball]`: 同じ tarball (または `--source` の
  ローカル tar.gz) を全件、published 年ごとに分割して登録。登録済みの年は skip (冪等)。
- 公開順序の不変条件は既存と同じ: Parquet 先行アップロード、カタログ差し替えは最後。

## 既存コードへの追従

- `verify` / `rebuild-catalog` のデータセット定義ループに ghsa を追加。
  整合検証は cve と同型: 「登録パス集合 = ストレージキー集合」+
  「max(modified) の日付部分 ≥ 日次キーの max 日付」。`--max-age-days` の
  stale 判定は max(modified) に対して行う。
- `datasets` ビューと DATA_LICENSES.md に CC-BY 4.0 のライセンス情報
  (帰属表示・変更の明示を含む) を追加。
- CLI の `type=click.Choice(["epss", "cve"])` に `"ghsa"` を追加。
- `publish.yml` に `vlake update ghsa` ステップ、`backfill.yml` の dataset
  選択肢に `ghsa` を追加 (`all` にも含める)。
- README: クエリ例・スキーマ節・バックフィル手順・ライセンス節に GHSA を追記。
- 依存追加: `cvss` (追加時に最新安定版をレジストリで確認する)。

## エラーハンドリング

- tarball 内の個別 JSON がパース不能・必須キー (id) 欠損: そのレコードを警告付きで
  skip (1件の破損で全体を止めない)。skip 件数を結果メッセージに含める。
- tarball が取得できない: 例外で fail (次回実行で回復)。
- modified 欠損レコード: published にフォールバック。それも無ければ skip。

## テスト

既存の test_cvelist / test_pipeline のパターンを踏襲 (ローカル Storage 使用):

- パーサ単体: 実レコード形の fixture JSON (通常 / withdrawn / CVSS_V4 と V3 併存 /
  severity 無し / ranges 複数 / modified 欠損) → スキーマ・採択規則・affected
  展開・フォールバックを検証
- backfill: fixture tarball → published 年ファイル生成・ソート・冪等 skip・
  unreviewed 配下の無視
- update: backfill 済みレイクに新しい modified のレコード入り tarball →
  差分のみ追記、同日再実行 skip、空テーブル時 refuse
- view: 同一 GHSA の複数版投入 → `ghsa` view が最新1行を返す
- verify: ghsa を含む整合検証・stale 判定
