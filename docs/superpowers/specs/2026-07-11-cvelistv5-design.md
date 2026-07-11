# cvelistV5 データセット追加 設計

2026-07-11。EPSS に続く2つ目のデータセットとして CVE List V5
(https://github.com/CVEProject/cvelistV5) を vlake に収録する。

## ライセンス (収録可否の根拠)

CVE データは **CVE Terms of Use** (SPDX: `cve-tou`) で提供される:

> CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive,
> no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
> derivative works of, publicly display, publicly perform, sublicense, and
> distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make for
> such purposes is authorized provided that you reproduce MITRE's copyright
> designation and this license in any such copy.

再配布・派生物作成が明示的に許諾されている。条件は MITRE の copyright 表示と
ライセンス文の複製のみ。`DATA_LICENSES.md` と `datasets` ビューに記載して満たす
(EPSS と同じ方式)。

## EPSS との本質的な違い

CVE レコードは**可変**。過去年のレコードも随時更新される (例: CVE-2021-44228 の
dateUpdated は 2025-10-21)。vlake は追記型 (frozen DuckLake, ducklake_add_data_files)
なので、スナップショット置換ではなく**追記型変更履歴 + 最新 view** で扱う。

## データソース

GitHub Releases の最新リリースに常に添付される baseline zip:
`YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (~550MB、毎日 00:00 UTC 断面の全レコード)。
zip 内は `cves/YYYY/NNxxx/CVE-YYYY-NNNN.json` (CVE JSON 5.x)。

- backfill も日次更新も**同じ zip** を使う。取得機構は1つ。
- 日次更新は「カタログの max(date_updated) より新しいレコードだけ」を追記する
  差分抽出なので、何日停止しても次の1回で完全回復する (delta zip の遷移管理不要)。
- hourly delta zip は使わない (取りこぼし検知が別途必要になるため不採用)。

## スキーマ

テーブル `cve_history` (append-only):

| 列 | 型 | 内容 |
|---|---|---|
| cve | VARCHAR | cveMetadata.cveId |
| state | VARCHAR | PUBLISHED / REJECTED |
| assigner | VARCHAR | cveMetadata.assignerShortName |
| title | VARCHAR | containers.cna.title (NULL 可) |
| description | VARCHAR | cna.descriptions の英語 (en*) 先頭。REJECTED は rejectedReasons 先頭 |
| cvss | DOUBLE | 最良1つの baseScore (下記採択規則) |
| cvss_version | VARCHAR | 採択した CVSS のバージョン (例 "3.1") |
| cvss_severity | VARCHAR | baseSeverity (v2 は NULL 可) |
| cvss_vector | VARCHAR | vectorString |
| cwe | VARCHAR[] | problemTypes 内の cweId 群 (重複除去、出現順) |
| date_published | TIMESTAMP | cveMetadata.datePublished |
| date_reserved | TIMESTAMP | cveMetadata.dateReserved |
| date_updated | TIMESTAMP | cveMetadata.dateUpdated (欠損時は datePublished、それも無ければ dateReserved) |
| raw | VARCHAR | レコード全体の JSON 文字列 (DuckDB の json 関数で掘れる) |

CVSS 採択規則: CNA コンテナ優先で cvssV4_0 > cvssV3_1 > cvssV3_0 > cvssV2_0。
CNA に無ければ ADP コンテナ (CISA Vulnrichment 等) から同順で採択。どこにも
無ければ NULL 群。

ビュー `cve` (カタログ内 view): CVE ごとに date_updated 最新の1行。

```sql
SELECT * FROM cve_history
QUALIFY row_number() OVER (PARTITION BY cve ORDER BY date_updated DESC) = 1
```

消費者は `SELECT * FROM vlake.cve WHERE cve = 'CVE-2021-44228'` で現在版が1行返る。
変更履歴が欲しければ `vlake.cve_history` を直接引く。

## ストレージレイアウト

```
cve/year=2021/cve-2021.parquet                        # backfill: CVE-ID 年ごと、cve ソート
cve/updates/year=2026/cve-updates-2026-07-11.parquet   # 日次差分 (dateUpdated > カタログ max)
```

- backfill の年ファイルは「baseline 断面での各レコード最新版」。日次差分が
  その上に積まれ、view が新しい方を選ぶ。
- 日次ファイルは1日数百〜数千レコード (数MB)。閉じた年の updates 集約は
  必要になったら EPSS の年集約と同じ方式で追加する (今回はやらない)。

## パイプライン

- `vlake update cve`: 最新リリースの baseline zip を取得 → 全レコードを走査し
  `date_updated > カタログの max(date_updated)` のものだけ Arrow 化 →
  `cve-updates-<baseline日付>.parquet` を put → add_file → カタログ公開。
  当日キーが登録済みなら skip (冪等)。テーブルが空なら refuse して backfill を促す。
- `vlake backfill cve [--source zip]`: 同じ zip (または `--source` のローカル zip) を
  全件、CVE-ID 年ごとに分割・cve ソートで登録。登録済みの年は skip (冪等)。
- 公開順序の不変条件は EPSS と同じ: Parquet 先行アップロード、カタログ差し替えは最後。

## 既存コードの一般化

- `verify` / `rebuild_catalog` は epss ハードコードを解き、データセット定義
  (prefix, テーブル名, キー→日付/年の対応) のループに一般化する。
  cve の verify は「登録パス集合 = ストレージキー集合」+
  「max(date_updated) の日付部分 ≥ 日次キーの max 日付」で整合を見る。
  `--max-age-days` の stale 判定は cve では max(date_updated) に対して行う。
- `datasets` ビューと DATA_LICENSES.md に cve-tou のライセンス情報を追加。
- `publish.yml` に `vlake update cve` ステップを追加 (14:30 UTC 実行なら当日
  0時 UTC の baseline が確実に存在する)。backfill.yml も cve に対応。
- CLI の `type=click.Choice(["epss"])` を `["epss", "cve"]` に拡張。

## エラーハンドリング

- zip 内の個別 JSON がパース不能・必須キー欠損: そのレコードを警告付きで skip
  (1件の破損で全体を止めない)。skip 件数を結果メッセージに含める。
- baseline zip が取得できない (Releases 障害): 例外で fail (次回実行で回復)。
- dateUpdated 欠損レコード: datePublished → dateReserved でフォールバック。

## テスト

既存の test_epss / test_pipeline のパターンを踏襲 (ローカル Storage 使用):

- パーサ単体: 実レコード形の fixture JSON (PUBLISHED / REJECTED / CVSS各所在 /
  dateUpdated 欠損) → スキーマ・採択規則・フォールバックを検証
- backfill: fixture zip → 年ファイル生成・ソート・冪等 skip
- update: backfill 済みレイクに新しい dateUpdated のレコード入り zip → 差分のみ追記、
  同日再実行 skip、空テーブル時 refuse
- view: 同一 CVE の複数版投入 → `cve` view が最新1行を返す
- verify: cve を含む整合検証・stale 判定
