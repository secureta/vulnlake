# Data Licenses

vulnlake のコードは Apache-2.0 (LICENSE 参照)。収録データのライセンスはデータセットごとに異なり、
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

## CVE (cvelistV5)

- **Source:** https://github.com/CVEProject/cvelistV5
  (daily baseline zip: GitHub Releases の `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip`)
- **License:** CVE Terms of Use (SPDX: `cve-tou`) — https://www.cve.org/Legal/TermsOfUse
- **Grant (verbatim):**
  > CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive,
  > no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
  > derivative works of, publicly display, publicly perform, sublicense, and
  > distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make
  > for such purposes is authorized provided that you reproduce MITRE's
  > copyright designation and this license in any such copy.
- **Copyright designation:** CVE® is a registered trademark of The MITRE
  Corporation. CVE Records: Copyright © 1999-2026 The MITRE Corporation.
- **Disclaimer:** This project redistributes CVE Records but is not endorsed or
  certified by MITRE or the CVE Program.

## GHSA (GitHub Advisory Database)

- **Source:** https://github.com/github/advisory-database
  (main ブランチ tarball、`advisories/github-reviewed/` のみ収録)
- **License:** Creative Commons Attribution 4.0 International (SPDX: `CC-BY-4.0`)
  — https://creativecommons.org/licenses/by/4.0/
- **Attribution:** GitHub Advisory Database — © GitHub, Inc.
  (https://github.com/github/advisory-database), licensed under CC-BY 4.0.
- **Modifications:** OSV 形式の JSON レコードを Parquet に変換し、列を抽出している
  (CC-BY 4.0 の「変更の明示」要件に基づく記載)。元レコード全体は `raw` 列に保持。
- **Disclaimer:** This project redistributes GitHub Advisory Database records
  but is not endorsed or certified by GitHub, Inc.

## ExploitDB (Exploit Database)

- **Source:** https://gitlab.com/exploit-database/exploitdb
  (index CSV: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv)
- **License:** GNU General Public License v2.0 or later (SPDX: `GPL-2.0-or-later`)
  — 全文は `licenses/GPL-2.0.txt`。
- **Grant:** GPLv2 は複製・改変・再配布を許諾する（コピーレフト）。本プロジェクトが
  再配布するのは exploitdb 由来の Parquet のみで、それを GPLv2 の下で提供する。
- **Scope of copyleft:** コピーレフトは exploitdb 由来の Parquet にのみ及ぶ。vulnlake の
  コード (Apache-2.0) は GPL 化しない（データを加工するプログラムはデータの二次的著作物では
  ない）。他データセット (EPSS/CVE/GHSA) も GPL 化しない（同一ストレージ上の independent な
  ファイルは GPLv2 §2 末尾の「単なる集積」に該当）。
- **Modifications:** `files_exploits.csv` を Parquet に変換し、`codes` 列から CVE を配列抽出、
  `code_url` を構築した（CSV→列抽出変換）。エクスプロイトのコード本体は再配布せず、
  各行は `code_url` (https://www.exploit-db.com/exploits/{id}) でコードを参照する。
- **Attribution:** Exploit Database
  (https://gitlab.com/exploit-database/exploitdb)、OffSec 保守、GPL-2.0-or-later。
- **Disclaimer:** This project redistributes the Exploit Database index but is
  not endorsed or certified by OffSec.

## nuclei-templates

- **Source:** https://github.com/projectdiscovery/nuclei-templates
  (main ブランチ tarball、テンプレート YAML の info ブロックのみ収録)
- **License:** MIT License (SPDX: `MIT`) — 全文は `licenses/MIT-nuclei-templates.txt`。
- **Modifications:** テンプレート YAML の info ブロック (id / severity / CVE /
  CVSS / タグ等) を抽出して Parquet に変換した。テンプレート本文
  (マッチャー・ペイロード) は再配布せず、各行は `template_url`
  (https://github.com/projectdiscovery/nuclei-templates/blob/main/{file})
  でテンプレートを参照する。
- **Attribution:** nuclei-templates — © ProjectDiscovery, Inc.
  (https://github.com/projectdiscovery/nuclei-templates), licensed under the
  MIT License.
- **Disclaimer:** This project redistributes nuclei-templates metadata but is
  not endorsed or certified by ProjectDiscovery, Inc.

## CWE (Common Weakness Enumeration)

- **Source:** https://cwe.mitre.org/data/downloads.html
  (cwec XML カタログ: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)
- **License:** CWE Terms of Use — https://cwe.mitre.org/about/termsofuse.html
  (帰属表示を条件に複製・改変・再配布を許諾)
- **Attribution:** CWE — Common Weakness Enumeration, © The MITRE Corporation
  (https://cwe.mitre.org/).
- **Modifications:** cwec XML の弱点・カテゴリ・ビューから主要フィールドを抽出して
  Parquet に変換している (全フィールドは収録しない。関係は nature/target_id に平坦化)。
- **Disclaimer:** This project redistributes CWE content but is not endorsed
  or certified by The MITRE Corporation.
