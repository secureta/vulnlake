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
