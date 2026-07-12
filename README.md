# vulnlake

Security datasets published as a **frozen DuckLake** on S3-compatible storage.
Currently included: **EPSS** (full daily history since 2021-04-14), **CVE**
(CVE List V5, full record history of changes), **GHSA** (GitHub Advisory
Database, github-reviewed advisories with package/version ranges),
**ExploitDB** (Exploit Database index, exploit metadata linked to code by URL),
**nuclei** (nuclei-templates index, detection template metadata linked to
templates by URL), **CWE** (Common Weakness Enumeration catalog), and **KEV**
(CISA Known Exploited Vulnerabilities catalog).

## Query it

```sql
-- DuckDB 1.5.2+
INSTALL ducklake;
INSTALL httpfs;
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
SELECT * FROM vlake.epss WHERE cve = 'CVE-2021-44228' ORDER BY date;
SELECT cve, title, cvss, cvss_severity FROM vlake.cve WHERE cve = 'CVE-2021-44228';
SELECT * FROM vlake.cve_history WHERE cve = 'CVE-2021-44228' ORDER BY date_updated;
SELECT * FROM vlake.cve_sources WHERE cve = 'CVE-2021-44228';
SELECT ghsa, summary, severity FROM vlake.ghsa WHERE cve = 'CVE-2021-44228';
SELECT ghsa, a.package, a.introduced, a.fixed
FROM vlake.ghsa, UNNEST(affected) AS t(a) WHERE a.ecosystem = 'npm';
SELECT edb_id, description, type, platform, code_url
FROM vlake.exploitdb WHERE list_contains(cve, 'CVE-2021-44228');
-- Is there a nuclei detection template for this CVE?
SELECT template_id, name, severity, template_url
FROM vlake.nuclei
WHERE list_contains(cve, 'CVE-2024-3400') AND NOT removed;
-- Is this CVE known to be exploited in the wild?
SELECT cve, vulnerability_name, date_added, due_date, known_ransomware_campaign_use
FROM vlake.kev WHERE cve = 'CVE-2021-44228' AND NOT removed;
SELECT * FROM vlake.datasets;  -- data sources & licenses
```

```text
┌────────────────┬─────────┬────────────┬────────────┬───────────────┐
│      cve       │  epss   │ percentile │    date    │ model_version │
├────────────────┼─────────┼────────────┼────────────┼───────────────┤
│ CVE-2021-44228 │ 0.99999 │        1.0 │ 2026-07-10 │ v2026.06.15   │
└────────────────┴─────────┴────────────┴────────────┴───────────────┘
```

Prefer plain Parquet? The same files are directly readable:

```sql
SELECT * FROM read_parquet('https://vlake.reta.work/epss/year=2026/*.parquet');
```

```python
import polars as pl
pl.read_parquet("https://vlake.reta.work/epss/year=2026/epss-2026-07-10.parquet")
```

## Schema

Each dataset is stored as an **append-only history table** plus a **latest
view** that returns just the most recent row per record — query the view for
current state, the history table to see how a record changed over time.
EPSS is the exception: its full daily history *is* the data, so there is no
separate view.

| Query this | Backed by | One row per | Content |
|---|---|---|---|
| `epss` | `epss` | CVE × date | EPSS exploit-prediction scores (full daily history) |
| `cve` | `cve_history` | CVE | CVE List V5 records (MITRE/CNA) |
| `cve_sources` | *(view)* | CVE | Cross-dataset presence summary for each CVE |
| `ghsa` | `ghsa_history` | GHSA ID | GitHub-reviewed advisories with affected package ranges |
| `exploitdb` | `exploitdb_history` | `edb_id` | Exploit Database index (metadata; code linked by URL) |
| `nuclei` | `nuclei_history` | `template_id` | nuclei-templates detection metadata (linked by URL) |
| `cwe` | `cwe_history` | `cwe_id` | CWE catalog snapshot (join target for `cwe` columns) |
| `kev` | `kev_history` | CVE | CISA Known Exploited Vulnerabilities catalog |
| `datasets` | *(view)* | dataset | Data sources, licenses & attributions |

Views tagged **tombstone** (`nuclei`, `kev`) keep records that disappeared
upstream, flagged `removed = true` with their last known values — filter
`WHERE NOT removed` for the currently-live set.

### `epss` — exploit prediction scores

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `epss` | DOUBLE | Probability (0–1) of exploitation in the next 30 days |
| `percentile` | DOUBLE | Rank among all scored CVEs; NULL for early-2021 files (column did not exist yet) |
| `date` | DATE | Score date |
| `model_version` | VARCHAR | EPSS model version that produced the score |

### `cve` / `cve_history` — CVE List V5

Append-only change history from cvelistV5 daily baselines. The `cve` view
returns the latest row per CVE.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `state` | VARCHAR | Record state (`PUBLISHED` / `REJECTED`) |
| `assigner` | VARCHAR | Assigning CNA |
| `title` | VARCHAR | Vulnerability title |
| `description` | VARCHAR | English description |
| `cvss` | DOUBLE | CVSS base score |
| `cvss_version` | VARCHAR | CVSS version (e.g. `3.1`) |
| `cvss_severity` | VARCHAR | Qualitative severity (e.g. `CRITICAL`) |
| `cvss_vector` | VARCHAR | CVSS vector string |
| `cwe` | VARCHAR[] | Associated CWE IDs (join to `cwe`) |
| `date_published` | TIMESTAMP | First publication |
| `date_reserved` | TIMESTAMP | CVE ID reservation |
| `date_updated` | TIMESTAMP | Last update (also the view's latest-row key) |
| `raw` | VARCHAR | Full CVE JSON 5.x record |

### `cve_sources` — cross-dataset CVE presence

Summary view for quickly checking which public datasets contain data for a CVE.
It is derived from `epss`, `cve`, `ghsa`, `exploitdb`, `nuclei`, and `kev`.
For tombstone-backed views (`nuclei`, `kev`), only rows with `removed = false`
count as present.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `has_epss` | BOOLEAN | Whether `epss` has at least one score row |
| `has_cve` | BOOLEAN | Whether the `cve` latest view has a row |
| `has_ghsa` | BOOLEAN | Whether the `ghsa` latest view has at least one linked advisory |
| `has_exploitdb` | BOOLEAN | Whether the `exploitdb` latest view has at least one linked entry |
| `has_nuclei` | BOOLEAN | Whether the `nuclei` latest view has at least one currently-live linked template |
| `has_kev` | BOOLEAN | Whether the `kev` latest view has a currently-live row |
| `epss_days` | BIGINT | Number of EPSS score days |
| `ghsa_count` | BIGINT | Number of linked GHSA advisories |
| `exploitdb_count` | BIGINT | Number of linked ExploitDB entries |
| `nuclei_count` | BIGINT | Number of linked currently-live nuclei templates |

### `ghsa` / `ghsa_history` — GitHub Advisory Database

Append-only change history of GitHub-reviewed advisories. The `ghsa` view
returns the latest row per GHSA ID. Numeric `cvss` is computed from the vector.

| Column | Type | Description |
|---|---|---|
| `ghsa` | VARCHAR | GHSA ID |
| `cve` | VARCHAR | Linked CVE ID (may be NULL) |
| `summary` | VARCHAR | Short advisory summary |
| `severity` | VARCHAR | Qualitative severity |
| `cvss` | DOUBLE | CVSS base score (computed from vector) |
| `cvss_version` | VARCHAR | CVSS version |
| `cvss_vector` | VARCHAR | CVSS vector string |
| `cwe` | VARCHAR[] | Associated CWE IDs (join to `cwe`) |
| `affected` | STRUCT(ecosystem, package, introduced, fixed, last_affected)[] | Affected package/version ranges; `UNNEST` to expand |
| `published` | TIMESTAMP | Publication time |
| `modified` | TIMESTAMP | Last modification (also the view's latest-row key) |
| `withdrawn` | TIMESTAMP | Withdrawal time, or NULL |
| `raw` | VARCHAR | Full OSV JSON record |

### `exploitdb` / `exploitdb_history` — Exploit Database index

Append-only index history from `files_exploits.csv`. The `exploitdb` view
returns the latest row per `edb_id` (by `date_updated`). Exploit code is not
redistributed — `code_url` links to it.

| Column | Type | Description |
|---|---|---|
| `edb_id` | INTEGER | Exploit-DB entry ID |
| `cve` | VARCHAR[] | Linked CVE IDs |
| `description` | VARCHAR | Exploit title |
| `type` | VARCHAR | Exploit type (e.g. `remote`, `webapps`) |
| `platform` | VARCHAR | Target platform |
| `author` | VARCHAR | Author |
| `port` | INTEGER | Target port, if applicable |
| `verified` | BOOLEAN | Whether OffSec verified the exploit |
| `tags` | VARCHAR | Tags |
| `aliases` | VARCHAR | Aliases |
| `codes` | VARCHAR | External reference codes |
| `file` | VARCHAR | Source path within the Exploit-DB repo |
| `code_url` | VARCHAR | Link to the exploit code |
| `source_url` | VARCHAR | Source reference URL |
| `application_url` | VARCHAR | Vulnerable application download URL |
| `screenshot_url` | VARCHAR | Screenshot URL |
| `date_published` | DATE | Publication date |
| `date_added` | DATE | Date added to Exploit-DB |
| `date_updated` | DATE | Last update (also the view's latest-row key) |

### `nuclei` / `nuclei_history` — nuclei-templates index

Append-only index of nuclei-templates `info` blocks. Templates carry no
upstream modification timestamp, so changes are detected by `digest` (SHA-256
of the template with its signature line stripped). The `nuclei` view returns
the latest row per `template_id`; disappeared templates become **tombstones**
(`removed = true`). `epss_score` / `epss_percentile` are snapshots embedded at
authoring time — the `epss` table is the source of truth for current scores.

| Column | Type | Description |
|---|---|---|
| `template_id` | VARCHAR | Template ID |
| `name` | VARCHAR | Template name |
| `severity` | VARCHAR | Severity |
| `description` | VARCHAR | Description |
| `author` | VARCHAR[] | Authors |
| `tags` | VARCHAR[] | Tags |
| `reference` | VARCHAR[] | Reference URLs |
| `cve` | VARCHAR[] | Linked CVE IDs |
| `cwe` | VARCHAR[] | Associated CWE IDs (join to `cwe`) |
| `cvss_score` | DOUBLE | CVSS base score (as authored) |
| `cvss_metrics` | VARCHAR | CVSS vector string |
| `epss_score` | DOUBLE | EPSS score snapshot (as authored) |
| `epss_percentile` | DOUBLE | EPSS percentile snapshot (as authored) |
| `cpe` | VARCHAR | CPE string |
| `vendor` | VARCHAR | Vendor |
| `product` | VARCHAR | Product |
| `verified` | BOOLEAN | Whether the template is verified |
| `type` | VARCHAR | Protocol/type (e.g. `http`) |
| `file` | VARCHAR | Source path within nuclei-templates |
| `template_url` | VARCHAR | Link to the template |
| `digest` | VARCHAR | SHA-256 change-detection digest |
| `fetched_date` | DATE | Fetch date (also the view's latest-row key) |
| `removed` | BOOLEAN | Tombstone flag (`true` = gone upstream) |

### `cwe` / `cwe_history` — CWE catalog

Versioned snapshots of the CWE catalog (weaknesses, categories and views, told
apart by `entry_type`). The `cwe` view returns the snapshot with the latest
`release_date`; join it against the `cwe` array columns of `cve` / `ghsa` /
`nuclei`. Deprecated entries remain with `status = 'Deprecated'`.

| Column | Type | Description |
|---|---|---|
| `cwe_id` | VARCHAR | CWE ID (e.g. `CWE-79`) |
| `entry_type` | VARCHAR | `weakness` / `category` / `view` |
| `name` | VARCHAR | Entry name |
| `abstraction` | VARCHAR | Abstraction level (e.g. `Base`, `Class`) |
| `status` | VARCHAR | Status (e.g. `Stable`, `Deprecated`) |
| `description` | VARCHAR | Description |
| `likelihood_of_exploit` | VARCHAR | Likelihood of exploit |
| `relations` | STRUCT(nature, target_id)[] | Relationships to other CWEs |
| `cwe_version` | VARCHAR | CWE catalog version |
| `release_date` | DATE | Snapshot release date (also the view's latest-row key) |

### `kev` / `kev_history` — CISA Known Exploited Vulnerabilities

Append-only history of the CISA KEV catalog. KEV records carry no modification
timestamp (`date_added` never changes after listing), so changes are detected
by comparing every field against the catalog's latest row. The `kev` view
returns the latest row per `cve`; withdrawn records become **tombstones**
(`removed = true`).

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `vendor_project` | VARCHAR | Vendor / project |
| `product` | VARCHAR | Product |
| `vulnerability_name` | VARCHAR | Vulnerability name |
| `short_description` | VARCHAR | Short description |
| `required_action` | VARCHAR | Required remediation action |
| `known_ransomware_campaign_use` | VARCHAR | Whether tied to known ransomware use |
| `notes` | VARCHAR | Notes / reference URLs |
| `cwe` | VARCHAR[] | Associated CWE IDs (join to `cwe`) |
| `date_added` | DATE | Date added to KEV |
| `due_date` | DATE | Federal remediation due date |
| `fetched_date` | DATE | Fetch date (also the view's latest-row key) |
| `removed` | BOOLEAN | Tombstone flag (`true` = withdrawn by CISA) |

### `datasets` — data sources & licenses

A view describing each dataset's provenance. See
[DATA_LICENSES.md](DATA_LICENSES.md).

| Column | Type | Description |
|---|---|---|
| `name` | VARCHAR | Dataset name |
| `source_url` | VARCHAR | Upstream source URL |
| `license_name` | VARCHAR | License identifier/name |
| `license_text` | VARCHAR | License text or license URL |
| `attribution` | VARCHAR | Required attribution text |
| `disclaimer` | VARCHAR | Source-specific disclaimer / endorsement notice |

### Storage layout

Data files are plain Parquet, readable directly (see [Query it](#query-it)).
Consumers who only use the DuckLake catalog can skip this.

| Dataset | Backfill / full snapshot files | Update files | Notes |
|---|---|---|---|
| `epss` | `epss/year=YYYY/epss-YYYY.parquet` | `epss/year=YYYY/epss-YYYY-MM-DD.parquet` (current year only) | Closed years consolidated into one per-year file, sorted by `cve, date`; day-level URLs exist only for the current year, year-level globs work for all |
| `cve` | `cve/year=YYYY/cve-YYYY.parquet` | `cve/updates/year=YYYY/cve-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by CVE-ID year, sorted by `cve`; deltas = records whose `dateUpdated` advanced past the catalog's max |
| `ghsa` | `ghsa/year=YYYY/ghsa-YYYY.parquet` | `ghsa/updates/year=YYYY/ghsa-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by published year, sorted by `ghsa`; deltas dated by run date |
| `exploitdb` | `exploitdb/year=YYYY/exploitdb-YYYY.parquet` | `exploitdb/updates/year=YYYY/exploitdb-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by `date_published` year, sorted by `edb_id`; deltas dated by run date |
| `nuclei` | *(none)* | `nuclei/updates/year=YYYY/nuclei-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full load |
| `cwe` | *(none)* | `cwe/version=<ver>/cwe-<ver>.parquet` | One full snapshot per CWE release (a few per year); `cwe/last-modified.txt` stores the upstream `Last-Modified` for conditional GETs |
| `kev` | *(none)* | `kev/updates/year=YYYY/kev-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full load |

## Build your own lake

```bash
uv sync
export VLAKE_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com  # or AWS S3 endpoint
export VLAKE_S3_BUCKET=my-vlake
export VLAKE_PUBLIC_URL=https://data.example.com   # public base URL of the bucket
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=auto   # `auto` works for R2; use a real region for AWS S3

# one-time backfill (avoids hammering the official CDN)
git clone --depth 1 https://github.com/empiricalsec/epss_scores /tmp/epss_scores
uv run vlake backfill epss --source /tmp/epss_scores
uv run vlake backfill cve   # baseline zip (~550MB) を自動ダウンロード
uv run vlake backfill ghsa  # リポジトリ tarball を自動ダウンロード
uv run vlake backfill exploitdb  # files_exploits.csv を自動ダウンロード

# daily
uv run vlake update epss
uv run vlake update cve
uv run vlake update ghsa
uv run vlake update exploitdb
uv run vlake update nuclei  # no backfill: the first run does a full load
uv run vlake update cwe     # no backfill: snapshot per CWE release
uv run vlake update kev     # no backfill: the first run does a full load
uv run vlake verify
```

No local machine needed for the backfill: after configuring the `publish`
Environment (below), open the **Actions** tab → **backfill** → **Run
workflow** and pick a **dataset** (`all` / `epss` / `cve` / `ghsa` / `exploitdb`). For epss the job
clones the mirror on the runner, consolidates closed years into per-year
Parquet files, and ingests the current year day by day; for cve it downloads
the latest cvelistV5 baseline zip (~550MB) and ingests it (roughly an hour
total for `all`). It is idempotent — already-registered years/days are
skipped — so re-running after a failure is safe. It shares the `publish`
concurrency group with the daily job, so the two never touch the catalog
concurrently. Note: if a backfill run dies partway, the daily `publish`
workflow's `verify` step will stay red (storage holds files the catalog does
not reference yet) until you re-dispatch **backfill** — that re-run completes
the recovery; the published catalog is never left in a broken state.

Local mode for testing: set `VLAKE_LOCAL_DIR=/some/dir` instead of the S3 variables.

The included GitHub Actions workflow (`.github/workflows/publish.yml`) runs
`vlake update epss`, `vlake update cve`, `vlake update ghsa` daily at 14:30 UTC
(EPSS publishes around 13:30 UTC; the cvelistV5 baseline is a 00:00 UTC snapshot).
Fork the repo and create a **`publish` Environment** (Settings → Environments →
New environment → name it `publish`) — the workflow's `environment: publish` line
only resolves Secrets/Variables stored there. Configure inside that Environment:

| Name | Where (in the `publish` Environment) | Why |
|---|---|---|
| `VLAKE_PUBLIC_URL` | **Environment variable** | Public by definition (it is the URL consumers use) |
| `VLAKE_S3_ENDPOINT` | **Environment secret** | May contain your account ID (e.g. R2 endpoint) |
| `VLAKE_S3_BUCKET` | **Environment secret** | Keeps the write-target bucket name private |
| `AWS_ACCESS_KEY_ID` | **Environment secret** | Credential |
| `AWS_SECRET_ACCESS_KEY` | **Environment secret** | Credential |

Keeping them in an Environment (rather than repository-level) means they are only
exposed to jobs that declare `environment: publish`, and you can add protection
rules: restrict **deployment branches** to `main` (recommended — a workflow edited
on any other branch then cannot reach the credentials) and optionally require
reviewers before each run.

Notes:
- Scheduled workflows are disabled by default on forks — after forking, open the
  **Actions** tab and enable workflows before the daily cron will run.
- `VLAKE_PUBLIC_URL` is baked into the catalog at publish time. If you change it
  later (e.g. moving to a new domain), run `vlake rebuild-catalog` afterwards so
  the catalog's data file paths point at the new URL.

## Data licenses

| Dataset | Source | License | Notes |
| --- | --- | --- | --- |
| EPSS | [FIRST.org EPSS](https://www.first.org/epss) | FIRST EPSS Usage Agreement (`LicenseRef-scancode-first-epss-usage`) | Redistributed with attribution. Not endorsed or certified by FIRST. |
| CVE | [CVE List V5](https://github.com/CVEProject/cvelistV5) | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) (SPDX: `cve-tou`) | CVE® is a registered trademark of The MITRE Corporation. CVE Records: Copyright © 1999-2026 The MITRE Corporation. Not endorsed or certified by MITRE or the CVE Program. |
| GHSA | [GitHub Advisory Database](https://github.com/github/advisory-database) — © GitHub, Inc. | [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) | Redistributed with modifications (OSV JSON → Parquet); original record kept in the `raw` column. Not endorsed or certified by GitHub, Inc. |
| ExploitDB | [Exploit Database index](https://gitlab.com/exploit-database/exploitdb) — maintained by OffSec | GPL-2.0-or-later (`licenses/GPL-2.0.txt`) | Only the derived index Parquet redistributed under GPL-2.0-or-later, with modifications (CSV → Parquet, exploit code not included — linked via `code_url`). Copyleft applies to that Parquet only; vulnlake's Apache-2.0 code and other datasets are unaffected (mere aggregation). Not endorsed or certified by OffSec. |
| nuclei | [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — © ProjectDiscovery, Inc. | MIT (`licenses/MIT-nuclei-templates.txt`) | Template metadata only; template bodies not redistributed (linked via `template_url`). Not endorsed or certified by ProjectDiscovery, Inc. |
| CWE | [Common Weakness Enumeration](https://cwe.mitre.org/) — © The MITRE Corporation | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html) | Redistributed with modifications (cwec XML → Parquet). Not endorsed or certified by The MITRE Corporation. |
| KEV | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 Universal (`licenses/CC0-1.0-kev.txt`) | Redistributed with modifications (JSON → Parquet). Not endorsed by CISA or DHS; the CISA Logo and DHS Seal are not used. Third-party links in the data are bound by the policies and licenses of those third-party websites. |

For full terms and attributions, see [DATA_LICENSES.md](DATA_LICENSES.md) and
the in-lake `datasets` view (`SELECT * FROM vlake.datasets`).

## Code license

Apache-2.0
