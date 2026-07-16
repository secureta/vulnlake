# vulnlake schema reference

For day-to-day use, start with the latest views below. Use history tables only
when you need change history. For tombstone-backed views (`nuclei`, `kev`,
`cloudflare_waf`), add `WHERE NOT removed` unless you intentionally want
records that disappeared upstream.

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
| `cloudflare_waf` | `cloudflare_waf_history` | vulnerability identifier × source URL | Vulnerability IDs mentioned in Cloudflare WAF ChangeLog entries |
| `datasets` | *(view)* | dataset | Data sources, licenses & attributions |

## Column reference

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
It is derived from `epss`, `cve`, `ghsa`, `exploitdb`, `nuclei`, `kev`, and
`cloudflare_waf`. For tombstone-backed views (`nuclei`, `kev`,
`cloudflare_waf`), only rows with `removed = false` count as present.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `has_epss` | BOOLEAN | Whether `epss` has at least one score row |
| `has_cve` | BOOLEAN | Whether the `cve` latest view has a row |
| `has_ghsa` | BOOLEAN | Whether the `ghsa` latest view has at least one linked advisory |
| `has_exploitdb` | BOOLEAN | Whether the `exploitdb` latest view has at least one linked entry |
| `has_nuclei` | BOOLEAN | Whether the `nuclei` latest view has at least one currently-live linked template |
| `has_kev` | BOOLEAN | Whether the `kev` latest view has a currently-live row |
| `has_cloudflare_waf` | BOOLEAN | Whether `cloudflare_waf` has at least one currently-live WAF ChangeLog mention for the CVE |
| `epss_days` | BIGINT | Number of EPSS score days |
| `ghsa_count` | BIGINT | Number of linked GHSA advisories |
| `exploitdb_count` | BIGINT | Number of linked ExploitDB entries |
| `nuclei_count` | BIGINT | Number of linked currently-live nuclei templates |
| `cloudflare_waf_count` | BIGINT | Number of linked currently-live Cloudflare WAF ChangeLog mentions |

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

### `cloudflare_waf` / `cloudflare_waf_history` — Cloudflare WAF ChangeLog vulnerability mentions

Append-only history of vulnerability identifiers extracted from Cloudflare WAF
ChangeLog MDX. The `cloudflare_waf` view returns the latest row per
`identifier + source_url`; mentions that disappear upstream become
**tombstones** (`removed = true`).

| Column | Type | Description |
|---|---|---|
| `identifier` | VARCHAR | Vulnerability identifier extracted from the ChangeLog, such as CVE or GHSA |
| `identifier_type` | VARCHAR | Identifier family (`CVE`, `GHSA`, `GO`, `PYSEC`, `RUSTSEC`) |
| `cve` | VARCHAR | Same as `identifier` for CVE rows, otherwise NULL |
| `source_title` | VARCHAR | ChangeLog entry title or historical table description |
| `source_url` | VARCHAR | Public Cloudflare Docs URL for the source ChangeLog entry/page |
| `source_date` | DATE | ChangeLog entry or historical table date, if available |
| `matched_text` | VARCHAR | Short text excerpt containing the identifier |
| `fetched_date` | DATE | Fetch date (also the view's latest-row key) |
| `removed` | BOOLEAN | Tombstone flag (`true` = mention disappeared upstream) |

### `datasets` — data sources & licenses

A view describing each dataset's provenance. See
[DATA_LICENSES.md](../DATA_LICENSES.md).

| Column | Type | Description |
|---|---|---|
| `name` | VARCHAR | Dataset name |
| `source_url` | VARCHAR | Upstream source URL |
| `license_name` | VARCHAR | License identifier/name |
| `license_text` | VARCHAR | License text or license URL |
| `attribution` | VARCHAR | Required attribution text |
| `disclaimer` | VARCHAR | Source-specific disclaimer / endorsement notice |

## Parquet storage layout

Consumers who use the DuckLake catalog can usually ignore this. It is useful if
you want to read the Parquet files directly or operate your own mirror.

| Dataset | Backfill / full snapshot files | Update files | Notes |
|---|---|---|---|
| `epss` | `epss/year=YYYY/epss-YYYY.parquet` | `epss/year=YYYY/epss-YYYY-MM-DD.parquet` (current year only) | Closed years consolidated into one per-year file, sorted by `cve, date`; day-level URLs exist only for the current year, year-level globs work for all |
| `cve` | `cve/year=YYYY/cve-YYYY.parquet` | `cve/updates/year=YYYY/cve-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by CVE-ID year, sorted by `cve`; deltas = records whose `dateUpdated` advanced past the catalog's max |
| `ghsa` | `ghsa/year=YYYY/ghsa-YYYY.parquet` | `ghsa/updates/year=YYYY/ghsa-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by published year, sorted by `ghsa`; deltas dated by run date |
| `exploitdb` | `exploitdb/year=YYYY/exploitdb-YYYY.parquet` | `exploitdb/updates/year=YYYY/exploitdb-updates-YYYY-MM-DD.parquet` | Snapshot partitioned by `date_published` year, sorted by `edb_id`; deltas dated by run date |
| `nuclei` | *(none)* | `nuclei/updates/year=YYYY/nuclei-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full load |
| `cwe` | *(none)* | `cwe/version=<ver>/cwe-<ver>.parquet` | One full snapshot per CWE release (a few per year); `cwe/last-modified.txt` stores the upstream `Last-Modified` for conditional GETs |
| `kev` | *(none)* | `kev/updates/year=YYYY/kev-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full load |
| `cloudflare_waf` | *(none)* | `cloudflare_waf/updates/year=YYYY/cloudflare-waf-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full current ChangeLog identifier snapshot |
