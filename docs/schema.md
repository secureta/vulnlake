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
| `cve_ssvc` | *(view)* | CVE × SSVC metric | CISA Coordinator SSVC values extracted from latest CVE records |
| `cve_ssvc_history` | *(view)* | CVE history row × SSVC metric | CISA Coordinator SSVC values extracted from CVE record history |
| `ssvc_decision` | *(view)* | SSVC parameter combination | CISA Coordinator SSVC 2.0.3 decision table |
| `cve_ssvc_candidates` | *(view)* | CVE × decision candidate | Decision candidates expanded from recorded CVE SSVC values |
| `ghsa` | `ghsa_history` | GHSA ID | GitHub-reviewed advisories with affected package ranges |
| `exploitdb` | `exploitdb_history` | `edb_id` | Exploit Database index (metadata; code linked by URL) |
| `nuclei` | `nuclei_history` | `template_id` | nuclei-templates detection metadata (linked by URL) |
| `cwe` | `cwe_history` | `cwe_id` | CWE catalog snapshot (join target for `cwe` columns) |
| `attack` | `attack_history` | ATT&CK matrix × external ID | MITRE ATT&CK Enterprise / Mobile / ICS objects |
| `attack_relationship` | `attack_relationship_history` | ATT&CK matrix × relationship ID | MITRE ATT&CK STIX relationship SROs with resolved endpoint names/IDs |
| `capec` | `capec_history` | CAPEC ID | CAPEC attack patterns with CWE and ATT&CK mappings |
| `cwe_attack_patterns` | *(view)* | CWE × CAPEC × ATT&CK mapping | Convenience bridge from CWE IDs to CAPEC and ATT&CK techniques |
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

### `cve_ssvc` / `cve_ssvc_history` — CISA Coordinator SSVC from CVE List V5

Views that extract CISA Coordinator SSVC metrics from the CVE List V5 `raw`
JSON. `cve_ssvc` reads the latest `cve` view. `cve_ssvc_history` reads
`cve_history` so SSVC changes can be audited over time. CVEs without CISA ADP
Vulnrichment SSVC rows do not appear in these views.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `date_updated` | TIMESTAMP | CVE record update time |
| `ssvc_version` | VARCHAR | SSVC decision table version from the record, currently `2.0.3` for CISA Coordinator rows |
| `ssvc_role` | VARCHAR | SSVC role, currently `CISA Coordinator` |
| `ssvc_timestamp` | TIMESTAMP | SSVC assessment timestamp |
| `ssvc_provider` | VARCHAR | ADP provider/title, typically `CISA ADP Vulnrichment` |
| `exploitation` | VARCHAR | Recorded SSVC Exploitation value (`none`, `public poc`, `active`) |
| `automatable` | VARCHAR | Recorded SSVC Automatable value (`yes`, `no`) |
| `technical_impact` | VARCHAR | Recorded SSVC Technical Impact value (`partial`, `total`) |
| `mission_impact` | VARCHAR | Recorded Mission and Well-Being Impact value if present; CISA Vulnrichment CVE rows often omit it |
| `recorded_decision` | VARCHAR | Decision recorded in CVE JSON if present |
| `ssvc_raw` | VARCHAR | SSVC metric JSON fragment extracted from the CVE record |

### `ssvc_decision` — CISA Coordinator SSVC decision table

CISA Coordinator SSVC 2.0.3 decision table. Filter any subset of parameter
columns to get all matching decisions; omitted parameters naturally return all
possible values.

| Column | Type | Description |
|---|---|---|
| `ssvc_version` | VARCHAR | SSVC decision table version (`2.0.3`) |
| `ssvc_role` | VARCHAR | SSVC role (`CISA Coordinator`) |
| `exploitation` | VARCHAR | Exploitation value (`none`, `public poc`, `active`) |
| `automatable` | VARCHAR | Automatable value (`yes`, `no`) |
| `technical_impact` | VARCHAR | Technical Impact value (`partial`, `total`) |
| `mission_impact` | VARCHAR | Mission and Well-Being Impact value (`low`, `medium`, `high`) |
| `decision` | VARCHAR | Computed CISA decision (`track`, `track*`, `attend`, `act`) |
| `decision_label` | VARCHAR | Display label (`Track`, `Track*`, `Attend`, `Act`) |
| `decision_rank` | INTEGER | Sort key from lowest to highest urgency (`track` = 1, `act` = 4) |

### `cve_ssvc_candidates` — CVE-based SSVC decision candidates

Joins `cve_ssvc` to `ssvc_decision`. Recorded CVE SSVC values constrain the
join. Missing recorded parameters expand to every value from `ssvc_decision`,
so CVEs with partial SSVC data return every possible decision candidate. CVEs
without SSVC data return zero rows.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `date_updated` | TIMESTAMP | Latest CVE record update time |
| `ssvc_version` | VARCHAR | SSVC decision table version used for candidate computation |
| `ssvc_role` | VARCHAR | SSVC role used for candidate computation |
| `ssvc_timestamp` | TIMESTAMP | Recorded SSVC assessment timestamp |
| `ssvc_provider` | VARCHAR | ADP provider/title |
| `exploitation` | VARCHAR | Candidate Exploitation value |
| `automatable` | VARCHAR | Candidate Automatable value |
| `technical_impact` | VARCHAR | Candidate Technical Impact value |
| `mission_impact` | VARCHAR | Candidate Mission and Well-Being Impact value |
| `recorded_exploitation` | VARCHAR | Exploitation value recorded in CVE JSON, or NULL if missing |
| `recorded_automatable` | VARCHAR | Automatable value recorded in CVE JSON, or NULL if missing |
| `recorded_technical_impact` | VARCHAR | Technical Impact value recorded in CVE JSON, or NULL if missing |
| `recorded_mission_impact` | VARCHAR | Mission and Well-Being Impact value recorded in CVE JSON, or NULL if missing |
| `recorded_decision` | VARCHAR | Decision recorded in CVE JSON if present |
| `computed_decision` | VARCHAR | Decision computed from `ssvc_decision` |
| `decision_matches` | BOOLEAN | Whether `recorded_decision` equals `computed_decision`; NULL when no recorded decision exists |
| `decision_label` | VARCHAR | Display label for `computed_decision` |
| `decision_rank` | INTEGER | Sort key from lowest to highest urgency |
| `ssvc_raw` | VARCHAR | SSVC metric JSON fragment extracted from the CVE record |

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

### `attack` / `attack_history` — MITRE ATT&CK

Append-only snapshots of the Enterprise, Mobile and ICS ATT&CK STIX bundles.
The `attack` view returns the latest row per matrix and ATT&CK external ID (for
example `enterprise` + `T1190`, `mobile` + `T1634`, `ics` + `T0814`).
`object_type` distinguishes techniques, tactics, mitigations, groups, software
and data sources.

| Column | Type | Description |
|---|---|---|
| `matrix` | VARCHAR | ATT&CK matrix (`enterprise`, `mobile`, `ics`) |
| `attack_id` | VARCHAR | ATT&CK external ID |
| `object_id` | VARCHAR | STIX object ID |
| `object_type` | VARCHAR | STIX object type (`attack-pattern`, `x-mitre-tactic`, `course-of-action`, etc.) |
| `name` | VARCHAR | Object name |
| `description` | VARCHAR | Description |
| `url` | VARCHAR | MITRE ATT&CK reference URL |
| `kill_chain_phases` | STRUCT(kill_chain_name, phase_name)[] | Tactic/phase labels present on techniques; `UNNEST` to expand |
| `revoked` | BOOLEAN | STIX revoked flag |
| `deprecated` | BOOLEAN | MITRE deprecated flag |
| `modified` | TIMESTAMP | STIX modified timestamp (also the view's latest-row key) |
| `raw` | VARCHAR | Full STIX object JSON |

### `attack_relationship` / `attack_relationship_history` — MITRE ATT&CK relationships

Append-only snapshots of ATT&CK STIX relationship SROs. The
`attack_relationship` view returns the latest row per matrix and relationship
ID. `source_*` and `target_*` columns resolve STIX refs to ATT&CK IDs, names and
object types when the endpoint object is present in the same bundle; unresolved
endpoints keep the raw `source_ref` / `target_ref` with NULL resolved fields.

| Column | Type | Description |
|---|---|---|
| `matrix` | VARCHAR | ATT&CK matrix (`enterprise`, `mobile`, `ics`) |
| `relationship_id` | VARCHAR | STIX relationship object ID |
| `relationship_type` | VARCHAR | Relationship type (`uses`, `mitigates`, `subtechnique-of`, `detects`, etc.) |
| `source_ref` | VARCHAR | Source STIX object ref |
| `source_attack_id` | VARCHAR | Source ATT&CK external ID, if resolvable |
| `source_name` | VARCHAR | Source object name, if resolvable |
| `source_type` | VARCHAR | Source STIX object type, if resolvable |
| `target_ref` | VARCHAR | Target STIX object ref |
| `target_attack_id` | VARCHAR | Target ATT&CK external ID, if resolvable |
| `target_name` | VARCHAR | Target object name, if resolvable |
| `target_type` | VARCHAR | Target STIX object type, if resolvable |
| `description` | VARCHAR | Relationship description |
| `revoked` | BOOLEAN | STIX revoked flag |
| `deprecated` | BOOLEAN | MITRE deprecated flag |
| `modified` | TIMESTAMP | STIX modified timestamp (also the view's latest-row key) |
| `raw` | VARCHAR | Full STIX relationship JSON |

### `capec` / `capec_history` — CAPEC attack patterns

Append-only snapshots of the CAPEC STIX bundle. The `capec` view returns the
latest row per CAPEC ID. `cwe` and `attack` are external-reference arrays for
joining CAPEC to CWE and ATT&CK.

| Column | Type | Description |
|---|---|---|
| `capec_id` | VARCHAR | CAPEC ID |
| `object_id` | VARCHAR | STIX object ID |
| `name` | VARCHAR | Attack pattern name |
| `description` | VARCHAR | Description |
| `url` | VARCHAR | CAPEC reference URL |
| `cwe` | VARCHAR[] | Related CWE IDs |
| `attack` | VARCHAR[] | Related ATT&CK technique IDs |
| `revoked` | BOOLEAN | STIX revoked flag |
| `deprecated` | BOOLEAN | MITRE deprecated flag |
| `modified` | TIMESTAMP | STIX modified timestamp (also the view's latest-row key) |
| `raw` | VARCHAR | Full STIX object JSON |

### `cwe_attack_patterns` — CWE to CAPEC / ATT&CK bridge

Convenience view derived from `capec` and `attack`. It expands CAPEC `cwe` and
`attack` arrays so CVE rows can be joined through their CWE IDs. CAPEC rows with
`revoked` or `deprecated` are excluded.

| Column | Type | Description |
|---|---|---|
| `cwe` | VARCHAR | CWE ID |
| `capec_id` | VARCHAR | CAPEC ID |
| `capec_name` | VARCHAR | CAPEC attack pattern name |
| `attack_id` | VARCHAR | ATT&CK technique ID; may be NULL if CAPEC has no ATT&CK mapping |
| `attack_name` | VARCHAR | ATT&CK technique name |
| `attack_object_type` | VARCHAR | ATT&CK STIX object type |
| `kill_chain_phases` | STRUCT(kill_chain_name, phase_name)[] | ATT&CK kill-chain/tactic phases |

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
| `attack` | *(none)* | `attack/updates/year=YYYY/attack-YYYY-MM-DD.parquet` | One combined Enterprise / Mobile / ICS ATT&CK object snapshot per update run; no separate backfill |
| `attack_relationship` | *(none)* | `attack/relationships/year=YYYY/attack-relationships-YYYY-MM-DD.parquet` | One combined Enterprise / Mobile / ICS ATT&CK relationship snapshot per update run; omitted when a test snapshot has no relationships |
| `capec` | *(none)* | `capec/updates/year=YYYY/capec-YYYY-MM-DD.parquet` | One full CAPEC snapshot per update run; no separate backfill |
| `kev` | *(none)* | `kev/updates/year=YYYY/kev-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full load |
| `cloudflare_waf` | *(none)* | `cloudflare_waf/updates/year=YYYY/cloudflare-waf-updates-YYYY-MM-DD.parquet` | No backfill — the first run is the full current ChangeLog identifier snapshot |
