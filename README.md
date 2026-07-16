# vulnlake

Security vulnerability datasets, published as a queryable **DuckLake** catalog.

vulnlake lets you ask questions such as:

- What is the latest CVE record for this vulnerability?
- How has its EPSS score changed over time?
- Is it in GitHub Advisory Database, ExploitDB, nuclei-templates, CWE, CISA KEV, or Cloudflare WAF?
- Which source and license does each row come from?

The public catalog is available over HTTPS. You do not need an account, API key,
or local database server — just DuckDB with the DuckLake and HTTPFS extensions.

> **Naming:** the project is **vulnlake**. The CLI/package/catalog shorthand is
> `vlake`.

## Quick start

Use DuckDB 1.5.2 or newer:

```sql
INSTALL ducklake;
INSTALL httpfs;
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;

SELECT cve, title, cvss, cvss_severity
FROM vlake.cve
WHERE cve = 'CVE-2021-44228';
```

Need a quick cross-dataset check for one CVE?

```sql
SELECT *
FROM vlake.cve_sources
WHERE cve = 'CVE-2021-44228';
```

Need EPSS history?

```sql
SELECT cve, epss, percentile, date, model_version
FROM vlake.epss
WHERE cve = 'CVE-2021-44228'
ORDER BY date DESC;
```

The result looks like this:

```text
┌────────────────┬─────────┬────────────┬────────────┬───────────────┐
│      cve       │  epss   │ percentile │    date    │ model_version │
├────────────────┼─────────┼────────────┼────────────┼───────────────┤
│ CVE-2021-44228 │ 0.99999 │        1.0 │ 2026-07-10 │ v2026.06.15   │
└────────────────┴─────────┴────────────┴────────────┴───────────────┘
```

## What is included

| Dataset | Use it for | Query current state with |
|---|---|---|
| EPSS | Daily exploit-prediction scores for CVEs | `vlake.epss` |
| CVE List V5 | CVE records from MITRE/CNAs | `vlake.cve` |
| GitHub Advisory Database | GitHub-reviewed advisories and affected package ranges | `vlake.ghsa` |
| ExploitDB | Exploit Database index metadata | `vlake.exploitdb` |
| nuclei-templates | Detection template metadata | `vlake.nuclei WHERE NOT removed` |
| CWE | Common Weakness Enumeration catalog | `vlake.cwe` |
| CISA KEV | Known Exploited Vulnerabilities catalog | `vlake.kev WHERE NOT removed` |
| Cloudflare WAF ChangeLog | Vulnerability IDs mentioned in Cloudflare WAF managed-rules updates | `vlake.cloudflare_waf WHERE NOT removed` |

Most datasets are modeled as:

- a latest view (`cve`, `ghsa`, `exploitdb`, `nuclei`, `cwe`, `kev`, `cloudflare_waf`) for normal queries
- a history table (`*_history`) when you need previous versions or change history

EPSS is already daily history, so it has no separate latest view.

## Common query patterns

### Build a small CVE triage row

```sql
SELECT
  c.cve,
  c.title,
  c.cvss,
  c.cvss_severity,
  e.epss,
  e.percentile,
  s.has_ghsa,
  s.has_exploitdb,
  s.has_nuclei,
  s.has_kev,
  s.has_cloudflare_waf
FROM vlake.cve AS c
LEFT JOIN vlake.cve_sources AS s USING (cve)
LEFT JOIN (
  SELECT cve, epss, percentile
  FROM vlake.epss
  QUALIFY row_number() OVER (PARTITION BY cve ORDER BY date DESC) = 1
) AS e USING (cve)
WHERE c.cve = 'CVE-2021-44228';
```

### Find GitHub advisories and affected packages

```sql
SELECT
  ghsa,
  a.ecosystem,
  a.package,
  a.introduced,
  a.fixed,
  a.last_affected
FROM vlake.ghsa, UNNEST(affected) AS t(a)
WHERE cve = 'CVE-2021-44228';
```

### Find exploit or detection references

```sql
SELECT edb_id, description, type, platform, code_url
FROM vlake.exploitdb
WHERE list_contains(cve, 'CVE-2021-44228');

SELECT template_id, name, severity, template_url
FROM vlake.nuclei
WHERE list_contains(cve, 'CVE-2024-3400')
  AND NOT removed;
```

### Check if a CVE is known-exploited in the wild

```sql
SELECT cve, vulnerability_name, date_added, due_date, known_ransomware_campaign_use
FROM vlake.kev
WHERE cve = 'CVE-2021-44228'
  AND NOT removed;
```

### Check whether Cloudflare WAF ChangeLog mentions a vulnerability

```sql
SELECT identifier, source_title, source_url, source_date
FROM vlake.cloudflare_waf
WHERE identifier = 'CVE-2025-53770'
  AND NOT removed;
```

### Join CVEs to CWE names

```sql
SELECT c.cve, c.title, w.cwe_id, w.name AS cwe_name
FROM vlake.cve AS c
LEFT JOIN vlake.cwe AS w ON list_contains(c.cwe, w.cwe_id)
WHERE c.cve = 'CVE-2021-44228';
```

## Plain Parquet access

DuckLake is the easiest entry point, but the same data files are plain Parquet:

```sql
SELECT *
FROM read_parquet('https://vlake.reta.work/epss/year=2026/*.parquet');
```

```python
import polars as pl

scores = pl.read_parquet("https://vlake.reta.work/epss/year=2026/epss-2026-07-10.parquet")
```

## For LLMs and agents

A compact query guide is published at:

https://vlake.reta.work/llms.txt

It is intended for tools that need canonical DuckDB query patterns without
reading the full README.

## Schema

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

For columns, history-table details, and direct Parquet paths, see the [full schema reference](docs/schema.md).

## Build your own lake

Most users can use the public catalog. Build your own only if you need a
separate bucket, domain, schedule, or retention policy.

### Local smoke test

Local mode writes both the catalog and Parquet files under one directory. It is
useful for testing the pipeline without S3 credentials:

```bash
uv sync
export VLAKE_LOCAL_DIR=/tmp/vlake-test
uv run vlake update kev
uv run vlake verify
```

### Publish to S3-compatible storage

Configure a bucket and the public URL where consumers will read the files:

```bash
uv sync
export VLAKE_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com  # or AWS S3 endpoint
export VLAKE_S3_BUCKET=my-vlake
export VLAKE_PUBLIC_URL=https://data.example.com
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=auto  # `auto` works for R2; use a real region for AWS S3
```

Backfill datasets that have historical snapshots:

```bash
# EPSS full history comes from a mirror, to avoid hammering the official CDN.
git clone --depth 1 https://github.com/empiricalsec/epss_scores /tmp/epss_scores
uv run vlake backfill epss --source /tmp/epss_scores

uv run vlake backfill cve        # downloads the latest cvelistV5 baseline zip (~550 MB)
uv run vlake backfill ghsa       # downloads the GitHub Advisory Database tarball
uv run vlake backfill exploitdb  # downloads files_exploits.csv
```

Then run updates daily:

```bash
uv run vlake update epss
uv run vlake update cve
uv run vlake update ghsa
uv run vlake update exploitdb
uv run vlake update nuclei  # first run is a full load
uv run vlake update cwe     # snapshot per CWE release
uv run vlake update kev     # first run is a full load
uv run vlake update cloudflare_waf  # first run is a full load
uv run vlake verify
```

The publish order is intentionally conservative: data Parquet files are uploaded
first, and the DuckLake catalog (`vlake.ducklake`) is replaced last. If a run
fails before the catalog is published, consumers keep seeing the previous stable
catalog; rerunning is safe and idempotent.

### GitHub Actions

This repository includes workflows for daily publishing and manual backfills.
To use them in a fork:

1. Enable workflows in the **Actions** tab.
2. Create an Environment named `publish`.
3. Put the following values in that Environment, not at repository level:

| Name | Store as | Why |
|---|---|---|
| `VLAKE_PUBLIC_URL` | Environment variable | Public base URL baked into the catalog |
| `VLAKE_S3_ENDPOINT` | Environment secret | S3/R2 endpoint may contain account details |
| `VLAKE_S3_BUCKET` | Environment secret | Write target bucket |
| `AWS_ACCESS_KEY_ID` | Environment secret | Credential |
| `AWS_SECRET_ACCESS_KEY` | Environment secret | Credential |

Recommended: restrict the `publish` Environment to the `main` branch so workflow
edits on other branches cannot access publishing credentials.

Notes:

- Scheduled workflows are disabled by default on forks until you enable them.
- `VLAKE_PUBLIC_URL` is stored inside the catalog. If you change domains later,
  run `uv run vlake rebuild-catalog` so file paths point at the new URL.
- The manual **backfill** workflow shares the same concurrency group as daily
  publishing, so the two jobs do not update the catalog at the same time.

## Licenses and attribution

The code in this repository is Apache-2.0. The data follows each upstream
source's license. Query `SELECT * FROM vlake.datasets` or read
[DATA_LICENSES.md](DATA_LICENSES.md) for the full terms, attribution text, and
disclaimers.

| Dataset | Source | License / note |
|---|---|---|
| EPSS | [FIRST.org EPSS](https://www.first.org/epss) | FIRST EPSS Usage Agreement; redistributed with attribution; not endorsed or certified by FIRST |
| CVE | [CVE List V5](https://github.com/CVEProject/cvelistV5) | CVE Terms of Use; CVE® is a registered trademark of The MITRE Corporation; not endorsed or certified by MITRE or the CVE Program |
| GHSA | [GitHub Advisory Database](https://github.com/github/advisory-database) | CC-BY 4.0; redistributed with modifications; not endorsed or certified by GitHub, Inc. |
| ExploitDB | [Exploit Database index](https://gitlab.com/exploit-database/exploitdb) | GPL-2.0-or-later for the derived ExploitDB Parquet metadata only; exploit code is not redistributed and is linked by `code_url` |
| nuclei | [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT; template metadata only, template bodies are not redistributed and are linked by `template_url` |
| CWE | [Common Weakness Enumeration](https://cwe.mitre.org/) | CWE Terms of Use; redistributed with modifications; not endorsed or certified by The MITRE Corporation |
| KEV | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 Universal; redistributed with modifications; not endorsed by CISA or DHS |
| cloudflare_waf | [Cloudflare WAF ChangeLog](https://developers.cloudflare.com/waf/change-log/) | CC-BY 4.0; vulnerability identifiers extracted from Cloudflare Docs MDX and converted to Parquet |

## Development

```bash
uv sync
uv run pytest -v
uv run ruff check .
uv run ruff format . --check
uv run zizmor .github/workflows/
```
