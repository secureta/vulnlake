# vulnlake

Security datasets published as a **frozen DuckLake** on S3-compatible storage.
Currently included: **EPSS** (full daily history since 2021-04-14) and **CVE**
(CVE List V5, full record history of changes).

## Query it

```sql
-- DuckDB 1.5.2+
INSTALL ducklake;
INSTALL httpfs;
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
SELECT * FROM vlake.epss WHERE cve = 'CVE-2021-44228' ORDER BY date;
SELECT cve, title, cvss, cvss_severity FROM vlake.cve WHERE cve = 'CVE-2021-44228';
SELECT * FROM vlake.cve_history WHERE cve = 'CVE-2021-44228' ORDER BY date_updated;
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

`epss(cve VARCHAR, epss DOUBLE, percentile DOUBLE, date DATE, model_version VARCHAR)`
— `percentile` is NULL for early 2021 files (the column did not exist yet).

Layout: closed years are consolidated into one Parquet per year
(`epss/year=2021/epss-2021.parquet`, sorted by `cve, date` so per-CVE history
queries prune well); only the current year has per-day files
(`epss-YYYY-MM-DD.parquet`). Day-level direct URLs therefore exist only for
the current year — year-level globs (`year=2021/*.parquet`) work for all years.

`cve_history(cve, state, assigner, title, description, cvss, cvss_version,
cvss_severity, cvss_vector, cwe VARCHAR[], date_published, date_reserved,
date_updated, raw)` — append-only change history from cvelistV5 daily
baselines. The `cve` view returns the latest row per CVE
(`raw` holds the full CVE JSON 5.x record).

Layout: `cve/year=YYYY/cve-YYYY.parquet` (backfill snapshot, partitioned by
CVE-ID year, sorted by cve) plus
`cve/updates/year=YYYY/cve-updates-YYYY-MM-DD.parquet` (daily deltas of
records whose `dateUpdated` advanced past the catalog's max).

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

# daily
uv run vlake update epss
uv run vlake update cve
uv run vlake verify
```

No local machine needed for the backfill: after configuring the `publish`
Environment (below), open the **Actions** tab → **backfill** → **Run
workflow** and pick a **dataset** (`all` / `epss` / `cve`). For epss the job
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
`vlake update epss` and `vlake update cve` daily at 14:30 UTC (EPSS publishes
around 13:30 UTC; the cvelistV5 baseline is a 00:00 UTC snapshot).
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

EPSS scores provided by FIRST.org — https://www.first.org/epss.
This project redistributes EPSS data but is not endorsed or certified by FIRST.
See [DATA_LICENSES.md](DATA_LICENSES.md) and the in-lake `datasets` view.

CVE data is redistributed under the CVE Terms of Use (SPDX: `cve-tou`) —
https://www.cve.org/Legal/TermsOfUse. CVE® is a registered trademark of The
MITRE Corporation. CVE Records: Copyright © 1999-2026 The MITRE Corporation.
See [DATA_LICENSES.md](DATA_LICENSES.md) and `SELECT * FROM vlake.datasets`.

## Code license

Apache-2.0
