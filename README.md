# vlake

Security datasets published as a **frozen DuckLake** on S3-compatible storage.
Currently included: **EPSS** (full daily history since 2021-04-14).

## Query it

```sql
-- DuckDB 1.5.2+
INSTALL ducklake;
ATTACH 'ducklake:https://<your-public-url>/vlake.ducklake' AS vlake;
SELECT * FROM vlake.epss WHERE cve = 'CVE-2021-44228' ORDER BY date;
SELECT * FROM vlake.datasets;  -- data sources & licenses
```

Prefer plain Parquet? The same files are directly readable:

```sql
SELECT * FROM read_parquet('https://<your-public-url>/epss/year=2026/*.parquet');
```

```python
import polars as pl
pl.read_parquet("https://<your-public-url>/epss/year=2026/epss-2026-07-10.parquet")
```

## Schema

`epss(cve VARCHAR, epss DOUBLE, percentile DOUBLE, date DATE, model_version VARCHAR)`
— `percentile` is NULL for early 2021 files (the column did not exist yet).

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

# daily
uv run vlake update epss
uv run vlake verify
```

Local mode for testing: set `VLAKE_LOCAL_DIR=/some/dir` instead of the S3 variables.

The included GitHub Actions workflow (`.github/workflows/publish.yml`) runs
`vlake update epss` daily at 14:30 UTC (EPSS publishes around 13:30 UTC).
Fork the repo, set the secrets above, and you have your own lake.

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

## Code license

Apache-2.0
