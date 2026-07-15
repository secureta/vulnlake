# vulnlake LLM query guide

This is a compact guide for writing DuckDB queries against the public vulnlake
DuckLake catalog. Prefer these query patterns over guessing from column names.

Public catalog:

```sql
INSTALL ducklake;
INSTALL httpfs;
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
```

For exact live columns, inspect the catalog instead of inferring:

```sql
SHOW TABLES FROM vlake;
DESCRIBE vlake.<table>;
```

## Querying rules

- Use latest views for current state: `vlake.cve`, `vlake.ghsa`,
  `vlake.exploitdb`, `vlake.nuclei`, `vlake.cwe`, and `vlake.kev`.
- Use history tables only when the user asks for previous versions, changes over
  time, or audit/history analysis: `vlake.cve_history`, `vlake.ghsa_history`,
  `vlake.exploitdb_history`, `vlake.nuclei_history`, `vlake.cwe_history`, and
  `vlake.kev_history`.
- `vlake.epss` is daily history. There is no separate latest EPSS view.
- For tombstone views, add `AND NOT removed` unless the user explicitly wants
  withdrawn or deleted upstream records: `vlake.nuclei` and `vlake.kev`.
- Use `list_contains(array_column, 'CVE-...')` for array columns such as
  `nuclei.cve`, `exploitdb.cve`, and `cwe` arrays.
- Use `UNNEST(affected)` to expand GHSA affected package/version ranges.
- `nuclei.epss_score` and `nuclei.epss_percentile` are template-authored
  snapshots. Use `vlake.epss` for current or historical EPSS scores.
- Use `SELECT * FROM vlake.datasets` for source, license, attribution, and
  disclaimer metadata.

## Which relation to query

| Need | Query |
|---|---|
| EPSS exploit prediction over time | `vlake.epss` |
| Current CVE List V5 record | `vlake.cve` |
| CVE record changes over time | `vlake.cve_history` |
| Current GitHub-reviewed advisories | `vlake.ghsa` |
| GHSA advisory changes over time | `vlake.ghsa_history` |
| Current ExploitDB metadata | `vlake.exploitdb` |
| ExploitDB metadata changes over time | `vlake.exploitdb_history` |
| Current nuclei template metadata | `vlake.nuclei WHERE NOT removed` |
| nuclei template metadata changes/deletions | `vlake.nuclei_history` |
| Current CWE catalog entries | `vlake.cwe` |
| CWE catalog snapshots over time | `vlake.cwe_history` |
| Current CISA KEV entries | `vlake.kev WHERE NOT removed` |
| KEV changes/withdrawals over time | `vlake.kev_history` |
| Dataset provenance and licenses | `vlake.datasets` |

## Canonical query patterns

EPSS score history for a CVE:

```sql
SELECT cve, epss, percentile, date, model_version
FROM vlake.epss
WHERE cve = 'CVE-2021-44228'
ORDER BY date DESC;
```

Current CVE record:

```sql
SELECT cve, title, description, cvss, cvss_version, cvss_severity, cwe
FROM vlake.cve
WHERE cve = 'CVE-2021-44228';
```

CVE record history:

```sql
SELECT cve, state, title, cvss, cvss_severity, date_updated
FROM vlake.cve_history
WHERE cve = 'CVE-2021-44228'
ORDER BY date_updated;
```

Current GHSA advisories for a CVE:

```sql
SELECT ghsa, summary, severity, cvss, cvss_vector, affected
FROM vlake.ghsa
WHERE cve = 'CVE-2021-44228';
```

Expand GHSA affected package ranges:

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

ExploitDB entries linked to a CVE:

```sql
SELECT edb_id, description, type, platform, verified, code_url
FROM vlake.exploitdb
WHERE list_contains(cve, 'CVE-2021-44228');
```

Currently-live nuclei templates linked to a CVE:

```sql
SELECT template_id, name, severity, type, template_url
FROM vlake.nuclei
WHERE list_contains(cve, 'CVE-2024-3400')
  AND NOT removed;
```

Join CVE records to current CWE names:

```sql
SELECT c.cve, c.title, w.cwe_id, w.name AS cwe_name
FROM vlake.cve AS c
LEFT JOIN vlake.cwe AS w ON list_contains(c.cwe, w.cwe_id)
WHERE c.cve = 'CVE-2021-44228';
```

Current CISA KEV entry:

```sql
SELECT cve, vulnerability_name, date_added, due_date, known_ransomware_campaign_use
FROM vlake.kev
WHERE cve = 'CVE-2021-44228'
  AND NOT removed;
```

Cross-dataset CVE summary:

```sql
SELECT
  c.cve,
  c.title,
  c.cvss,
  c.cvss_severity,
  e.epss,
  e.percentile,
  k.date_added AS kev_date_added,
  count(DISTINCT g.ghsa) AS ghsa_count,
  count(DISTINCT x.edb_id) AS exploitdb_count,
  count(DISTINCT n.template_id) AS nuclei_template_count
FROM vlake.cve AS c
LEFT JOIN (
  SELECT cve, epss, percentile
  FROM vlake.epss
  QUALIFY row_number() OVER (PARTITION BY cve ORDER BY date DESC) = 1
) AS e USING (cve)
LEFT JOIN vlake.kev AS k ON c.cve = k.cve AND NOT k.removed
LEFT JOIN vlake.ghsa AS g ON c.cve = g.cve
LEFT JOIN vlake.exploitdb AS x ON list_contains(x.cve, c.cve)
LEFT JOIN vlake.nuclei AS n ON list_contains(n.cve, c.cve) AND NOT n.removed
WHERE c.cve = 'CVE-2021-44228'
GROUP BY c.cve, c.title, c.cvss, c.cvss_severity, e.epss, e.percentile, k.date_added;
```

## Licensing and redistribution notes

- Check `SELECT * FROM vlake.datasets` before summarizing source licenses,
  attributions, or disclaimers.
- ExploitDB exploit code is not redistributed. vulnlake includes index metadata
  only and links to the original code with `code_url`.
- nuclei template bodies are not redistributed. vulnlake includes template
  metadata only and links to the original template with `template_url`.
- For the human-oriented project overview and schema reference, see
  `https://github.com/secureta/vlake#schema`.
