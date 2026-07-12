import csv
import gzip
import io
import json
import tarfile
import zipfile
from datetime import date
from pathlib import Path


def make_epss_csv_gz(
    score_date: date,
    rows: list[tuple],
    *,
    with_comment: bool = True,
    with_percentile: bool = True,
    model_version: str = "v2026.06.15",
    date_suffix: str = "T12:00:34Z",
) -> bytes:
    """実フォーマットを模した EPSS CSV (.gz) を作る。

    rows: with_percentile=True なら (cve, epss, percentile)、False なら (cve, epss)
    """
    lines = []
    if with_comment:
        lines.append(
            f"#model_version:{model_version},score_date:{score_date.isoformat()}{date_suffix}"
        )
    lines.append("cve,epss,percentile" if with_percentile else "cve,epss")
    for row in rows:
        lines.append(",".join(str(v) for v in row))
    return gzip.compress(("\n".join(lines) + "\n").encode())


def make_cve_record(
    cve_id: str,
    *,
    state: str = "PUBLISHED",
    assigner: str = "sample",
    date_updated: str | None = "2026-07-10T12:00:00.000Z",
    date_published: str | None = "2021-12-10T00:00:00.000Z",
    date_reserved: str | None = "2021-11-26T00:00:00.000Z",
    title: str | None = "Sample vulnerability title",
    description: str | None = "A sample vulnerability.",
    cna_metrics: list | None = None,
    adp_metrics: list | None = None,
    cwes: list[str] | None = None,
    rejected_reasons: list[str] | None = None,
) -> dict:
    """CVE JSON 5.x のレコード構造を模した dict を作る。"""
    meta: dict = {
        "cveId": cve_id,
        "assignerOrgId": "org-x",
        "assignerShortName": assigner,
        "state": state,
    }
    if date_published:
        meta["datePublished"] = date_published
    if date_reserved:
        meta["dateReserved"] = date_reserved
    if date_updated:
        meta["dateUpdated"] = date_updated
    cna: dict = {"providerMetadata": {"orgId": "org-x"}}
    if title:
        cna["title"] = title
    if state == "REJECTED":
        cna["rejectedReasons"] = [
            {"lang": "en", "value": v} for v in (rejected_reasons or [])
        ]
    elif description:
        cna["descriptions"] = [{"lang": "en", "value": description}]
    if cna_metrics:
        cna["metrics"] = cna_metrics
    if cwes:
        cna["problemTypes"] = [
            {
                "descriptions": [
                    {"type": "CWE", "lang": "en", "description": c, "cweId": c}
                ]
            }
            for c in cwes
        ]
    containers: dict = {"cna": cna}
    if adp_metrics:
        containers["adp"] = [
            {
                "title": "CISA ADP Vulnrichment",
                "providerMetadata": {"orgId": "org-y"},
                "metrics": adp_metrics,
            }
        ]
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": meta,
        "containers": containers,
    }


def make_baseline_zip(path: Path, records: list[dict], *, nested: bool = True) -> None:
    """cvelistV5 の baseline zip を模す。nested=True が実配布形式 (cves.zip を内包)。"""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        for rec in records:
            cve_id = rec["cveMetadata"]["cveId"]
            year = cve_id.split("-")[1]
            zf.writestr(f"cves/{year}/{cve_id}.json", json.dumps(rec))
    path.parent.mkdir(parents=True, exist_ok=True)
    if nested:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("cves.zip", inner.getvalue())
    else:
        path.write_bytes(inner.getvalue())


def make_ghsa_record(
    ghsa_id: str,
    *,
    aliases: tuple[str, ...] = ("CVE-2021-44228",),
    summary: str | None = "Sample advisory summary",
    severity_label: str | None = "CRITICAL",
    severity: list | None = None,
    cwe_ids: tuple[str, ...] = ("CWE-502",),
    affected: list | None = None,
    published: str | None = "2021-12-10T00:40:56Z",
    modified: str | None = "2026-07-10T12:00:00Z",
    withdrawn: str | None = None,
) -> dict:
    """GitHub Advisory Database の OSV レコード構造を模した dict を作る。

    severity=None ならデフォルトで CVSS_V3 の 10.0 ベクタを入れる。
    severity=[] で severity 無しになる。affected も同様。
    """
    if severity is None:
        severity = [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
        ]
    if affected is None:
        affected = [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}],
                    }
                ],
            }
        ]
    rec: dict = {
        "schema_version": "1.4.0",
        "id": ghsa_id,
        "aliases": list(aliases),
        "severity": severity,
        "affected": affected,
        "database_specific": {
            "cwe_ids": list(cwe_ids),
            "severity": severity_label,
            "github_reviewed": True,
        },
    }
    if summary:
        rec["summary"] = summary
        rec["details"] = summary + " (details)"
    if published:
        rec["published"] = published
    if modified:
        rec["modified"] = modified
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def make_ghsa_tarball(
    path: Path, records: list[dict], *, unreviewed: list[dict] = ()
) -> None:
    """github/advisory-database の main tarball を模す (top dir + OSV JSON)。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for area, recs in (("github-reviewed", records), ("unreviewed", unreviewed)):
            for rec in recs:
                yyyy, mm = rec["published"][0:4], rec["published"][5:7]
                name = (
                    f"advisory-database-main/advisories/{area}/"
                    f"{yyyy}/{mm}/{rec['id']}/{rec['id']}.json"
                )
                data = json.dumps(rec).encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


_EXPLOITDB_COLUMNS = [
    "id",
    "file",
    "description",
    "date_published",
    "author",
    "type",
    "platform",
    "port",
    "date_added",
    "date_updated",
    "verified",
    "codes",
    "tags",
    "aliases",
    "screenshot_url",
    "application_url",
    "source_url",
]


def make_exploitdb_csv(records: list[dict]) -> bytes:
    """files_exploits.csv を模した CSV バイト列を作る。

    records: 列名→値の dict のリスト。未指定の列は空文字列になる。
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_EXPLOITDB_COLUMNS)
    writer.writeheader()
    for rec in records:
        writer.writerow({c: rec.get(c, "") for c in _EXPLOITDB_COLUMNS})
    return buf.getvalue().encode()
