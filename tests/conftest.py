import csv
import gzip
import io
import json
import tarfile
import zipfile
from datetime import date
from pathlib import Path

import yaml


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


def make_nuclei_yaml(
    template_id: str,
    *,
    name: str = "Sample Template",
    severity: str | None = "critical",
    description: str | None = "A sample detection template.",
    author: str | list | None = "pdteam,researcher",
    tags: str | None = "cve,rce",
    reference: list | None = None,
    cve_id: str | list | None = "CVE-2024-3400",
    cwe_id: str | list | None = "CWE-20,CWE-77",
    cvss_score: float | None = 10.0,
    cvss_metrics: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    epss_score: float | None = 0.99999,
    epss_percentile: float | None = 1.0,
    cpe: str | None = "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*",
    vendor: str | None = "vendor",
    product: str | None = "product",
    verified: bool | None = True,
    with_classification: bool = True,
    with_metadata: bool = True,
    protocol_key: str = "http",
    body_marker: str = "v1",
    with_signature: bool = True,
) -> bytes:
    """実フォーマットを模した nuclei テンプレート YAML を作る。

    body_marker は本文差分の注入点 (変えると content_digest が変わる)。
    with_signature=True で実テンプレート同様の末尾署名行 (# digest:) を付ける。
    """
    info: dict = {
        "name": name,
        "author": author,
        "severity": severity,
        "description": description,
        "tags": tags,
    }
    info = {k: v for k, v in info.items() if v is not None}
    if reference is None:
        reference = ["https://example.com/advisory"]
    if reference:
        info["reference"] = reference
    if with_classification:
        cls = {
            "cvss-metrics": cvss_metrics,
            "cvss-score": cvss_score,
            "cve-id": cve_id,
            "cwe-id": cwe_id,
            "epss-score": epss_score,
            "epss-percentile": epss_percentile,
            "cpe": cpe,
        }
        info["classification"] = {k: v for k, v in cls.items() if v is not None}
    if with_metadata:
        meta = {
            "verified": verified,
            "vendor": vendor,
            "product": product,
            "shodan-query": "http.favicon.hash:-631559155",
        }
        info["metadata"] = {k: v for k, v in meta.items() if v is not None}
    doc = {"id": template_id, "info": info, protocol_key: [{"marker": body_marker}]}
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    if with_signature:
        text += f"# digest: 4a0adeadbeef{body_marker}\n"
    return text.encode()


def make_nuclei_tarball(
    path: Path, files: dict[str, bytes], *, with_noise: bool = True
) -> None:
    """projectdiscovery/nuclei-templates の main tarball を模す (top dir 付き)。

    files: リポジトリ相対パス → 内容。with_noise=True で除外対象
    (.github/ helpers/ profiles/ と非 YAML) のダミーを混ぜる。
    """
    noise = (
        {
            ".github/workflows/ci.yml": b"name: ci\n",
            "helpers/payloads/generic.yaml": b"payload: x\n",
            "profiles/cves.yml": b"tags: [cve]\n",
            "README.md": b"# nuclei-templates\n",
            "cves.json": b"{}\n",
        }
        if with_noise
        else {}
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for rel, data in {**files, **noise}.items():
            info = tarfile.TarInfo(f"nuclei-templates-main/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def make_kev_record(
    cve: str = "CVE-2021-44228",
    *,
    vendor_project: str = "Apache",
    product: str = "Log4j2",
    vulnerability_name: str = "Apache Log4j2 Remote Code Execution Vulnerability",
    date_added: str = "2021-12-10",
    short_description: str = "Log4j2 contains a JNDI injection vulnerability.",
    required_action: str = "Apply updates per vendor instructions.",
    due_date: str = "2021-12-24",
    known_ransomware_campaign_use: str = "Known",
    notes: str = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    cwes: list[str] | None = None,
) -> dict:
    """KEV カタログの vulnerabilities 配列 1 レコードを実フォーマットで模す。"""
    return {
        "cveID": cve,
        "vendorProject": vendor_project,
        "product": product,
        "vulnerabilityName": vulnerability_name,
        "dateAdded": date_added,
        "shortDescription": short_description,
        "requiredAction": required_action,
        "dueDate": due_date,
        "knownRansomwareCampaignUse": known_ransomware_campaign_use,
        "notes": notes,
        "cwes": ["CWE-917"] if cwes is None else cwes,
    }


def make_kev_json(
    records: list[dict],
    *,
    catalog_version: str = "2026.07.10",
    date_released: str = "2026-07-10T17:00:25.7327Z",
) -> bytes:
    """CISA KEV フィード JSON 全体を実フォーマットで模す。"""
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": catalog_version,
            "dateReleased": date_released,
            "count": len(records),
            "vulnerabilities": records,
        }
    ).encode()
