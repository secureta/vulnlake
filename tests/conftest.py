import csv
import gzip
import io
import json
import tarfile
import zipfile
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

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


def _cwe_attr(value: str) -> str:
    """XML 属性値用エスケープ (ダブルクォート含む)。"""
    return escape(value, {'"': "&quot;"})


def _cwe_weakness_xml(w: dict) -> str:
    rels = "".join(
        f'<Related_Weakness Nature="{n}" CWE_ID="{cid}" View_ID="{vid}"/>'
        for n, cid, vid in w.get("relations", ())
    )
    related = f"<Related_Weaknesses>{rels}</Related_Weaknesses>" if rels else ""
    likelihood = (
        f"<Likelihood_Of_Exploit>{w['likelihood']}</Likelihood_Of_Exploit>"
        if w.get("likelihood")
        else ""
    )
    return (
        f'<Weakness ID="{w["id"]}" Name="{_cwe_attr(w.get("name", "Weakness"))}" '
        f'Abstraction="{w.get("abstraction", "Base")}" Structure="Simple" '
        f'Status="{w.get("status", "Stable")}">'
        f"<Description>{escape(w.get('description', 'A sample weakness.'))}</Description>"
        f"{related}{likelihood}</Weakness>"
    )


def _cwe_category_xml(c: dict) -> str:
    members = "".join(
        f'<Has_Member CWE_ID="{cid}" View_ID="{c["id"]}"/>'
        for cid in c.get("members", ())
    )
    relationships = f"<Relationships>{members}</Relationships>" if members else ""
    return (
        f'<Category ID="{c["id"]}" Name="{_cwe_attr(c.get("name", "Category"))}" '
        f'Status="{c.get("status", "Draft")}">'
        f"<Summary>{escape(c.get('summary', 'A sample category.'))}</Summary>"
        f"{relationships}</Category>"
    )


def _cwe_view_xml(v: dict) -> str:
    members = "".join(
        f'<Has_Member CWE_ID="{cid}" View_ID="{v["id"]}"/>'
        for cid in v.get("members", ())
    )
    members_block = f"<Members>{members}</Members>" if members else ""
    return (
        f'<View ID="{v["id"]}" Name="{_cwe_attr(v.get("name", "View"))}" '
        f'Type="Graph" Status="{v.get("status", "Draft")}">'
        f"<Objective>{escape(v.get('objective', 'A sample view.'))}</Objective>"
        f"{members_block}</View>"
    )


def make_cwe_xml_zip(
    *,
    version: str = "4.20",
    date_str: str = "2026-04-30",
    weaknesses: list[dict] | None = None,
    categories: list[dict] | None = None,
    views: list[dict] | None = None,
) -> bytes:
    """実フォーマットを模した cwec XML zip を作る。

    デフォルトは弱点3件 (CWE-79 / CWE-74 / Deprecated の CWE-1187) +
    カテゴリ1件 (CWE-137) + ビュー1件 (CWE-1000) = 5 エントリ。
    CWE-79 の ChildOf 74 は実データ同様 View_ID 違いで重複させてある
    (パーサの dedupe を検証するため)。
    """
    if weaknesses is None:
        weaknesses = [
            {
                "id": "79",
                "name": (
                    "Improper Neutralization of Input During Web Page "
                    "Generation ('Cross-site Scripting')"
                ),
                "abstraction": "Base",
                "status": "Stable",
                "description": (
                    "The product does not neutralize user-controllable input "
                    "before it is placed in output used as a web page."
                ),
                "likelihood": "High",
                "relations": [
                    ("ChildOf", "74", "1000"),
                    ("ChildOf", "74", "1003"),
                    ("PeerOf", "352", "1000"),
                ],
            },
            {
                "id": "74",
                "name": (
                    "Improper Neutralization of Special Elements in Output "
                    "Used by a Downstream Component ('Injection')"
                ),
                "abstraction": "Class",
                "status": "Draft",
                "description": "A sample injection class weakness.",
                "relations": [("ChildOf", "707", "1000")],
            },
            {
                "id": "1187",
                "name": "DEPRECATED: Use of Uninitialized Resource",
                "abstraction": "Base",
                "status": "Deprecated",
                "description": (
                    "This entry has been deprecated because it was a "
                    "duplicate of CWE-908."
                ),
            },
        ]
    if categories is None:
        categories = [
            {
                "id": "137",
                "name": "Data Neutralization Issues",
                "status": "Draft",
                "summary": (
                    "Weaknesses in this category are related to the creation "
                    "or neutralization of data using an incorrect format."
                ),
                "members": ["74", "79"],
            }
        ]
    if views is None:
        views = [
            {
                "id": "1000",
                "name": "Research Concepts",
                "status": "Draft",
                "objective": (
                    "This view is intended to facilitate research into weaknesses."
                ),
                "members": ["74"],
            }
        ]
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Weakness_Catalog Name="CWE" Version="{version}" Date="{date_str}" '
        'xmlns="http://cwe.mitre.org/cwe-7" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">'
        f"<Weaknesses>{''.join(_cwe_weakness_xml(w) for w in weaknesses)}</Weaknesses>"
        f"<Categories>{''.join(_cwe_category_xml(c) for c in categories)}</Categories>"
        f"<Views>{''.join(_cwe_view_xml(v) for v in views)}</Views>"
        "</Weakness_Catalog>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"cwec_v{version}.xml", xml)
    return buf.getvalue()
