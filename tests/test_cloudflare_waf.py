from datetime import date

import httpx
import pyarrow.parquet as pq
import pytest

from vlake import cloudflare_waf


def test_extract_identifiers_supports_multiple_vulnerability_id_types():
    text = (
        "CVE:CVE-2026-1281 and cve-2026-1340, "
        "GHSA-abcd-1234-wxyz, GO-2024-1234, PYSEC-2023-45, "
        "RUSTSEC-2024-0001 are mentioned. CVE-2026-1281 repeats."
    )

    assert cloudflare_waf.extract_identifiers(text) == [
        ("CVE-2026-1281", "CVE"),
        ("CVE-2026-1340", "CVE"),
        ("GHSA-ABCD-1234-WXYZ", "GHSA"),
        ("GO-2024-1234", "GO"),
        ("PYSEC-2023-45", "PYSEC"),
        ("RUSTSEC-2024-0001", "RUSTSEC"),
    ]


def test_parse_current_changelog_mdx_extracts_frontmatter_and_context():
    raw = b"""---
title: "WAF Release - 2026-03-12 - Emergency"
description: Cloudflare WAF managed rulesets emergency release
date: 2026-03-12
---

import { RuleID } from "~/components";

This release adds detections for Ivanti EPMM (CVE-2026-1281 and CVE-2026-1340).

<td>Ivanti EPMM - Code Injection - CVE:CVE-2026-1281 CVE:CVE-2026-1340</td>
"""

    rows = cloudflare_waf.parse_markdown(
        "src/content/changelog/waf/2026-03-12-emergency-waf-release.mdx", raw
    )

    assert [(r["identifier"], r["identifier_type"]) for r in rows] == [
        ("CVE-2026-1281", "CVE"),
        ("CVE-2026-1340", "CVE"),
    ]
    assert rows[0]["cve"] == "CVE-2026-1281"
    assert rows[0]["source_title"] == "WAF Release - 2026-03-12 - Emergency"
    assert rows[0]["source_date"] == date(2026, 3, 12)
    assert rows[0]["source_url"] == (
        "https://developers.cloudflare.com/changelog/2026-03-12-emergency-waf-release/"
    )
    assert "CVE-2026-1281" in rows[0]["matched_text"]


def test_parse_scheduled_changelog_uses_scheduled_changes_url():
    raw = b"""---
title: WAF Release - Scheduled changes for 2026-07-20
date: 2026-07-14
publish_future_dated_entry: true
---

<td>Adobe ColdFusion - Path Traversal - CVE:CVE-2026-48282</td>
"""

    rows = cloudflare_waf.parse_markdown(
        "src/content/changelog/waf/scheduled-waf-release.mdx", raw
    )

    assert rows[0]["identifier"] == "CVE-2026-48282"
    assert rows[0]["source_url"] == (
        "https://developers.cloudflare.com/waf/change-log/scheduled-changes/"
    )


def test_parse_historical_table_uses_row_description_and_change_date():
    raw = b"""---
title: "Historical (2024)"
---
<table><tbody>
<tr>
<td>Cloudflare Specials</td>
<td><RuleID id="fc7338307e484b9f8d460aca6bc398e9" /></td>
<td>100675</td>
<td>Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205</td>
<td>2024-10-21</td>
<td>Log</td>
<td>Block</td>
</tr>
</tbody></table>
"""

    rows = cloudflare_waf.parse_markdown(
        "src/content/docs/waf/change-log/historical-2024.mdx", raw
    )

    assert rows == [
        {
            "identifier": "CVE-2023-38205",
            "identifier_type": "CVE",
            "cve": "CVE-2023-38205",
            "source_title": "Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205",
            "source_url": "https://developers.cloudflare.com/waf/change-log/historical-2024/",
            "source_date": date(2024, 10, 21),
            "matched_text": "Adobe ColdFusion - Auth Bypass - CVE:CVE-2023-38205",
        }
    ]


def test_parse_dir_deduplicates_identifier_per_source_url(tmp_path):
    p = (
        tmp_path
        / "src"
        / "content"
        / "changelog"
        / "waf"
        / "2026-01-01-waf-release.mdx"
    )
    p.parent.mkdir(parents=True)
    p.write_text(
        """---
title: WAF Release
date: 2026-01-01
---
CVE-2026-0001 appears twice: CVE:CVE-2026-0001.
"""
    )

    rows = cloudflare_waf.parse_dir(tmp_path)

    assert len(rows) == 1
    assert rows[0]["identifier"] == "CVE-2026-0001"


def test_rows_to_table_key_and_parquet_roundtrip(tmp_path):
    rows = [
        {
            "identifier": "GHSA-ABCD-1234-WXYZ",
            "identifier_type": "GHSA",
            "cve": None,
            "source_title": "sample",
            "source_url": "https://developers.cloudflare.com/changelog/sample/",
            "source_date": date(2026, 1, 2),
            "matched_text": "GHSA-abcd-1234-wxyz",
            "fetched_date": date(2026, 7, 16),
            "removed": False,
        },
        {
            "identifier": "CVE-2026-0001",
            "identifier_type": "CVE",
            "cve": "CVE-2026-0001",
            "source_title": "sample",
            "source_url": "https://developers.cloudflare.com/changelog/sample/",
            "source_date": date(2026, 1, 1),
            "matched_text": "CVE-2026-0001",
            "fetched_date": date(2026, 7, 16),
            "removed": False,
        },
    ]

    table = cloudflare_waf.rows_to_table(rows)
    assert table.column_names == [
        "identifier",
        "identifier_type",
        "cve",
        "source_title",
        "source_url",
        "source_date",
        "matched_text",
        "fetched_date",
        "removed",
    ]
    assert table.column("identifier").to_pylist() == [
        "CVE-2026-0001",
        "GHSA-ABCD-1234-WXYZ",
    ]
    assert cloudflare_waf.key_for_update(date(2026, 7, 16)) == (
        "cloudflare_waf/updates/year=2026/cloudflare-waf-updates-2026-07-16.parquet"
    )

    out = tmp_path / "rows.parquet"
    cloudflare_waf.write_parquet(table, out)
    assert pq.read_table(out).schema == cloudflare_waf.SCHEMA


def _no_sleep(monkeypatch):
    monkeypatch.setattr(cloudflare_waf.time, "sleep", lambda s: None)


def test_get_with_retry_recovers_from_transient_503(monkeypatch):
    """publish 2026-08-17 の回帰: raw.githubusercontent.com の単発 503 で
    ステップ全体を落とさず、バックオフ後の再試行で回復する。
    """
    _no_sleep(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request.url)
        if len(calls) < 3:
            return httpx.Response(503, text="first byte timeout")
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        resp = cloudflare_waf._get_with_retry(client, "https://example.test/x.mdx")
    assert resp.text == "ok"
    assert len(calls) == 3


def test_get_with_retry_gives_up_after_persistent_503(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(503, text="first byte timeout")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            cloudflare_waf._get_with_retry(client, "https://example.test/x.mdx")
    assert len(calls) == cloudflare_waf._RETRY_ATTEMPTS


def test_get_with_retry_does_not_retry_permanent_404(monkeypatch):
    """404 は上流のパス消滅 (恒久エラー) なので再試行せず即座に失敗させる。"""
    _no_sleep(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(404, text="not found")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            cloudflare_waf._get_with_retry(client, "https://example.test/gone.mdx")
    assert len(calls) == 1


def test_get_with_retry_recovers_from_connect_error(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request.url)
        if len(calls) == 1:
            raise httpx.ConnectError("connection reset")
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        resp = cloudflare_waf._get_with_retry(client, "https://example.test/x.mdx")
    assert resp.text == "ok"
    assert len(calls) == 2
