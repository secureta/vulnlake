from tests.conftest import make_nuclei_yaml
from vlake import nuclei


def test_parse_template_full():
    raw = make_nuclei_yaml("CVE-2024-3400", cve_id="CVE-2024-3400")
    row = nuclei.parse_template("http/cves/2024/CVE-2024-3400.yaml", raw)
    assert row["template_id"] == "CVE-2024-3400"
    assert row["name"] == "Sample Template"
    assert row["severity"] == "critical"
    assert row["description"] == "A sample detection template."
    assert row["author"] == ["pdteam", "researcher"]
    assert row["tags"] == ["cve", "rce"]
    assert row["reference"] == ["https://example.com/advisory"]
    assert row["cve"] == ["CVE-2024-3400"]
    assert row["cwe"] == ["CWE-20", "CWE-77"]
    assert row["cvss_score"] == 10.0
    assert row["cvss_metrics"].startswith("CVSS:3.1/")
    assert row["epss_score"] == 0.99999
    assert row["epss_percentile"] == 1.0
    assert row["cpe"].startswith("cpe:2.3:")
    assert row["vendor"] == "vendor"
    assert row["product"] == "product"
    assert row["verified"] is True
    assert row["type"] == "http"
    assert row["file"] == "http/cves/2024/CVE-2024-3400.yaml"
    assert row["template_url"] == (
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
        "http/cves/2024/CVE-2024-3400.yaml"
    )
    assert len(row["digest"]) == 64
    # fetched_date / removed は pipeline が付与する
    assert "fetched_date" not in row
    assert "removed" not in row


def test_parse_template_list_forms():
    raw = make_nuclei_yaml(
        "tpl-list",
        author=["alice", " bob "],
        cve_id=["CVE-2020-0001", "cve-2020-0002", "GHSA-not-a-cve"],
        cwe_id=["CWE-79"],
    )
    row = nuclei.parse_template("http/a.yaml", raw)
    assert row["author"] == ["alice", "bob"]
    # 大文字化し CVE-\d{4}-\d+ 形式のみ採用
    assert row["cve"] == ["CVE-2020-0001", "CVE-2020-0002"]
    assert row["cwe"] == ["CWE-79"]


def test_parse_template_without_classification_and_metadata():
    raw = make_nuclei_yaml(
        "tpl-bare",
        severity=None,
        with_classification=False,
        with_metadata=False,
        reference=[],
    )
    row = nuclei.parse_template("http/bare.yaml", raw)
    assert row["severity"] is None
    assert row["cve"] == []
    assert row["cwe"] == []
    assert row["reference"] == []
    assert row["cvss_score"] is None
    assert row["epss_score"] is None
    assert row["cpe"] is None
    assert row["vendor"] is None
    assert row["product"] is None
    assert row["verified"] is False


def test_parse_template_type_normalization():
    cases = [
        ("http", "http"),
        ("requests", "http"),  # 旧形式
        ("network", "network"),
        ("tcp", "network"),  # 旧形式
        ("workflows", "workflows"),
        ("javascript", "javascript"),
        ("unknownproto", None),
    ]
    for key, expected in cases:
        raw = make_nuclei_yaml("tpl-type", protocol_key=key)
        assert nuclei.parse_template("x/t.yaml", raw)["type"] == expected


def test_content_digest_ignores_signature_line():
    signed = make_nuclei_yaml("tpl-a", body_marker="same", with_signature=True)
    unsigned = make_nuclei_yaml("tpl-a", body_marker="same", with_signature=False)
    resigned = unsigned + b"# digest: ffff0000differentsignature\n"
    assert nuclei.content_digest(signed) == nuclei.content_digest(unsigned)
    assert nuclei.content_digest(resigned) == nuclei.content_digest(unsigned)
    changed = make_nuclei_yaml("tpl-a", body_marker="other")
    assert nuclei.content_digest(changed) != nuclei.content_digest(signed)


def test_parse_template_rejects_non_templates():
    assert nuclei.parse_template("x.yaml", b"id: [unclosed\n") is None  # 壊れた YAML
    assert nuclei.parse_template("x.yaml", b"- a\n- b\n") is None  # dict でない
    assert nuclei.parse_template("x.yaml", b"just: config\n") is None  # id/info 無し
    assert nuclei.parse_template("x.yaml", b"id: x\nhttp: []\n") is None  # info 無し
