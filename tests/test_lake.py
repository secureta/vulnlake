import json
from datetime import date, datetime
from pathlib import Path

import duckdb

from tests.conftest import make_cve_record, make_epss_csv_gz, make_ghsa_record
from vlake import cvelist, epss, exploitdb, ghsa
from vlake.lake import Lake


def _make_parquet(tmp_path: Path, d: date) -> Path:
    raw = make_epss_csv_gz(
        d, [("CVE-1999-0001", 0.1, 0.5), ("CVE-1999-0002", 0.2, 0.6)]
    )
    table, _, _ = epss.parse(raw, fallback_date=d)
    out = tmp_path / f"epss-{d.isoformat()}.parquet"
    epss.write_parquet(table, out)
    return out


def test_create_register_and_read_back(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    pq2 = _make_parquet(tmp_path, date(2026, 7, 10))

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.registered_paths() == set()
    assert lake.add_file("epss", str(pq1)) is True
    assert lake.add_file("epss", str(pq1)) is False  # 冪等
    assert lake.add_file("epss", str(pq2)) is True
    assert lake.registered_paths() == {str(pq1), str(pq2)}
    lake.set_message("epss 2026-07-10")
    lake.close()

    # 消費者と同じ経路: 素の duckdb で ATTACH して読む
    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    n, days = con.execute(
        "SELECT count(*), count(DISTINCT date) FROM frozen.epss"
    ).fetchone()
    assert (n, days) == (4, 2)
    top = con.execute(
        "SELECT cve FROM frozen.epss WHERE date = DATE '2026-07-10' ORDER BY epss DESC LIMIT 1"
    ).fetchone()[0]
    assert top == "CVE-1999-0002"


def _make_cve_parquet(tmp_path: Path, cve_id: str, updated: str, name: str) -> Path:
    rec = make_cve_record(cve_id, date_updated=updated)
    row = cvelist.parse_record(json.dumps(rec).encode())
    out = tmp_path / name
    cvelist.write_parquet(cvelist.rows_to_table([row]), out)
    return out


def _ssvc_metric(
    *,
    exploitation: str | None = "active",
    automatable: str | None = "yes",
    technical_impact: str | None = "partial",
    mission_impact: str | None = None,
    decision: str | None = None,
    role: str = "CISA Coordinator",
    version: str = "2.0.3",
    timestamp: str = "2024-09-16T19:00:51.927416Z",
) -> dict:
    """CISA ADP Vulnrichment の SSVC metric 断片を作る。"""
    options = []
    if exploitation is not None:
        options.append({"Exploitation": exploitation})
    if automatable is not None:
        options.append({"Automatable": automatable})
    if technical_impact is not None:
        options.append({"Technical Impact": technical_impact})
    if mission_impact is not None:
        options.append({"Mission and Well-Being Impact": mission_impact})
    content = {
        "id": "CVE-2024-0001",
        "role": role,
        "options": options,
        "version": version,
        "timestamp": timestamp,
    }
    if decision is not None:
        content["decision"] = decision
    return {"other": {"type": "ssvc", "content": content}}


def _cve_raw_with_ssvc(cve_id: str, **kwargs) -> str:
    """SSVC 付き CVE JSON 5.x 文字列を作る。"""
    rec = make_cve_record(
        cve_id,
        date_updated=kwargs.pop("date_updated", "2026-07-10T00:00:00Z"),
        adp_metrics=[_ssvc_metric(**kwargs)],
    )
    return json.dumps(rec)


def test_cve_history_and_latest_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    old = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2025-01-01T00:00:00Z", "a.parquet"
    )
    new = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2026-01-01T00:00:00Z", "b.parquet"
    )

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.max_cve_date_updated() is None
    lake.add_file("cve_history", str(old))
    lake.add_file("cve_history", str(new))
    assert lake.max_cve_date_updated() == datetime(2026, 1, 1)
    lake.refresh_cve_view()
    lake.refresh_cve_view()  # 再実行しても壊れない
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 2
    rows = con.execute("SELECT cve, date_updated FROM frozen.cve").fetchall()
    assert rows == [("CVE-2021-0001", datetime(2026, 1, 1))]


def test_cve_ssvc_history_view_extracts_cisa_coordinator_ssvc(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated, raw) VALUES (?, TIMESTAMP '2026-07-10 00:00:00', ?)",
            [
                "CVE-2024-0001",
                _cve_raw_with_ssvc(
                    "CVE-2024-0001",
                    exploitation="active",
                    automatable="yes",
                    technical_impact="partial",
                    mission_impact="high",
                    decision="act",
                ),
            ],
        )

        lake.refresh_cve_ssvc_history_view()
        lake.refresh_cve_ssvc_history_view()  # 再実行しても壊れない
        rows = lake.query(
            "SELECT cve, ssvc_version, ssvc_role, ssvc_provider, "
            "exploitation, automatable, technical_impact, mission_impact, "
            "recorded_decision, ssvc_timestamp, ssvc_raw "
            "FROM lake.cve_ssvc_history"
        )
        assert len(rows) == 1
        row = rows[0]
        assert row[:9] == (
            "CVE-2024-0001",
            "2.0.3",
            "CISA Coordinator",
            "CISA ADP Vulnrichment",
            "active",
            "yes",
            "partial",
            "high",
            "act",
        )
        assert row[9] == datetime(2024, 9, 16, 19, 0, 51, 927416)
        assert json.loads(row[10])["other"]["type"] == "ssvc"
    finally:
        lake.close()


def test_cve_ssvc_view_uses_latest_cve_view(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated, raw) VALUES "
            "('CVE-2024-0001', TIMESTAMP '2026-07-09 00:00:00', ?), "
            "('CVE-2024-0001', TIMESTAMP '2026-07-10 00:00:00', ?)",
            [
                _cve_raw_with_ssvc(
                    "CVE-2024-0001",
                    date_updated="2026-07-09T00:00:00Z",
                    exploitation="none",
                ),
                _cve_raw_with_ssvc(
                    "CVE-2024-0001",
                    date_updated="2026-07-10T00:00:00Z",
                    exploitation="active",
                ),
            ],
        )

        lake.refresh_cve_view()
        lake.refresh_cve_ssvc_view()
        got = lake.query("SELECT cve, exploitation FROM lake.cve_ssvc")
        assert got == [("CVE-2024-0001", "active")]
    finally:
        lake.close()


def test_cve_ssvc_views_ignore_non_ssvc_and_missing_cisa_adp(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        no_adp = json.dumps(make_cve_record("CVE-2024-0002"))
        wrong_role = json.dumps(
            make_cve_record(
                "CVE-2024-0003",
                adp_metrics=[_ssvc_metric(role="Supplier")],
            )
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated, raw) VALUES "
            "('CVE-2024-0002', TIMESTAMP '2026-07-10 00:00:00', ?), "
            "('CVE-2024-0003', TIMESTAMP '2026-07-10 00:00:00', ?)",
            [no_adp, wrong_role],
        )

        lake.refresh_cve_view()
        lake.refresh_cve_ssvc_history_view()
        lake.refresh_cve_ssvc_view()
        assert lake.query("SELECT count(*) FROM lake.cve_ssvc_history") == [(0,)]
        assert lake.query("SELECT count(*) FROM lake.cve_ssvc") == [(0,)]
    finally:
        lake.close()


def test_ssvc_decision_view_supports_partial_input_queries(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.refresh_ssvc_decision_view()
        assert lake.query("SELECT count(*) FROM lake.ssvc_decision") == [(36,)]
        got = lake.query(
            "SELECT mission_impact, decision, decision_label, decision_rank "
            "FROM lake.ssvc_decision "
            "WHERE exploitation = 'active' "
            "  AND automatable = 'no' "
            "  AND technical_impact = 'total' "
            "ORDER BY mission_impact"
        )
        assert got == [
            ("high", "act", "Act", 4),
            ("low", "track", "Track", 1),
            ("medium", "attend", "Attend", 3),
        ]
    finally:
        lake.close()


def test_cve_ssvc_candidates_expands_missing_parameters_and_compares_decision(
    tmp_path,
):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated, raw) VALUES (?, TIMESTAMP '2026-07-10 00:00:00', ?)",
            [
                "CVE-2024-0001",
                _cve_raw_with_ssvc(
                    "CVE-2024-0001",
                    exploitation="active",
                    automatable="no",
                    technical_impact="total",
                    mission_impact=None,
                    decision="act",
                ),
            ],
        )

        lake.refresh_cve_view()
        lake.refresh_cve_ssvc_view()
        lake.refresh_ssvc_decision_view()
        lake.refresh_cve_ssvc_candidates_view()
        rows = lake.query(
            "SELECT exploitation, automatable, technical_impact, mission_impact, "
            "recorded_exploitation, recorded_automatable, recorded_technical_impact, "
            "recorded_mission_impact, recorded_decision, computed_decision, "
            "decision_matches, decision_rank "
            "FROM lake.cve_ssvc_candidates "
            "WHERE cve = 'CVE-2024-0001' "
            "ORDER BY decision_rank, mission_impact"
        )
        assert rows == [
            (
                "active",
                "no",
                "total",
                "low",
                "active",
                "no",
                "total",
                None,
                "act",
                "track",
                False,
                1,
            ),
            (
                "active",
                "no",
                "total",
                "medium",
                "active",
                "no",
                "total",
                None,
                "act",
                "attend",
                False,
                3,
            ),
            (
                "active",
                "no",
                "total",
                "high",
                "active",
                "no",
                "total",
                None,
                "act",
                "act",
                True,
                4,
            ),
        ]
    finally:
        lake.close()


def test_cve_ssvc_candidates_returns_zero_rows_without_ssvc(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated, raw) VALUES "
            "('CVE-2024-0002', TIMESTAMP '2026-07-10 00:00:00', ?)",
            [json.dumps(make_cve_record("CVE-2024-0002"))],
        )

        lake.refresh_cve_view()
        lake.refresh_cve_ssvc_view()
        lake.refresh_ssvc_decision_view()
        lake.refresh_cve_ssvc_candidates_view()
        assert lake.query("SELECT count(*) FROM lake.cve_ssvc_candidates") == [(0,)]
    finally:
        lake.close()


def test_registered_paths_scoped_by_table(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    epss_pq = _make_parquet(tmp_path, date(2026, 7, 10))
    cve_pq = _make_cve_parquet(
        tmp_path, "CVE-2021-0001", "2026-01-01T00:00:00Z", "c.parquet"
    )

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.add_file("epss", str(epss_pq))
    lake.add_file("cve_history", str(cve_pq))
    assert lake.registered_paths() == {str(epss_pq), str(cve_pq)}
    assert lake.registered_paths("epss") == {str(epss_pq)}
    assert lake.registered_paths("cve_history") == {str(cve_pq)}
    lake.close()


def test_reopen_existing_catalog_without_data_path(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    pq1 = _make_parquet(tmp_path, date(2026, 7, 9))
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.add_file("epss", str(pq1))
    lake.close()

    # 既存カタログは data_path なしで再オープンできる
    lake2 = Lake(catalog)
    assert lake2.registered_paths() == {str(pq1)}
    assert lake2.add_file("epss", str(pq1)) is False
    lake2.close()


def test_datasets_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    lake.refresh_datasets_view([epss.LICENSE_INFO])
    lake.refresh_datasets_view([epss.LICENSE_INFO])  # 再実行しても壊れない
    rows = lake.query("SELECT name, attribution FROM lake.datasets")
    assert rows[0][0] == "epss"
    assert rows[0][1] == epss.LICENSE_INFO["attribution"]
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.datasets").fetchone()[0] == 1


def _make_ghsa_parquet(tmp_path: Path, ghsa_id: str, modified: str, name: str) -> Path:
    rec = make_ghsa_record(ghsa_id, modified=modified)
    row = ghsa.parse_record(json.dumps(rec).encode())
    out = tmp_path / name
    ghsa.write_parquet(ghsa.rows_to_table([row]), out)
    return out


def test_ghsa_history_and_latest_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    old = _make_ghsa_parquet(
        tmp_path, "GHSA-aaaa-bbbb-cccc", "2025-01-01T00:00:00Z", "g1.parquet"
    )
    new = _make_ghsa_parquet(
        tmp_path, "GHSA-aaaa-bbbb-cccc", "2026-01-01T00:00:00Z", "g2.parquet"
    )

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.max_ghsa_modified() is None
    lake.add_file("ghsa_history", str(old))
    lake.add_file("ghsa_history", str(new))
    assert lake.max_ghsa_modified() == datetime(2026, 1, 1)
    lake.refresh_ghsa_view()
    lake.refresh_ghsa_view()  # 再実行しても壊れない
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert con.execute("SELECT count(*) FROM frozen.ghsa_history").fetchone()[0] == 2
    rows = con.execute("SELECT ghsa, modified FROM frozen.ghsa").fetchall()
    assert rows == [("GHSA-aaaa-bbbb-cccc", datetime(2026, 1, 1))]
    # ネスト列 affected を UNNEST で掘れる
    pkg = con.execute(
        "SELECT a.package FROM frozen.ghsa, UNNEST(affected) AS t(a) LIMIT 1"
    ).fetchone()[0]
    assert pkg == "org.apache.logging.log4j:log4j-core"


def _make_exploitdb_parquet(
    tmp_path: Path, edb_id: str, updated: str, name: str, desc: str = "x"
) -> Path:
    from tests.conftest import make_exploitdb_csv

    raw = make_exploitdb_csv(
        [
            {
                "id": edb_id,
                "date_updated": updated,
                "date_published": "2010-01-01",
                "description": desc,
                "codes": "CVE-2010-0001",
            }
        ]
    )
    rows = [r for r in (exploitdb.parse_row(r) for r in exploitdb.iter_rows(raw)) if r]
    out = tmp_path / name
    exploitdb.write_parquet(exploitdb.rows_to_table(rows), out)
    return out


def test_exploitdb_history_and_latest_view(tmp_path):
    catalog = tmp_path / "vlake.ducklake"
    old = _make_exploitdb_parquet(tmp_path, "42", "2025-01-01", "e1.parquet", "old")
    new = _make_exploitdb_parquet(tmp_path, "42", "2026-01-01", "e2.parquet", "new")

    lake = Lake(catalog, data_path=str(tmp_path / "unused"))
    lake.ensure_tables()
    assert lake.max_exploitdb_date_updated() is None
    lake.add_file("exploitdb_history", str(old))
    lake.add_file("exploitdb_history", str(new))
    assert lake.max_exploitdb_date_updated() == date(2026, 1, 1)
    assert lake.exploitdb_edb_ids_at(date(2026, 1, 1)) == {42}
    assert lake.exploitdb_edb_ids_at(date(2025, 1, 1)) == {42}
    lake.refresh_exploitdb_view()
    lake.refresh_exploitdb_view()  # 再実行しても壊れない
    lake.close()

    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(f"ATTACH 'ducklake:{catalog}' AS frozen (READ_ONLY)")
    assert (
        con.execute("SELECT count(*) FROM frozen.exploitdb_history").fetchone()[0] == 2
    )
    rows = con.execute("SELECT edb_id, description FROM frozen.exploitdb").fetchall()
    assert rows == [(42, "new")]
    # cve は配列列: list_contains で引ける
    hit = con.execute(
        "SELECT edb_id FROM frozen.exploitdb WHERE list_contains(cve, 'CVE-2010-0001')"
    ).fetchone()[0]
    assert hit == 42


def test_nuclei_latest_rows_and_view(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        assert lake.nuclei_latest_rows() == []
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.nuclei_history "  # noqa: S608
            "(template_id, digest, file, fetched_date, removed) VALUES "
            "('tpl-a', 'd1', 'http/a.yaml', DATE '2026-07-10', false), "
            "('tpl-a', 'd2', 'http/a.yaml', DATE '2026-07-12', false), "
            "('tpl-b', 'd3', 'http/b.yaml', DATE '2026-07-10', true)"
        )
        rows = {r["template_id"]: r for r in lake.nuclei_latest_rows()}
        assert rows["tpl-a"]["digest"] == "d2"  # 最新 fetched_date の行
        assert rows["tpl-b"]["removed"] is True
        assert rows["tpl-a"]["name"] is None  # 未指定列も列名付きで返る

        lake.refresh_nuclei_view()
        got = lake.query(
            "SELECT template_id, digest FROM lake.nuclei ORDER BY template_id"
        )
        assert got == [("tpl-a", "d2"), ("tpl-b", "d3")]
    finally:
        lake.close()


def test_kev_latest_rows_and_view(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        assert lake.kev_latest_rows() == []
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.kev_history "  # noqa: S608
            "(cve, vendor_project, fetched_date, removed) VALUES "
            "('CVE-2024-0001', 'v1', DATE '2026-07-10', false), "
            "('CVE-2024-0001', 'v2', DATE '2026-07-12', false), "
            "('CVE-2024-0002', 'v3', DATE '2026-07-10', true)"
        )
        rows = {r["cve"]: r for r in lake.kev_latest_rows()}
        assert rows["CVE-2024-0001"]["vendor_project"] == "v2"  # 最新 fetched_date の行
        assert rows["CVE-2024-0002"]["removed"] is True
        assert rows["CVE-2024-0001"]["product"] is None  # 未指定列も列名付きで返る

        lake.refresh_kev_view()
        got = lake.query("SELECT cve, vendor_project FROM lake.kev ORDER BY cve")
        assert got == [("CVE-2024-0001", "v2"), ("CVE-2024-0002", "v3")]
    finally:
        lake.close()


def test_cloudflare_waf_latest_rows_and_view(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        assert lake.cloudflare_waf_latest_rows() == []
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cloudflare_waf_history "  # noqa: S608
            "(identifier, identifier_type, cve, source_title, source_url, "
            "source_date, matched_text, fetched_date, removed) VALUES "
            "('CVE-2026-0001', 'CVE', 'CVE-2026-0001', 'old', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'old text', DATE '2026-07-10', false), "
            "('CVE-2026-0001', 'CVE', 'CVE-2026-0001', 'new', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'new text', DATE '2026-07-12', false), "
            "('GHSA-ABCD-1234-WXYZ', 'GHSA', NULL, 'removed', "
            " 'https://developers.cloudflare.com/changelog/b/', "
            " DATE '2026-01-02', 'ghsa text', DATE '2026-07-12', true)"
        )
        rows = {
            (r["identifier"], r["source_url"]): r
            for r in lake.cloudflare_waf_latest_rows()
        }
        assert (
            rows[("CVE-2026-0001", "https://developers.cloudflare.com/changelog/a/")][
                "source_title"
            ]
            == "new"
        )
        assert (
            rows[
                (
                    "GHSA-ABCD-1234-WXYZ",
                    "https://developers.cloudflare.com/changelog/b/",
                )
            ]["removed"]
            is True
        )

        lake.refresh_cloudflare_waf_view()
        got = lake.query(
            "SELECT identifier, source_title, removed FROM lake.cloudflare_waf "
            "ORDER BY identifier"
        )
        assert got == [
            ("CVE-2026-0001", "new", False),
            ("GHSA-ABCD-1234-WXYZ", "removed", True),
        ]
    finally:
        lake.close()


def test_cve_sources_view_summarizes_dataset_presence(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.epss "  # noqa: S608
            "(cve, epss, percentile, date, model_version) VALUES "
            "('CVE-2024-0001', 0.1, 0.2, DATE '2026-07-10', 'v1'), "
            "('CVE-2024-0001', 0.2, 0.3, DATE '2026-07-11', 'v1'), "
            "('CVE-2024-0002', 0.3, 0.4, DATE '2026-07-10', 'v1')"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cve_history "  # noqa: S608
            "(cve, date_updated) VALUES "
            "('CVE-2024-0001', TIMESTAMP '2026-07-10 00:00:00'), "
            "('CVE-2024-0001', TIMESTAMP '2026-07-11 00:00:00')"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.ghsa_history "  # noqa: S608
            "(ghsa, cve, modified) VALUES "
            "('GHSA-aaaa-bbbb-cccc', 'CVE-2024-0001', TIMESTAMP '2026-07-10 00:00:00'), "
            "('GHSA-dddd-eeee-ffff', 'CVE-2024-0001', TIMESTAMP '2026-07-11 00:00:00'), "
            "('GHSA-gggg-hhhh-iiii', NULL, TIMESTAMP '2026-07-11 00:00:00')"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.exploitdb_history "  # noqa: S608
            "(edb_id, cve, date_updated) VALUES "
            "(10, ['CVE-2024-0001', 'CVE-2024-0003'], DATE '2026-07-10'), "
            "(11, ['CVE-2024-0003'], DATE '2026-07-11')"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.nuclei_history "  # noqa: S608
            "(template_id, cve, fetched_date, removed) VALUES "
            "('tpl-live', ['CVE-2024-0001'], DATE '2026-07-10', false), "
            "('tpl-removed', ['CVE-2024-0004'], DATE '2026-07-10', true)"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.kev_history "  # noqa: S608
            "(cve, fetched_date, removed) VALUES "
            "('CVE-2024-0001', DATE '2026-07-10', false), "
            "('CVE-2024-0005', DATE '2026-07-10', true)"
        )
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cloudflare_waf_history "  # noqa: S608
            "(identifier, identifier_type, cve, source_title, source_url, "
            "source_date, matched_text, fetched_date, removed) VALUES "
            "('CVE-2024-0001', 'CVE', 'CVE-2024-0001', 'waf-a', "
            " 'https://developers.cloudflare.com/changelog/a/', "
            " DATE '2026-01-01', 'CVE-2024-0001', DATE '2026-07-10', false), "
            "('CVE-2024-0001', 'CVE', 'CVE-2024-0001', 'waf-b', "
            " 'https://developers.cloudflare.com/changelog/b/', "
            " DATE '2026-01-02', 'CVE-2024-0001', DATE '2026-07-10', false), "
            "('CVE-2024-0006', 'CVE', 'CVE-2024-0006', 'removed', "
            " 'https://developers.cloudflare.com/changelog/c/', "
            " DATE '2026-01-03', 'CVE-2024-0006', DATE '2026-07-10', true)"
        )

        lake.refresh_cve_view()
        lake.refresh_ghsa_view()
        lake.refresh_exploitdb_view()
        lake.refresh_nuclei_view()
        lake.refresh_kev_view()
        lake.refresh_cloudflare_waf_view()
        lake.refresh_cve_sources_view()
        lake.refresh_cve_sources_view()  # 再実行しても壊れない

        got = lake.query(
            "SELECT cve, has_epss, has_cve, has_ghsa, has_exploitdb, "
            "has_nuclei, has_kev, has_cloudflare_waf, epss_days, ghsa_count, "
            "exploitdb_count, nuclei_count, cloudflare_waf_count "
            "FROM lake.cve_sources ORDER BY cve"
        )
        assert got == [
            (
                "CVE-2024-0001",
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                2,
                2,
                1,
                1,
                2,
            ),
            (
                "CVE-2024-0002",
                True,
                False,
                False,
                False,
                False,
                False,
                False,
                1,
                0,
                0,
                0,
                0,
            ),
            (
                "CVE-2024-0003",
                False,
                False,
                False,
                True,
                False,
                False,
                False,
                0,
                0,
                2,
                0,
                0,
            ),
        ]
    finally:
        lake.close()


def test_cwe_view_returns_latest_snapshot(tmp_path):
    lake = Lake(tmp_path / "cat.ducklake", data_path=str(tmp_path / "data"))
    try:
        lake.ensure_tables()
        lake.con.execute(
            f"INSERT INTO {lake.ALIAS}.cwe_history "  # noqa: S608
            "(cwe_id, entry_type, cwe_version, release_date) VALUES "
            "('CWE-79', 'weakness', '4.9', DATE '2025-11-19'), "
            "('CWE-79', 'weakness', '4.20', DATE '2026-04-30'), "
            "('CWE-9999', 'weakness', '4.9', DATE '2025-11-19')"
        )
        lake.refresh_cwe_view()
        # 文字列比較では '4.9' > '4.20' になるが、release_date 最大の断面が返る
        got = lake.query("SELECT cwe_id, cwe_version FROM lake.cwe")
        assert got == [("CWE-79", "4.20")]
    finally:
        lake.close()
