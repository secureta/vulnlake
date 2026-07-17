# SSVC DuckDB Views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** DuckDB 経由で CVE List V5 の CISA Coordinator SSVC 実データと decision 候補を問い合わせられる view 群を追加する。

**Architecture:** 既存の `cve.raw` / `cve_history.raw` を DuckDB JSON 関数で動的に展開する view を `src/vlake/lake.py` に追加する。CISA Coordinator SSVC 2.0.3 の公式 decision table は固定 `VALUES` view として公開し、`cve_ssvc_candidates` で CVE 記録値と結合して不足パラメータを全展開する。公式 decision table は `Mission and Well-Being Impact` も必要とするため、実装列名は `mission_impact` とし、CVE 側で未記録なら候補展開する。

**Tech Stack:** Python 3.14, DuckDB 1.5.4, DuckLake, pytest, ruff, zizmor, Markdown docs.

## Global Constraints

- 正式名は **vulnlake**、CLI/package/catalog shorthand は `vlake`。`vlake` 識別子を不統一としてリネームしない。
- コード内のコメント・docstring・コミットメッセージは日本語。
- 公開順序の不変条件を維持する: Parquet データファイルを先にアップロードし、カタログ (`vlake.ducklake`) の差し替えは必ず最後。
- 今回は Web UI / Web API を実装しない。
- 今回は SSVC 抽出済み Parquet/table を物理化しない。
- 初期対象は cvelistV5 の CISA ADP Vulnrichment に含まれる `CISA Coordinator` SSVC のみ。
- ネットワーク越しの git 操作 (`git push` / `git fetch` / `git pull` など) は実行しない。
- schema view 変更時は `docs/schema.md` / README Schema summary / `docs/llms.md` を同期する。
- commit 前または完了報告前に `mise run lint` と `mise run sast` を成功させる。commit 前 gate として `mise run pre-commit` を実行する。

---

## File Structure

- `src/vlake/lake.py`
  - `refresh_cve_ssvc_history_view()` / `refresh_cve_ssvc_view()` / `refresh_ssvc_decision_view()` / `refresh_cve_ssvc_candidates_view()` を追加する。
  - 重複を避けるため private helper `_refresh_cve_ssvc_view(source: str, target: str)` を追加する。
  - SQL は view 定義だけを追加し、`ensure_tables()` の物理テーブル定義は変更しない。
- `src/vlake/pipeline.py`
  - `_publish_catalog()` の view refresh 経路に SSVC view を追加する。
  - 既存の Parquet 登録順序は変更しない。
- `tests/test_lake.py`
  - SSVC 抽出 view / decision view / candidate view の単体テストを追加する。
- `tests/test_pipeline_cve.py`
  - `rebuild_catalog()` 後に SSVC view が公開される統合テストを追加する。
- `docs/schema.md`
  - 概要表と SSVC view カラム表を追加する。
- `README.md`
  - Schema summary と common query patterns に SSVC 例を追加する。
- `docs/llms.md`
  - LLM 用 canonical query に SSVC 候補取得例を追加する。

---

### Task 1: Lake の SSVC view 群

**Files:**
- Modify: `tests/test_lake.py`
- Modify: `src/vlake/lake.py`

**Interfaces:**
- Consumes: `Lake.ensure_tables()`, existing `lake.cve` / `lake.cve_history` relations.
- Produces:
  - `Lake.refresh_cve_ssvc_history_view(self) -> None`
  - `Lake.refresh_cve_ssvc_view(self) -> None`
  - `Lake.refresh_ssvc_decision_view(self) -> None`
  - `Lake.refresh_cve_ssvc_candidates_view(self) -> None`
  - Views: `lake.cve_ssvc_history`, `lake.cve_ssvc`, `lake.ssvc_decision`, `lake.cve_ssvc_candidates`

- [ ] **Step 1: `tests/test_lake.py` に SSVC fixture helper を追加**

Add these helpers after `_make_cve_parquet()`:

```python
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
```

- [ ] **Step 2: `tests/test_lake.py` に failing tests を追加**

Append these tests after `test_cve_history_and_latest_view()`:

```python
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


def test_cve_ssvc_candidates_expands_missing_parameters_and_compares_decision(tmp_path):
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_lake.py -k "ssvc" -v
```

Expected: FAIL with `AttributeError: 'Lake' object has no attribute 'refresh_cve_ssvc_history_view'` or equivalent missing-method failures.

- [ ] **Step 4: `src/vlake/lake.py` に SSVC extraction helper と history/latest view methods を追加**

Insert this block immediately after `refresh_cve_view()`:

```python
    def _refresh_cve_ssvc_view(self, source: str, target: str) -> None:
        """CVE JSON 5.x raw から CISA Coordinator SSVC を抽出する view を作る。"""
        self.con.execute(
            # ALIAS はクラス定数、source/target は呼び出し側の固定文字列
            f"""CREATE OR REPLACE VIEW {self.ALIAS}.{target} AS
            WITH
            ssvc_metrics AS (
                SELECT
                    src.cve,
                    src.date_updated,
                    json_extract_string(metric, '$.other.content.version') AS ssvc_version,
                    json_extract_string(metric, '$.other.content.role') AS ssvc_role,
                    try_cast(
                        json_extract_string(metric, '$.other.content.timestamp') AS TIMESTAMP
                    ) AS ssvc_timestamp,
                    coalesce(
                        json_extract_string(adp, '$.title'),
                        json_extract_string(adp, '$.providerMetadata.shortName')
                    ) AS ssvc_provider,
                    lower(json_extract_string(metric, '$.other.content.decision'))
                        AS recorded_decision,
                    cast(metric AS VARCHAR) AS ssvc_raw,
                    metric
                FROM {self.ALIAS}.{source} AS src
                JOIN UNNEST(
                    coalesce(json_extract(src.raw, '$.containers.adp')::JSON[], []::JSON[])
                ) AS adp_items(adp) ON true
                JOIN UNNEST(
                    coalesce(json_extract(adp, '$.metrics')::JSON[], []::JSON[])
                ) AS metric_items(metric) ON true
                WHERE (
                    json_extract_string(adp, '$.title') = 'CISA ADP Vulnrichment'
                    OR json_extract_string(adp, '$.providerMetadata.shortName') = 'CISA-ADP'
                )
                  AND lower(json_extract_string(metric, '$.other.type')) = 'ssvc'
                  AND json_extract_string(metric, '$.other.content.role') = 'CISA Coordinator'
            ),
            expanded_options AS (
                SELECT ssvc_metrics.*, opt
                FROM ssvc_metrics
                LEFT JOIN UNNEST(
                    coalesce(
                        json_extract(metric, '$.other.content.options')::JSON[],
                        []::JSON[]
                    )
                ) AS option_items(opt) ON true
            )
            SELECT
                cve,
                date_updated,
                ssvc_version,
                ssvc_role,
                ssvc_timestamp,
                ssvc_provider,
                max(
                    CASE WHEN json_extract_string(opt, '$.Exploitation') IS NOT NULL
                    THEN lower(json_extract_string(opt, '$.Exploitation')) END
                ) AS exploitation,
                max(
                    CASE WHEN json_extract_string(opt, '$.Automatable') IS NOT NULL
                    THEN lower(json_extract_string(opt, '$.Automatable')) END
                ) AS automatable,
                max(
                    CASE WHEN json_extract_string(opt, '$.Technical Impact') IS NOT NULL
                    THEN lower(json_extract_string(opt, '$.Technical Impact')) END
                ) AS technical_impact,
                max(
                    CASE
                    WHEN json_extract_string(opt, '$."Mission and Well-Being Impact"') IS NOT NULL
                    THEN lower(json_extract_string(opt, '$."Mission and Well-Being Impact"'))
                    END
                ) AS mission_impact,
                recorded_decision,
                ssvc_raw
            FROM expanded_options
            GROUP BY
                cve,
                date_updated,
                ssvc_version,
                ssvc_role,
                ssvc_timestamp,
                ssvc_provider,
                recorded_decision,
                ssvc_raw"""  # noqa: S608
        )

    def refresh_cve_ssvc_history_view(self) -> None:
        """cve_history から CISA Coordinator SSVC 履歴を抽出する view。"""
        self._refresh_cve_ssvc_view("cve_history", "cve_ssvc_history")

    def refresh_cve_ssvc_view(self) -> None:
        """最新 cve view から CISA Coordinator SSVC を抽出する view。"""
        self._refresh_cve_ssvc_view("cve", "cve_ssvc")
```

- [ ] **Step 5: `src/vlake/lake.py` に `refresh_ssvc_decision_view()` を追加**

Insert this method after `refresh_cve_ssvc_view()`:

```python
    def refresh_ssvc_decision_view(self) -> None:
        """CISA Coordinator SSVC 2.0.3 の decision table を公開する view。"""
        self.con.execute(
            # ALIAS はクラス定数、VALUES は固定表
            f"""CREATE OR REPLACE VIEW {self.ALIAS}.ssvc_decision AS
            SELECT
                '2.0.3' AS ssvc_version,
                'CISA Coordinator' AS ssvc_role,
                exploitation,
                automatable,
                technical_impact,
                mission_impact,
                decision,
                CASE decision
                    WHEN 'track' THEN 'Track'
                    WHEN 'track*' THEN 'Track*'
                    WHEN 'attend' THEN 'Attend'
                    WHEN 'act' THEN 'Act'
                END AS decision_label,
                CASE decision
                    WHEN 'track' THEN 1
                    WHEN 'track*' THEN 2
                    WHEN 'attend' THEN 3
                    WHEN 'act' THEN 4
                END AS decision_rank
            FROM (VALUES
                ('none', 'no', 'partial', 'low', 'track'),
                ('none', 'no', 'partial', 'medium', 'track'),
                ('none', 'no', 'partial', 'high', 'track'),
                ('none', 'no', 'total', 'low', 'track'),
                ('none', 'no', 'total', 'medium', 'track'),
                ('none', 'no', 'total', 'high', 'track*'),
                ('none', 'yes', 'partial', 'low', 'track'),
                ('none', 'yes', 'partial', 'medium', 'track'),
                ('none', 'yes', 'partial', 'high', 'attend'),
                ('none', 'yes', 'total', 'low', 'track'),
                ('none', 'yes', 'total', 'medium', 'track'),
                ('none', 'yes', 'total', 'high', 'attend'),
                ('public poc', 'no', 'partial', 'low', 'track'),
                ('public poc', 'no', 'partial', 'medium', 'track'),
                ('public poc', 'no', 'partial', 'high', 'track*'),
                ('public poc', 'no', 'total', 'low', 'track'),
                ('public poc', 'no', 'total', 'medium', 'track*'),
                ('public poc', 'no', 'total', 'high', 'attend'),
                ('public poc', 'yes', 'partial', 'low', 'track'),
                ('public poc', 'yes', 'partial', 'medium', 'track'),
                ('public poc', 'yes', 'partial', 'high', 'attend'),
                ('public poc', 'yes', 'total', 'low', 'track'),
                ('public poc', 'yes', 'total', 'medium', 'track*'),
                ('public poc', 'yes', 'total', 'high', 'attend'),
                ('active', 'no', 'partial', 'low', 'track'),
                ('active', 'no', 'partial', 'medium', 'track'),
                ('active', 'no', 'partial', 'high', 'attend'),
                ('active', 'no', 'total', 'low', 'track'),
                ('active', 'no', 'total', 'medium', 'attend'),
                ('active', 'no', 'total', 'high', 'act'),
                ('active', 'yes', 'partial', 'low', 'attend'),
                ('active', 'yes', 'partial', 'medium', 'attend'),
                ('active', 'yes', 'partial', 'high', 'act'),
                ('active', 'yes', 'total', 'low', 'attend'),
                ('active', 'yes', 'total', 'medium', 'act'),
                ('active', 'yes', 'total', 'high', 'act')
            ) AS t(exploitation, automatable, technical_impact, mission_impact, decision)"""  # noqa: S608
        )
```

- [ ] **Step 6: `src/vlake/lake.py` に `refresh_cve_ssvc_candidates_view()` を追加**

Insert this method after `refresh_ssvc_decision_view()`:

```python
    def refresh_cve_ssvc_candidates_view(self) -> None:
        """CVE 記録値を起点に不足 SSVC パラメータを展開した decision 候補 view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"""CREATE OR REPLACE VIEW {self.ALIAS}.cve_ssvc_candidates AS
            SELECT
                s.cve,
                s.date_updated,
                coalesce(s.ssvc_version, d.ssvc_version) AS ssvc_version,
                coalesce(s.ssvc_role, d.ssvc_role) AS ssvc_role,
                s.ssvc_timestamp,
                s.ssvc_provider,
                d.exploitation,
                d.automatable,
                d.technical_impact,
                d.mission_impact,
                s.exploitation AS recorded_exploitation,
                s.automatable AS recorded_automatable,
                s.technical_impact AS recorded_technical_impact,
                s.mission_impact AS recorded_mission_impact,
                s.recorded_decision,
                d.decision AS computed_decision,
                CASE
                    WHEN s.recorded_decision IS NULL OR d.decision IS NULL THEN NULL
                    ELSE s.recorded_decision = d.decision
                END AS decision_matches,
                d.decision_label,
                d.decision_rank,
                s.ssvc_raw
            FROM {self.ALIAS}.cve_ssvc AS s
            JOIN {self.ALIAS}.ssvc_decision AS d
              ON (s.ssvc_version IS NULL OR s.ssvc_version = d.ssvc_version)
             AND (s.ssvc_role IS NULL OR s.ssvc_role = d.ssvc_role)
             AND (s.exploitation IS NULL OR s.exploitation = d.exploitation)
             AND (s.automatable IS NULL OR s.automatable = d.automatable)
             AND (s.technical_impact IS NULL OR s.technical_impact = d.technical_impact)
             AND (s.mission_impact IS NULL OR s.mission_impact = d.mission_impact)"""  # noqa: S608
        )
```

- [ ] **Step 7: Run SSVC lake tests**

Run:

```bash
uv run pytest tests/test_lake.py -k "ssvc" -v
```

Expected: PASS for all SSVC tests.

- [ ] **Step 8: Run full lake tests**

Run:

```bash
uv run pytest tests/test_lake.py -v
```

Expected: PASS.

- [ ] **Step 9: Commit Task 1**

Run:

```bash
git add src/vlake/lake.py tests/test_lake.py
git commit -m "feat: SSVC抽出とdecision候補viewを追加"
```

---

### Task 2: publish / rebuild_catalog refresh 経路

**Files:**
- Modify: `tests/test_pipeline_cve.py`
- Modify: `src/vlake/pipeline.py`

**Interfaces:**
- Consumes: Task 1 methods on `Lake`.
- Produces: `_publish_catalog()` refreshes `ssvc_decision`, `cve_ssvc_history`, `cve_ssvc`, and `cve_ssvc_candidates` before catalog upload.

- [ ] **Step 1: `tests/test_pipeline_cve.py` に SSVC helper を追加**

Add these helpers near the top of `tests/test_pipeline_cve.py`, after imports and before `_records()`:

```python
def _ssvc_metric(
    *,
    exploitation: str = "active",
    automatable: str = "no",
    technical_impact: str = "total",
) -> dict:
    """CISA Coordinator SSVC 2.0.3 の metric 断片を作る。"""
    return {
        "other": {
            "type": "ssvc",
            "content": {
                "id": "CVE-2024-0001",
                "role": "CISA Coordinator",
                "options": [
                    {"Exploitation": exploitation},
                    {"Automatable": automatable},
                    {"Technical Impact": technical_impact},
                ],
                "version": "2.0.3",
                "timestamp": "2024-09-16T19:00:51.927416Z",
            },
        }
    }
```

- [ ] **Step 2: `test_rebuild_catalog_covers_both_datasets` を SSVC view 確認付きに変更**

Replace the first `make_baseline_zip(zp, _records())` line inside `test_rebuild_catalog_covers_both_datasets` with:

```python
    ssvc_record = make_cve_record(
        "CVE-2024-0001",
        date_updated="2026-07-10T00:00:00Z",
        adp_metrics=[_ssvc_metric()],
    )
    make_baseline_zip(zp, [ssvc_record, *_records()])
```

Replace the final three assertions in the same test with:

```python
    assert con.execute("SELECT count(*) FROM frozen.epss").fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM frozen.cve_history").fetchone()[0] == 4
    assert con.execute("SELECT count(*) FROM frozen.cve").fetchone()[0] == 4
    assert con.execute("SELECT count(*) FROM frozen.ssvc_decision").fetchone()[0] == 36
    assert con.execute("SELECT count(*) FROM frozen.cve_ssvc").fetchone()[0] == 1
    assert (
        con.execute(
            "SELECT computed_decision FROM frozen.cve_ssvc_candidates "
            "WHERE cve = 'CVE-2024-0001' AND mission_impact = 'high'"
        ).fetchone()[0]
        == "act"
    )
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
uv run pytest tests/test_pipeline_cve.py::test_rebuild_catalog_covers_both_datasets -v
```

Expected: FAIL with missing `frozen.ssvc_decision`, `frozen.cve_ssvc`, or `frozen.cve_ssvc_candidates` relation.

- [ ] **Step 4: Update `_publish_catalog()` in `src/vlake/pipeline.py`**

In `_publish_catalog()`, after `lake.refresh_cve_view()` and before `lake.refresh_ghsa_view()`, insert:

```python
    lake.refresh_ssvc_decision_view()
    lake.refresh_cve_ssvc_history_view()
    lake.refresh_cve_ssvc_view()
    lake.refresh_cve_ssvc_candidates_view()
```

The resulting view refresh order must include:

```python
    lake.refresh_cve_view()
    lake.refresh_ssvc_decision_view()
    lake.refresh_cve_ssvc_history_view()
    lake.refresh_cve_ssvc_view()
    lake.refresh_cve_ssvc_candidates_view()
    lake.refresh_ghsa_view()
```

- [ ] **Step 5: Run targeted pipeline test**

Run:

```bash
uv run pytest tests/test_pipeline_cve.py::test_rebuild_catalog_covers_both_datasets -v
```

Expected: PASS.

- [ ] **Step 6: Run CVE pipeline tests**

Run:

```bash
uv run pytest tests/test_pipeline_cve.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit Task 2**

Run:

```bash
git add src/vlake/pipeline.py tests/test_pipeline_cve.py
git commit -m "feat: SSVC viewをカタログ公開経路に追加"
```

---

### Task 3: schema / README / llms ドキュメント同期

**Files:**
- Modify: `docs/schema.md`
- Modify: `README.md`
- Modify: `docs/llms.md`

**Interfaces:**
- Consumes: Task 1 view names and columns.
- Produces: Public documentation for `cve_ssvc`, `cve_ssvc_history`, `ssvc_decision`, and `cve_ssvc_candidates`.

- [ ] **Step 1: `docs/schema.md` の概要表に SSVC view を追加**

In `docs/schema.md`, in the overview table after the `cve_sources` row, insert:

```markdown
| `cve_ssvc` | *(view)* | CVE × SSVC metric | CISA Coordinator SSVC values extracted from latest CVE records |
| `cve_ssvc_history` | *(view)* | CVE history row × SSVC metric | CISA Coordinator SSVC values extracted from CVE record history |
| `ssvc_decision` | *(view)* | SSVC parameter combination | CISA Coordinator SSVC 2.0.3 decision table |
| `cve_ssvc_candidates` | *(view)* | CVE × decision candidate | Decision candidates expanded from recorded CVE SSVC values |
```

- [ ] **Step 2: `docs/schema.md` に SSVC セクションを追加**

In `docs/schema.md`, after the `cve_sources` section and before the `ghsa` section, insert:

```markdown
### `cve_ssvc` / `cve_ssvc_history` — CISA Coordinator SSVC from CVE List V5

Views that extract CISA Coordinator SSVC metrics from the CVE List V5 `raw`
JSON. `cve_ssvc` reads the latest `cve` view. `cve_ssvc_history` reads
`cve_history` so SSVC changes can be audited over time. CVEs without CISA ADP
Vulnrichment SSVC rows do not appear in these views.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `date_updated` | TIMESTAMP | CVE record update time |
| `ssvc_version` | VARCHAR | SSVC decision table version from the record, currently `2.0.3` for CISA Coordinator rows |
| `ssvc_role` | VARCHAR | SSVC role, currently `CISA Coordinator` |
| `ssvc_timestamp` | TIMESTAMP | SSVC assessment timestamp |
| `ssvc_provider` | VARCHAR | ADP provider/title, typically `CISA ADP Vulnrichment` |
| `exploitation` | VARCHAR | Recorded SSVC Exploitation value (`none`, `public poc`, `active`) |
| `automatable` | VARCHAR | Recorded SSVC Automatable value (`yes`, `no`) |
| `technical_impact` | VARCHAR | Recorded SSVC Technical Impact value (`partial`, `total`) |
| `mission_impact` | VARCHAR | Recorded Mission and Well-Being Impact value if present; CISA Vulnrichment CVE rows often omit it |
| `recorded_decision` | VARCHAR | Decision recorded in CVE JSON if present |
| `ssvc_raw` | VARCHAR | SSVC metric JSON fragment extracted from the CVE record |

### `ssvc_decision` — CISA Coordinator SSVC decision table

CISA Coordinator SSVC 2.0.3 decision table. Filter any subset of parameter
columns to get all matching decisions; omitted parameters naturally return all
possible values.

| Column | Type | Description |
|---|---|---|
| `ssvc_version` | VARCHAR | SSVC decision table version (`2.0.3`) |
| `ssvc_role` | VARCHAR | SSVC role (`CISA Coordinator`) |
| `exploitation` | VARCHAR | Exploitation value (`none`, `public poc`, `active`) |
| `automatable` | VARCHAR | Automatable value (`yes`, `no`) |
| `technical_impact` | VARCHAR | Technical Impact value (`partial`, `total`) |
| `mission_impact` | VARCHAR | Mission and Well-Being Impact value (`low`, `medium`, `high`) |
| `decision` | VARCHAR | Computed CISA decision (`track`, `track*`, `attend`, `act`) |
| `decision_label` | VARCHAR | Display label (`Track`, `Track*`, `Attend`, `Act`) |
| `decision_rank` | INTEGER | Sort key from lowest to highest urgency (`track` = 1, `act` = 4) |

### `cve_ssvc_candidates` — CVE-based SSVC decision candidates

Joins `cve_ssvc` to `ssvc_decision`. Recorded CVE SSVC values constrain the
join. Missing recorded parameters expand to every value from `ssvc_decision`,
so CVEs with partial SSVC data return every possible decision candidate. CVEs
without SSVC data return zero rows.

| Column | Type | Description |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `date_updated` | TIMESTAMP | Latest CVE record update time |
| `ssvc_version` | VARCHAR | SSVC decision table version used for candidate computation |
| `ssvc_role` | VARCHAR | SSVC role used for candidate computation |
| `ssvc_timestamp` | TIMESTAMP | Recorded SSVC assessment timestamp |
| `ssvc_provider` | VARCHAR | ADP provider/title |
| `exploitation` | VARCHAR | Candidate Exploitation value |
| `automatable` | VARCHAR | Candidate Automatable value |
| `technical_impact` | VARCHAR | Candidate Technical Impact value |
| `mission_impact` | VARCHAR | Candidate Mission and Well-Being Impact value |
| `recorded_exploitation` | VARCHAR | Exploitation value recorded in CVE JSON, or NULL if missing |
| `recorded_automatable` | VARCHAR | Automatable value recorded in CVE JSON, or NULL if missing |
| `recorded_technical_impact` | VARCHAR | Technical Impact value recorded in CVE JSON, or NULL if missing |
| `recorded_mission_impact` | VARCHAR | Mission and Well-Being Impact value recorded in CVE JSON, or NULL if missing |
| `recorded_decision` | VARCHAR | Decision recorded in CVE JSON if present |
| `computed_decision` | VARCHAR | Decision computed from `ssvc_decision` |
| `decision_matches` | BOOLEAN | Whether `recorded_decision` equals `computed_decision`; NULL when no recorded decision exists |
| `decision_label` | VARCHAR | Display label for `computed_decision` |
| `decision_rank` | INTEGER | Sort key from lowest to highest urgency |
| `ssvc_raw` | VARCHAR | SSVC metric JSON fragment extracted from the CVE record |
```

- [ ] **Step 3: `README.md` の Common query patterns に SSVC 例を追加**

In `README.md`, after the “Build a small CVE triage row” query block and before “Find GitHub advisories and affected packages”, insert:

```markdown
### Check CISA Coordinator SSVC candidates

CVE List V5 can include CISA ADP Vulnrichment SSVC values. When a CVE record
omits parameters needed for a decision, `cve_ssvc_candidates` expands the
missing values and returns every possible computed decision.

```sql
SELECT
  cve,
  exploitation,
  automatable,
  technical_impact,
  mission_impact,
  recorded_decision,
  computed_decision,
  decision_matches
FROM vlake.cve_ssvc_candidates
WHERE cve = 'CVE-2023-38205'
ORDER BY decision_rank, mission_impact;
```
```

- [ ] **Step 4: `README.md` の Schema overview table に SSVC 行を追加**

In `README.md`, in the `## Schema` overview table after the `cve_sources` row, insert:

```markdown
| `cve_ssvc` | *(view)* | CVE × SSVC metric | CISA Coordinator SSVC values extracted from latest CVE records |
| `cve_ssvc_candidates` | *(view)* | CVE × decision candidate | CISA Coordinator SSVC decision candidates expanded from recorded CVE values |
| `ssvc_decision` | *(view)* | SSVC parameter combination | CISA Coordinator SSVC 2.0.3 decision table |
```

- [ ] **Step 5: `docs/llms.md` の query rules と relation table に SSVC を追加**

In `docs/llms.md`, in the “Querying rules” bullet list after the `vlake.epss` bullet, insert:

```markdown
- Use `vlake.cve_ssvc_candidates` for CISA Coordinator SSVC decision candidates
  for a CVE. Missing recorded parameters, especially `mission_impact`, expand
  to all possible values from `vlake.ssvc_decision`.
```

In the “Which relation to query” table after `CVE record changes over time`, insert:

```markdown
| Current CISA Coordinator SSVC values | `vlake.cve_ssvc` |
| CISA Coordinator SSVC changes over time | `vlake.cve_ssvc_history` |
| CISA Coordinator SSVC decision candidates for a CVE | `vlake.cve_ssvc_candidates` |
| CISA Coordinator SSVC decision table | `vlake.ssvc_decision` |
```

- [ ] **Step 6: `docs/llms.md` の canonical query patterns に SSVC 例を追加**

In `docs/llms.md`, after the “CVE record history” query block and before “Current GHSA advisories for a CVE”, insert:

```markdown
CISA Coordinator SSVC decision candidates for a CVE:

```sql
SELECT
  cve,
  exploitation,
  automatable,
  technical_impact,
  mission_impact,
  recorded_decision,
  computed_decision,
  decision_matches
FROM vlake.cve_ssvc_candidates
WHERE cve = 'CVE-2023-38205'
ORDER BY decision_rank, mission_impact;
```

CISA Coordinator SSVC decision table with partial input:

```sql
SELECT exploitation, automatable, technical_impact, mission_impact, decision
FROM vlake.ssvc_decision
WHERE exploitation = 'active'
  AND automatable = 'no';
```
```

- [ ] **Step 7: Run schema documentation checks**

Run:

```bash
uv run python .pi/skills/readme-schema-sync/scripts/check_readme_schema.py
awk '
/^\|/ { n=gsub(/\|/,"|"); if(inblock && n!=prev){print "PIPE MISMATCH line "NR": "$0; bad=1} prev=n; inblock=1; next }
{ inblock=0 } END{ if(!bad) print "OK: table pipes consistent" }
' README.md docs/schema.md
git diff --check -- README.md docs/schema.md docs/llms.md
```

Expected:

```text
OK
OK: table pipes consistent
```

`git diff --check` should produce no output.

- [ ] **Step 8: Commit Task 3**

Run:

```bash
git add README.md docs/schema.md docs/llms.md
git commit -m "docs: SSVC viewの利用方法とスキーマを追加"
```

---

### Task 4: 全体検証と lint / SAST gate

**Files:**
- No source edits expected unless verification fails.

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: Verified branch ready for review.

- [ ] **Step 1: Run targeted tests**

Run:

```bash
uv run pytest tests/test_lake.py -k "ssvc" -v
uv run pytest tests/test_pipeline_cve.py::test_rebuild_catalog_covers_both_datasets -v
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
uv run pytest -v
```

Expected: PASS.

- [ ] **Step 3: Run lint and SAST**

Run:

```bash
mise run lint
mise run sast
```

Expected:

```text
All checks passed!
No findings to report. Good job!
```

- [ ] **Step 4: Run commit gate**

Run:

```bash
mise run pre-commit
```

Expected: PASS.

- [ ] **Step 5: Inspect status and log**

Run:

```bash
git status --short
git log --oneline -5
```

Expected: `git status --short` has no unstaged or uncommitted source/doc changes from this feature. The recent log includes:

```text
feat: SSVC抽出とdecision候補viewを追加
feat: SSVC viewをカタログ公開経路に追加
docs: SSVC viewの利用方法とスキーマを追加
```

If any command fails, fix the cause, rerun the failed command, and then rerun `mise run pre-commit` before reporting success.

---

## Self-Review

- Spec coverage:
  - DuckDB-only interface: Tasks 1–3.
  - Dynamic extraction from `cve.raw` / `cve_history.raw`: Task 1.
  - `cve_ssvc`, `cve_ssvc_history`, `ssvc_decision`, `cve_ssvc_candidates`: Task 1.
  - Partial input expansion: Task 1 candidate view tests.
  - Recorded vs computed decision comparison: Task 1 candidate test.
  - SSVC-missing CVEs return 0 rows: Task 1 zero-row test.
  - Catalog publish / rebuild refresh: Task 2.
  - README / schema / llms docs: Task 3.
  - Lint / SAST gate: Task 4.
- Adjustment from spec: official CISA Coordinator SSVC 2.0.3 decision table requires `Mission and Well-Being Impact`. The plan adds `mission_impact` to `ssvc_decision`, `cve_ssvc`, and `cve_ssvc_candidates`; CVE records that omit it expand all `low` / `medium` / `high` candidates.
- No implementation task changes Parquet storage layout, dataset keys, or update/backfill ordering.
