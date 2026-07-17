"""DuckLake カタログ (vlake.ducklake) への書き込みセッション。

カタログはローカルファイルとして操作し、呼び出し側が Storage 経由で
ダウンロード/アップロードする。データファイルは ducklake_add_data_files()
で絶対 URL (またはローカル絶対パス) を登録する。
"""

from __future__ import annotations

from pathlib import Path

import duckdb


def _q(s: str) -> str:
    """SQL 文字列リテラル用エスケープ。"""
    return s.replace("'", "''")


class Lake:
    ALIAS = "lake"
    META = "__ducklake_metadata_lake"

    def __init__(self, catalog_path: Path, data_path: str | None = None):
        self._closed = False
        self.con = duckdb.connect()
        self.con.execute("INSTALL ducklake; LOAD ducklake;")
        self.con.execute("INSTALL httpfs; LOAD httpfs;")
        options = f" (DATA_PATH '{_q(data_path)}')" if data_path else ""
        self.con.execute(
            f"ATTACH 'ducklake:{_q(str(catalog_path))}' AS {self.ALIAS}{options}"
        )

    def ensure_tables(self) -> None:
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.epss (
                cve VARCHAR,
                epss DOUBLE,
                percentile DOUBLE,
                date DATE,
                model_version VARCHAR
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.cve_history (
                cve VARCHAR,
                state VARCHAR,
                assigner VARCHAR,
                title VARCHAR,
                description VARCHAR,
                cvss DOUBLE,
                cvss_version VARCHAR,
                cvss_severity VARCHAR,
                cvss_vector VARCHAR,
                cwe VARCHAR[],
                date_published TIMESTAMP,
                date_reserved TIMESTAMP,
                date_updated TIMESTAMP,
                raw VARCHAR
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.ghsa_history (
                ghsa VARCHAR,
                cve VARCHAR,
                summary VARCHAR,
                severity VARCHAR,
                cvss DOUBLE,
                cvss_version VARCHAR,
                cvss_vector VARCHAR,
                cwe VARCHAR[],
                affected STRUCT(
                    ecosystem VARCHAR,
                    package VARCHAR,
                    introduced VARCHAR,
                    fixed VARCHAR,
                    last_affected VARCHAR
                )[],
                published TIMESTAMP,
                modified TIMESTAMP,
                withdrawn TIMESTAMP,
                raw VARCHAR
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.exploitdb_history (
                edb_id INTEGER,
                cve VARCHAR[],
                description VARCHAR,
                type VARCHAR,
                platform VARCHAR,
                author VARCHAR,
                port INTEGER,
                verified BOOLEAN,
                tags VARCHAR,
                aliases VARCHAR,
                codes VARCHAR,
                file VARCHAR,
                code_url VARCHAR,
                source_url VARCHAR,
                application_url VARCHAR,
                screenshot_url VARCHAR,
                date_published DATE,
                date_added DATE,
                date_updated DATE
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.nuclei_history (
                template_id VARCHAR,
                name VARCHAR,
                severity VARCHAR,
                description VARCHAR,
                author VARCHAR[],
                tags VARCHAR[],
                reference VARCHAR[],
                cve VARCHAR[],
                cwe VARCHAR[],
                cvss_score DOUBLE,
                cvss_metrics VARCHAR,
                epss_score DOUBLE,
                epss_percentile DOUBLE,
                cpe VARCHAR,
                vendor VARCHAR,
                product VARCHAR,
                verified BOOLEAN,
                type VARCHAR,
                file VARCHAR,
                template_url VARCHAR,
                digest VARCHAR,
                fetched_date DATE,
                removed BOOLEAN
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.kev_history (
                cve VARCHAR,
                vendor_project VARCHAR,
                product VARCHAR,
                vulnerability_name VARCHAR,
                short_description VARCHAR,
                required_action VARCHAR,
                known_ransomware_campaign_use VARCHAR,
                notes VARCHAR,
                cwe VARCHAR[],
                date_added DATE,
                due_date DATE,
                fetched_date DATE,
                removed BOOLEAN
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.cloudflare_waf_history (
                identifier VARCHAR,
                identifier_type VARCHAR,
                cve VARCHAR,
                source_title VARCHAR,
                source_url VARCHAR,
                source_date DATE,
                matched_text VARCHAR,
                fetched_date DATE,
                removed BOOLEAN
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.cwe_history (
                cwe_id VARCHAR,
                entry_type VARCHAR,
                name VARCHAR,
                abstraction VARCHAR,
                status VARCHAR,
                description VARCHAR,
                likelihood_of_exploit VARCHAR,
                relations STRUCT(nature VARCHAR, target_id VARCHAR)[],
                cwe_version VARCHAR,
                release_date DATE
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.attack_history (
                matrix VARCHAR,
                attack_id VARCHAR,
                object_id VARCHAR,
                object_type VARCHAR,
                name VARCHAR,
                description VARCHAR,
                url VARCHAR,
                kill_chain_phases STRUCT(kill_chain_name VARCHAR, phase_name VARCHAR)[],
                revoked BOOLEAN,
                deprecated BOOLEAN,
                modified TIMESTAMP,
                raw VARCHAR
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.attack_relationship_history (
                matrix VARCHAR,
                relationship_id VARCHAR,
                relationship_type VARCHAR,
                source_ref VARCHAR,
                source_attack_id VARCHAR,
                source_name VARCHAR,
                source_type VARCHAR,
                target_ref VARCHAR,
                target_attack_id VARCHAR,
                target_name VARCHAR,
                target_type VARCHAR,
                description VARCHAR,
                revoked BOOLEAN,
                deprecated BOOLEAN,
                modified TIMESTAMP,
                raw VARCHAR
            )"""
        )
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.capec_history (
                capec_id VARCHAR,
                object_id VARCHAR,
                name VARCHAR,
                description VARCHAR,
                url VARCHAR,
                cwe VARCHAR[],
                attack VARCHAR[],
                revoked BOOLEAN,
                deprecated BOOLEAN,
                modified TIMESTAMP,
                raw VARCHAR
            )"""
        )

    def registered_paths(self, table: str | None = None) -> set[str]:
        if table is None:
            rows = self.con.execute(
                # META はクラス定数の固定識別子で外部入力は入らない
                f"SELECT path FROM {self.META}.ducklake_data_file WHERE end_snapshot IS NULL"  # noqa: S608
            ).fetchall()
        else:
            rows = self.con.execute(
                # META はクラス定数の固定識別子、table は _q() でエスケープ済み
                f"""SELECT f.path FROM {self.META}.ducklake_data_file f
                    JOIN {self.META}.ducklake_table t ON f.table_id = t.table_id
                    WHERE f.end_snapshot IS NULL AND t.end_snapshot IS NULL
                      AND t.table_name = '{_q(table)}'"""  # noqa: S608
            ).fetchall()
        return {r[0] for r in rows}

    def max_cve_date_updated(self):
        """cve_history の最新 date_updated (空なら None)。日次差分の判定に使う。"""
        return self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT max(date_updated) FROM {self.ALIAS}.cve_history"  # noqa: S608
        ).fetchone()[0]

    def refresh_cve_view(self) -> None:
        """CVE ごとに date_updated 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.cve AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.cve_history "
            f"QUALIFY row_number() OVER (PARTITION BY cve ORDER BY date_updated DESC) = 1"
        )

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

    def max_ghsa_modified(self):
        """ghsa_history の最新 modified (空なら None)。日次差分の判定に使う。"""
        return self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT max(modified) FROM {self.ALIAS}.ghsa_history"  # noqa: S608
        ).fetchone()[0]

    def refresh_ghsa_view(self) -> None:
        """GHSA ごとに modified 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.ghsa AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.ghsa_history "
            f"QUALIFY row_number() OVER (PARTITION BY ghsa ORDER BY modified DESC) = 1"
        )

    def max_exploitdb_date_updated(self):
        """exploitdb_history の最新 date_updated (空なら None)。日次差分の判定に使う。"""
        return self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT max(date_updated) FROM {self.ALIAS}.exploitdb_history"  # noqa: S608
        ).fetchone()[0]

    def exploitdb_edb_ids_at(self, d) -> set[int]:
        """指定 date_updated に既に登録済みの edb_id 集合。

        date_updated は日単位のため、同一最大日に後から現れた行を差分に含めるか
        判定するのに使う (既登録は除外、二重計上を防ぐ)。
        """
        rows = self.con.execute(
            # ALIAS はクラス定数、d はパラメータ化済みで注入されない
            f"SELECT edb_id FROM {self.ALIAS}.exploitdb_history WHERE date_updated = ?",  # noqa: S608
            [d],
        ).fetchall()
        return {r[0] for r in rows}

    def refresh_exploitdb_view(self) -> None:
        """edb_id ごとに date_updated 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.exploitdb AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.exploitdb_history "
            f"QUALIFY row_number() OVER (PARTITION BY edb_id ORDER BY date_updated DESC) = 1"
        )

    def nuclei_latest_rows(self) -> list[dict]:
        """template_id ごと fetched_date 最新の1行を列名付き dict で返す (空なら [])。

        nuclei は更新日時ウォーターマークが使えないため、update の差分検出と
        トゥームストーン生成 (最終値の引き継ぎ) にこの全行スナップショットを使う。
        """
        cur = self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT * FROM {self.ALIAS}.nuclei_history "  # noqa: S608
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY template_id ORDER BY fetched_date DESC) = 1"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def refresh_nuclei_view(self) -> None:
        """template_id ごとに fetched_date 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.nuclei AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.nuclei_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY template_id ORDER BY fetched_date DESC) = 1"
        )

    def kev_latest_rows(self) -> list[dict]:
        """cve ごと fetched_date 最新の1行を列名付き dict で返す (空なら [])。

        KEV はレコード単位の更新日時が無いため、update の差分検出と
        トゥームストーン生成 (最終値の引き継ぎ) にこの全行スナップショットを使う。
        """
        cur = self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT * FROM {self.ALIAS}.kev_history "  # noqa: S608
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY cve ORDER BY fetched_date DESC) = 1"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def refresh_kev_view(self) -> None:
        """cve ごとに fetched_date 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.kev AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.kev_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY cve ORDER BY fetched_date DESC) = 1"
        )

    def cloudflare_waf_latest_rows(self) -> list[dict]:
        """identifier + source_url ごと fetched_date 最新の1行を列名付き dict で返す。"""
        cur = self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"SELECT * FROM {self.ALIAS}.cloudflare_waf_history "  # noqa: S608
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY identifier, source_url ORDER BY fetched_date DESC) = 1"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def refresh_cloudflare_waf_view(self) -> None:
        """identifier + source_url ごとに fetched_date 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.cloudflare_waf AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.cloudflare_waf_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY identifier, source_url ORDER BY fetched_date DESC) = 1"
        )

    def refresh_cve_sources_view(self) -> None:
        """CVE ごとに関連データが存在する公開 view/table を要約する view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"""CREATE OR REPLACE VIEW {self.ALIAS}.cve_sources AS
            WITH
            epss_src AS (
                SELECT cve, count(*) AS epss_days
                FROM {self.ALIAS}.epss
                GROUP BY cve
            ),
            cve_src AS (
                SELECT cve
                FROM {self.ALIAS}.cve
            ),
            ghsa_src AS (
                SELECT cve, count(*) AS ghsa_count
                FROM {self.ALIAS}.ghsa
                WHERE cve IS NOT NULL
                GROUP BY cve
            ),
            exploitdb_src AS (
                SELECT x.cve, count(*) AS exploitdb_count
                FROM {self.ALIAS}.exploitdb, UNNEST(cve) AS x(cve)
                WHERE x.cve IS NOT NULL
                GROUP BY x.cve
            ),
            nuclei_src AS (
                SELECT x.cve, count(*) AS nuclei_count
                FROM {self.ALIAS}.nuclei, UNNEST(cve) AS x(cve)
                WHERE x.cve IS NOT NULL AND NOT removed
                GROUP BY x.cve
            ),
            kev_src AS (
                SELECT cve
                FROM {self.ALIAS}.kev
                WHERE NOT removed
            ),
            cloudflare_waf_src AS (
                SELECT cve, count(*) AS cloudflare_waf_count
                FROM {self.ALIAS}.cloudflare_waf
                WHERE cve IS NOT NULL AND NOT removed
                GROUP BY cve
            ),
            all_cves AS (
                SELECT cve FROM epss_src
                UNION
                SELECT cve FROM cve_src
                UNION
                SELECT cve FROM ghsa_src
                UNION
                SELECT cve FROM exploitdb_src
                UNION
                SELECT cve FROM nuclei_src
                UNION
                SELECT cve FROM kev_src
                UNION
                SELECT cve FROM cloudflare_waf_src
            )
            SELECT
                all_cves.cve,
                epss_src.cve IS NOT NULL AS has_epss,
                cve_src.cve IS NOT NULL AS has_cve,
                ghsa_src.cve IS NOT NULL AS has_ghsa,
                exploitdb_src.cve IS NOT NULL AS has_exploitdb,
                nuclei_src.cve IS NOT NULL AS has_nuclei,
                kev_src.cve IS NOT NULL AS has_kev,
                cloudflare_waf_src.cve IS NOT NULL AS has_cloudflare_waf,
                COALESCE(epss_src.epss_days, 0) AS epss_days,
                COALESCE(ghsa_src.ghsa_count, 0) AS ghsa_count,
                COALESCE(exploitdb_src.exploitdb_count, 0) AS exploitdb_count,
                COALESCE(nuclei_src.nuclei_count, 0) AS nuclei_count,
                COALESCE(cloudflare_waf_src.cloudflare_waf_count, 0) AS cloudflare_waf_count
            FROM all_cves
            LEFT JOIN epss_src ON all_cves.cve = epss_src.cve
            LEFT JOIN cve_src ON all_cves.cve = cve_src.cve
            LEFT JOIN ghsa_src ON all_cves.cve = ghsa_src.cve
            LEFT JOIN exploitdb_src ON all_cves.cve = exploitdb_src.cve
            LEFT JOIN nuclei_src ON all_cves.cve = nuclei_src.cve
            LEFT JOIN kev_src ON all_cves.cve = kev_src.cve
            LEFT JOIN cloudflare_waf_src ON all_cves.cve = cloudflare_waf_src.cve"""  # noqa: S608
        )

    def refresh_cwe_view(self) -> None:
        """release_date 最大のバージョン断面 (全エントリ) を返す view。

        cwe_version の文字列比較は '4.9' > '4.20' となるため使わない。
        """
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.cwe AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.cwe_history WHERE release_date = "
            f"(SELECT max(release_date) FROM {self.ALIAS}.cwe_history)"
        )

    def refresh_attack_view(self) -> None:
        """matrix, attack_id ごとに modified 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.attack AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.attack_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY matrix, attack_id ORDER BY modified DESC) = 1"
        )

    def refresh_attack_relationship_view(self) -> None:
        """matrix, relationship_id ごとに modified 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.attack_relationship AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.attack_relationship_history "
            f"QUALIFY row_number() OVER "
            f"(PARTITION BY matrix, relationship_id ORDER BY modified DESC) = 1"
        )

    def refresh_capec_view(self) -> None:
        """capec_id ごとに modified 最新の1行を返す view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"CREATE OR REPLACE VIEW {self.ALIAS}.capec AS "  # noqa: S608
            f"SELECT * FROM {self.ALIAS}.capec_history "
            f"QUALIFY row_number() OVER (PARTITION BY capec_id ORDER BY modified DESC) = 1"
        )

    def refresh_cwe_attack_patterns_view(self) -> None:
        """CWE から CAPEC と ATT&CK technique をたどる連携 view。"""
        self.con.execute(
            # ALIAS はクラス定数の固定識別子で外部入力は入らない
            f"""CREATE OR REPLACE VIEW {self.ALIAS}.cwe_attack_patterns AS
            SELECT
                cwe.cwe,
                capec.capec_id,
                capec.name AS capec_name,
                attack.attack_id,
                attack.name AS attack_name,
                attack.object_type AS attack_object_type,
                attack.kill_chain_phases
            FROM {self.ALIAS}.capec, UNNEST(cwe) AS cwe(cwe)
            LEFT JOIN UNNEST(attack) AS capec_attack(attack_id) ON true
            LEFT JOIN {self.ALIAS}.attack AS attack
                ON attack.matrix = 'enterprise'
               AND attack.attack_id = capec_attack.attack_id
            WHERE NOT capec.revoked AND NOT capec.deprecated"""  # noqa: S608
        )

    def add_file(self, table: str, path: str) -> bool:
        if path in self.registered_paths():
            return False
        self.con.execute(
            f"CALL ducklake_add_data_files('{self.ALIAS}', '{_q(table)}', '{_q(path)}')"
        )
        return True

    def set_message(self, message: str) -> None:
        try:
            self.con.execute(
                f"CALL {self.ALIAS}.set_commit_message('vlake', '{_q(message)}')"
            )
        except duckdb.Error:
            pass  # 拡張のバージョンによっては未対応。注記は必須機能ではない

    def refresh_datasets_view(self, infos: list[dict]) -> None:
        cols = (
            "name",
            "source_url",
            "license_name",
            "license_text",
            "attribution",
            "disclaimer",
        )
        values = ", ".join(
            "(" + ", ".join(f"'{_q(str(info[c]))}'" for c in cols) + ")"
            for info in infos
        )
        self.con.execute(
            # ALIAS/cols は固定、values は _q() でエスケープ済み
            f"CREATE OR REPLACE VIEW {self.ALIAS}.datasets AS "  # noqa: S608
            f"SELECT * FROM (VALUES {values}) AS t({', '.join(cols)})"
        )

    def query(self, sql: str) -> list[tuple]:
        return self.con.execute(sql).fetchall()

    def close(self) -> None:
        if self._closed:
            return
        self.con.close()
        self._closed = True
