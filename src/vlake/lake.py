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
