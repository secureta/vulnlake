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
