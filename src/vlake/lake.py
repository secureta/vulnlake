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
        self.con.execute(f"ATTACH 'ducklake:{_q(str(catalog_path))}' AS {self.ALIAS}{options}")

    def ensure_epss_table(self) -> None:
        self.con.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ALIAS}.epss (
                cve VARCHAR,
                epss DOUBLE,
                percentile DOUBLE,
                date DATE,
                model_version VARCHAR
            )"""
        )

    def registered_paths(self) -> set[str]:
        rows = self.con.execute(
            f"SELECT path FROM {self.META}.ducklake_data_file WHERE end_snapshot IS NULL"
        ).fetchall()
        return {r[0] for r in rows}

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
        cols = ("name", "source_url", "license_name", "license_text", "attribution", "disclaimer")
        values = ", ".join(
            "(" + ", ".join(f"'{_q(str(info[c]))}'" for c in cols) + ")" for info in infos
        )
        self.con.execute(
            f"CREATE OR REPLACE VIEW {self.ALIAS}.datasets AS "
            f"SELECT * FROM (VALUES {values}) AS t({', '.join(cols)})"
        )

    def query(self, sql: str) -> list[tuple]:
        return self.con.execute(sql).fetchall()

    def close(self) -> None:
        if self._closed:
            return
        self.con.close()
        self._closed = True
