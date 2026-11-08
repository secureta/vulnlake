import json
import sys
from pathlib import Path

import duckdb

PUBLIC_TABLES = (
    "epss",
    "cve_history",
    "ghsa_history",
    "exploitdb_history",
    "nuclei_history",
    "kev_history",
    "cloudflare_waf_history",
    "cwe_history",
    "attack_history",
    "attack_relationship_history",
    "capec_history",
)
PUBLIC_VIEWS = (
    "datasets",
    "cve",
    "ssvc_decision",
    "cve_ssvc_history",
    "cve_ssvc",
    "cve_ssvc_candidates",
    "ghsa",
    "exploitdb",
    "nuclei",
    "cwe",
    "kev",
    "cloudflare_waf",
    "attack",
    "attack_relationship",
    "capec",
    "cve_sources",
    "cwe_attack_patterns",
)


def _rows(relation):
    relation = relation.select(
        *[
            duckdb.ColumnExpression(name).cast("VARCHAR").alias(name)
            if str(dtype) == "TIMESTAMP WITH TIME ZONE"
            else duckdb.ColumnExpression(name)
            for name, dtype in zip(relation.columns, relation.types, strict=True)
        ]
    )
    rows = [
        dict(zip(relation.columns, row, strict=True)) for row in relation.fetchall()
    ]
    return sorted(
        json.loads(json.dumps(rows, default=str)),
        key=lambda row: json.dumps(row, sort_keys=True),
    )


def read_metadata(catalog: Path) -> dict:
    with duckdb.connect(str(catalog), read_only=True) as con:
        return {
            name: _rows(con.table(name))
            for (name,) in con.execute("SHOW TABLES").fetchall()
            if name.startswith("ducklake_")
        }


def read_catalog(catalog: Path) -> dict:
    metadata = read_metadata(catalog)
    with duckdb.connect() as con:
        con.execute("INSTALL ducklake; LOAD ducklake;")
        con.execute("INSTALL httpfs; LOAD httpfs;")
        con.execute(
            "ATTACH "
            + str(duckdb.ConstantExpression("ducklake:" + str(catalog)))
            + " AS frozen (READ_ONLY)"
        )
        return {
            "reader_version": duckdb.__version__,
            "metadata": metadata,
            "tables": {
                name: _rows(
                    con.sql("SELECT * FROM query_table(?)", params=["frozen." + name])
                )
                for name in PUBLIC_TABLES
            },
            "views": {
                name: _rows(
                    con.sql("SELECT * FROM query_table(?)", params=["frozen." + name])
                )
                for name in PUBLIC_VIEWS
            },
        }


def create_legacy_catalog(catalog: Path, parquet: str) -> dict:
    with duckdb.connect() as con:
        con.execute("INSTALL ducklake; LOAD ducklake;")
        con.execute(
            "ATTACH "
            + str(duckdb.ConstantExpression("ducklake:" + str(catalog)))
            + " AS legacy (DATA_PATH "
            + str(duckdb.ConstantExpression(str(catalog.parent / "unused")))
            + ")"
        )
        con.execute(
            "CREATE TABLE legacy.epss (cve VARCHAR, epss DOUBLE, percentile DOUBLE, "
            "date DATE, model_version VARCHAR)"
        )
        con.execute("BEGIN")
        con.execute("CALL legacy.set_commit_message('compat-reader', 'legacy seed')")
        con.execute("CALL ducklake_add_data_files('legacy', 'epss', ?)", [parquet])
        con.execute("COMMIT")
    return read_metadata(catalog)


if __name__ == "__main__":
    request = json.load(sys.stdin)
    catalog = Path(request["catalog"])
    result = (
        create_legacy_catalog(catalog, request["parquet"])
        if request.get("mode") == "create"
        else read_catalog(catalog)
    )
    print(json.dumps(result))
