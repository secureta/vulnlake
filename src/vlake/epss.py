"""EPSS (Exploit Prediction Scoring System) データセット。

データ提供: FIRST.org — https://www.first.org/epss
本プロジェクトは EPSS データを再配布するが、FIRST の公認・認証を受けたものではない。
"""

from __future__ import annotations

import gzip
import io
from datetime import date
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

NAME = "epss"

SCHEMA = pa.schema(
    [
        ("cve", pa.string()),
        ("epss", pa.float64()),
        ("percentile", pa.float64()),  # 2021年初期ファイルには存在しない (NULL)
        ("date", pa.date32()),
        ("model_version", pa.string()),
    ]
)

CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DATED_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"

LICENSE_INFO = {
    "name": NAME,
    "source_url": "https://www.first.org/epss/data_stats",
    "license_name": "FIRST EPSS Usage Agreement (LicenseRef-scancode-first-epss-usage)",
    "license_text": (
        '"We grant the use of EPSS scores freely to the public, subject to the '
        "following conditions. ... we ask that if you are using EPSS, that you "
        'provide appropriate attribution where possible." '
        "— https://www.first.org/epss/faq"
    ),
    "attribution": (
        "EPSS scores provided by FIRST.org — https://www.first.org/epss. "
        "Citation: Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, "
        "Idris Adjerid (2021), Exploit Prediction Scoring System, "
        "Digital Threats Research and Practice, 2(3)."
    ),
    "disclaimer": (
        "This project redistributes EPSS data but is not endorsed or certified by FIRST."
    ),
}


def parse(raw_gz: bytes, fallback_date: date) -> tuple[pa.Table, date, str]:
    """gzip 圧縮された EPSS 日次 CSV を Arrow テーブルに変換する。

    3世代のフォーマットに対応:
    - コメント行なし + cve,epss (2021年初期) → model_version="v1"、日付は fallback_date
    - #model_version:...,score_date:...+0000 + cve,epss,percentile
    - #model_version:...,score_date:...Z + cve,epss,percentile
    """
    data = gzip.decompress(raw_gz)
    model_version = "v1"
    score_date = fallback_date
    if data.startswith(b"#"):
        line, _, data = data.partition(b"\n")
        meta = dict(
            kv.split(":", 1) for kv in line[1:].decode().split(",") if ":" in kv
        )
        model_version = meta.get("model_version", "v1")
        if "score_date" in meta:
            score_date = date.fromisoformat(meta["score_date"][:10])

    table = pacsv.read_csv(
        io.BytesIO(data),
        convert_options=pacsv.ConvertOptions(
            column_types={
                "cve": pa.string(),
                "epss": pa.float64(),
                "percentile": pa.float64(),
            }
        ),
    )
    n = table.num_rows
    if "percentile" not in table.column_names:
        table = table.append_column("percentile", pa.nulls(n, pa.float64()))
    table = table.append_column("date", pa.array([score_date] * n, pa.date32()))
    table = table.append_column("model_version", pa.array([model_version] * n))
    return table.select(SCHEMA.names).cast(SCHEMA), score_date, model_version


def key_for(d: date) -> str:
    return f"epss/year={d.year}/epss-{d.isoformat()}.parquet"


def year_key_for(year: int) -> str:
    """確定した過去年を集約した年ファイルのキー。"""
    return f"epss/year={year}/epss-{year}.parquet"


def write_parquet(table: pa.Table, path: Path) -> None:
    pq.write_table(table, path, compression="zstd")


def fetch(target: date | None = None) -> bytes | None:
    """日次 CSV を取得する。未公開 (404/403) なら None。"""
    url = DATED_URL.format(d=target.isoformat()) if target else CURRENT_URL
    resp = httpx.get(url, follow_redirects=True, timeout=120)
    if resp.status_code in (403, 404):
        return None
    resp.raise_for_status()
    return resp.content
