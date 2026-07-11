from datetime import date

import pyarrow.parquet as pq

from tests.conftest import make_epss_csv_gz
from vlake import epss


def test_parse_current_format():
    raw = make_epss_csv_gz(
        date(2026, 7, 10),
        [("CVE-1999-0001", 0.03351, 0.87263), ("CVE-2021-44228", 0.97565, 0.99999)],
    )
    table, score_date, mv = epss.parse(raw, fallback_date=date(2000, 1, 1))
    assert score_date == date(2026, 7, 10)  # コメント行優先、fallback は無視
    assert mv == "v2026.06.15"
    assert table.schema.equals(epss.SCHEMA)
    assert table.num_rows == 2
    d = table.to_pylist()[1]
    assert d == {
        "cve": "CVE-2021-44228",
        "epss": 0.97565,
        "percentile": 0.99999,
        "date": date(2026, 7, 10),
        "model_version": "v2026.06.15",
    }


def test_parse_v3_format_offset_timestamp():
    raw = make_epss_csv_gz(
        date(2023, 6, 1),
        [("CVE-2020-5902", 0.97, 0.999)],
        model_version="v2023.03.01",
        date_suffix="T00:00:00+0000",
    )
    _, score_date, mv = epss.parse(raw, fallback_date=date(2000, 1, 1))
    assert score_date == date(2023, 6, 1)
    assert mv == "v2023.03.01"


def test_parse_v1_no_comment_no_percentile():
    raw = make_epss_csv_gz(
        date(2021, 4, 14),
        [("CVE-2020-5902", 0.65117), ("CVE-2018-19571", 0.04773)],
        with_comment=False,
        with_percentile=False,
    )
    table, score_date, mv = epss.parse(raw, fallback_date=date(2021, 4, 14))
    assert score_date == date(2021, 4, 14)  # fallback (ファイル名由来) を採用
    assert mv == "v1"
    assert table.schema.equals(epss.SCHEMA)
    assert table.column("percentile").null_count == 2


def test_key_for():
    assert epss.key_for(date(2021, 4, 14)) == "epss/year=2021/epss-2021-04-14.parquet"


def test_write_parquet_roundtrip(tmp_path):
    raw = make_epss_csv_gz(date(2026, 7, 10), [("CVE-1999-0001", 0.1, 0.5)])
    table, _, _ = epss.parse(raw, fallback_date=date(2026, 7, 10))
    out = tmp_path / "day.parquet"
    epss.write_parquet(table, out)
    back = pq.read_table(out)
    assert back.schema.equals(epss.SCHEMA)
    assert back.num_rows == 1


def test_year_key_for():
    assert epss.year_key_for(2021) == "epss/year=2021/epss-2021.parquet"


def test_license_info_complete():
    for key in (
        "name",
        "source_url",
        "license_name",
        "license_text",
        "attribution",
        "disclaimer",
    ):
        assert epss.LICENSE_INFO[key]
    assert "not endorsed or certified by FIRST" in epss.LICENSE_INFO["disclaimer"]
