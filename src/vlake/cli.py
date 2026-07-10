from __future__ import annotations

from pathlib import Path

import click

from . import pipeline
from .config import Config


@click.group()
def main() -> None:
    """vlake — security datasets as a frozen DuckLake."""


@main.command()
@click.argument("dataset", type=click.Choice(["epss"]))
@click.option("--date", "target", type=click.DateTime(["%Y-%m-%d"]), default=None,
              help="取得する日付 (省略時は最新)")
def update(dataset: str, target) -> None:
    """日次更新 (冪等)。"""
    cfg = Config.from_env()
    click.echo(pipeline.update_epss(cfg, target.date() if target else None))


@main.command()
@click.argument("dataset", type=click.Choice(["epss"]))
@click.option("--source", required=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="empiricalsec/epss_scores の clone ディレクトリ")
def backfill(dataset: str, source: Path) -> None:
    """全履歴の一括取り込み (冪等)。"""
    cfg = Config.from_env()
    click.echo(pipeline.backfill_epss(cfg, source))


@main.command("rebuild-catalog")
def rebuild_catalog() -> None:
    """ストレージ上の Parquet 一覧からカタログを再構築する。"""
    cfg = Config.from_env()
    click.echo(pipeline.rebuild_catalog(cfg))


@main.command()
@click.option("--max-age-days", type=int, default=None,
              help="カタログの最新日がこの日数より古ければ stale として exit 1 にする")
def verify(max_age_days: int | None) -> None:
    """カタログとストレージの整合を検証する。"""
    cfg = Config.from_env()
    report = pipeline.verify(cfg, max_age_days=max_age_days)
    click.echo(str(report))
    if not report["ok"] or report["stale"]:
        raise SystemExit(1)
