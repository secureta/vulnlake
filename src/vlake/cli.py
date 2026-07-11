from __future__ import annotations

from pathlib import Path

import click

from . import pipeline
from .config import Config


@click.group()
def main() -> None:
    """vlake — security datasets as a frozen DuckLake."""


@main.command()
@click.argument("dataset", type=click.Choice(["epss", "cve"]))
@click.option(
    "--date",
    "target",
    type=click.DateTime(["%Y-%m-%d"]),
    default=None,
    help="取得する日付 (epss のみ。省略時は最新)",
)
def update(dataset: str, target) -> None:
    """日次更新 (冪等)。"""
    cfg = Config.from_env()
    if dataset == "cve":
        if target is not None:
            raise click.UsageError("cve は常に最新 baseline を取得します (--date 非対応)")
        result = pipeline.update_cve(cfg)
        click.echo(result)
        if result.startswith("refused"):
            # backfill 未実施のまま日次更新だけが緑になるサイレント失敗を防ぐ
            raise SystemExit(1)
    else:
        click.echo(pipeline.update_epss(cfg, target.date() if target else None))


@main.command()
@click.argument("dataset", type=click.Choice(["epss", "cve"]))
@click.option(
    "--source",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help="epss: mirror clone ディレクトリ (必須) / cve: baseline zip ファイル (省略時は最新をダウンロード)",
)
def backfill(dataset: str, source: Path | None) -> None:
    """全履歴の一括取り込み (冪等)。"""
    cfg = Config.from_env()
    if dataset == "epss":
        if source is None or not source.is_dir():
            raise click.UsageError("epss には --source <mirror clone ディレクトリ> が必要です")
        click.echo(pipeline.backfill_epss(cfg, source))
    else:
        if source is not None and not source.is_file():
            raise click.UsageError("cve の --source は baseline zip ファイルです")
        click.echo(pipeline.backfill_cve(cfg, source))


@main.command("rebuild-catalog")
def rebuild_catalog() -> None:
    """ストレージ上の Parquet 一覧からカタログを再構築する。"""
    cfg = Config.from_env()
    click.echo(pipeline.rebuild_catalog(cfg))


@main.command()
@click.option(
    "--max-age-days",
    type=int,
    default=None,
    help="カタログの最新日がこの日数より古ければ stale として exit 1 にする",
)
def verify(max_age_days: int | None) -> None:
    """カタログとストレージの整合を検証する。"""
    cfg = Config.from_env()
    report = pipeline.verify(cfg, max_age_days=max_age_days)
    click.echo(str(report))
    if not report["ok"] or report["stale"]:
        raise SystemExit(1)
