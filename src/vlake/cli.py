from __future__ import annotations

from pathlib import Path

import click

from . import pipeline
from .config import Config


@click.group()
def main() -> None:
    """vlake — security datasets as a frozen DuckLake."""


@main.command()
@click.argument(
    "dataset",
    type=click.Choice(["epss", "cve", "ghsa", "exploitdb", "nuclei", "cwe", "kev"]),
)
@click.option(
    "--date",
    "target",
    type=click.DateTime(["%Y-%m-%d"]),
    default=None,
    help="取得する日付 (epss のみ。省略時は最新)",
)
def update(dataset: str, target) -> None:
    """日次更新 (冪等)。nuclei / cwe / kev は backfill 不要 (初回 update が全量投入)。"""
    cfg = Config.from_env()
    if dataset == "epss":
        click.echo(pipeline.update_epss(cfg, target.date() if target else None))
        return
    if target is not None:
        raise click.UsageError(
            f"{dataset} は常に最新スナップショットを取得します (--date 非対応)"
        )
    updaters = {
        "cve": pipeline.update_cve,
        "ghsa": pipeline.update_ghsa,
        "exploitdb": pipeline.update_exploitdb,
        "nuclei": pipeline.update_nuclei,
        "cwe": pipeline.update_cwe,
        "kev": pipeline.update_kev,
    }
    result = updaters[dataset](cfg)
    click.echo(result)
    if result.startswith("refused"):
        # backfill 未実施のまま日次更新だけが緑になるサイレント失敗を防ぐ
        raise SystemExit(1)


@main.command()
@click.argument("dataset", type=click.Choice(["epss", "cve", "ghsa", "exploitdb"]))
@click.option(
    "--source",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "epss: mirror clone ディレクトリ (必須) / cve: baseline zip / "
        "ghsa: リポジトリ tarball / exploitdb: files_exploits.csv "
        "(cve/ghsa/exploitdb は省略時に最新をダウンロード)"
    ),
)
def backfill(dataset: str, source: Path | None) -> None:
    """全履歴の一括取り込み (冪等)。"""
    cfg = Config.from_env()
    if dataset == "epss":
        if source is None or not source.is_dir():
            raise click.UsageError(
                "epss には --source <mirror clone ディレクトリ> が必要です"
            )
        click.echo(pipeline.backfill_epss(cfg, source))
    elif dataset == "cve":
        if source is not None and not source.is_file():
            raise click.UsageError("cve の --source は baseline zip ファイルです")
        click.echo(pipeline.backfill_cve(cfg, source))
    elif dataset == "ghsa":
        if source is not None and not source.is_file():
            raise click.UsageError("ghsa の --source はリポジトリ tarball ファイルです")
        click.echo(pipeline.backfill_ghsa(cfg, source))
    else:
        if source is not None and not source.is_file():
            raise click.UsageError(
                "exploitdb の --source は files_exploits.csv ファイルです"
            )
        click.echo(pipeline.backfill_exploitdb(cfg, source))


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
