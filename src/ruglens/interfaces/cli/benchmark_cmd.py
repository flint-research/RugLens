"""Benchmark command integration for the CLI."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ruglens.benchmark.dataset import GoldenRecord, load_golden_dataset
from ruglens.benchmark.runner import BenchmarkReport, BenchmarkRunner
from ruglens.chains.registry import is_solana_chain
from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import RugLensError
from ruglens.core.models import AssessmentReport
from ruglens.orchestrator.engine import AssessmentEngine

console = Console()
error_console = Console(stderr=True)


def benchmark(
    dataset: Annotated[Path, typer.Option("--dataset", "-d", help="Golden JSONL dataset")],
    rpc: Annotated[
        list[str] | None,
        typer.Option("--rpc", help="RPC URL; repeat for failover"),
    ] = None,
    limit: Annotated[
        int | None, typer.Option("--limit", help="Assess only the first N records")
    ] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", help="Concurrent assessments")] = 1,
    no_simulation: Annotated[
        bool, typer.Option("--no-sim", help="Disable Anvil simulation")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit full benchmark JSON")] = False,
    include_records: Annotated[
        bool,
        typer.Option("--include-records", help="Include per-record predictions in JSON"),
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write JSON results")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run a reproducible benchmark over a labeled golden dataset."""
    try:
        settings = RugLensSettings.from_env(
            {
                "simulation_enabled": not no_simulation,
                "persist_reports": False,
                "load_cached_reports": False,
                "log_level": "DEBUG" if verbose else "INFO",
            }
        )
    except (PydanticValidationError, RugLensError) as exc:
        error_console.print(f"[bold red]Invalid configuration:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        records = load_golden_dataset(dataset)
    except ValueError as exc:
        error_console.print(f"[bold red]Dataset error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    async def run() -> BenchmarkReport:
        async with await AssessmentEngine.build(settings, enable_repository=False) as engine:

            async def assess(record: GoldenRecord) -> AssessmentReport:
                return await engine.assess_token(
                    record.chain_id,
                    record.token_address,
                    None if is_solana_chain(record.chain_id) else record.evaluation_block,
                    rpc_urls=tuple(rpc) if rpc else None,
                    use_cached_report=False,
                )

            runner = BenchmarkRunner(assess, concurrency=concurrency)
            return await runner.run(records, limit=limit)

    try:
        report = asyncio.run(run())
    except RugLensError as exc:
        error_console.print(f"[bold red]Benchmark failed:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        error_console.print(f"[bold red]Benchmark rejected:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    metrics = report.metrics
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Samples", str(metrics.sample_count))
    summary.add_row("Scam / benign", f"{metrics.scam_count} / {metrics.benign_count}")
    summary.add_row("Precision", f"{metrics.precision:.1%}")
    summary.add_row("Recall", f"{metrics.recall:.1%}")
    summary.add_row("F1", f"{metrics.f1:.1%}")
    summary.add_row("False positive rate", f"{metrics.fpr:.1%}")
    summary.add_row("Unknown rate", f"{metrics.unknown_rate:.1%}")
    summary.add_row("Errors", str(metrics.errors))
    summary.add_row(
        "P50 / P95 latency", f"{metrics.p50_latency_ms:,.0f} / {metrics.p95_latency_ms:,.0f} ms"
    )
    summary.add_row("Peak RSS", f"{metrics.peak_rss_mb:,.1f} MiB")
    summary.add_row("Elapsed", f"{report.elapsed_seconds:,.1f} s")
    console.print(Panel(summary, title="[bold]RugLens Benchmark[/bold]", expand=False))

    payload = json.dumps(report.as_dict(include_records=include_records), indent=2)
    if output is not None:
        try:
            output.expanduser().write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            error_console.print(f"[bold red]Could not write {output}:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Benchmark written to[/green] {output}")
    if json_output:
        typer.echo(payload)
