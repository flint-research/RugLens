"""RugLens command-line interface (Typer + Rich)."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ruglens import __version__
from ruglens.chains.registry import chain_display_name, is_solana_chain, resolve_chain_selector
from ruglens.core.config import RugLensSettings
from ruglens.core.enums import RiskLevel
from ruglens.core.exceptions import RugLensError, ValidationError
from ruglens.core.models import AssessmentReport
from ruglens.detectors.registry import build_registry
from ruglens.detectors.solana import solana_detector_descriptors
from ruglens.interfaces.cli.benchmark_cmd import benchmark
from ruglens.orchestrator.engine import AssessmentEngine

app = typer.Typer(
    name="ruglens",
    help="Evidence-driven EVM and Solana token rug-pull and risk detection.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

_RISK_STYLE: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MODERATE: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.UNKNOWN: "cyan",
}


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _load_sources(source_dir: Path | None) -> dict[str, str]:
    if source_dir is None:
        return {}
    directory = source_dir.expanduser().resolve()
    if not directory.is_dir():
        raise ValidationError(f"Source directory does not exist: {source_dir}")
    files: dict[str, str] = {}
    total = 0
    for path in sorted(directory.rglob("*.sol")):
        if len(files) >= 50:
            raise ValidationError("At most 50 Solidity source files are supported")
        content = path.read_text(encoding="utf-8", errors="replace")
        total += len(content.encode("utf-8", errors="ignore"))
        if total > 2_000_000:
            raise ValidationError("Solidity sources exceed the 2 MB limit")
        files[path.relative_to(directory).as_posix()] = content
    if not files:
        raise ValidationError(f"No .sol files found under {source_dir}")
    return files


_METRIC_ORDER = (
    "creator_holdings_pct",
    "top1_holder_pct",
    "top10_holder_pct",
    "largest_cluster_share_pct",
    "cluster_probability",
    "largest_cluster_size",
    "cluster_creator_linked",
    "program_controlled_pct",
    "burned_pct",
    "mint_authority_active",
    "freeze_authority_active",
    "metadata_mutable",
    "liquidity_custody_pct",
    "liquidity_depth_verified",
    "lp_lock_verified",
    "token_program",
    "creator",
    "creator_source",
)


def _render_metrics(metrics: dict[str, object]) -> None:
    rows = [(key, metrics[key]) for key in _METRIC_ORDER if key in metrics]
    if not rows:
        return
    table = Table(title="Key metrics", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    for key, value in rows:
        if isinstance(value, float) and key == "cluster_probability":
            formatted = f"{value:.1%}"
        elif isinstance(value, float) and key.endswith("_pct"):
            formatted = f"{value:.2f}%"
        elif isinstance(value, bool):
            formatted = "yes" if value else "no"
        elif value is None:
            formatted = "-"
        else:
            formatted = escape(str(value))
        table.add_row(escape(key), formatted)
    console.print(table)


def _render_report(report: AssessmentReport) -> None:
    token = report.token
    display = f"{token.symbol} - {token.name}" if token else "Unknown token"
    style = _RISK_STYLE[report.risk_level]
    header = Table.grid(padding=(0, 1))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Token", escape(display))
    header.add_row("Address", report.token_address)
    header.add_row("Chain", chain_display_name(report.chain_id))
    header.add_row(
        "Slot" if is_solana_chain(report.chain_id) else "Block",
        f"{report.block_number:,}",
    )
    header.add_row("Risk", f"[{style}]{report.risk_level.value}[/{style}]")
    header.add_row(
        "Confidence",
        f"{report.confidence_score:.1%}",
    )
    header.add_row(
        "Data coverage",
        f"{report.data_coverage:.1%}",
    )
    header.add_row("Assessment", str(report.assessment_id))
    header.add_row("Duration", f"{report.duration_ms:,.0f} ms")
    header.add_row("RPC calls", f"{report.rpc_calls:,}")
    console.print(Panel(header, title="[bold]RugLens Assessment[/bold]", expand=False))

    if report.metrics:
        _render_metrics(report.metrics)

    if report.findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Rule", overflow="fold")
        table.add_column("Finding", overflow="fold")
        table.add_column("Conf.", justify="right")
        for finding in report.findings:
            severity_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "cyan",
            }.get(finding.severity.value, "white")
            table.add_row(
                f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
                escape(finding.rule_id),
                escape(finding.title),
                f"{finding.confidence:.0%}",
            )
        console.print(table)
    else:
        console.print("[green]No evidence-backed findings were emitted.[/green]")

    status_table = Table(title="Detectors", show_header=True)
    status_table.add_column("Detector")
    status_table.add_column("Status")
    for detector_id, status in sorted(report.detector_statuses.items()):
        status_style = "green" if status.value == "SUCCESS" else "yellow"
        status_table.add_row(
            escape(detector_id), f"[{status_style}]{status.value}[/{status_style}]"
        )
    console.print(status_table)

    if report.limitations:
        lines = "\n".join(f"- {escape(item)}" for item in report.limitations)
        console.print(Panel(lines, title="Limitations & evidence gaps", border_style="yellow"))
    console.print(f"[dim]{escape(report.summary)}[/dim]")


@app.command("assess")
def assess(
    address: Annotated[str, typer.Argument(help="ERC-20 contract address or Solana mint address")],
    chain: Annotated[
        str,
        typer.Option("--chain", "-c", help="eth, bsc, base, solana, or numeric chain id"),
    ] = "eth",
    rpc: Annotated[
        list[str] | None,
        typer.Option(
            "--rpc", help="RPC URL; repeat for failover. Defaults to env/public endpoints."
        ),
    ] = None,
    block: Annotated[
        int | None,
        typer.Option(
            "--block",
            "-b",
            help="Pin an EVM assessment to a block (Solana V1 records the observed slot)",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the canonical AssessmentReport JSON"),
    ] = False,
    no_simulation: Annotated[
        bool,
        typer.Option("--no-sim", help="Skip Anvil trade simulation (reduces coverage)"),
    ] = False,
    no_store: Annotated[
        bool,
        typer.Option("--no-store", help="Do not read or write the local report database"),
    ] = False,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Ignore a cached block-pinned report"),
    ] = False,
    source_dir: Annotated[
        Path | None,
        typer.Option("--source-dir", help="Optional verified Solidity sources for Slither"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON output to a file"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug logging"),
    ] = False,
) -> None:
    """Assess a token end-to-end using static, dynamic, and on-chain evidence."""
    try:
        settings = RugLensSettings.from_env(
            {
                "simulation_enabled": not no_simulation,
                "persist_reports": not no_store,
                "load_cached_reports": not refresh,
                "slither_enabled": bool(source_dir),
                "log_level": "DEBUG" if verbose else "INFO",
            }
        )
    except (PydanticValidationError, RugLensError) as exc:
        error_console.print(f"[bold red]Invalid configuration:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    _configure_logging(settings.log_level)

    async def run() -> AssessmentReport:
        sources = _load_sources(source_dir)
        selected_chain_id = resolve_chain_selector(chain)
        async with await AssessmentEngine.build(
            settings,
            enable_repository=not no_store,
        ) as engine:
            return await engine.assess_token(
                selected_chain_id,
                address,
                block,
                rpc_urls=tuple(rpc) if rpc else None,
                source_files=sources or None,
                use_cached_report=not refresh,
            )

    try:
        report = asyncio.run(run())
    except RugLensError as exc:
        error_console.print(f"[bold red]Assessment failed:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except KeyboardInterrupt as exc:
        error_console.print("[yellow]Interrupted[/yellow]")
        raise typer.Exit(code=130) from exc

    if json_output or output is not None:
        payload = report.to_json()
        if output is not None:
            try:
                output.expanduser().write_text(payload + "\n", encoding="utf-8")
            except OSError as exc:
                error_console.print(f"[bold red]Could not write {output}:[/bold red] {exc}")
                raise typer.Exit(code=1) from exc
            console.print(f"[green]Report written to[/green] {output}")
        if json_output:
            typer.echo(payload)
        if not json_output and output is not None:
            _render_report(report)
    else:
        _render_report(report)


@app.command("detectors")
def detectors(
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit detector metadata JSON")
    ] = False,
) -> None:
    """List built-in and plugin detectors."""
    settings = RugLensSettings.from_env({"log_level": "DEBUG" if verbose else "INFO"})
    _configure_logging(settings.log_level)
    registry = build_registry(settings)
    descriptors = registry.descriptors() + solana_detector_descriptors(settings)
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "detectors": [descriptor.as_dict() for descriptor in descriptors],
                    "plugin_errors": list(registry.plugin_errors),
                },
                indent=2,
            )
        )
        return
    table = Table(title="Registered detectors")
    table.add_column("Detector", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Required", no_wrap=True)
    table.add_column("Coverage area", no_wrap=True)
    table.add_column("Family", no_wrap=True)
    table.add_column("Origin", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for descriptor in descriptors:
        table.add_row(
            descriptor.detector_id,
            descriptor.category.value,
            "yes" if descriptor.required else "no",
            descriptor.coverage_area.value if descriptor.coverage_area else "-",
            descriptor.chain_family,
            descriptor.origin,
            escape(descriptor.description),
        )
    console.print(table)
    for error in registry.plugin_errors:
        error_console.print(f"[yellow]Plugin warning:[/yellow] {escape(error)}")


@app.command("serve")
def serve(
    host: Annotated[str | None, typer.Option("--host", help="Bind address")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Bind port")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run the FastAPI service locally."""
    try:
        settings = RugLensSettings.from_env(
            {
                "api_host": host or "127.0.0.1",
                "api_port": port or 8000,
                "log_level": "DEBUG" if verbose else "INFO",
            }
        )
    except (PydanticValidationError, RugLensError) as exc:
        error_console.print(f"[bold red]Invalid configuration:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    _configure_logging(settings.log_level)
    try:
        import uvicorn

        from ruglens.interfaces.api.app import create_app
    except ImportError as exc:  # pragma: no cover - FastAPI is a hard dependency
        error_console.print(f"[red]API dependencies are unavailable: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
    )


app.command("benchmark")(benchmark)


@app.command("version")
def version() -> None:
    """Print the engine version."""
    console.print(f"RugLens {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
