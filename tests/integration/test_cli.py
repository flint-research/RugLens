"""CLI smoke tests (no network access)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ruglens.interfaces.cli.main import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "RugLens" in result.output


def test_detectors_command(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RUGLENS_PLUGINS_ENABLED", "false")
    result = runner.invoke(app, ["detectors", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    ids = {item["detector_id"] for item in payload["detectors"]}
    assert "bytecode_selectors" in ids
    assert "dynamic_honeypot" in ids
    assert "holder_distribution" in ids
    assert "solana_authorities" in ids
    assert "solana_clusters" in ids


def test_assess_rejects_invalid_address_without_network(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RUGLENS_PLUGINS_ENABLED", "false")
    result = runner.invoke(
        app,
        ["assess", "not-an-address", "--chain", "eth", "--no-store", "--no-sim"],
    )
    assert result.exit_code == 2
    assert "Assessment failed" in result.output


def test_assess_rejects_unknown_chain(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RUGLENS_PLUGINS_ENABLED", "false")
    result = runner.invoke(
        app,
        ["assess", "0x" + "11" * 20, "--chain", "arbitrum", "--no-store", "--no-sim"],
    )
    assert result.exit_code == 2
    assert "Unsupported chain" in result.output


def test_assess_rejects_invalid_solana_mint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RUGLENS_PLUGINS_ENABLED", "false")
    result = runner.invoke(
        app,
        ["assess", "0x" + "11" * 20, "--chain", "solana", "--no-store", "--no-sim"],
    )
    assert result.exit_code == 2
    assert "Invalid Solana public key" in result.output


def test_invalid_configuration_is_reported(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RUGLENS_API_PORT", "not-a-port")
    result = runner.invoke(
        app,
        ["assess", "0x" + "11" * 20, "--chain", "eth", "--no-store", "--no-sim"],
    )
    assert result.exit_code == 2
    assert "Invalid configuration" in result.output


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("assess", "benchmark", "detectors", "serve", "version"):
        assert command in result.output
