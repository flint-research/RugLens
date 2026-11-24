"""Slither parser and optional source-detector tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from tests.helpers import FakeChainAdapter, make_context

from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.exceptions import DetectorError
from ruglens.core.interfaces import DetectorDependencies
from ruglens.detectors.static.slither_runner import (
    SlitherIssue,
    SlitherRunner,
    SlitherSourceDetector,
)


def test_slither_json_parser_extracts_findings() -> None:
    payload = {
        "results": {
            "detectors": [
                {
                    "check": "arbitrary-send-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Arbitrary send \x1b[31mto attacker\x1b[0m",
                    "elements": [{"name": "withdraw", "type": "function"}],
                },
                {
                    "check": "pragma",
                    "impact": "Informational",
                    "confidence": "High",
                    "description": "Floating pragma",
                    "elements": [],
                },
            ]
        }
    }
    issues = SlitherRunner._parse(json.dumps(payload).encode())
    assert len(issues) == 2
    assert issues[0].check == "arbitrary-send-eth"
    assert "\x1b" not in issues[0].description
    assert issues[0].elements[0]["name"] == "withdraw"


def test_slither_parser_rejects_non_json() -> None:
    with pytest.raises(DetectorError):
        SlitherRunner._parse(b"not json")


@pytest.mark.asyncio
async def test_slither_runner_executes_external_command(tmp_path: Path) -> None:
    script = tmp_path / "fake_slither.py"
    payload = {
        "results": {
            "detectors": [
                {
                    "check": "unprotected-upgrade",
                    "impact": "High",
                    "confidence": "High",
                    "description": "Upgrade is unprotected",
                    "elements": [],
                }
            ]
        }
    }
    script.write_text(
        f"import json\nprint(json.dumps({payload!r}))\n",
        encoding="utf-8",
    )
    runner = SlitherRunner(command=[sys.executable, str(script)], timeout=5.0)
    issues = await runner.run({"Token.sol": "contract Token {}"})
    assert [issue.check for issue in issues] == ["unprotected-upgrade"]


@pytest.mark.asyncio
async def test_slither_runner_enforces_timeout(tmp_path: Path) -> None:
    script = tmp_path / "slow_slither.py"
    script.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
    runner = SlitherRunner(command=[sys.executable, str(script)], timeout=0.3)
    with pytest.raises(DetectorError, match="timeout"):
        await runner.run({"Token.sol": "contract Token {}"})


def test_slither_safe_path_blocks_traversal(tmp_path: Path) -> None:
    assert SlitherRunner._safe_target(tmp_path, "../escape.sol") is not None
    target = SlitherRunner._safe_target(tmp_path, "../../etc/passwd")
    assert target is not None
    assert target.is_relative_to(tmp_path.resolve())
    assert SlitherRunner._safe_target(tmp_path, "") is None


class FakeRunner:
    def __init__(self, issues=None, error: Exception | None = None) -> None:
        self.issues = issues or []
        self.error = error
        self.available = True

    async def run(self, sources):
        if self.error is not None:
            raise self.error
        return self.issues


@pytest.mark.asyncio
async def test_slither_detector_maps_impacts(settings) -> None:
    enabled = settings.model_copy(update={"slither_enabled": True})
    runner = FakeRunner(
        [
            SlitherIssue(
                check="controlled-delegatecall",
                impact="High",
                confidence="Medium",
                description="Controlled delegatecall",
                elements=(),
            )
        ]
    )
    detector = SlitherSourceDetector(enabled, runner=runner)
    context = make_context().model_copy(update={"source_files": {"Token.sol": "contract Token {}"}})
    outcome = await detector.detect(context, DetectorDependencies(chain=FakeChainAdapter()))
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_area is None
    assert outcome.findings[0].rule_id == "SLITHER-CONTROLLED-DELEGATECALL"
    assert outcome.findings[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_slither_detector_skips_without_opt_in_or_sources(settings) -> None:
    detector = SlitherSourceDetector(settings, runner=FakeRunner())
    disabled = await detector.detect(make_context(), DetectorDependencies(chain=FakeChainAdapter()))
    assert disabled.status is DetectorStatus.SKIPPED
    enabled = settings.model_copy(update={"slither_enabled": True})
    no_sources = await SlitherSourceDetector(enabled, runner=FakeRunner()).detect(
        make_context(), DetectorDependencies(chain=FakeChainAdapter())
    )
    assert no_sources.status is DetectorStatus.SKIPPED


@pytest.mark.asyncio
async def test_slither_detector_reports_runner_failure(settings) -> None:
    enabled = settings.model_copy(update={"slither_enabled": True})
    detector = SlitherSourceDetector(enabled, runner=FakeRunner(error=DetectorError("boom")))
    context = make_context().model_copy(update={"source_files": {"Token.sol": "contract Token {}"}})
    outcome = await detector.detect(context, DetectorDependencies(chain=FakeChainAdapter()))
    assert outcome.status is DetectorStatus.FAILED
    assert outcome.coverage_area is None
    assert outcome.error == "boom"
