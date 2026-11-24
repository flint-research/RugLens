"""Optional, isolated Slither subprocess integration.

Slither is AGPL-3.0 licensed. It is never imported into the RugLens process and
is invoked only as an opt-in external CLI with a hard timeout, output cap, and
best-effort process-tree termination.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import DetectorError
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, TokenContext
from ruglens.core.sanitization import sanitize_reason, sanitize_text

logger = logging.getLogger(__name__)

_MAX_OUTPUT_BYTES = 5_000_000
_MAX_STDERR_BYTES = 64_000
_MAX_SOURCE_BYTES = 2_000_000
_MAX_FILES = 50

_resource_import: Any = None
try:  # POSIX only; imported before fork so preexec_fn stays import-free.
    import resource as _resource_module

    _resource_import = _resource_module
except ImportError:  # pragma: no cover - Windows
    pass
_RESOURCE: Any = cast(Any, _resource_import)


@dataclass(frozen=True, slots=True)
class SlitherIssue:
    """A normalized Slither detector result."""

    check: str
    impact: str
    confidence: str
    description: str
    elements: tuple[dict[str, Any], ...]


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise DetectorError(f"Slither output exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _limit_resources() -> None:  # pragma: no cover - POSIX only
    if _RESOURCE is None:
        return
    try:
        _RESOURCE.setrlimit(
            _RESOURCE.RLIMIT_AS,
            (512 * 1024 * 1024, 512 * 1024 * 1024),
        )
        _RESOURCE.setrlimit(_RESOURCE.RLIMIT_CPU, (20, 20))
    except (AttributeError, OSError, ValueError):
        pass


class SlitherRunner:
    """Run Slither against a bounded, sanitized source tree."""

    def __init__(
        self,
        *,
        binary: str = "slither",
        timeout: float = 15.0,
        extra_args: Sequence[str] = (),
        command: Sequence[str] | None = None,
    ) -> None:
        self._binary = binary
        self._timeout = timeout
        self._extra_args = tuple(extra_args)
        self._command = tuple(command) if command else (binary,)

    @property
    def available(self) -> bool:
        """Whether the Slither executable is installed."""
        executable = self._command[0]
        if Path(executable).is_file():
            return True
        return shutil.which(executable) is not None

    async def run(self, sources: Mapping[str, str]) -> list[SlitherIssue]:
        """Execute Slither and parse its JSON detector output."""
        if not self.available:
            raise DetectorError(
                f"Slither executable {self._binary!r} not found; install slither-analyzer "
                "separately and opt in with RUGLENS_SLITHER_ENABLED=true."
            )
        if not sources:
            return []
        if len(sources) > _MAX_FILES:
            raise DetectorError(f"Too many source files (max {_MAX_FILES})")
        work_dir = Path(tempfile.mkdtemp(prefix="ruglens-slither-"))
        try:
            total = 0
            for name, content in sources.items():
                if len(content.encode("utf-8", errors="ignore")) > _MAX_SOURCE_BYTES:
                    raise DetectorError(f"Source file {name!r} is too large")
                total += len(content)
                if total > _MAX_SOURCE_BYTES * 2:
                    raise DetectorError("Combined Solidity source is too large")
                target = self._safe_target(work_dir, name)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", errors="replace")
            command = [*self._command, ".", "--json", "-", *self._extra_args]
            return await self._execute(command, work_dir)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    @staticmethod
    def _safe_target(work_dir: Path, name: str) -> Path | None:
        relative = PurePosixPath(name.replace("\\", "/"))
        parts = [
            part
            for part in relative.parts
            if part not in {"", ".", ".."} and not part.startswith("/")
        ]
        if not parts:
            return None
        target = work_dir.joinpath(*parts).resolve()
        try:
            target.relative_to(work_dir.resolve())
        except ValueError:
            return None
        return target

    async def _execute(self, command: Sequence[str], work_dir: Path) -> list[SlitherIssue]:
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.__dict__.get("CREATE_NEW_PROCESS_GROUP", 0)
        else:
            kwargs["preexec_fn"] = _limit_resources
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(work_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(_read_limited(process.stdout, _MAX_OUTPUT_BYTES))
        stderr_task = asyncio.create_task(_read_limited(process.stderr, _MAX_STDERR_BYTES))
        try:
            try:
                stdout, _ = await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task),
                    timeout=self._timeout,
                )
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except TimeoutError as exc:
                raise DetectorError(f"Slither exceeded the {self._timeout:.0f}s timeout") from exc
            finally:
                await self._terminate(process)
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        if process.returncode not in (0, 255):
            raise DetectorError(f"Slither exited with code {process.returncode}")
        return self._parse(stdout)

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            if os.name == "nt":
                killer = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/F",
                    "/T",
                    "/PID",
                    str(process.pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
            else:
                process.kill()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=3.0)

    @staticmethod
    def _parse(stdout: bytes) -> list[SlitherIssue]:
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return []
        start = text.find("{")
        if start < 0:
            raise DetectorError("Slither produced no JSON object")
        try:
            payload = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise DetectorError(f"Could not parse Slither JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise DetectorError("Slither JSON root is not an object")
        results = payload.get("results")
        if not isinstance(results, dict):
            return []
        detectors = results.get("detectors")
        if not isinstance(detectors, list):
            return []
        issues: list[SlitherIssue] = []
        for item in detectors:
            if not isinstance(item, dict):
                continue
            check = sanitize_text(item.get("check", "unknown"), max_length=80)
            impact = sanitize_text(item.get("impact", "Informational"), max_length=32)
            confidence = sanitize_text(item.get("confidence", "Low"), max_length=32)
            description = sanitize_reason(item.get("description", ""), max_length=600)
            raw_elements = item.get("elements", [])
            elements: list[dict[str, Any]] = []
            if isinstance(raw_elements, list):
                for element in raw_elements[:5]:
                    if isinstance(element, dict):
                        elements.append(
                            {
                                "name": sanitize_text(element.get("name", ""), max_length=120),
                                "type": sanitize_text(element.get("type", ""), max_length=60),
                                "source_mapping": element.get("source_mapping", {}),
                            }
                        )
            issues.append(
                SlitherIssue(
                    check=check,
                    impact=impact,
                    confidence=confidence,
                    description=description,
                    elements=tuple(elements),
                )
            )
        return issues[:64]


_IMPACT_SEVERITY: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "optimization": Severity.INFO,
}


class SlitherSourceDetector(BaseDetector):
    """Optional source-AST findings from an isolated Slither subprocess."""

    detector_id = "slither_source"
    category = DetectorCategory.SOURCE
    coverage_area = None
    description = "Optional isolated Slither CLI over caller-supplied verified Solidity sources."
    required = False

    def __init__(
        self,
        settings: RugLensSettings,
        runner: SlitherRunner | None = None,
    ) -> None:
        super().__init__(settings)
        self._runner = runner or SlitherRunner(
            binary=settings.slither_binary,
            timeout=settings.slither_timeout,
        )

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        if not self.settings.slither_enabled:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                error="Slither source analysis is disabled",
                duration_ms=elapsed(),
            )
        if not context.source_files:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                error="No verified Solidity source files were supplied",
                duration_ms=elapsed(),
            )
        if not self._runner.available:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                error="Slither executable is not installed",
                duration_ms=elapsed(),
            )
        try:
            issues = await self._runner.run(context.source_files)
        except DetectorError as exc:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error=str(exc),
                duration_ms=elapsed(),
            )
        findings = [
            Finding.create(
                rule_id=f"SLITHER-{issue.check.upper().replace(' ', '-')}",
                detector_id=self.detector_id,
                category=DetectorCategory.SOURCE,
                severity=_IMPACT_SEVERITY.get(issue.impact.lower(), Severity.LOW),
                confidence=0.7,
                title=f"Slither: {issue.check}",
                description=issue.description or f"Slither reported {issue.check}.",
                evidence={
                    "check": issue.check,
                    "impact": issue.impact,
                    "slither_confidence": issue.confidence,
                    "elements": list(issue.elements),
                },
                target=context.token_address,
                block_number=context.block_number,
            )
            for issue in issues
        ]
        return self.make_outcome(
            findings=findings,
            limitations=(
                "Source analysis is supplementary; bytecode and simulation remain authoritative.",
            ),
            details={"issue_count": len(issues)},
            duration_ms=elapsed(),
        )
