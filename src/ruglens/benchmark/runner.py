"""Benchmark execution against a golden dataset."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ruglens.benchmark.dataset import GoldenRecord
from ruglens.benchmark.memory import peak_rss_mb
from ruglens.benchmark.metrics import BenchmarkMetrics, RecordResult, evaluate_records
from ruglens.core.exceptions import RugLensError
from ruglens.core.models import AssessmentReport
from ruglens.core.sanitization import sanitize_reason

AssessmentCallable = Callable[[GoldenRecord], Awaitable[AssessmentReport]]


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    """Metrics plus run metadata."""

    metrics: BenchmarkMetrics
    dataset_size: int
    concurrency: int
    elapsed_seconds: float

    def as_dict(self, *, include_records: bool = False) -> dict[str, Any]:
        payload = self.metrics.as_dict(include_records=include_records)
        payload["run"] = {
            "dataset_size": self.dataset_size,
            "concurrency": self.concurrency,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }
        return payload


class BenchmarkRunner:
    """Run assessments sequentially or with bounded concurrency."""

    def __init__(
        self,
        assess: AssessmentCallable,
        *,
        concurrency: int = 1,
        timeout: float = 180.0,
    ) -> None:
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._assess = assess
        self._concurrency = concurrency
        self._timeout = timeout

    async def run(
        self,
        records: Sequence[GoldenRecord],
        *,
        limit: int | None = None,
    ) -> BenchmarkReport:
        """Assess every record and compute metrics from measured outputs."""
        if limit is not None and limit <= 0:
            raise ValueError("limit must be a positive integer")
        selected = list(records[:limit] if limit is not None else records)
        if not selected:
            raise ValueError("No golden records selected")
        started = time.perf_counter()
        peak_before = peak_rss_mb()
        semaphore = asyncio.Semaphore(self._concurrency)

        async def run_one(record: GoldenRecord) -> tuple[RecordResult, AssessmentReport | None]:
            async with semaphore:
                begin = time.perf_counter()
                try:
                    report = await asyncio.wait_for(self._assess(record), timeout=self._timeout)
                except TimeoutError:
                    return (
                        RecordResult(
                            token_address=record.token_address,
                            chain_id=record.chain_id,
                            label=record.ground_truth_label,
                            risk_level=None,
                            latency_ms=(time.perf_counter() - begin) * 1000,
                            error="benchmark assessment timed out",
                        ),
                        None,
                    )
                except RugLensError as exc:
                    return (
                        RecordResult(
                            token_address=record.token_address,
                            chain_id=record.chain_id,
                            label=record.ground_truth_label,
                            risk_level=None,
                            latency_ms=(time.perf_counter() - begin) * 1000,
                            error=sanitize_reason(str(exc), max_length=300) or "assessment failed",
                        ),
                        None,
                    )
                except Exception as exc:
                    return (
                        RecordResult(
                            token_address=record.token_address,
                            chain_id=record.chain_id,
                            label=record.ground_truth_label,
                            risk_level=None,
                            latency_ms=(time.perf_counter() - begin) * 1000,
                            error=sanitize_reason(str(exc), max_length=300) or type(exc).__name__,
                        ),
                        None,
                    )
                return (
                    RecordResult(
                        token_address=record.token_address,
                        chain_id=record.chain_id,
                        label=record.ground_truth_label,
                        risk_level=report.risk_level,
                        latency_ms=(time.perf_counter() - begin) * 1000,
                    ),
                    report,
                )

        outputs = await asyncio.gather(*(run_one(record) for record in selected))
        results = [item[0] for item in outputs]
        elapsed = time.perf_counter() - started
        peak_after = peak_rss_mb()
        metrics = evaluate_records(
            selected,
            results,
            peak_rss_mb=max(peak_before, peak_after),
        )
        return BenchmarkReport(
            metrics=metrics,
            dataset_size=len(selected),
            concurrency=self._concurrency,
            elapsed_seconds=elapsed,
        )
