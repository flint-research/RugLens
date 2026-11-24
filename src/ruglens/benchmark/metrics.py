"""Detection metrics for benchmark runs."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ruglens.benchmark.dataset import GoldenRecord
from ruglens.core.enums import RiskLevel


def percentile(values: Sequence[float], fraction: float) -> float:
    """Linear-interpolated percentile (fraction in [0, 1])."""
    if not values:
        return 0.0
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be between 0 and 1")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


@dataclass(frozen=True, slots=True)
class RecordResult:
    """One prediction joined to its ground-truth label and latency."""

    token_address: str
    chain_id: int
    label: str
    risk_level: RiskLevel | None
    latency_ms: float
    error: str | None = None

    @property
    def is_scam(self) -> bool:
        return self.label != "BENIGN"

    @property
    def predicted_danger(self) -> bool:
        return self.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}

    @property
    def is_unknown(self) -> bool:
        return self.risk_level is RiskLevel.UNKNOWN or self.risk_level is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "token_address": self.token_address,
            "chain_id": self.chain_id,
            "label": self.label,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "predicted_danger": self.predicted_danger,
            "unknown": self.is_unknown,
            "latency_ms": round(self.latency_ms, 3),
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkMetrics:
    """Measured accuracy, reliability, latency, and memory metrics."""

    sample_count: int
    scam_count: int
    benign_count: int
    tp: int
    fp: int
    tn: int
    fn: int
    unknown_count: int
    errors: int
    precision: float
    recall: float
    f1: float
    fpr: float
    unknown_rate: float
    p50_latency_ms: float
    p95_latency_ms: float
    peak_rss_mb: float
    record_results: tuple[RecordResult, ...] = field(repr=False)

    def as_dict(self, *, include_records: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "sample_count": self.sample_count,
            "scam_count": self.scam_count,
            "benign_count": self.benign_count,
            "confusion_matrix": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
            "fpr": round(self.fpr, 6),
            "unknown_count": self.unknown_count,
            "unknown_rate": round(self.unknown_rate, 6),
            "errors": self.errors,
            "latency_ms": {
                "p50": round(self.p50_latency_ms, 3),
                "p95": round(self.p95_latency_ms, 3),
            },
            "peak_rss_mb": round(self.peak_rss_mb, 3),
        }
        if include_records:
            payload["records"] = [result.as_dict() for result in self.record_results]
        return payload


def evaluate_records(
    records: Sequence[GoldenRecord],
    results: Sequence[RecordResult],
    *,
    peak_rss_mb: float = 0.0,
) -> BenchmarkMetrics:
    """Join labels to predictions and compute benchmark metrics.

    A token is predicted dangerous only when the final risk level is CRITICAL or
    HIGH. UNKNOWN is treated as not-flagged for precision/recall/FPR and is also
    reported separately via the unknown rate.
    """
    if len(records) != len(results):
        raise ValueError("records and results must have the same length")
    tp = fp = tn = fn = unknown = errors = 0
    scam_count = benign_count = 0
    latencies: list[float] = []
    for record, result in zip(records, results, strict=True):
        if record.token_address != result.token_address:
            raise ValueError("record/result address mismatch")
        latencies.append(result.latency_ms)
        if result.error:
            errors += 1
        if record.is_scam:
            scam_count += 1
        else:
            benign_count += 1
        if result.is_unknown:
            unknown += 1
        if record.is_scam:
            if result.predicted_danger:
                tp += 1
            else:
                fn += 1
        elif result.predicted_danger:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    count = len(records)
    return BenchmarkMetrics(
        sample_count=count,
        scam_count=scam_count,
        benign_count=benign_count,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        unknown_count=unknown,
        errors=errors,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        unknown_rate=unknown / count if count else 0.0,
        p50_latency_ms=percentile(latencies, 0.50),
        p95_latency_ms=percentile(latencies, 0.95),
        peak_rss_mb=peak_rss_mb,
        record_results=tuple(results),
    )
