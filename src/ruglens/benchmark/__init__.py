"""Golden-dataset benchmarking and metrics."""

from __future__ import annotations

from ruglens.benchmark.dataset import (
    GoldenRecord,
    assign_family_ids,
    bytecode_family_id,
    deduplicate_by_family,
    family_split,
    group_by_family,
    load_golden_dataset,
    strip_solidity_metadata,
    temporal_family_split,
)
from ruglens.benchmark.memory import peak_rss_mb
from ruglens.benchmark.metrics import BenchmarkMetrics, RecordResult, evaluate_records, percentile
from ruglens.benchmark.runner import BenchmarkReport, BenchmarkRunner

__all__ = [
    "BenchmarkMetrics",
    "BenchmarkReport",
    "BenchmarkRunner",
    "GoldenRecord",
    "RecordResult",
    "assign_family_ids",
    "bytecode_family_id",
    "deduplicate_by_family",
    "evaluate_records",
    "family_split",
    "group_by_family",
    "load_golden_dataset",
    "peak_rss_mb",
    "percentile",
    "strip_solidity_metadata",
    "temporal_family_split",
]
