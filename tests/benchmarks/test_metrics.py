"""Benchmark metrics and runner tests."""

from __future__ import annotations

import pytest

from ruglens.benchmark.dataset import GoldenRecord
from ruglens.benchmark.memory import peak_rss_mb
from ruglens.benchmark.metrics import RecordResult, evaluate_records, percentile
from ruglens.benchmark.runner import BenchmarkRunner
from ruglens.core.enums import DetectorStatus, RiskLevel
from ruglens.core.exceptions import RpcError
from ruglens.core.models import AssessmentReport


def record(index: int, label: str) -> GoldenRecord:
    return GoldenRecord(
        token_address=f"0x{index:040x}",
        chain_id=1,
        deployment_block=10,
        evaluation_block=20,
        ground_truth_label=label,
        source_provenance="test",
    )


def result(record_obj: GoldenRecord, risk: RiskLevel | None, latency: float = 10.0):
    return RecordResult(
        token_address=record_obj.token_address,
        chain_id=1,
        label=record_obj.ground_truth_label,
        risk_level=risk,
        latency_ms=latency,
    )


def make_report(risk: RiskLevel) -> AssessmentReport:
    return AssessmentReport(
        chain_id=1,
        token_address=f"0x{'1' * 40}",
        block_number=10,
        risk_level=risk,
        confidence_score=0.8,
        data_coverage=0.9,
        detector_statuses={"x": DetectorStatus.SUCCESS},
    )


def test_confusion_matrix_and_rates() -> None:
    records = [
        record(1, "SCAM_HONEYPOT"),
        record(2, "SCAM_HONEYPOT"),
        record(3, "BENIGN"),
        record(4, "BENIGN"),
    ]
    results = [
        result(records[0], RiskLevel.HIGH, 10),
        result(records[1], RiskLevel.LOW, 20),
        result(records[2], RiskLevel.CRITICAL, 30),
        result(records[3], RiskLevel.LOW, 40),
    ]
    metrics = evaluate_records(records, results, peak_rss_mb=123.0)
    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (1, 1, 1, 1)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5
    assert metrics.fpr == 0.5
    assert metrics.unknown_rate == 0.0
    assert metrics.p50_latency_ms == 25.0
    assert metrics.p95_latency_ms == pytest.approx(38.5)
    assert metrics.peak_rss_mb == 123.0
    payload = metrics.as_dict()
    assert payload["confusion_matrix"]["tp"] == 1
    assert "records" not in payload


def test_unknown_and_errors_are_tracked() -> None:
    records = [record(1, "SCAM_HONEYPOT"), record(2, "BENIGN")]
    results = [
        result(records[0], RiskLevel.UNKNOWN),
        RecordResult(
            token_address=records[1].token_address,
            chain_id=1,
            label="BENIGN",
            risk_level=None,
            latency_ms=5,
            error="rpc failed",
        ),
    ]
    metrics = evaluate_records(records, results)
    assert metrics.unknown_count == 2
    assert metrics.unknown_rate == 1.0
    assert metrics.errors == 1
    assert metrics.fn == 1
    assert metrics.tn == 1
    assert metrics.fpr == 0.0


def test_percentile_edges() -> None:
    assert percentile([], 0.5) == 0.0
    assert percentile([5], 0.5) == 5.0
    assert percentile([1, 2, 3, 4, 5], 0.5) == 3.0
    assert percentile([1, 2, 3, 4, 5], 0.0) == 1.0
    with pytest.raises(ValueError):
        percentile([1], 1.5)


def test_peak_rss_is_available() -> None:
    assert peak_rss_mb() >= 0.0


@pytest.mark.asyncio
async def test_benchmark_runner_assesses_and_scores(monkeypatch) -> None:
    records = [
        record(1, "SCAM_HONEYPOT"),
        record(2, "BENIGN"),
        record(3, "BENIGN"),
    ]

    async def assess(record_obj: GoldenRecord) -> AssessmentReport:
        risk = (
            RiskLevel.HIGH
            if record_obj.token_address == records[0].token_address
            else RiskLevel.LOW
        )
        return make_report(risk)

    report = await BenchmarkRunner(assess, concurrency=2).run(records)
    assert report.metrics.sample_count == 3
    assert report.metrics.tp == 1
    assert report.metrics.fp == 0
    assert report.metrics.tn == 2
    assert report.metrics.recall == 1.0
    assert report.metrics.precision == 1.0
    assert report.metrics.p50_latency_ms >= 0.0
    assert report.as_dict()["run"]["dataset_size"] == 3


@pytest.mark.asyncio
async def test_benchmark_runner_records_assessment_errors() -> None:
    records = [record(1, "BENIGN")]

    async def assess(record_obj: GoldenRecord) -> AssessmentReport:
        raise RpcError("upstream down")

    report = await BenchmarkRunner(assess).run(records)
    assert report.metrics.errors == 1
    assert report.metrics.unknown_rate == 1.0
    assert report.metrics.record_results[0].error == "upstream down"
