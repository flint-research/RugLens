"""Domain model and sanitization tests."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.helpers import TOKEN, make_finding, make_outcome

from ruglens.core.enums import DetectorCategory, DetectorStatus, RiskLevel, Severity
from ruglens.core.models import (
    AssessmentReport,
    Finding,
    TokenMetadata,
    compute_finding_id,
)
from ruglens.core.sanitization import sanitize_reason, sanitize_text, sanitize_token_name


def test_finding_id_is_deterministic_and_address_case_insensitive() -> None:
    first = compute_finding_id("RULE-1", TOKEN, 10)
    second = compute_finding_id("RULE-1", TOKEN.lower(), 10)
    third = compute_finding_id("RULE-1", TOKEN, 11)
    assert first == second
    assert first != third
    assert len(first) == 64


def test_finding_builder_and_confidence_bounds() -> None:
    finding = make_finding(confidence=0.9)
    assert finding.finding_id == compute_finding_id(finding.rule_id, TOKEN, 100)
    with pytest.raises(ValidationError):
        make_finding(confidence=1.5)
    with pytest.raises(ValidationError):
        Finding.create(
            rule_id="R",
            detector_id="d",
            category=DetectorCategory.STATIC,
            severity=Severity.LOW,
            confidence=0.5,
            title="t",
            description="d",
            evidence={},
            target=TOKEN,
            block_number=-1,
        )


def test_detector_outcome_forces_zero_coverage_on_failure() -> None:
    outcome = make_outcome(
        status=DetectorStatus.FAILED,
        coverage_fraction=0.9,
    )
    assert outcome.coverage_fraction == 0.0
    assert outcome.succeeded is False


def test_report_json_round_trip_is_stable() -> None:
    report = AssessmentReport(
        assessment_id=uuid4(),
        chain_id=1,
        token_address=TOKEN,
        block_number=100,
        risk_level=RiskLevel.MODERATE,
        confidence_score=0.7,
        data_coverage=0.9,
        findings=(make_finding(),),
        detector_statuses={"x": DetectorStatus.SUCCESS},
        limitations=("note",),
        token=TokenMetadata(name="Token", symbol="TKN", decimals=18, total_supply=100),
    )
    payload = report.to_json()
    parsed = AssessmentReport.from_json(payload)
    assert parsed == report
    assert parsed.timestamp.tzinfo is not None
    assert parsed.to_json() == payload


def test_naive_timestamp_is_normalized_to_utc() -> None:
    report = AssessmentReport(
        chain_id=1,
        token_address=TOKEN,
        block_number=1,
        risk_level=RiskLevel.UNKNOWN,
        confidence_score=0.0,
        data_coverage=0.0,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )
    assert report.timestamp.tzinfo is not None


def test_metadata_sanitizes_ansi_html_and_control_characters() -> None:
    metadata = TokenMetadata(
        name="\x1b[31mEvil<script>alert(1)</script>\x00 Token",
        symbol="\x1b[2JTOK\x07",
        decimals=18,
        total_supply=1,
    )
    assert "\x1b" not in metadata.name
    assert "\x00" not in metadata.name
    assert "<" not in metadata.name
    assert "Evil" in metadata.name
    assert metadata.symbol == "TOK"


def test_sanitizers_bound_lengths_and_handle_bytes() -> None:
    assert sanitize_text(b"\xffhello\x00", fallback="x") == "hello"
    assert sanitize_text("a" * 500, max_length=10) == "a" * 10
    assert sanitize_text(None, fallback="fallback") == "fallback"
    assert sanitize_token_name("") == "Unknown Token"
    assert "\x1b" not in sanitize_reason("\x1b[31mreverted\x1b[0m")
