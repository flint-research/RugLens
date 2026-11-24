"""Static bytecode detector tests."""

from __future__ import annotations

import pytest
from tests.helpers import FakeChainAdapter, make_context

from ruglens.chains.evm.abi import selector
from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.interfaces import DetectorDependencies
from ruglens.detectors.static.bytecode_rules import BytecodeSelectorDetector


def dispatch(signature: str) -> bytes:
    return b"\x63" + selector(signature) + b"\x14"


@pytest.mark.asyncio
async def test_static_detector_emits_group_and_opcode_findings(settings) -> None:
    detector = BytecodeSelectorDetector(settings)
    bytecode = (
        dispatch("mint(address,uint256)") + dispatch("setMaxTxAmount(uint256)") + b"\xf4\xff\x00"
    )
    context = make_context(bytecode=bytecode)
    outcome = await detector.detect(context, DetectorDependencies(chain=FakeChainAdapter()))
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_fraction == 1.0
    rules = {finding.rule_id for finding in outcome.findings}
    assert "STATIC-MINT-001" in rules
    assert "STATIC-LIMITS-001" in rules
    assert "STATIC-SELFDESTRUCT-001" in rules
    assert "STATIC-DELEGATECALL-001" in rules
    mint = next(f for f in outcome.findings if f.rule_id == "STATIC-MINT-001")
    assert mint.severity is Severity.MEDIUM
    assert mint.evidence["selectors"][0]["signature"] == "mint(address,uint256)"


@pytest.mark.asyncio
async def test_static_detector_fails_without_bytecode(settings) -> None:
    detector = BytecodeSelectorDetector(settings)
    outcome = await detector.detect(
        make_context(bytecode=b""), DetectorDependencies(chain=FakeChainAdapter())
    )
    assert outcome.status is DetectorStatus.FAILED
    assert outcome.coverage_fraction == 0.0


@pytest.mark.asyncio
async def test_static_detector_clean_bytecode_has_no_findings(settings) -> None:
    detector = BytecodeSelectorDetector(settings)
    outcome = await detector.detect(
        make_context(bytecode=bytes.fromhex("6080604052348015600f57600080fd5b50")),
        DetectorDependencies(chain=FakeChainAdapter()),
    )
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.findings == ()
