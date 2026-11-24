"""SDK tests for local and HTTP clients."""

from __future__ import annotations

import httpx
import pytest
from tests.helpers import TOKEN, make_finding

from ruglens.core.enums import DetectorStatus, RiskLevel, Severity
from ruglens.core.exceptions import RugLensError
from ruglens.core.models import AssessmentReport
from ruglens.interfaces.sdk import HttpRugLensClient, RugLensClient


class FakeSdkEngine:
    def __init__(self) -> None:
        self.closed = False

    async def assess_token(self, chain_id: int, address: str, block_number=None, **kwargs):
        return make_report(chain_id, block_number or 10)

    async def get_report(self, assessment_id: str):
        return None

    async def close(self) -> None:
        self.closed = True


def make_report(chain_id: int = 1, block: int = 10) -> AssessmentReport:
    return AssessmentReport(
        chain_id=chain_id,
        token_address=TOKEN,
        block_number=block,
        risk_level=RiskLevel.HIGH,
        confidence_score=0.9,
        data_coverage=0.85,
        findings=(make_finding(severity=Severity.HIGH),),
        detector_statuses={"x": DetectorStatus.SUCCESS},
        limitations=(),
    )


@pytest.mark.asyncio
async def test_local_sdk_uses_injected_engine() -> None:
    engine = FakeSdkEngine()
    async with RugLensClient(engine=engine) as client:
        report = await client.assess("eth", TOKEN, 55)
        assert report.chain_id == 1
        assert report.block_number == 55
        assert await client.get_report("00000000-0000-0000-0000-000000000000") is None
    assert engine.closed is False


@pytest.mark.asyncio
async def test_local_sdk_resolves_solana_selector() -> None:
    calls: list[tuple[int, str]] = []

    class _Engine:
        async def assess_token(self, chain_id, address, block_number=None, **kwargs):
            calls.append((chain_id, address))
            return make_report(chain_id, block_number or 1)

        async def get_report(self, assessment_id):
            return None

    client = RugLensClient(engine=_Engine())  # type: ignore[arg-type]
    report = await client.assess("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    assert report.chain_id == 101
    assert calls == [(101, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")]


@pytest.mark.asyncio
async def test_http_sdk_parses_report_and_handles_errors() -> None:
    report = make_report()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/assess":
            return httpx.Response(200, json=report.model_dump(mode="json"))
        if request.url.path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/detectors":
            return httpx.Response(200, json={"detectors": [{"detector_id": "x"}]})
        return httpx.Response(404, json={"detail": "missing"})

    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://test")
    sdk = HttpRugLensClient("http://test", client=http_client)
    result = await sdk.assess("eth", TOKEN, 10)
    assert result == report
    assert (await sdk.health())["status"] == "ok"
    assert (await sdk.detectors())[0]["detector_id"] == "x"
    await sdk.close()  # injected client is not closed


@pytest.mark.asyncio
async def test_http_sdk_raises_on_error_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "Custom RPC URLs are disabled"})

    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://test")
    sdk = HttpRugLensClient("http://test", client=http_client)
    with pytest.raises(RugLensError, match="disabled"):
        await sdk.assess("eth", TOKEN)
    await sdk.close()
