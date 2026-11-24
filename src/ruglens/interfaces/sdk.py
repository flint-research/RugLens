"""Async Python SDK for local and hosted RugLens deployments."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import RugLensError, ValidationError
from ruglens.core.models import AssessmentReport
from ruglens.core.sanitization import sanitize_reason, sanitize_text
from ruglens.orchestrator.engine import AssessmentEngine


class RugLensClient:
    """In-process async client with no auth, tenant, or billing state."""

    def __init__(
        self,
        settings: RugLensSettings | None = None,
        *,
        engine: AssessmentEngine | None = None,
        enable_repository: bool = True,
    ) -> None:
        self._settings = settings
        self._engine = engine
        self._owns_engine = engine is None
        self._enable_repository = enable_repository

    async def __aenter__(self) -> RugLensClient:
        if self._engine is None:
            self._engine = await AssessmentEngine.build(
                self._settings,
                enable_repository=self._enable_repository,
            )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    @property
    def engine(self) -> AssessmentEngine:
        """The initialized engine."""
        if self._engine is None:
            raise RugLensError("Client is not initialized; use 'async with RugLensClient(...)'")
        return self._engine

    async def assess(
        self,
        chain: int | str,
        address: str,
        block_number: int | None = None,
        *,
        rpc_urls: Sequence[str] | None = None,
        source_files: Mapping[str, str] | None = None,
        use_cached_report: bool = True,
    ) -> AssessmentReport:
        """Assess a token in-process."""
        if self._engine is None:
            await self.__aenter__()
        return await self.engine.assess_token(
            int(chain) if isinstance(chain, int) else _chain_id(chain),
            address,
            block_number,
            rpc_urls=rpc_urls,
            source_files=source_files,
            use_cached_report=use_cached_report,
        )

    async def get_report(self, assessment_id: str) -> AssessmentReport | None:
        """Retrieve a persisted report."""
        return await self.engine.get_report(assessment_id)

    async def close(self) -> None:
        """Close an owned engine."""
        if self._engine is not None and self._owns_engine:
            await self._engine.close()
            self._engine = None


class HttpRugLensClient:
    """Async client for a RugLens REST API deployment."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        *,
        timeout: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValidationError("base_url must use http or https")
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
        )
        self._owns_client = client is None

    async def __aenter__(self) -> HttpRugLensClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def assess(
        self,
        chain: int | str,
        address: str,
        block_number: int | None = None,
        *,
        rpc_url: str | None = None,
        use_cached_report: bool = True,
    ) -> AssessmentReport:
        """Call ``POST /v1/assess`` and validate the report contract."""
        payload: dict[str, Any] = {
            "chain": chain,
            "address": address,
            "block_number": block_number,
            "use_cached_report": use_cached_report,
        }
        if rpc_url is not None:
            payload["rpc_url"] = rpc_url
        response = await self._client.post("/v1/assess", json=payload)
        self._raise_for_status(response)
        try:
            return AssessmentReport.model_validate(response.json())
        except ValueError as exc:
            raise RugLensError(f"API returned an invalid AssessmentReport: {exc}") from exc

    async def health(self) -> dict[str, Any]:
        """Call ``GET /v1/health``."""
        response = await self._client.get("/v1/health")
        self._raise_for_status(response)
        data = response.json()
        if not isinstance(data, dict):
            raise RugLensError("API health response is malformed")
        return data

    async def detectors(self) -> list[dict[str, Any]]:
        """Call ``GET /v1/detectors``."""
        response = await self._client.get("/v1/detectors")
        self._raise_for_status(response)
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("detectors"), list):
            raise RugLensError("API detector response is malformed")
        return [entry for entry in data["detectors"] if isinstance(entry, dict)]

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        detail = ""
        try:
            payload = response.json()
            if isinstance(payload, dict):
                detail = sanitize_reason(payload.get("detail", ""))
        except ValueError:
            detail = sanitize_text(response.text, max_length=300)
        raise RugLensError(
            f"RugLens API returned HTTP {response.status_code}" + (f": {detail}" if detail else "")
        )

    async def close(self) -> None:
        """Close the owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()


def _chain_id(chain: str) -> int:
    from ruglens.chains.registry import resolve_chain_selector

    return resolve_chain_selector(chain)
