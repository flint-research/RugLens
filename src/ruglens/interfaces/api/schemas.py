"""FastAPI request/response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AssessRequest(BaseModel):
    """Public assessment input. No auth or tenant state is accepted."""

    model_config = ConfigDict(extra="forbid")

    chain: str | int = Field(
        default="eth",
        description="Chain slug or numeric id (eth, bsc, base, solana, 101)",
    )
    address: str = Field(
        min_length=3,
        max_length=64,
        description="EVM token address or Solana mint address",
    )
    block_number: int | None = Field(default=None, ge=0, description="Optional pinned block")
    rpc_url: str | None = Field(
        default=None,
        max_length=2048,
        description="Custom RPC URL (disabled unless explicitly enabled by the operator)",
    )
    use_cached_report: bool = True


class HealthResponse(BaseModel):
    """Liveness plus local capability information."""

    status: str = "ok"
    version: str
    engine_ready: bool
    anvil_available: bool
    simulation_enabled: bool
    detector_count: int
    uptime_seconds: float


class DetectorListResponse(BaseModel):
    """Detector metadata."""

    detectors: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    """Stable error envelope."""

    detail: str
