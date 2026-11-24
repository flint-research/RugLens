"""API routes."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException, Request, status

from ruglens import __version__
from ruglens.chains.registry import resolve_chain_selector
from ruglens.core.exceptions import (
    InvalidAddressError,
    InvalidTokenError,
    RpcError,
    RugLensError,
    UnsupportedChainError,
    ValidationError,
)
from ruglens.core.models import AssessmentReport
from ruglens.core.sanitization import sanitize_text
from ruglens.interfaces.api.schemas import (
    AssessRequest,
    DetectorListResponse,
    ErrorResponse,
    HealthResponse,
)
from ruglens.interfaces.api.security import validate_public_rpc_url
from ruglens.orchestrator.engine import AssessmentEngine
from ruglens.simulation.anvil import AnvilManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")


def _engine(request: Request) -> AssessmentEngine:
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Assessment engine is not initialized",
        )
    return engine


@router.post(
    "/assess",
    response_model=AssessmentReport,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    summary="Assess an EVM token",
)
async def assess(request: Request, payload: AssessRequest) -> AssessmentReport:
    """Run a full evidence-based assessment and return AssessmentReport JSON."""
    settings = request.app.state.settings
    engine = _engine(request)

    rpc_urls = None
    if payload.rpc_url:
        if not settings.api_allow_custom_rpc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom RPC URLs are disabled by the server operator",
            )
        try:
            validated = await validate_public_rpc_url(
                payload.rpc_url,
                allow_private=settings.api_allow_private_rpc,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        rpc_urls = (validated,)

    semaphore = request.app.state.assessment_semaphore
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=settings.api_queue_timeout)
    except TimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Assessment workers are at capacity; retry shortly",
        ) from exc
    except asyncio.CancelledError:  # pragma: no cover - client disconnect
        raise
    try:
        selected_chain_id = resolve_chain_selector(payload.chain)
        report = await engine.assess_token(
            selected_chain_id,
            payload.address,
            payload.block_number,
            rpc_urls=rpc_urls,
            use_cached_report=payload.use_cached_report,
        )
    except (UnsupportedChainError, InvalidAddressError, InvalidTokenError, ValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RpcError as exc:
        logger.warning("Assessment RPC failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="An upstream RPC request failed; try a different endpoint",
        ) from exc
    except RugLensError as exc:
        logger.exception("Assessment failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=sanitize_text(str(exc), max_length=300) or "Assessment failed",
        ) from exc
    finally:
        semaphore.release()
    return report


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness and local capability information."""
    settings = request.app.state.settings
    engine = getattr(request.app.state, "engine", None)
    started_at = getattr(request.app.state, "started_at", time.monotonic())
    detector_count = 0
    if engine is not None:
        detector_count = int(getattr(engine, "detector_count", len(engine.registry.detectors)))
    return HealthResponse(
        version=__version__,
        engine_ready=engine is not None,
        anvil_available=AnvilManager.is_available(settings.anvil_binary),
        simulation_enabled=settings.simulation_enabled,
        detector_count=detector_count,
        uptime_seconds=max(0.0, time.monotonic() - started_at),
    )


@router.get("/detectors", response_model=DetectorListResponse)
async def detectors(request: Request) -> DetectorListResponse:
    """List registered detectors and their coverage roles."""
    engine = _engine(request)
    return DetectorListResponse(
        detectors=[descriptor.as_dict() for descriptor in engine.detector_descriptors()]
    )
