"""Typed domain exceptions for RugLens."""

from __future__ import annotations


class RugLensError(Exception):
    """Base class for all RugLens errors."""


class ConfigurationError(RugLensError):
    """Invalid or incomplete engine configuration."""


class ValidationError(RugLensError):
    """User-supplied data failed validation."""


class UnsupportedChainError(ValidationError):
    """The requested chain is not registered."""


class InvalidAddressError(ValidationError):
    """The supplied token or owner address is malformed."""


class InvalidTokenError(ValidationError):
    """The target address does not contain contract bytecode."""


class RpcError(RugLensError):
    """An RPC request failed after all failover attempts."""

    def __init__(self, message: str, *, method: str | None = None) -> None:
        self.method = method
        super().__init__(message)


class RpcTimeoutError(RpcError):
    """An RPC request exceeded its timeout."""


class RpcResponseTooLargeError(RpcError):
    """An RPC response exceeded the configured size ceiling."""


class RateLimitError(RpcError):
    """An RPC endpoint returned a rate-limit response."""


class CacheError(RugLensError):
    """The bytecode cache could not be read or written."""


class SimulationError(RugLensError):
    """Base class for local EVM simulation failures."""


class AnvilUnavailableError(SimulationError):
    """The anvil binary is missing or failed to start."""


class SimulationTimeoutError(SimulationError):
    """A simulation or Anvil operation exceeded its deadline."""


class SimulationRevertError(SimulationError):
    """A simulated transaction reverted."""


class SimulationSetupError(SimulationError):
    """The fork state is not usable for a V2 trade simulation."""


class DetectorError(RugLensError):
    """A detector failed while processing untrusted input."""


class DetectorTimeoutError(DetectorError):
    """A detector exceeded its per-detector deadline."""


class PluginError(RugLensError):
    """A user-supplied detector plugin could not be loaded."""


class RepositoryError(RugLensError):
    """Persistence of an assessment failed."""


class UnsafeUrlError(ValidationError):
    """A caller-supplied URL violates the SSRF policy."""
