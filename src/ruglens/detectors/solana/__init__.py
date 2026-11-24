"""Solana-native detector package."""

from __future__ import annotations

from ruglens.core.config import RugLensSettings
from ruglens.core.interfaces import BaseSolanaDetector
from ruglens.detectors.registry import DetectorDescriptor
from ruglens.detectors.solana.authorities import SolanaAuthoritiesDetector
from ruglens.detectors.solana.cluster import SolanaClusterDetector
from ruglens.detectors.solana.holders import SolanaHolderDetector
from ruglens.detectors.solana.liquidity import SolanaLiquidityDetector

SOLANA_DETECTOR_CLASSES: tuple[type[BaseSolanaDetector], ...] = (
    SolanaAuthoritiesDetector,
    SolanaHolderDetector,
    SolanaClusterDetector,
    SolanaLiquidityDetector,
)


def build_solana_detectors(settings: RugLensSettings) -> list[BaseSolanaDetector]:
    """Instantiate all built-in Solana detectors."""
    return [detector_class(settings) for detector_class in SOLANA_DETECTOR_CLASSES]


def solana_detector_descriptors(settings: RugLensSettings) -> list[DetectorDescriptor]:
    """Return Solana detector metadata for CLI/API discovery."""
    return [
        DetectorDescriptor(
            detector_id=detector.detector_id,
            category=detector.category,
            required=detector.required,
            coverage_area=detector.coverage_area,
            description=detector.description,
            origin="builtin",
            chain_family="solana",
        )
        for detector in build_solana_detectors(settings)
    ]


__all__ = [
    "SOLANA_DETECTOR_CLASSES",
    "SolanaAuthoritiesDetector",
    "SolanaClusterDetector",
    "SolanaHolderDetector",
    "SolanaLiquidityDetector",
    "build_solana_detectors",
    "solana_detector_descriptors",
]
