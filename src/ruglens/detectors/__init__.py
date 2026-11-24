"""Detector implementations and plugin registry."""

from __future__ import annotations

from ruglens.detectors.registry import (
    DEFAULT_DETECTOR_CLASSES,
    DetectorDescriptor,
    DetectorRegistry,
    PluginLoadReport,
    build_default_detectors,
    build_registry,
    discover_plugins,
)

__all__ = [
    "DEFAULT_DETECTOR_CLASSES",
    "DetectorDescriptor",
    "DetectorRegistry",
    "PluginLoadReport",
    "build_default_detectors",
    "build_registry",
    "discover_plugins",
]
