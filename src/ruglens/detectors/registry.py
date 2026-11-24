"""Detector registration and user plugin discovery."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruglens.core.config import RugLensSettings
from ruglens.core.enums import CoverageArea, DetectorCategory
from ruglens.core.interfaces import BaseDetector
from ruglens.detectors.dynamic.honeypot_sim import DynamicHoneypotDetector
from ruglens.detectors.onchain.holders import HolderDistributionDetector
from ruglens.detectors.onchain.liquidity import LiquidityDetector
from ruglens.detectors.onchain.ownership import OwnershipDetector
from ruglens.detectors.static.bytecode_rules import BytecodeSelectorDetector
from ruglens.detectors.static.slither_runner import SlitherSourceDetector

logger = logging.getLogger(__name__)

DEFAULT_DETECTOR_CLASSES: tuple[type[BaseDetector], ...] = (
    BytecodeSelectorDetector,
    DynamicHoneypotDetector,
    OwnershipDetector,
    LiquidityDetector,
    HolderDistributionDetector,
    SlitherSourceDetector,
)

_PLUGIN_ID = re.compile(r"^[a-z0-9_]{3,64}$")


@dataclass(frozen=True, slots=True)
class PluginLoadReport:
    """Outcome of scanning the user plugin directory."""

    detectors: tuple[BaseDetector, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DetectorDescriptor:
    """Serializable detector metadata for the API and CLI."""

    detector_id: str
    category: DetectorCategory
    required: bool
    coverage_area: CoverageArea | None
    description: str
    origin: str
    chain_family: str = "evm"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "detector_id": self.detector_id,
            "category": self.category.value,
            "required": self.required,
            "coverage_area": self.coverage_area.value if self.coverage_area else None,
            "description": self.description,
            "origin": self.origin,
            "chain_family": self.chain_family,
        }


class DetectorRegistry:
    """Ordered detector registry with duplicate protection."""

    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        *,
        plugin_errors: tuple[str, ...] = (),
    ) -> None:
        self._detectors: list[BaseDetector] = []
        self._origins: dict[str, str] = {}
        self._plugin_errors = plugin_errors
        for detector in detectors or []:
            self.register(detector, origin="builtin")

    def register(self, detector: BaseDetector, *, origin: str = "plugin") -> None:
        """Add a detector, rejecting duplicate ids."""
        if detector.detector_id in self._origins:
            raise ValueError(f"Duplicate detector id: {detector.detector_id}")
        self._detectors.append(detector)
        self._origins[detector.detector_id] = origin

    @property
    def detectors(self) -> tuple[BaseDetector, ...]:
        """Registered detectors in execution order."""
        return tuple(self._detectors)

    @property
    def plugin_errors(self) -> tuple[str, ...]:
        """Errors encountered while loading optional plugins."""
        return self._plugin_errors

    def descriptors(self) -> list[DetectorDescriptor]:
        """Return metadata for every registered detector."""
        return [
            DetectorDescriptor(
                detector_id=detector.detector_id,
                category=detector.category,
                required=detector.required,
                coverage_area=detector.coverage_area,
                description=detector.description,
                origin=self._origins.get(detector.detector_id, "plugin"),
            )
            for detector in self._detectors
        ]

    def get(self, detector_id: str) -> BaseDetector | None:
        """Look up a detector by id."""
        return next(
            (detector for detector in self._detectors if detector.detector_id == detector_id),
            None,
        )


def build_default_detectors(settings: RugLensSettings) -> list[BaseDetector]:
    """Instantiate every built-in detector."""
    return [detector_class(settings) for detector_class in DEFAULT_DETECTOR_CLASSES]


def build_registry(settings: RugLensSettings) -> DetectorRegistry:
    """Build the built-in registry plus any user plugins."""
    builtins = build_default_detectors(settings)
    report = discover_plugins(
        settings,
        reserved_ids={detector.detector_id for detector in builtins},
    )
    registry = DetectorRegistry(plugin_errors=report.errors)
    for detector in builtins:
        registry.register(detector, origin="builtin")
    for detector in report.detectors:
        registry.register(detector, origin="plugin")
    return registry


def discover_plugins(
    settings: RugLensSettings,
    *,
    reserved_ids: set[str] | None = None,
) -> PluginLoadReport:
    """Load detectors from ``<data_dir>/plugins/*.py``.

    Plugins are trusted local Python code. They may emit findings but cannot
    claim a coverage area, so a broken or malicious plugin can never inflate
    confidence in an otherwise incomplete assessment.
    """
    if not settings.plugins_enabled:
        return PluginLoadReport()
    plugin_dir = settings.resolved_plugin_dir()
    if not plugin_dir.exists() or not plugin_dir.is_dir():
        return PluginLoadReport()

    reserved = reserved_ids or set()
    loaded: list[BaseDetector] = []
    errors: list[str] = []
    seen = set(reserved)

    for path in sorted(plugin_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                raise ValueError("plugin file exceeds 1 MB")
            module = _load_module(path)
            classes = [
                obj
                for _, obj in sorted(
                    inspect.getmembers(module, inspect.isclass), key=lambda item: item[0]
                )
                if obj is not BaseDetector
                and issubclass(obj, BaseDetector)
                and obj.__module__ == module.__name__
                and not inspect.isabstract(obj)
            ]
            if not classes:
                raise ValueError("no concrete BaseDetector subclass found")
            for detector_class in classes:
                detector = detector_class(settings)
                _validate_plugin(detector)
                if detector.detector_id in seen:
                    raise ValueError(f"duplicate detector id {detector.detector_id!r}")
                seen.add(detector.detector_id)
                loaded.append(detector)
                logger.info("Loaded RugLens plugin detector %s from %s", detector.detector_id, path)
        except Exception as exc:
            message = f"Plugin {path.name} was skipped: {exc}"
            logger.warning(message)
            errors.append(message)
    return PluginLoadReport(detectors=tuple(loaded), errors=tuple(errors))


def _load_module(path: Path) -> Any:
    digest = hashlib.sha256(f"{path}:{path.stat().st_mtime_ns}".encode()).hexdigest()[:12]
    module_name = f"ruglens_user_plugin_{path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError("could not create an import spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


def _validate_plugin(detector: BaseDetector) -> None:
    detector_id = getattr(detector, "detector_id", "")
    if not isinstance(detector_id, str) or not _PLUGIN_ID.fullmatch(detector_id):
        raise ValueError(f"invalid detector id {detector_id!r}")
    if not isinstance(detector.category, DetectorCategory):
        raise ValueError("category must be a DetectorCategory")
    if getattr(detector, "coverage_area", None) is not None:
        raise ValueError("plugins may not claim a coverage area")
    if getattr(detector, "required", True):
        raise ValueError("plugins must set required = False")
    if not isinstance(getattr(detector, "description", None), str):
        raise ValueError("description must be a string")
    if not inspect.iscoroutinefunction(getattr(detector, "detect", None)):
        raise ValueError("detect() must be async")
