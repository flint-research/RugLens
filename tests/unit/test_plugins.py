"""Plugin loader tests."""

from __future__ import annotations

from pathlib import Path

from ruglens.core.config import RugLensSettings
from ruglens.detectors.registry import build_registry, discover_plugins


def plugin_settings(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        plugin_dir=tmp_path / "plugins",
        plugins_enabled=True,
        persist_reports=False,
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
    )


VALID_PLUGIN = """
from ruglens.core.enums import CoverageArea, DetectorCategory
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, TokenContext


class DemoDetector(BaseDetector):
    detector_id = "demo_plugin"
    category = DetectorCategory.STATIC
    coverage_area = None
    description = "Demo plugin for tests"
    required = False

    async def detect(self, context: TokenContext, dependencies: DetectorDependencies) -> DetectorOutcome:
        return self.make_outcome(details={"plugin": True})
"""


def test_valid_plugin_is_loaded(tmp_path: Path) -> None:
    settings = plugin_settings(tmp_path)
    settings.resolved_plugin_dir().mkdir(parents=True)
    (settings.resolved_plugin_dir() / "demo.py").write_text(VALID_PLUGIN, encoding="utf-8")
    report = discover_plugins(settings)
    assert report.errors == ()
    assert [detector.detector_id for detector in report.detectors] == ["demo_plugin"]
    registry = build_registry(settings)
    assert registry.get("demo_plugin") is not None
    descriptor = next(item for item in registry.descriptors() if item.detector_id == "demo_plugin")
    assert descriptor.origin == "plugin"
    assert descriptor.coverage_area is None


def test_plugin_claiming_coverage_is_rejected(tmp_path: Path) -> None:
    settings = plugin_settings(tmp_path)
    settings.resolved_plugin_dir().mkdir(parents=True)
    bad = VALID_PLUGIN.replace("coverage_area = None", "coverage_area = CoverageArea.BYTECODE")
    (settings.resolved_plugin_dir() / "bad.py").write_text(bad, encoding="utf-8")
    report = discover_plugins(settings)
    assert report.detectors == ()
    assert any("coverage area" in error for error in report.errors)


def test_broken_and_duplicate_plugins_are_reported(tmp_path: Path) -> None:
    settings = plugin_settings(tmp_path)
    plugin_dir = settings.resolved_plugin_dir()
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "broken.py").write_text("this is not python", encoding="utf-8")
    duplicate = VALID_PLUGIN.replace("demo_plugin", "bytecode_selectors")
    (plugin_dir / "duplicate.py").write_text(duplicate, encoding="utf-8")
    report = discover_plugins(settings, reserved_ids={"bytecode_selectors"})
    assert report.detectors == ()
    assert len(report.errors) == 2
    assert any("duplicate" in error for error in report.errors)
    assert any("broken.py" in error for error in report.errors)
