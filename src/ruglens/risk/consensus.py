"""Finding deduplication and evidence merging.

Two detectors may independently prove the same defect (for example bytecode
selectors and Slither both finding ``mint``). Findings sharing a deterministic
``finding_id`` are merged into one canonical finding: the strongest evidence is
retained, the highest confidence wins, and every source payload is preserved
under ``evidence["sources"]``. Deduplication is idempotent and order-independent.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from ruglens.core.enums import Severity
from ruglens.core.models import Finding


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _source_payload(finding: Finding) -> dict[str, Any]:
    evidence = {key: value for key, value in finding.evidence.items() if key != "sources"}
    return {
        "detector_id": finding.detector_id,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "evidence": evidence,
    }


def _collect_sources(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        existing = finding.evidence.get("sources")
        if isinstance(existing, list):
            for entry in existing:
                if not isinstance(entry, dict):
                    continue
                key = (str(entry.get("detector_id", "")), str(entry.get("rule_id", "")))
                current = sources.get(key)
                if current is None or _canonical_json(entry) > _canonical_json(current):
                    sources[key] = dict(entry)
        payload = _source_payload(finding)
        key = (payload["detector_id"], payload["rule_id"])
        current = sources.get(key)
        if current is None or _canonical_json(payload) > _canonical_json(current):
            sources[key] = payload
    return [sources[key] for key in sorted(sources)]


class ConsensusEngine:
    """Merge duplicate findings deterministically."""

    def deduplicate(self, findings: Iterable[Finding]) -> list[Finding]:
        """Return a canonical, sorted finding list."""
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            groups.setdefault(finding.finding_id, []).append(finding)

        merged: list[Finding] = []
        for finding_id in sorted(groups):
            group = groups[finding_id]
            if len(group) == 1:
                merged.append(group[0])
                continue
            merged.append(self._merge(group))
        merged.sort(key=lambda item: (-item.severity.rank, -item.confidence, item.rule_id))
        return merged

    def _merge(self, group: Sequence[Finding]) -> Finding:
        ordered = sorted(
            group,
            key=lambda item: (
                item.confidence,
                item.severity.rank,
                item.detector_id,
                item.rule_version,
                item.title,
                item.description,
            ),
        )
        winner = ordered[-1]
        severity = max((item.severity for item in group), key=lambda value: value.rank)
        confidence = max(item.confidence for item in group)
        references = sorted({reference for item in group for reference in item.references})
        sources = _collect_sources(group)
        base_evidence = {key: value for key, value in winner.evidence.items() if key != "sources"}
        evidence: dict[str, Any] = {**base_evidence, "sources": sources}
        return winner.model_copy(
            update={
                "severity": severity,
                "confidence": confidence,
                "references": references,
                "evidence": evidence,
            }
        )

    @staticmethod
    def independent_findings(findings: Sequence[Finding]) -> list[Finding]:
        """Return findings with unique rule ids (used by escalation gates)."""
        by_rule: dict[str, Finding] = {}
        for finding in findings:
            current = by_rule.get(finding.rule_id)
            if current is None or finding.confidence > current.confidence:
                by_rule[finding.rule_id] = finding
        return sorted(by_rule.values(), key=lambda item: (-item.severity.rank, item.rule_id))


def maximum_severity(findings: Sequence[Finding]) -> Severity | None:
    """Return the highest severity in a finding list, if any."""
    if not findings:
        return None
    return max((finding.severity for finding in findings), key=lambda value: value.rank)
