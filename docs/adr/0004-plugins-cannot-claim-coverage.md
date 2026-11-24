# 0004 — Plugins cannot claim coverage

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** Community detectors are useful for novel scam patterns, but an optional or broken
  plugin must not make an otherwise incomplete assessment look complete. Coverage is a safety
  signal, not a popularity metric.
- **Decision:** The plugin loader rejects any detector with a non-null `coverage_area` or
  `required = True`. The orchestrator also strips coverage area from any non-required detector
  outcome. Plugin findings still participate in severity gates. Plugin load errors are surfaced
  as report limitations.
- **Consequences:**
  - A plugin cannot fill a missing dynamic/liquidity/ownership slot.
  - New required detectors must ship in the core with tests, fixtures, and coverage weights.
  - Plugins can still raise risk through findings, which is fail-safe.
  - Plugin authors get clear validation errors.
