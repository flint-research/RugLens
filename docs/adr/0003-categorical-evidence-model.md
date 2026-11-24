# 0003 — Categorical risk with explicit coverage

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** A single 0–100 score masks catastrophic findings, mixes severity with confidence,
  and silently improves when data sources fail. Users need explainable, reproducible verdicts.
- **Decision:** Use five categorical levels (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN`),
  a `data_coverage` ratio, and structured findings. Coverage uses fixed weights:
  dynamic 0.35, bytecode 0.25, liquidity 0.20, ownership 0.15, holders 0.05. The denominator is
  always 1.0. LOW requires coverage ≥0.80 and no CRITICAL/HIGH/MEDIUM findings. UNKNOWN applies
  below 0.65, below 0.80 without findings, or when dangerous findings are below confidence
  gates. Deduplication is idempotent and preserves all source evidence.
- **Consequences:**
  - An incomplete engine cannot normalize coverage to 100 and return LOW.
  - Missing RPC/simulation data is visible and actionable.
  - Every verdict is explainable by findings, confidence, and coverage.
  - The model is deterministic and testable with property-based invariants.
