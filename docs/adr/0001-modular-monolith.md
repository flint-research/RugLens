# 0001 — Modular monolith with one-way boundaries

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** RugLens must run on a 7 GB / 8 vCPU / no-GPU host, be operable by autonomous
  agents, and later scale selected workers for Flint Cloud without architectural forks.
- **Decision:** Build a single deployable Python package with strict subsystem boundaries:
  `core -> chains -> simulation -> detectors -> risk -> orchestrator -> interfaces`. Domain
  models and protocols live in `core`; concrete dependencies are injected. Storage and
  benchmark modules depend inward only. No service mesh, message broker, graph database, or
  distributed cache is part of V1.
- **Consequences:**
  - One process is easy to test, package, and self-host.
  - Risk cannot import detector internals; detectors cannot compute final risk.
  - Flint Cloud can replace repositories, RPC pools, and simulation workers by injection.
  - Individual workers can be extracted later without changing the report contract.
  - The module count is larger than a script, but boundaries keep changes local.
