# 0002 — Isolated, semaphore-gated Anvil forks

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** Active honeypots and dynamic taxes cannot be proven by static analysis. Anvil
  (`revm`) supports fast, block-pinned mainnet forks and account impersonation with no live
  broadcast, but each process costs memory and can leak or hang.
- **Decision:**
  - Every dynamic assessment spawns an ephemeral Anvil fork at the pinned block.
  - A process-local `asyncio.Semaphore(settings.simulation_concurrency)` (default 2) gates the
    full process lifetime.
  - Startup is polled with a hard deadline; readiness, RPC, whole-simulation, and shutdown
    deadlines are separate.
  - Cleanup is guaranteed in `finally`: `terminate`, bounded wait, then `kill`, followed by
    temp-directory deletion and semaphore release.
  - The simulator impersonates a deterministic clean wallet, clears its code, sets native
    balance, and never uses a real key.
- **Consequences:**
  - Real buy/sell tax and sell reverts are measured, not inferred.
  - Infrastructure failures degrade coverage (SKIPPED/TIMEOUT/FAILED), never produce clean
    evidence.
  - Historical simulations require an archive-capable RPC.
  - Concurrency is deliberately low; throughput scales by adding workers, not by unbounded
    forks.
