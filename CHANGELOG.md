# Changelog

All notable changes to RugLens are documented here. Format follows Keep a Changelog; versions
follow Semantic Versioning.

## [0.2.0] — 2026-11-24

### Added

- Native Solana mainnet support via engine selector `101` (`--chain solana`).
- Direct Solana JSON-RPC client with failover, rate limiting, redirect protection, separate
  connect/total timeouts, and a streaming 5 MB response cap.
- Dependency-free Base58 codec, program-derived-address derivation, and Ed25519 on-curve checks.
- SPL Token and Token-2022 mint parsing, extension analysis, Base64 fallback, Metaplex metadata
  decoding, and Token-2022 tokenMetadata fallback.
- Mint/freeze/update-authority classification (wallet vs. SPL multisig vs. program-controlled) so
  governed stablecoins are not reported as single-wallet controls.
- `solana_authorities`, `solana_holders`, `solana_clusters`, and `solana_liquidity` detectors.
- Creator holdings, top-1/top-10 retail concentration, burn/program-controlled custody exclusion,
  funding-linked cluster share, and transparent cluster probability metrics.
- Solana coverage profile (authorities 0.30, holders 0.30, clusters 0.25, liquidity custody 0.15).
- CLI key-metrics panel, Solana API dispatch/SDK support, Base58 report persistence, and
  `docs/SOLANA.md` with research-backed thresholds and limitations.
- Offline Solana fixtures/tests for clean, moderate, critical, and failed-cluster scenarios.

### Notes

- Solana V1 has no sell simulation, exact DEX depth, or LP burn/lock verification. These gaps are
  explicitly reported and cannot produce LOW risk without coverage.
- Standard Solana JSON-RPC does not support historical account pinning; reports record the
  observed slot.
- Docker runtime and live golden benchmark remain environment/CI blockers described in TASKS.

## [0.1.0] — 2026-11-24

### Added

- Core domain model: categorical risk, coverage, deterministic findings, immutable reports.
- Resilient AsyncWeb3 client with failover, rate limiting, streaming 5 MB response cap,
  Multicall3 batching, and SQLite block-aware bytecode cache.
- Isolated anvil manager with semaphore, startup/RPC/shutdown deadlines, and guaranteed cleanup.
- Measured DEX V2 buy/approve/sell simulation with buy/sell tax, gas griefing, and honeypot
  classification.
- Static bytecode selector/opcode detector; ownership and EIP-1967 proxy detector; V2 liquidity
  depth and LP lock detector (unlocked-LP HIGH requires verified EOA-majority proof); bounded
  holder concentration detector; optional isolated Slither.
- Deterministic risk consensus: idempotent deduplication, weighted coverage, veto/escalation
  gates, property-based invariant tests.
- End-to-end orchestrator, Typer/Rich CLI with table and JSON output, FastAPI service, async
  SDK, and SQLAlchemy report persistence.
- 15 offline end-to-end token fixtures plus a real forked Solidity simulation suite.
- Golden dataset ingestion with CBOR-metadata stripping and bytecode-family splits; benchmark
  metrics and CLI; custom detector plugin loader.
- Docker/compose packaging, CI quality/test/docker jobs, pip-audit workflow, and documentation.

### Notes

- Docker compose runtime verification and a live golden benchmark were not executed in the
  development environment (no Docker daemon, no funded archive RPC). Both are CI/release steps.
- V1 supports Uniswap V2-style wrapped-native pairs on Ethereum, BSC, and Base only.
