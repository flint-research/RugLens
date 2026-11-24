# Roadmap

This document summarizes product-level direction and milestone status.

## Milestone 1 — foundation and vertical slice

**Complete.** Core domain models, resilient RPC/cache, Multicall3, isolated Anvil lifecycle,
measured DEX V2 simulation, bytecode and honeypot detectors, property-tested risk engine, full
orchestrator, and Typer/Rich CLI with canonical JSON.

**Exit evidence:** unit, fixture, property, and local Anvil simulation tests pass; clean/tax/
honeypot outcomes match expectations on real forked bytecode.

## Milestone 2 — detection breadth

**Complete.** Ownership and EIP-1967 proxy classification, liquidity depth and LP burn/lock
checks, holder concentration with bounded Transfer replay, optional isolated Slither source
analysis, and 15 end-to-end offline token fixtures.

**Exit evidence:** fixture suite includes clean, honeypot, 12/30/60% tax, EOA mint, blacklist,
EOA proxy admin, unlocked LP, low liquidity, concentrated holders, absent pair, partial data,
gas griefing, and multisig-governed mint patterns.

## Milestone 3 — service and self-hosting

**Complete except local Docker execution.** FastAPI endpoints, SSRF/body hardening, async SDK,
SQLAlchemy persistence, and multi-stage Docker/compose packaging. The development VM had no
Docker daemon; the CI workflow builds the image.

**Exit evidence:** API, storage, SDK, SSRF, and Anvil cleanup tests pass. Docker runtime
verification remains a release/CI step.

## Milestone 4 — benchmarks, plugins, CI, documentation

**Complete except a live measured benchmark.** Golden JSONL ingestion, Solidity metadata
stripping, family/temporal splits, metrics/runner/CLI, plugin loader, CI/security workflows, and
full documentation.

**Exit evidence:** benchmark tests validate metric math and ingestion; no accuracy claim is
published because no funded archive RPC was available in the development environment.

## Milestone 5 — native Solana rug profile (v0.2.0)

**Complete.** Solana selector `101`, direct JSON-RPC client, Base58/PDA/Ed25519 decoding, SPL and
Token-2022 mint/extension parsing, Metaplex metadata and Token-2022 metadata fallback, creator
holdings, top-1/top-10 retail concentration, funding-linked clusters with a transparent cluster
probability, program-controlled custody detection, CLI/API/SDK dispatch, Solana metrics, and
offline fixtures.

**Explicit V1 gaps:** no Solana sell-path simulation, exact DEX depth, or LP lock verification.
These are disclosed in coverage and limitations, not filled with third-party data.

## Next

- Solana venue adapters for exact Raydium/Orca/Meteora/PumpSwap pool depth and LP-lock checks.
- Solana creation-transaction and deployer-history enrichment with bounded RPC budgets.
- Additional EVM chains through registry configuration and venue configs.
- Uniswap V3 / Algebra venue adapters, keeping coverage explicit.
- Deployer history and bounded holder/deployer funding graphs, JIT only.
- Interpretable tabular ML after a family-deduplicated, time-split dataset exists; never inside
  the deterministic gate.
- Postgres/Valkey backend for Flint Cloud workers; tenant isolation outside the open-source core.
- Signed rule bundles and reproducibility manifests for regulated deployments.
