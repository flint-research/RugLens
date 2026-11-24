# RugLens Architecture

## 1. Goals and constraints

RugLens is a **modular monolith** designed for a 7 GB RAM / 8 vCPU / no-GPU host. It supports
EVM chains (Ethereum, BSC, Base) and Solana mainnet with native adapters. It must run with no
third-party token-security API, produce pinned/observed evidence, and fail toward `UNKNOWN`
rather than a false `LOW`. Individual subsystems can later be extracted (for example,
simulation workers for Flint Cloud) without changing the domain contract.

The stable boundary is `AssessmentReport.model_dump_json()`. CLI, REST, SDK, storage, webhooks,
and downstream Flint products consume the same Pydantic v2 schema.

## 2. Dependency boundaries

Strict one-way imports:

```text
core/           -> (nothing internal)
chains/         -> core
simulation/     -> core, chains (EVM only)
detectors/      -> core, chains (interfaces), simulation (interfaces)
risk/           -> core only
storage/        -> core
orchestrator/   -> chains, simulation, detectors, risk, storage
interfaces/     -> orchestrator, core
benchmark/      -> core, chains (address validation), orchestrator (runner is callable-based)
```

`risk/` never imports detector implementations. EVM and Solana detectors are separate packages
and never import one another. Plugins are loaded through `detectors/registry.py` and receive the
same `BaseDetector` interface. Solana has its own `BaseSolanaDetector` contract with the same
outcome semantics.

## 3. Data flow

```text
CLI / FastAPI / SDK
        |
        v
AssessmentEngine (family dispatcher, chain 101 = Solana)
  |-- EVM path --------------------------------------------------------------
  |     |-- validate checksummed address + optional pinned block
  |     |-- load cached block-pinned report (optional)
  |     |-- hydrate TokenContext via ChainAdapter
  |     |     |-- runtime bytecode (immutable SQLite cache)
  |     |     |-- ERC-20 metadata, V2 pair, reserves, LP locks
  |     |     `-- caller-supplied Solidity sources (optional)
  |     |-- static / dynamic Anvil / ownership / liquidity / holders / Slither
  |
  |-- Solana path -----------------------------------------------------------
  |     |-- validate Base58 mint, record current confirmed slot
  |     |-- hydrate SolanaTokenContext via Solana JSON-RPC
  |     |     |-- SPL/Token-2022 mint + extensions
  |     |     |-- Metaplex metadata or Token-2022 tokenMetadata
  |     |     |-- creator (metadata or bounded creation tx)
  |     |     |-- 20 largest token accounts, owner classification
  |     |     `-- creator token accounts, burn/custody supply
  |     |-- SolanaAuthorities / SolanaHolder / SolanaCluster / SolanaLiquidity
  |     |-- Solana coverage profile (no EVM dynamic-trade area)
  |
  |-- RiskEvaluator: dedup -> coverage -> gates -> findings/limitations
  `-- AssessmentReport + metrics -> SQLite (optional) -> CLI/JSON/API/SDK
```

The Solana path uses `httpx` JSON-RPC with failover, token-bucket rate limiting, separate
connect/total timeouts, redirects disabled, and a streaming 5 MB response cap. No Solana SDK or
Rust binding is required: Base58, PDA derivation, Ed25519 on-curve checks, account parsing, and
Metaplex decoding are implemented in Python.

## 4. Domain models

### `Finding`

Fields: deterministic `finding_id`, `rule_id`, `rule_version`, `detector_id`, category,
severity, confidence, title, description, structured evidence, references, target, block.
`finding_id = sha256(rule_id | lowercase(target) | block_number)`.

### `DetectorOutcome`

Every detector returns status (`SUCCESS`, `FAILED`, `SKIPPED`, `TIMEOUT`), findings, a coverage
fraction, limitations, duration, and diagnostic details. Non-SUCCESS outcomes are forced to
zero coverage by a Pydantic validator.

### `TokenContext`

Shared hydrated state: bytecode and hash, sanitized metadata, router/WETH, pair addresses and
raw reserves, LP supply/balances, optional holder snapshot, proxy slots, sources, and hydration
notes. Pair reserves are stored as raw `(reserve0, reserve1)`; orientation is resolved against
`pair_token0/pair_token1` by consumers.

### `AssessmentReport`

Immutable: UUID, engine version, chain/token/block, timestamp, risk level, confidence, data
coverage, findings, detector statuses, limitations, metadata, summary, `metrics`, duration, RPC
call count. `to_json()` is the canonical serialization contract.

`metrics` is an additive, token-family-specific map. EVM reports currently leave it empty; Solana
reports include creator/retail percentages, authority classifications, cluster share/probability,
custody percentage, and explicit `liquidity_depth_verified` / `lp_lock_verified` booleans.

### Solana models

`SolanaMintState`, `SolanaMetadata`, `SolanaCreator`, `SolanaHolder`, and `SolanaTokenContext`
live in `core/solana_models.py`. They record parsed mint/extensions, update authority, creator
source, top-account owner classification, burn/program-controlled amounts, and hydration notes.
The EVM `TokenContext` remains separate so Solana is not forced into `eth_call`/bytecode concepts.

## 5. Chain layer

- **`CappedAsyncHTTPProvider`** subclasses AsyncWeb3's HTTP provider, streams response chunks,
  checks `Content-Length`, disables redirects (to limit SSRF pivot surfaces), applies separate
  connect/total timeouts, and raises before parsing if the 5 MB cap is exceeded.
- **`EvmClient`** owns ordered endpoints, a token-bucket limiter, per-endpoint cooldowns,
  exponential backoff, failover, and a shared concurrency semaphore. Every state read is pinned
  to a block number.
- **Multicall3** (`aggregate3`) batches metadata, pair, ownership, governance, and balance reads.
  If Multicall3 is unavailable, the client falls back to individual `eth_call`s and records
  per-call failure.
- **`BytecodeCache`** stores immutable code by `(chain_id, address, block)` in SQLite, with LRU
  pruning to a configurable byte ceiling (default 1 GiB). Mutable state is never cached beyond
  a pinned assessment.

## 6. Simulation

`AnvilManager` owns ephemeral forks:

- process-local `asyncio.Semaphore(settings.simulation_concurrency)` (default 2);
- free-port selection, startup polling with a hard deadline;
- stdout/stderr captured in a temp directory;
- `try/finally` termination: `terminate` -> bounded wait -> `kill`; temp directory removed;
- no persistent process, no broadcast, no wallet keys.

`TradeSimulator` runs one sequence at a pinned block:

1. Spawn a fork from the configured RPC at the assessment block.
2. Select a deterministic clean wallet (or configured address), set native balance, clear code,
   impersonate it, and verify zero starting token balance.
3. Buy with `swapExactETHForTokensSupportingFeeOnTransferTokens` (0.1 native by default).
4. Compare received tokens to a router quote (or reserve math fallback) to derive buy tax.
5. Approve the router and sell 100% of the token balance with
   `swapExactTokensForETHSupportingFeeOnTransferTokens`.
6. Add gas cost back to the native delta, compare with a post-buy quote to derive sell tax.
7. Classify sell reverts or <1% output as a honeypot; record gas and revert reasons.

All RPC calls to Anvil have their own timeout; the whole simulation has a separate deadline.
The detector maps infrastructure failures to SKIPPED/TIMEOUT/FAILED, never to a clean result.

## 7. Detectors

| Detector | Method | Coverage |
| --- | --- | ---: |
| `bytecode_selectors` | `pyevmasm` disassembly, curated selector groups, opcode counts | 0.25 |
| `dynamic_honeypot` | real forked buy/sell | 0.35 |
| `ownership` | owner/governance calls, EIP-1967 slots, proxy admin type | 0.15 |
| `liquidity` | V2 pair depth, LP burn/known locker balances, EOA-majority proof | 0.20 |
| `holder_distribution` | bounded Transfer replay, balance verification, pair/burn exclusion | 0.05 |
| `slither_source` | optional external CLI over supplied sources | none |

Static capability findings are MEDIUM unless ownership context raises them. A confirmed sell
revert is CRITICAL. An EOA-owned mint capability is HIGH; a multisig/timelock-governed one is
MEDIUM.

### Solana detectors

| Detector | Method | Coverage |
| --- | --- | ---: |
| `solana_authorities` | Mint/freeze authority classification, Metaplex update authority, Token-2022 extensions | 0.30 |
| `solana_holders` | Creator balance, top-1/top-10 wallet aggregation, burn/PDA exclusion | 0.30 |
| `solana_clusters` | Earliest funding source for top wallets, common-funder groups, probability heuristic | 0.25 |
| `solana_liquidity` | Off-curve/program-controlled custody detection; no depth/LP-lock claim | 0.15 |

Authority accounts are read directly: SPL Token multisig accounts are recognized from parsed
`multisig` data, executable/PDA authorities are program-controlled, and only an EOA-like wallet
keeps the HIGH capability severity. Metadata mutability is LOW when governed and MEDIUM when a
single wallet controls it. Token-2022 permanent delegate, default frozen accounts, pausable,
non-transferable, transfer hooks, transfer fees, mint close authority, and confidential transfers
are evaluated with explicit limitations for undecoded extensions.

Creator identity comes from Metaplex creators or the fee payer of an earliest mint transaction
only when the signature window is not saturated. Creator holdings are summed across all creator
token accounts. Top holders are aggregated by owner, excluding burn and program-controlled
accounts, and divided by circulating supply after those exclusions.

Cluster analysis traces the earliest bounded transaction for the top retail wallets, excludes
program-controlled funders, groups common funders (minimum three wallets for a campaign finding),
and reports a transparent `cluster_probability` heuristic. Truncated windows and failed traces
reduce coverage or fail the detector; exchange-funded wallets can produce false correlations.

Solana V1 has no sell-path simulation, exact DEX pool discovery, or LP lock verification. The
liquidity detector only identifies program-controlled custody and always records
`liquidity_depth_verified: false`. Those gaps are visible in limitations and in the Solana
coverage profile.

## 8. Risk engine

`ConsensusEngine` groups findings by deterministic ID, keeps the highest-confidence payload,
preserves every detector's evidence under `evidence["sources"]`, and sorts deterministically.
Deduplication is idempotent and order-independent.

`CoverageCalculator` uses family profiles. EVM weights: dynamic 0.35, bytecode 0.25, liquidity
0.20, ownership 0.15, holders 0.05. Solana weights: authorities 0.30, holders 0.30, clusters
0.25, liquidity custody 0.15. The denominator is always 1.0, so an unregistered or failed
detector lowers coverage rather than normalizing it away. Duplicate detectors in one area use
the best fraction. A failed cluster detector alone leaves Solana coverage at 0.75, preventing a
clean-but-unclustered token from resolving LOW.

`RiskEvaluator` applies:

1. CRITICAL if any CRITICAL finding has confidence ≥0.85.
2. HIGH if any HIGH finding ≥0.70 or ≥3 independent MEDIUM findings ≥0.70.
3. UNKNOWN if coverage <0.65 before any moderate verdict.
4. MODERATE if a MEDIUM finding ≥0.50 remains and coverage ≥0.65.
5. UNKNOWN if dangerous findings are below gates, or coverage <0.80 without findings.
6. LOW only when no CRITICAL/HIGH/MEDIUM findings exist and coverage ≥0.80.

`confidence_score` is the maximum decisive finding confidence for CRITICAL/HIGH/MODERATE. For
LOW and coverage-driven UNKNOWN it equals `data_coverage`; for an UNKNOWN caused solely by
dangerous findings below their confidence gates, it is the highest such finding confidence.
`hypothesis` tests assert all invariants.

Unlocked LP is HIGH only when a bounded Transfer-log replay plus `balanceOf` verification proves
that a single EOA controls at least the high threshold of LP supply. Without that proof, or when
the holder is a contract, the result is MEDIUM and the gap is stated in limitations. This avoids
treating an unrecognized locker or LP custodian as a proven rug vector.

## 9. Persistence

`storage/database.py` creates an async SQLAlchemy engine. `AssessmentRow` indexes chain, token,
slot/block, risk, coverage, version, and insertion sequence, while the full canonical report is
stored as JSON. `SQLAlchemyReportRepository` supports idempotent save, lookup by UUID,
latest/exact-block lookup, and recent listing. EVM addresses are checksum-normalized; Solana
Base58 addresses are preserved. SQLite is the default; any SQLAlchemy async URL (e.g. PostgreSQL)
can be injected for Flint Cloud. Monotonic insertion sequencing avoids timestamp-resolution ties
in latest-report queries.

## 10. Interfaces and security

- **CLI:** Typer + Rich, table and canonical JSON output, deterministic exit codes. Solana
  reports show a key-metrics panel and label the observation point as a slot.
- **API:** FastAPI endpoints `/v1/assess`, `/v1/health`, `/v1/detectors`; family-aware chain
  selector; bounded concurrency; strict body-size ASGI middleware; custom RPC off by default;
  DNS + IP SSRF validation when enabled; stable error envelope.
- **SDK:** `RugLensClient` (in-process) and `HttpRugLensClient` (remote), both accepting
  `"solana"` or chain selector 101.
- Metadata is sanitized at ingestion (ANSI/control/HTML stripping, bounded length).
- Slither remains an optional subprocess (AGPL boundary), with timeout, output cap, source-size
  cap, path traversal prevention, and best-effort process-tree termination.

## 11. Plugin boundary

`discover_plugins` imports files from `~/.ruglens/plugins/*.py`, validates IDs, and requires
plugins to set `required = False` and `coverage_area = None`. Supplying a coverage area is
rejected. The engine additionally strips any coverage area from non-required outcomes. Plugin
findings still participate in risk gates; plugin load errors appear as report limitations.

## 12. Benchmarks

`benchmark/dataset.py` loads JSONL, strips Solidity CBOR metadata, hashes normalized runtime
bytecode into family IDs, and provides family-aware random or temporal splits.
`benchmark/metrics.py` computes precision, recall, F1, FPR, Unknown Rate, P50/P95 latency, and
peak RSS. `benchmark/runner.py` records failures as UNKNOWN rather than dropping them. Benchmark
claims are only valid from executed runs.

## 13. Resource profile

At rest: Python process, SQLite, no GPU. Per EVM assessment: one shared chain client, concurrent
detector tasks, and at most `simulation_concurrency` Anvil forks. Each Anvil instance is
ephemeral. Per Solana assessment: one JSON-RPC client and at most eight bounded funding traces,
with no subprocess. The engine adds no background indexer, message queue, graph database, or
model runtime. Default per-assessment EVM simulation native balance is 0.1; gas limits and trade
size are configurable.

## 14. Architectural decisions and deviations

- Added `chains/evm/provider.py` to enforce the RPC response cap at the transport layer.
- Added `chains/evm/factory.py` so one process can serve multiple chains with a shared cache.
- Split the original `ConsensusEngine` concept into coverage, consensus, and evaluator modules
  so each invariant is independently testable.
- Added `benchmark/` Python package; this is the Milestone 4 ingestion/metrics engine behind the
  CLI command.
- Added a separate `chains/solana/` + `detectors/solana/` path instead of forcing Solana into EVM
  bytecode/call abstractions. Solana uses chain selector 101 and its own coverage profile.
- Solana Base58, PDA derivation, Ed25519 on-curve checks, account parsing, and Metaplex decoding
  are dependency-free Python. This keeps the image small and auditable.
- No ML, no source-code execution, no third-party security APIs, no fast-moving external
  blacklists.
- V1 intentionally supports only Uniswap V2-style WETH pairs on EVM and program-controlled
  custody detection (not exact depth/LP locks) on Solana.
