# RugLens

**Open-source, evidence-driven rug-pull and token-risk detection for EVM chains and Solana.**

RugLens is built by [Flint Research](https://github.com/flint-research). On EVM it inspects
bytecode, measures real buy/sell behaviour on an isolated Foundry Anvil fork, and verifies DEX
liquidity and holder concentration. On Solana it reads mint/freeze/metadata authorities,
Token-2022 extensions, creator holdings, top-holder concentration, and funding-linked holder
clusters directly from JSON-RPC. Both paths return a categorical risk verdict with structured
evidence. RugLens does not call GoPlus, TokenSniffer, Honeypot.is, RugCheck, or any other
security API.

```
CRITICAL · HIGH · MODERATE · LOW · UNKNOWN       +       data_coverage 0.0–1.0
```

A LOW verdict is impossible below 80% data coverage. Missing RPC state, failed detectors, or
unusable liquidity degrades coverage and yields UNKNOWN unless a CRITICAL or HIGH risk was
already proven.

---

## Why RugLens

- **No opaque score.** Catastrophic evidence is not averaged away into a 0–100 number.
- **No silent safety.** Detector failures reduce coverage; they never produce a clean result.
- **No external security APIs.** Core detection runs from direct RPC state, local bytecode
  analysis, and isolated simulations.
- **Block-pinned reproducibility.** Reports record chain, token, block, engine version, rule
  versions, and structured evidence.
- **Apache-2.0 core.** Self-host locally or inside a private VPC with no telemetry.

## Status

| Milestone | Scope | State |
| --- | --- | --- |
| 1 | Core models, RPC/cache, Anvil simulation, bytecode + honeypot detectors, risk engine, CLI | Complete |
| 2 | Ownership/proxy, liquidity, holder concentration, optional Slither, 15 offline fixtures | Complete |
| 3 | FastAPI, SDK, SQLite persistence, Docker packaging | Complete (Docker config not executed in the development VM; built in CI) |
| 4 | Golden data ingestion, benchmark runner, plugins, CI, docs | Complete; live accuracy metrics require a funded archival RPC and are deliberately not claimed |
| 5 | Native Solana rug profile: authorities, Token-2022, creator/holders, funding clusters, liquidity custody | Complete (see [`docs/SOLANA.md`](docs/SOLANA.md)) |

## Requirements

- Python **3.11+**
- **Foundry** (`anvil`, `cast`) for EVM dynamic simulation. Installation:
  <https://book.getfoundry.sh/getting-started/installation>
- An HTTP(S) archive-capable EVM RPC endpoint for historical block simulations (public endpoints
  are enough for recent blocks on Ethereum/BSC/Base, but not for arbitrary historical forks).
- A Solana JSON-RPC endpoint for Solana assessments. It must allow `getTokenLargestAccounts`,
  `getTokenAccountsByOwner`, `getSignaturesForAddress`, and `getTransaction` with
  `maxSupportedTransactionVersion: 1`. Many free endpoints block or aggressively rate-limit
  these methods; use a paid/private endpoint for reliable holder and cluster analysis.
- No GPU. The engine is designed to run inside roughly 1.5 GB per assessment worker.

## Install

```bash
git clone https://github.com/flint-research/ruglens.git
cd ruglens
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Install optional source analysis separately; it is never imported in-process:

```bash
pip install slither-analyzer
```

## Quickstart

```bash
export RUGLENS_RPC_URL_ETHEREUM="https://your-archive-rpc.example"
ruglens assess 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --chain eth
```

Pin an exact block for a reproducible review, and emit machine-readable JSON:

```bash
ruglens assess 0xTokenAddress --chain base --block 12345678 --json --output report.json
```

Solana uses a mint address and a native assessment path:

```bash
export RUGLENS_RPC_URL_SOLANA="https://your-solana-rpc.example"
ruglens assess EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --chain solana
ruglens assess <SOLANA_MINT> --chain solana --json --output solana-report.json
```

The Rich output includes a **Key metrics** panel with creator %, top-1/top-10 holder %, largest
cluster share, cluster probability, program-controlled custody %, and authority state.

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--chain/-c` | `eth`, `bsc`, `base`, `solana`, or a numeric chain id |
| `--rpc` | Repeatable RPC URL list for failover |
| `--block/-b` | Pin an EVM assessment to a block (Solana V1 records the observed slot) |
| `--json` | Emit the canonical `AssessmentReport` JSON |
| `--no-sim` | Skip EVM Anvil simulation; coverage drops by 35 points |
| `--no-store` | Do not read/write the local report database |
| `--refresh` | Ignore a cached block-pinned report |
| `--source-dir` | Supply verified `.sol` files for optional Slither (EVM only) |

List detectors:

```bash
ruglens detectors
```

## How an assessment works

1. **Validate & pin** the chain and checksummed token address, then resolve the assessment
   block (latest or caller-supplied).
2. **Hydrate context** with batched `Multicall3` reads: ERC-20 metadata, V2 pair discovery,
   reserves, LP supply, and burn/locker balances. Bytecode is cached immutably in SQLite.
3. **Run detectors concurrently** with per-detector deadlines:
   - static selector/opcode analysis (`pyevmasm`),
   - dynamic buy → approve → sell simulation on a pinned Anvil fork,
   - ownership/governance and EIP-1967 proxy inspection,
   - liquidity depth and LP burn/lock verification,
   - bounded Transfer-log holder concentration,
   - optional isolated Slither CLI over supplied sources.
4. **Consolidate evidence**: deduplicate findings, preserve every source payload, compute
   weighted coverage, apply veto/escalation gates.
5. **Persist and report** the immutable `AssessmentReport` (CLI table/JSON, REST, SDK).

### Detectors

EVM:

| Detector ID | Coverage weight | What it proves |
| --- | ---: | --- |
| `bytecode_selectors` | 0.25 | Mint/blacklist/pause/tax/upgrade selectors and dangerous opcodes |
| `dynamic_honeypot` | 0.35 | Sell reverts, measured buy/sell tax, gas griefing |
| `ownership` | 0.15 | Owner type, mint contextualization, active EIP-1967 proxy/admin |
| `liquidity` | 0.20 | V2 native depth, LP burned/locked percentage |
| `holder_distribution` | 0.05 | Top-10 concentration excluding pairs and burn addresses |
| `slither_source` | optional | Supplementary source-level findings; never affects coverage |

Solana (weights sum to 1.0; no EVM dynamic-trade area):

| Detector ID | Coverage weight | What it proves |
| --- | ---: | --- |
| `solana_authorities` | 0.30 | Mint/freeze authority type, metadata mutability, Token-2022 risks |
| `solana_holders` | 0.30 | Creator %, top-1/top-10 retail concentration, burn/custody exclusion |
| `solana_clusters` | 0.25 | Common earliest funder groups, cluster share, cluster probability |
| `solana_liquidity` | 0.15 | Program-controlled custody presence; explicitly does not claim depth/LP lock |

Solana authority findings are contextualized: an SPL multisig or program-controlled authority
is reported as MEDIUM (or LOW for metadata), while a single-wallet authority is HIGH. This avoids
labeling a centralized stablecoin's multisig-controlled mint as if a single EOA held it.

### Solana creator/cluster metrics

RugLens returns `metrics` alongside findings:

- `creator_holdings_pct` — creator token balance as a share of circulating supply.
- `top1_holder_pct`, `top10_holder_pct` — retail wallets only; pool/PDA/burn accounts excluded.
- `largest_cluster_share_pct` — supply held by wallets sharing an earliest funding source.
- `cluster_probability` — transparent heuristic from linked-wallet count, share, and creator link,
  **not** a calibrated statistical probability.
- `mint_authority_type`, `freeze_authority_type`, `metadata_update_authority_type` — wallet,
  multisig, program-controlled, or unknown.
- `liquidity_custody_pct` — supply in program-controlled accounts; depth and LP lock are not
  verified.

Thresholds default to creator >10%/>20%, top-1 >10%/>20%, top-10 >30%/>50%, and cluster
>=10%/>30% of circulating supply. They are configurable. See [`docs/SOLANA.md`](docs/SOLANA.md)
for the research basis and exact methodology.

### Risk gates

| Result | Deterministic condition |
| --- | --- |
| CRITICAL | A CRITICAL finding with confidence ≥ 0.85 (e.g., confirmed honeypot, >50% tax) |
| HIGH | A HIGH finding with confidence ≥ 0.70, or ≥3 independent MEDIUM findings ≥ 0.70 |
| MODERATE | At least one MEDIUM finding (confidence ≥ 0.50), coverage ≥ 0.65, no higher gate |
| LOW | No CRITICAL/HIGH/MEDIUM findings and coverage ≥ 0.80 |
| UNKNOWN | Coverage < 0.65, coverage < 0.80 without findings, or dangerous findings below gates |

Findings are block-pinned and hashed (`sha256(rule_id|target|block)`). Buy/sell taxes are
measured against router quotes, not inferred from source code. Capabilities such as `mint()`
are not conflated with proven exploits.

## REST API

```bash
ruglens serve --host 127.0.0.1 --port 8000
```

```bash
curl -s http://127.0.0.1:8000/v1/health | jq
curl -s -X POST http://127.0.0.1:8000/v1/assess \
  -H "Content-Type: application/json" \
  -d '{"chain":"eth","address":"0x...","block_number":20500000}' | jq
curl -s -X POST http://127.0.0.1:8000/v1/assess \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}' | jq
```

Endpoints:

- `POST /v1/assess` — full assessment, validates the address and optionally a custom RPC URL.
- `GET /v1/health` — engine/Anvil/simulation capability and uptime.
- `GET /v1/detectors` — EVM and Solana detector metadata, coverage roles, and family.
- OpenAPI docs at `/docs`.

Solana responses include the same `AssessmentReport` structure plus a `metrics` object. The
recorded `block_number` is the observed Solana slot; standard JSON-RPC does not provide
historical account pinning.

Security defaults: request bodies are capped at 32 KiB, custom RPC URLs are disabled, and when
enabled they are DNS-resolved and rejected for loopback, RFC 1918, link-local, CGNAT, and
other internal ranges. Metadata is stripped of ANSI/control characters and angle brackets
before it reaches a terminal or JSON consumer. RPC responses are streamed and hard-capped at
5 MB.

## Python SDK

```python
import asyncio
from ruglens.core.config import RugLensSettings
from ruglens.interfaces.sdk import RugLensClient, HttpRugLensClient

async def main() -> None:
    settings = RugLensSettings.from_env()
    async with RugLensClient(settings) as client:
        report = await client.assess("eth", "0xTokenAddress", block_number=20_500_000)
        print(report.risk_level, report.data_coverage)

    async with HttpRugLensClient("http://127.0.0.1:8000") as api:
        report = await api.assess("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        print(report.model_dump_json(indent=2))
        print(report.metrics["cluster_probability"])

asyncio.run(main())
```

## Configuration

All settings use `RUGLENS_*` environment variables. See `.env.example` and
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md). Core controls:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RUGLENS_RPC_URL_ETHEREUM` / `_BSC` / `_BASE` | public endpoints | Comma-separated EVM failover list |
| `RUGLENS_RPC_URL_SOLANA` | public endpoints | Solana JSON-RPC failover list |
| `RUGLENS_SIMULATION_CONCURRENCY` | `2` | Hard cap on concurrent Anvil forks |
| `RUGLENS_DETECTOR_TIMEOUT` | `90` | Per-detector deadline (seconds) |
| `RUGLENS_SIMULATION_TIMEOUT` | `60` | Whole trade-simulation deadline |
| `RUGLENS_DATA_DIR` | `~/.ruglens` | Cache, reports, plugins |
| `RUGLENS_API_ALLOW_CUSTOM_RPC` | `false` | Enable caller-supplied RPC URLs |
| `RUGLENS_SLITHER_ENABLED` | `false` | Opt into isolated Slither analysis |
| `RUGLENS_SOLANA_CLUSTER_MAX_WALLETS` | `8` | Holder wallets traced for funding links |
| `RUGLENS_SOLANA_CREATOR_HIGH_PCT` | `0.20` | Creator HIGH threshold (fraction of circulating) |
| `RUGLENS_SOLANA_TOP10_HIGH_PCT` | `0.50` | Top-10 HIGH threshold |
| `RUGLENS_SOLANA_CLUSTER_HIGH_PCT` | `0.30` | Linked-cluster HIGH threshold |

RPC override precedence: repeatable `--rpc` > chain-specific env var > built-in public
endpoints.

## Benchmarks

Golden datasets are JSONL and bytecode-family aware:

```bash
ruglens benchmark \
  --dataset datasets/golden/bluechip.jsonl \
  --rpc "$RUGLENS_RPC_URL_ETHEREUM" \
  --output benchmark-report.json
```

The runner reports Precision, Recall, F1, FPR, Unknown Rate, P50/P95 latency, peak RSS, and
the confusion matrix. Only measured runs may be cited. The repository ships a 10-token benign
EVM blue-chip set; scam labels must be supplied from appropriately licensed sources. Solana
records use chain `101` and Base58 mint addresses. Solidity CBOR metadata is stripped before
family hashing, and family/temporal splits prevent evaluation leakage. See
[`datasets/golden/README.md`](datasets/golden/README.md).

## Custom plugins

Place Python files in `~/.ruglens/plugins/` (or `RUGLENS_PLUGIN_DIR`). A plugin subclasses
`BaseDetector` and must declare `required = False` and `coverage_area = None`, so a broken or
malicious plugin cannot inflate coverage. Plugins are trusted local code and run in-process.

```python
from ruglens.core.interfaces import BaseDetector
from ruglens.core.enums import DetectorCategory

class MyDetector(BaseDetector):
    detector_id = "my_detector"
    category = DetectorCategory.STATIC
    coverage_area = None
    required = False
    description = "My custom check"

    async def detect(self, context, dependencies):
        return self.make_outcome()
```

Plugin load failures are reported as report limitations. Plugins are EVM-only in V1; Solana
detectors are built-in and use the native Solana context. See `docs/ARCHITECTURE.md`.

## Docker

```bash
docker compose -f docker/docker-compose.yml up --build
curl http://127.0.0.1:8000/v1/health
```

The image is multi-stage, runs as UID 10001, bundles Anvil from the official Foundry image,
drops Linux capabilities, enables `init` for zombie reaping, and uses a 1.5 GB memory limit
with simulation concurrency 1 by default. Set RPC environment variables in `.env` or your
shell before starting.

> The development environment used to build this repository had no Docker daemon. The image
> build is exercised by `.github/workflows/ci.yml`; local `docker compose up` was not executed
> here.

## Development

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pytest -q
pytest -q --cov=ruglens.core --cov=ruglens.risk --cov-fail-under=80
```

- Unit + property-based + offline fixture tests need no network.
- `tests/integration/simulation/` spawns real Anvil processes and compiles/uses committed
  Solidity fixtures. Tests skip cleanly if `anvil` is absent.
- Regenerate compiled test contracts with `forge build --root contracts` followed by
  `python scripts/export_simulation_contracts.py`.
- Regenerate synthetic offline fixtures with `python scripts/build_integration_fixtures.py`.

The suite includes 15 end-to-end offline EVM token patterns, four offline Solana scenarios
with creator/cluster metrics, a property-based proof suite for risk invariants, and a real
forked buy/approve/sell test (clean, 10% tax, honeypot). API, SSRF, body-limit, storage, SDK,
Solana RPC-client, and benchmark tests also run offline; live Solana RPC smoke checks are manual.

## Security model

- No wallet connection, private key, signature, or live transaction is ever requested or sent.
- All analysis is read-only or executed on a local, non-broadcasting Anvil fork.
- Solana reads are read-only JSON-RPC; token-account state is observed at the current confirmed
  bank and is not replayed.
- Anvil forks are gated by a semaphore, hard timeouts, and guaranteed `try/finally`
  termination.
- Token metadata is untrusted; it is sanitized before display or serialization.
- Third-party RPC payloads are size-capped; malformed data fails closed.
- Slither is optional, invoked as an external CLI (AGPL boundary), and never imported into the
  core.
- Report persistence stores only public on-chain evidence; there is no tenant/billing/auth
  state in the open-source core.

Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).

## Known limitations

- V1 simulates **Uniswap V2 / PancakeSwap V2 / BaseSwap V2** pairs only. Tokens with liquidity
  exclusively on V3/other venues lose dynamic and liquidity coverage and trend toward UNKNOWN.
- Simulations require an archive-capable RPC for historical blocks; public endpoints may rate
  limit or lack old state.
- Holder analysis replays a bounded Transfer-log window; very old or highly active tokens may
  be flagged as partially covered.
- Dynamic taxes are measured for a 0.1 native-currency trade at the pinned block; they are not
  a promise about other sizes or future state.
- Recognition of multisigs, timelocks, and LP lockers is interface-based and non-exhaustive.
  `LIQ-LOCK-UNVERIFIED-001` exists to avoid claiming certainty when balances cannot be read.
  HIGH unlocked-LP requires proof of a majority EOA holder; unrecognized contract custody is
  downgraded to MEDIUM with a limitation rather than overstated.
- Source/AST analysis is optional and off by default. RugLens never autonomously updates rules
  or thresholds.
- Solana V1 has **no sell-path simulation** because there is no single canonical V2-style swap
  call. It instead uses native authority, Token-2022, holder, funding-cluster, and custody
  evidence. Solana liquidity **depth and LP lock status are explicitly unverified**; no HIGH
  liquidity verdict is issued from an unrecognized venue.
- Solana creator percentage depends on Metaplex creators or an earliest mint transaction. If the
  mint has a large signature history, creator inference is skipped and the metric is absent rather
  than guessed.
- Solana top-holder percentages use the 20 largest token accounts, aggregate them by wallet, and
  exclude burn and off-curve/program-controlled accounts. This is not a full holder census.
- Solana cluster probability is a transparent heuristic (linked-wallet count + supply share +
  creator link), not a statistical model. Exchange-funded wallets can produce false correlations.
- Standard Solana JSON-RPC does not provide historical account pinning. The report records the
  observed slot as a reproducibility marker; `--block` is rejected for Solana.

## Project layout

```text
src/ruglens/
  core/          domain enums, models, interfaces, config, Solana models, sanitization
  chains/        EVM and Solana RPC clients, registries, caches, Base58/PDA/parsers
  simulation/    Anvil lifecycle manager, EVM trade simulator, provider
  detectors/     EVM static/dynamic/on-chain, Solana authorities/holders/clusters/liquidity
  risk/          deduplication, weighted coverage profiles, veto/escalation gates
  storage/       async SQLAlchemy report persistence
  benchmark/     golden ingestion, family splits, metrics, runner
  orchestrator/  end-to-end EVM and Solana assessment engines
  interfaces/    Typer CLI, FastAPI API, async SDK
docs/            architecture, Solana methodology, development, roadmap, ADRs
datasets/        offline integration fixtures and golden templates
contracts/       Solidity fixtures used only by simulation tests
tests/           unit, integration, simulation, benchmarks, Solana fixtures
docker/          multi-stage image and compose file
```

Architecture decisions and dependency rules: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Setup, environment audit, and operations: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## License

Code: Apache-2.0 (`LICENSE`). Documentation: CC-BY-4.0. Slither is AGPL-3.0 and is not
bundled; users who opt in install and run it separately.
