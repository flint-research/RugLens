# Development and Operations

## 1. Environment audit (this build)

Measured in the repository development environment on 2026-11-24:

| Resource | Value |
| --- | --- |
| OS | Windows (PowerShell), x86_64 |
| Python | 3.13.9 at `C:\Users\thege\AppData\Local\Programs\Python\Python313\python.exe` |
| RAM | 7,371,540 KiB total; ~724,496 KiB free at audit time |
| Disk free | 17,340,674,048 bytes (~16.1 GiB) |
| GPU | None |
| Foundry | anvil 1.5.1-stable, cast 1.5.1-stable, forge 1.5.1-stable |
| Docker | Not installed in the development VM |
| Package manager | `uv` 0.13.0; pip 26.2.2 |

`anvil` was present, so no Foundry installation was required. The repository keeps this audit
and the installation path for machines where Foundry is missing.

## 2. Prerequisites

- Python 3.11, 3.12, or 3.13.
- `uv` (recommended) or `pip`.
- Foundry for dynamic simulation:
  - Linux/macOS: `curl -L https://foundry.paradigm.xyz | bash && foundryup`
  - Windows (PowerShell): `irm https://foundry.paradigm.xyz | iex`, then `foundryup`
  - Verify: `anvil --version && cast --version`
- Optional: `slither-analyzer` if you want source analysis. Do not add it to core dependencies;
  it is AGPL-3.0 and must remain an external CLI.
- Optional: Docker + Compose v2 for container self-hosting.

## 3. Setup

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
uv pip install -e ".[dev]"
```

Or with pip:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the CLI:

```bash
ruglens version
ruglens detectors
```

## 4. RPC configuration

RPC URLs are resolved in this order:

1. repeatable `--rpc` flags,
2. `RUGLENS_RPC_URL_ETHEREUM`, `RUGLENS_ETH_RPC_URL`, or `RUGLENS_RPC_URL_1` (and equivalents
   for BSC/Base),
3. built-in public endpoints.

Comma-separated lists provide failover. Use an archive-capable endpoint for historical
`--block` assessments, because Anvil must fetch storage at that block.

```bash
export RUGLENS_RPC_URL_ETHEREUM="https://primary.example,https://fallback.example"
```

Recommended provider capabilities: `eth_call`, `eth_getCode`, `eth_getStorageAt`,
`eth_getLogs` over multi-million block windows, and historical state at the target block. Rate
limits should exceed the token-bucket setting (default 20 req/s).

### Solana RPC

```bash
export RUGLENS_RPC_URL_SOLANA="https://primary-solana.example,https://fallback.example"
```

A Solana assessment needs these standard methods:

- `getSlot`
- `getAccountInfo` with `jsonParsed` and Base64 encodings
- `getMultipleAccounts`
- `getTokenLargestAccounts`
- `getTokenAccountsByOwner`
- `getSignaturesForAddress`
- `getTransaction` with `maxSupportedTransactionVersion: 1`

Many free/public endpoints return HTTP 403 or aggressive rate limits for holder and funding
methods. That is handled as missing coverage (often `UNKNOWN`), not as safe. Use a paid/private
endpoint for reliable Solana holder and cluster analysis. Solana reads are at the current
confirmed bank; historical slot pinning is not supported by standard JSON-RPC, so `--block` is
rejected for Solana.

`getTransaction` version 1 is requested so newer transactions can be parsed. Creator inference is
skipped when the mint's signature window is saturated; metadata creators are preferred. A
`creator` metric may therefore be absent for old or very active mints.

## 5. Quality gates

These are mandatory before a task is marked complete:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pytest tests/unit/
pytest tests/integration/fixtures/
pytest tests/integration/simulation/     # requires anvil
```

The complete suite, with the core/risk coverage floor:

```bash
pytest -q --cov=ruglens.core --cov=ruglens.risk --cov-report=term-missing --cov-fail-under=80
```

Current measured result in the development VM: all tests pass; core/risk line coverage exceeds
the 80% CI gate. Coverage and accuracy numbers are not claims until produced by the current
commit.

## 6. Test tiers

| Path | Network | Anvil | Notes |
| --- | --- | --- | --- |
| `tests/unit/` | No | No | Models, config, risk, selectors, EVM/Solana detectors, Base58/PDA, SSRF |
| `tests/benchmarks/` | No | No | Golden ingestion, family splits, metrics, runner |
| `tests/integration/fixtures/` | No | No | 15 end-to-end EVM patterns and 4 Solana scenarios |
| `tests/integration/` (other) | Loopback only | Passes only in simulation tests | HTTP RPC fake servers, SQLite, API, SDK, CLI |
| `tests/integration/simulation/` | Loopback only | Yes | Real Solidity fixtures, fork, tax/honeypot measurement |

Simulation tests are marked `@pytest.mark.simulation` and skip if `anvil` or compiled contract
fixtures are unavailable. They start a local origin chain, deploy committed bytecode, fork it,
and execute real swaps. They never contact a live chain. Solana tests use a scripted JSON-RPC
adapter and run fully offline; V1 does not run a Solana local validator or sell-path simulation.

## 7. Rebuilding test contracts

The compiled Solidity fixtures are committed, so CI does not need `solc`.

```bash
forge build --root contracts
python scripts/export_simulation_contracts.py
```

This writes `tests/fixtures/simulation_contracts.json` from Foundry artifacts. Only anvil/cast
are needed to run tests; forge/solc are only needed to change the contracts.

## 8. Regenerating offline integration fixtures

```bash
python scripts/build_integration_fixtures.py
pytest tests/integration/fixtures/ -q
```

The generator writes deterministic synthetic token patterns to
`datasets/fixtures/integration/`. These are test patterns, not real-token claims and not
benchmark accuracy data.

## 9. Docker

```bash
cp .env.example .env      # edit RPC URLs
docker compose -f docker/docker-compose.yml up --build
curl http://127.0.0.1:8000/v1/health
```

The image runs as a non-root user, bundles Anvil from the official Foundry image, drops all
capabilities, uses `init` to reap child processes, and defaults to one concurrent simulation.
The Docker build is validated by CI. It was not run in the development VM because Docker was
not installed.

## 10. Plugins

Create `~/.ruglens/plugins/my_detector.py` (or set `RUGLENS_PLUGIN_DIR`). Requirements:

- subclass `BaseDetector`;
- implement `async def detect(...)`;
- set `required = False`;
- set `coverage_area = None`;
- use a unique lowercase `detector_id` (3–64 chars: `[a-z0-9_]`).

The loader rejects plugins that claim a coverage area or duplicate a built-in ID. Plugin errors
are surfaced in the report's limitations. Plugins run with full process privileges; only enable
directories you trust. Plugin discovery is EVM-only in V1; Solana detectors are built-ins using
the Solana token context.

## 11. Optional Slither

```bash
pip install slither-analyzer
RUGLENS_SLITHER_ENABLED=true ruglens assess 0xToken --chain eth --source-dir path/to/sources
```

Boundaries: 15 s timeout, 5 MB output cap, 2 MB combined source cap, 50-file cap, safe path
normalization, and process-tree termination. Slither findings are supplementary and do not
affect coverage.

## 12. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Anvil executable ... not found` | Install Foundry or set `RUGLENS_ANVIL_BINARY` |
| Solana `HTTP 403` / `rate limited` on holder calls | Public RPC blocks `getTokenLargestAccounts`/`getTokenAccountsByOwner`/funding methods; use a paid/private Solana RPC |
| Solana `UNKNOWN` with holder/liquidity FAILED | Holder/custody data was unavailable; coverage dropped as designed |
| Solana creator metric absent | Metadata has no creators and mint signature history exceeded the bounded window; RugLens refuses to guess |
| Solana `getTransaction` version error | The RPC does not support `maxSupportedTransactionVersion: 1`; upgrade/change provider |
| `--block` rejected for Solana | Standard JSON-RPC has no historical account pinning; use the observed slot |
| Solana `cluster_probability` high but no HIGH finding | Probability is a heuristic; findings require the configured cluster share and minimum wallet count |
| Dynamic detector `SKIPPED: no V2 pair` | Token is not on the configured V2 venue; coverage drops |
| Dynamic detector `FAILED` / `TIMEOUT` | RPC lacks historical state, rate limit, or fork too slow; use an archive RPC |
| `EVM error NotActivated` on a local fork | Very low block numbers on chain-id 1 predate PUSH0/Shanghai; fork a modern block or use an unknown local chain id in tests |
| `LIQ-LOCK-UNVERIFIED-001` | One or more LP holder balance calls failed; do not assume locked |
| `UNKNOWN` verdict | Normal fail-closed behavior when coverage <0.65/<0.80 or data is missing |
| API `400 Custom RPC URLs are disabled` | Operator has not set `RUGLENS_API_ALLOW_CUSTOM_RPC=true` |
| Rate-limit retries | Lower `RUGLENS_RPC_RATE_LIMIT`, add endpoints, or use a paid RPC |
| Anvil port or Windows firewall prompt | Anvil binds localhost; allow local loopback or run in Docker/Linux |

## 13. Resource discipline

- Never run more than two Anvil forks by default; `simulation_concurrency` is enforced by a
  semaphore.
- Every fork has startup, RPC, simulation, and shutdown deadlines.
- Do not add ML/GPU dependencies or a live-chain indexer.
- RPC responses are streamed with a 5 MB cap. Bytecode above 50 KB is rejected.
- Holder replay is bounded by lookback, chunk count, and max events; truncation is disclosed
  as reduced coverage and a limitation.
- Solana holder analysis uses the largest 20 accounts and at most 8 funding traces by default;
  both the bound and resulting partial coverage are disclosed.
- Subprocesses (Anvil, Slither) must always be terminated in `finally`.

## 14. Release checklist

1. `ruff`, `ruff format --check`, `mypy`, full `pytest` all green.
2. Core/risk coverage gate green.
3. No new third-party security API, ML framework, or GPU dependency.
4. If EVM rules changed: bump `rule_version`, add a fixture, and regenerate benchmark results.
5. If Solana rules changed: update `docs/SOLANA.md`, thresholds, offline scenarios, and note the
   observed-slot/limitation semantics.
6. If schemas changed: update docs and the Flint Cloud contract notes.
7. Docker build job green.
8. Tag the release; never mutate published reports or rules in place.
