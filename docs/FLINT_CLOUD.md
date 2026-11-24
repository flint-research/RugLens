# Flint Cloud Integration

The open-source engine is intentionally stateless and free of authentication, tenants, billing,
and telemetry. Flint Cloud imports `ruglens` as a dependency and supplies managed infrastructure
around it.

## Stable contracts

- `AssessmentEngine.assess_token(chain_id, address, block_number=None, ...) -> AssessmentReport`
- `AssessmentReport.model_dump_json()` / `.to_json()`
- `Finding`, `DetectorOutcome`, and `DetectorStatus` schemas
- `ReportRepository` protocol
- `ChainAdapterFactory` and `TradeSimulatorFactory` injection points
- Detector registry and plugin boundary

## Injection points

| Concern | Open-source default | Flint Cloud option |
| --- | --- | --- |
| RPC | Public endpoints/env URLs | Managed EVM + Solana RPC pools, failover, quotas |
| Bytecode cache | Local SQLite | Shared immutable object cache |
| Reports | SQLite | PostgreSQL with tenant-scoped rows |
| Simulation | Local ephemeral Anvil | Isolated worker pool with memory caps |
| Solana holder/cluster RPC | Endpoint-supplied JSON-RPC | Dedicated high-rate Solana RPC with method allowlists |
| Detectors | Built-ins + local plugins | Reviewed rule bundles, signed releases |
| Auth/billing | None | Reverse proxy / control plane |

Immutable public-chain artifacts (EVM bytecode, block-pinned results, Solana mint/account
snapshots) may be shared globally, subject to report reproducibility. Solana observed-slot
results are not historical pins; store the slot and timestamp and treat them as point-in-time
evidence. Watchlists, alert subscriptions, webhooks, and per-tenant history must remain isolated
by `tenant_id` outside the core package.

## Scaling notes

- Each simulation worker is CPU-light but memory-bounded; schedule by fork concurrency, not by
  request count alone.
- Share the block-aware bytecode cache across workers; never share Anvil processes.
- Persist `assessment_id`, chain/token/block, engine/rule versions, and canonical JSON; do not
  store only the risk level.
- Reports are immutable. A new engine version or rule version creates a new report.
- Use the `Finding.finding_id` and report IDs as idempotency keys for webhooks.

## Ecosystem handoffs

- **SwarmSec:** ABIs, bytecode hashes, privileged selectors, proxy architecture.
- **Pathmark:** deployer/LP creator addresses and suspicious holder clusters.
- **CloneHunter / ContractMap:** normalized bytecode family IDs from the benchmark module.

No commercial code, tenant table, or SaaS credential belongs in this repository.
