# API Reference

Base URL: `http://127.0.0.1:8000` (default). OpenAPI UI: `/docs`.

## POST /v1/assess

Request:

```json
{
  "chain": "eth",
  "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "block_number": 20500000,
  "use_cached_report": true
}
```

- `chain`: slug (`eth`, `bsc`, `base`, `solana`), numeric chain id (`101` = Solana), or numeric
  string.
- `address`: EVM token contract address or Solana mint address.
- `block_number`: optional pinned EVM block; omitted means the current head. Solana rejects this
  in V1 because standard JSON-RPC has no historical account pinning.
- `rpc_url`: optional; rejected unless the server sets `RUGLENS_API_ALLOW_CUSTOM_RPC=true`, and
  always subject to SSRF validation.
- `use_cached_report`: use a stored assessment at the same chain/token/exact block (EVM).

Success: `200` with a canonical `AssessmentReport`:

```json
{
  "assessment_id": "…",
  "engine_version": "0.2.0",
  "chain_id": 1,
  "token_address": "0x…",
  "block_number": 20500000,
  "timestamp": "2026-11-24T12:00:00Z",
  "risk_level": "HIGH",
  "confidence_score": 0.9,
  "data_coverage": 1.0,
  "findings": [
    {
      "finding_id": "sha256…",
      "rule_id": "OWN-MINT-EOA-001",
      "rule_version": "1.0.0",
      "detector_id": "ownership",
      "category": "OWNERSHIP",
      "severity": "HIGH",
      "confidence": 0.88,
      "title": "Minting capability with live ownership",
      "description": "…",
      "evidence": {"owner": "0x…", "selectors": []},
      "references": [],
      "target": "0x…",
      "block_number": 20500000
    }
  ],
  "detector_statuses": {
    "bytecode_selectors": "SUCCESS",
    "dynamic_honeypot": "SUCCESS",
    "ownership": "SUCCESS",
    "liquidity": "SUCCESS",
    "holder_distribution": "SUCCESS",
    "slither_source": "SKIPPED"
  },
  "limitations": ["optional:slither_source status SKIPPED: No verified Solidity source files were supplied"],
  "token": {"name": "…", "symbol": "…", "decimals": 18, "total_supply": "…"},
  "summary": "HIGH risk; 1 finding(s); data coverage 100% across 10 detectors.",
  "metrics": {},
  "duration_ms": 1840.2,
  "rpc_calls": 23
}
```

### Solana example

```bash
curl -s -X POST http://127.0.0.1:8000/v1/assess \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}'
```

Solana reports include `metrics` such as:

```json
{
  "chain_family": "solana",
  "slot": 473391423,
  "token_program": "SPL Token",
  "creator": "…",
  "creator_holdings_pct": 12.5,
  "top1_holder_pct": 8.2,
  "top10_holder_pct": 34.1,
  "largest_cluster_size": 3,
  "largest_cluster_share_pct": 22.0,
  "cluster_probability": 0.61,
  "mint_authority_type": "multisig",
  "freeze_authority_type": "multisig",
  "metadata_update_authority_type": "multisig",
  "program_controlled_pct": 18.4,
  "liquidity_custody_pct": 18.4,
  "liquidity_depth_verified": false,
  "lp_lock_verified": false
}
```

`block_number` is the observed Solana slot. It is a reproducibility marker, not a request to
replay historical account state.

Errors use `{"detail": "..."}`:

| Status | Meaning |
| --- | --- |
| 400 | Unsupported chain, invalid EVM/Solana address, no bytecode/mint, custom RPC disallowed/unsafe |
| 413 | Request body exceeds `RUGLENS_API_MAX_BODY_BYTES` |
| 422 | Pydantic schema failure |
| 429 | Assessment worker pool saturated for `RUGLENS_API_QUEUE_TIMEOUT` seconds |
| 500 | Unexpected engine failure (sanitized) |
| 502 | Upstream RPC failure after retries |
| 503 | Engine not initialized |

## GET /v1/health

```json
{
  "status": "ok",
  "version": "0.2.0",
  "engine_ready": true,
  "anvil_available": true,
  "simulation_enabled": true,
  "detector_count": 10,
  "uptime_seconds": 123.4
}
```

Health does not call an RPC or spawn Anvil.

## GET /v1/detectors

```json
{
  "detectors": [
    {
      "detector_id": "bytecode_selectors",
      "category": "STATIC",
      "required": true,
      "coverage_area": "BYTECODE",
      "description": "pyevmasm disassembly: …",
      "origin": "builtin",
      "chain_family": "evm"
    },
    {
      "detector_id": "solana_clusters",
      "category": "CLUSTERS",
      "required": true,
      "coverage_area": "SOLANA_CLUSTERS",
      "description": "Bounded earliest-transaction funding trace …",
      "origin": "builtin",
      "chain_family": "solana"
    }
  ]
}
```

## Concurrency and timeouts

Assessments are gated by `RUGLENS_API_MAX_CONCURRENT` (default 2); a request that cannot acquire
a slot within `RUGLENS_API_QUEUE_TIMEOUT` (default 1 s) receives 429. Each detector has
`RUGLENS_DETECTOR_TIMEOUT` (default 90 s); Anvil forks are independently capped. A client timeout
below the detector budget may abort work that would otherwise complete; use at least a few
minutes for cold historical simulations.
