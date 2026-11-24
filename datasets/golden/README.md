# Golden Dataset

RugLens evaluates detection accuracy only from **executed benchmark runs** over
labeled, block-pinned records. No metric in the repository is a marketing claim.

## Files

- `bluechip.jsonl` — 10 real, widely held Ethereum tokens labeled `BENIGN`.
  This is the starting point for the mandatory blue-chip false-positive gate.
  It contains no scam labels and is not sufficient on its own for evaluating
  recall.
- Records may use EVM addresses (`0x...`, chain 1/56/8453) or Solana mint addresses
  (Base58, chain `101`). Solana results include creator/top-holder/cluster metrics.
- `schema.json` — machine-readable record schema.
- Scam fixtures are **not bundled by default** because commercial/commercial-
  incompatible dataset licenses must never leak into the Apache-2.0 repository.
  Curate scam records from sources listed in `07_DATA_AND_INTELLIGENCE.md` and
  keep `source_provenance` accurate.

## Record format (JSONL)

One JSON object per line:

```json
{
  "token_address": "0x...",
  "chain_id": 1,
  "deployment_block": 19100230,
  "evaluation_block": 19100500,
  "ground_truth_label": "SCAM_HONEYPOT",
  "contract_family_id": "sha256_normalized_bytecode",
  "verified_source": false,
  "source_provenance": "academic_dataset_v2",
  "notes": "Confirmed 100% sell tax triggered 200 blocks post-launch."
}
```

Optional `bytecode` enables local bytecode-family hashing. Otherwise supply a
precomputed `contract_family_id` from a trusted ingestion pipeline.

For Solana records (`chain_id: 101`), `token_address` is a Base58 mint. Standard Solana RPC
does not support historical account pinning, so benchmarks evaluate the current bank and treat
`evaluation_block` as advisory metadata.

## Leakage controls

1. **Bytecode-family deduplication:** Solidity CBOR metadata is stripped and the
   normalized runtime bytecode is hashed. All records sharing a family must stay
   in the same split. Use `ruglens.benchmark.dataset.family_split` or
   `temporal_family_split` rather than a naive random split.
2. **Temporal splitting:** Evaluate rules written in period T against tokens
   deployed in period T+1.

## Running

```bash
ruglens benchmark --dataset datasets/golden/bluechip.jsonl --rpc "$RUGLENS_ETH_RPC_URL"
```

The runner reports Precision, Recall, F1, FPR, Unknown Rate, P50/P95 latency,
peak RSS, and the confusion matrix. Predictions are positive only for
`CRITICAL`/`HIGH` classifications; `UNKNOWN` counts as not-flagged and is also
tracked separately. Reported latency and memory include the local engine process
and Anvil subprocess wall time, but peak RSS is measured for the Python worker.
