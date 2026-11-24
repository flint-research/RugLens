# Offline Integration Fixtures

Each JSON file in `integration/` is a synthetic, self-contained EVM scenario used by
`tests/integration/fixtures/test_offline_fixtures.py`. The loader builds an in-memory chain adapter
from metadata, bytecode, pair state, token balances, proxy slots, logs, and a fake simulation
result.

These fixtures are not real tokens, are not claims about any deployed contract, and must never be
used to compute benchmark accuracy. They exist to test end-to-end risk behavior without network
access.

| Fixture | Expected | Pattern |
| --- | --- | --- |
| `clean_token` | LOW | deep burned LP, dispersed holders, clean trade |
| `honeypot_token` | CRITICAL | buy succeeds, sell reverts |
| `tax_12pct` | MODERATE | measured sell tax above 10% |
| `tax_30pct` | HIGH | measured sell tax above 25% |
| `tax_60pct` | CRITICAL | measured sell tax above 50% |
| `mintable_eoa` | HIGH | mint selector + EOA owner |
| `blacklist_eoa` | MODERATE | blacklist selector + EOA owner |
| `proxy_admin_eoa` | HIGH | active EIP-1967 implementation + EOA admin |
| `unlocked_lp` | HIGH | zero burn/locked LP supply |
| `low_liquidity` | HIGH | 0.05 native reserve |
| `concentrated_holders` | HIGH | one holder controls nearly all circulating supply |
| `no_v2_pair` | UNKNOWN | dynamic coverage lost; no V2 pair |
| `partial_data` | UNKNOWN | metadata and pair absent; multiple detectors fail |
| `multisig_mint` | MODERATE | mint capability under a multisig |
| `gas_griefing` | MODERATE | sell gas above threshold |

Regenerate with:

```bash
python scripts/build_integration_fixtures.py
```

The generator is deterministic. If an expected risk changes because a rule changed, update the
fixture's rationale deliberately—never loosen a gate just to keep a test green.
