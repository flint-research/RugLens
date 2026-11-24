# Solidity Test Contracts

`src/MockDex.sol` contains minimal, test-only contracts:

- `MockERC20`: fixed 18 decimals, configurable buy/sell tax, router-aware sell blocking,
  mint/approve/transfer/transferFrom.
- `MockRouter`: V2-shaped reserves, `getAmountsOut`, and fee-on-transfer buy/sell functions.

They are deployed to a local origin Anvil chain by
`tests/integration/simulation/test_trade_sim.py`; a second Anvil forks that origin at a pinned
block and runs the real `TradeSimulator`. Nothing is deployed to a live network.

Only compiled creation bytecode (`tests/fixtures/simulation_contracts.json`) is required at test
time. Rebuild:

```bash
forge build --root contracts
python scripts/export_simulation_contracts.py
```

The contracts are test fixtures, not audited production code, and are excluded from the Python
package and Docker image.
