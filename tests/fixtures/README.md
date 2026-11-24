# Test Fixtures

- `simulation_contracts.json` — compiled creation bytecode for `MockERC20` and `MockRouter`,
  exported from Foundry. Committed so CI only needs `anvil`, not `solc`/`forge`.
- Integration fixture JSON lives in `datasets/fixtures/integration/`.

Regenerate compiled bytecode after changing `contracts/src/MockDex.sol`:

```bash
forge build --root contracts
python scripts/export_simulation_contracts.py
pytest tests/integration/simulation/ -q
```

The simulation fixture is a minimal V2-shaped router/pair and ERC-20 with configurable buy/sell
tax and a sell-block switch. It exists only to validate tax measurement and honeypot detection on
a real local fork.
