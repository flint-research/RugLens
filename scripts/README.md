# Scripts

- `build_integration_fixtures.py` — regenerate synthetic offline token fixtures.
- `export_simulation_contracts.py` — export compiled Foundry bytecode into the committed test
  fixture used by local Anvil simulation tests.

Both scripts are deterministic and require no network access once Foundry artifacts exist for the
contract exporter. They are development tools, not runtime dependencies.
