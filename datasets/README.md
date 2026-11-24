# Datasets

- `golden/` — labeled JSONL records for benchmark runs. Includes a 10-token benign blue-chip seed
  set and the schema. Scam labels must come from appropriately licensed sources.
- `fixtures/` — offline test fixtures. `integration/` contains synthetic token patterns used by
  the full pipeline tests; they are not real-token claims or accuracy data.

Golden records are validated and family-hashed at load time. See
[`golden/README.md`](golden/README.md) and [`fixtures/README.md`](fixtures/README.md).
