# Contributing to RugLens

Thanks for helping improve open, evidence-driven token security tooling.

## Ground rules

- Core detection must not wrap GoPlus, TokenSniffer, Honeypot.is, or similar APIs.
- No ML/GPU frameworks, full-chain indexers, or heavyweight infrastructure in V1.
- Findings must be backed by block-pinned on-chain state, bytecode evidence, or a local
  simulation trace.
- Safety over completeness: failed data must reduce coverage, never produce a clean verdict.
- By contributing, you agree your code is licensed under Apache-2.0 and documentation under
  CC-BY-4.0.

## Setup and checks

```bash
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pytest -q
```

Simulation tests require Foundry (`anvil`). They are local-only and skip when Anvil is absent.

## Solana changes

Read `docs/SOLANA.md` first. Solana changes must use direct JSON-RPC and the native
`SolanaTokenContext`; do not force them through EVM bytecode, `eth_call`, or the EVM coverage
weights. Do not claim sell-path, depth, or LP-lock verification that V1 does not implement. Add
or update offline Solana fixtures in `tests/solana_helpers.py` and
`tests/integration/fixtures/test_solana_engine.py`.

## Adding a detector

1. Read `docs/ARCHITECTURE.md` and the risk model.
2. Subclass `BaseDetector` in `src/ruglens/detectors/`.
3. Declare a unique detector ID, category, description, coverage role, and required status.
4. Return `DetectorOutcome` objects with explicit statuses, limitations, and coverage fraction.
5. Never calculate the final risk level or import another detector.
6. Add positive, negative, timeout, and failure tests. Add an offline fixture if the detector
   changes end-to-end risk.
7. If the detector is a plugin, set `required = False` and `coverage_area = None`.

New **required** coverage areas change the safety model and need an ADR plus updates to
`risk/coverage.py`, docs, and property tests.

## Rule changes

- Bump `rule_version` for changed evidence semantics.
- Add a regression fixture for every false positive/negative fix.
- Never weaken a confidence threshold to make a fixture pass; fix the rule instead.
- Do not publish accuracy claims without an executed benchmark over a family-deduplicated,
  time-split dataset.

## Security-sensitive changes

Changes touching RPC parsing, SSRF, subprocesses, plugins, metadata sanitization, persistence, or
API limits need explicit tests and a note in `SECURITY.md` if assumptions change. Report
vulnerabilities privately per `SECURITY.md`, not in a public issue.

## Pull requests

- Keep changes focused and explain the evidence model impact.
- Include the quality-gate output in the description.
- Update documentation where behavior or configuration changed.
- Do not include secrets, databases, coverage output, or contract build artifacts.
