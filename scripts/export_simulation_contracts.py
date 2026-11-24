"""Export compiled test contracts into a compact, committed fixture."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "contracts" / "out" / "MockDex.sol"
TARGET = ROOT / "tests" / "fixtures" / "simulation_contracts.json"


def main() -> None:
    payload: dict[str, dict[str, str]] = {}
    for name in ("MockERC20", "MockRouter"):
        artifact = json.loads((ARTIFACTS / f"{name}.json").read_text(encoding="utf-8"))
        payload[name] = {
            "bytecode": artifact["bytecode"]["object"],
            "deployed_bytecode": artifact["deployedBytecode"]["object"],
        }
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {TARGET}")


if __name__ == "__main__":
    main()
