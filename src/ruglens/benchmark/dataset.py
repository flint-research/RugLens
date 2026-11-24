"""Golden dataset ingestion, metadata normalization, and leak-free splitting."""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Self

from eth_utils.address import is_address, to_checksum_address
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ruglens.chains.solana.base58 import is_valid_pubkey


class GoldenRecord(BaseModel):
    """One labeled, reproducible golden-dataset entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_address: str
    chain_id: int = Field(gt=0)
    deployment_block: int = Field(ge=0)
    evaluation_block: int | None = Field(default=None, ge=0)
    ground_truth_label: str
    contract_family_id: str | None = None
    verified_source: bool = False
    source_provenance: str = "unknown"
    notes: str = ""
    bytecode: str | None = None

    @field_validator("token_address")
    @classmethod
    def _address(cls, value: str) -> str:
        if is_address(value):
            return to_checksum_address(value)
        if is_valid_pubkey(value):
            return value
        raise ValueError(f"invalid EVM or Solana token address: {value}")

    @field_validator("ground_truth_label")
    @classmethod
    def _label(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized != "BENIGN" and not normalized.startswith("SCAM_"):
            raise ValueError("label must be BENIGN or SCAM_<TYPE>")
        return normalized

    @field_validator("bytecode")
    @classmethod
    def _bytecode(cls, value: str | None) -> str | None:
        if value is None:
            return None
        raw = value[2:] if value.startswith("0x") else value
        try:
            bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError("bytecode is not valid hex") from exc
        return "0x" + raw.lower()

    @model_validator(mode="after")
    def _window(self) -> Self:
        if self.evaluation_block is not None and self.evaluation_block < self.deployment_block:
            raise ValueError("evaluation_block precedes deployment_block")
        if self.chain_id == 101:
            if not is_valid_pubkey(self.token_address):
                raise ValueError("Solana golden records require a Base58 mint address")
        elif not is_address(self.token_address):
            raise ValueError("EVM golden records require an EVM token address")
        return self

    @property
    def is_scam(self) -> bool:
        """Whether the label is a positive (scam) class."""
        return self.ground_truth_label != "BENIGN"


def load_golden_dataset(path: Path | str) -> list[GoldenRecord]:
    """Read JSONL golden records with strict size and line validation."""
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Golden dataset does not exist: {source}")
    if source.stat().st_size > 100_000_000:
        raise ValueError("Golden dataset exceeds 100 MB")
    records: list[GoldenRecord] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if len(stripped) > 2_000_000:
                raise ValueError(f"Line {line_number} exceeds 2 MB")
            try:
                payload = json.loads(stripped)
                records.append(GoldenRecord.model_validate(payload))
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"Invalid golden record on line {line_number}: {exc}") from exc
    if not records:
        raise ValueError("Golden dataset is empty")
    return assign_family_ids(records)


def strip_solidity_metadata(bytecode: bytes) -> bytes:
    """Remove trailing Solidity CBOR metadata, when present."""
    if len(bytecode) < 4:
        return bytecode
    metadata_length = int.from_bytes(bytecode[-2:], "big")
    if metadata_length <= 0 or metadata_length > len(bytecode) - 2:
        return bytecode
    start = len(bytecode) - 2 - metadata_length
    marker = bytecode[start]
    if not 0xA1 <= marker <= 0xBF:  # CBOR map beginning
        return bytecode
    return bytecode[:start]


def bytecode_family_id(bytecode_hex: str) -> str:
    """Stable SHA-256 of metadata-normalized runtime bytecode."""
    raw = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    normalized = strip_solidity_metadata(bytes.fromhex(raw))
    return hashlib.sha256(normalized).hexdigest()


def assign_family_ids(records: Iterable[GoldenRecord]) -> list[GoldenRecord]:
    """Fill missing family ids from available bytecode."""
    assigned: list[GoldenRecord] = []
    for record in records:
        if record.contract_family_id is None and record.bytecode:
            assigned.append(
                record.model_copy(
                    update={"contract_family_id": bytecode_family_id(record.bytecode)}
                )
            )
        else:
            assigned.append(record)
    return assigned


def family_key(record: GoldenRecord) -> str:
    """Family key; falls back to address for un-hashed records."""
    return record.contract_family_id or f"address:{record.chain_id}:{record.token_address.lower()}"


def group_by_family(records: Sequence[GoldenRecord]) -> dict[str, list[GoldenRecord]]:
    """Group records by bytecode family."""
    groups: dict[str, list[GoldenRecord]] = {}
    for record in records:
        groups.setdefault(family_key(record), []).append(record)
    return groups


def deduplicate_by_family(
    records: Sequence[GoldenRecord],
    *,
    prefer_scam: bool = True,
) -> list[GoldenRecord]:
    """Keep one representative per bytecode family."""
    representatives: list[GoldenRecord] = []
    for _, group in sorted(group_by_family(records).items()):
        ordered = sorted(
            group,
            key=lambda item: (
                0 if (item.is_scam and prefer_scam) else 1,
                item.chain_id,
                item.token_address,
            ),
        )
        representatives.append(ordered[0])
    return representatives


def _validate_fraction(value: float) -> None:
    if not 0.0 < value < 1.0:
        raise ValueError("holdout_fraction must be between 0 and 1")


def family_split(
    records: Sequence[GoldenRecord],
    *,
    holdout_fraction: float = 0.2,
    seed: int = 7,
) -> tuple[list[GoldenRecord], list[GoldenRecord]]:
    """Split development/holdout while keeping each family entirely on one side."""
    _validate_fraction(holdout_fraction)
    groups = group_by_family(records)
    keys = sorted(groups)
    if len(keys) <= 1:
        return list(records), []
    random.Random(seed).shuffle(keys)
    target = max(1, round(len(records) * holdout_fraction))
    holdout_keys: set[str] = set()
    count = 0
    for key in keys:
        if count >= target:
            break
        holdout_keys.add(key)
        count += len(groups[key])
    if len(holdout_keys) == len(keys) and len(keys) > 1:
        holdout_keys.remove(keys[0])
    development = [record for record in records if family_key(record) not in holdout_keys]
    holdout = [record for record in records if family_key(record) in holdout_keys]
    return development, holdout


def temporal_family_split(
    records: Sequence[GoldenRecord],
    *,
    cutoff_block: int,
) -> tuple[list[GoldenRecord], list[GoldenRecord]]:
    """Time split by family: families deployed before the cutoff go to development."""
    development: list[GoldenRecord] = []
    holdout: list[GoldenRecord] = []
    for _, group in sorted(group_by_family(records).items()):
        earliest = min(record.deployment_block for record in group)
        if earliest < cutoff_block:
            development.extend(group)
        else:
            holdout.extend(group)
    return development, holdout
