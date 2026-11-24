"""Golden dataset normalization and split tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ruglens.benchmark.dataset import (
    GoldenRecord,
    assign_family_ids,
    bytecode_family_id,
    deduplicate_by_family,
    family_split,
    group_by_family,
    load_golden_dataset,
    strip_solidity_metadata,
    temporal_family_split,
)


def make_record(
    index: int,
    *,
    family: str | None = None,
    deployment: int = 100,
    label: str = "BENIGN",
    bytecode: str | None = None,
) -> GoldenRecord:
    return GoldenRecord(
        token_address=f"0x{index:040x}",
        chain_id=1,
        deployment_block=deployment,
        evaluation_block=deployment + 100,
        ground_truth_label=label,
        contract_family_id=family,
        source_provenance="test",
        bytecode=bytecode,
    )


def test_solidity_metadata_stripping_and_family_hash() -> None:
    runtime = bytes.fromhex("6080604052348015600f57600080fd5b50")
    metadata_one = b"\xa1\x65hello"
    metadata_two = b"\xa1\x65world"
    first = runtime + metadata_one + len(metadata_one).to_bytes(2, "big")
    second = runtime + metadata_two + len(metadata_two).to_bytes(2, "big")
    assert strip_solidity_metadata(first) == runtime
    assert strip_solidity_metadata(second) == runtime
    assert bytecode_family_id("0x" + first.hex()) == bytecode_family_id("0x" + second.hex())
    assert bytecode_family_id("0x" + first.hex()) != bytecode_family_id(
        "0x" + (runtime + b"\x00").hex()
    )


def test_family_ids_are_filled_from_bytecode() -> None:
    runtime = "0x6080604052"
    record = make_record(1, bytecode=runtime)
    [assigned] = assign_family_ids([record])
    assert assigned.contract_family_id == bytecode_family_id(runtime)


def test_family_split_never_leaks_a_family() -> None:
    records = [
        *[make_record(index, family="family-a") for index in range(1, 4)],
        *[make_record(index, family="family-b") for index in range(4, 7)],
        *[make_record(index, family="family-c") for index in range(7, 10)],
        *[make_record(index, family="family-d") for index in range(10, 13)],
    ]
    development, holdout = family_split(records, holdout_fraction=0.25, seed=3)
    assert development and holdout
    dev_groups = set(group_by_family(development))
    hold_groups = set(group_by_family(holdout))
    assert dev_groups.isdisjoint(hold_groups)
    assert set(dev_groups | hold_groups) == {
        "family-a",
        "family-b",
        "family-c",
        "family-d",
    }
    assert len(development) + len(holdout) == len(records)


def test_temporal_split_is_family_aware() -> None:
    old = [
        GoldenRecord(
            token_address=f"0x{index:040x}",
            chain_id=1,
            deployment_block=100,
            ground_truth_label="BENIGN",
            contract_family_id="old",
            source_provenance="test",
        )
        for index in range(1, 3)
    ]
    new = [
        GoldenRecord(
            token_address=f"0x{index:040x}",
            chain_id=1,
            deployment_block=500,
            ground_truth_label="SCAM_HONEYPOT",
            contract_family_id="new",
            source_provenance="test",
        )
        for index in range(3, 5)
    ]
    development, holdout = temporal_family_split(old + new, cutoff_block=250)
    assert development == old
    assert holdout == new


def test_deduplicate_by_family_prefers_scam() -> None:
    records = [
        make_record(1, family="same", label="BENIGN"),
        make_record(2, family="same", label="SCAM_HONEYPOT"),
        make_record(3, family="other", label="BENIGN"),
    ]
    representatives = deduplicate_by_family(records)
    assert [record.contract_family_id for record in representatives] == ["other", "same"]
    same = next(record for record in representatives if record.contract_family_id == "same")
    assert same.is_scam


def test_solana_mint_address_is_accepted() -> None:
    record = GoldenRecord(
        token_address="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        chain_id=101,
        deployment_block=1,
        evaluation_block=100,
        ground_truth_label="BENIGN",
        source_provenance="test",
    )
    assert record.chain_id == 101
    assert record.token_address == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    with pytest.raises(ValueError):
        GoldenRecord(
            token_address="0x" + "11" * 20,
            chain_id=101,
            deployment_block=1,
            ground_truth_label="BENIGN",
            source_provenance="test",
        )
    with pytest.raises(ValueError):
        GoldenRecord(
            token_address="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            chain_id=1,
            deployment_block=1,
            ground_truth_label="BENIGN",
            source_provenance="test",
        )


def test_record_validation_rejects_bad_labels_and_addresses() -> None:
    with pytest.raises(ValueError):
        GoldenRecord(
            token_address="not-an-address",
            chain_id=1,
            deployment_block=1,
            ground_truth_label="BENIGN",
            source_provenance="test",
        )
    with pytest.raises(ValueError):
        GoldenRecord(
            token_address=f"0x{'1' * 40}",
            chain_id=1,
            deployment_block=1,
            ground_truth_label="UNKNOWN",
            source_provenance="test",
        )


def test_bluechip_dataset_loads() -> None:
    root = Path(__file__).resolve().parents[2]
    records = load_golden_dataset(root / "datasets" / "golden" / "bluechip.jsonl")
    assert len(records) == 10
    assert all(record.ground_truth_label == "BENIGN" for record in records)
    assert all(record.chain_id == 1 for record in records)


def test_load_golden_dataset_reports_bad_line(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"token_address": "0x0"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        load_golden_dataset(path)


def test_load_golden_dataset_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "ok.jsonl"
    record = {
        "token_address": f"0x{'1' * 40}",
        "chain_id": 1,
        "deployment_block": 1,
        "ground_truth_label": "BENIGN",
        "source_provenance": "test",
    }
    path.write_text("\n" + json.dumps(record) + "\n\n", encoding="utf-8")
    records = load_golden_dataset(path)
    assert len(records) == 1
