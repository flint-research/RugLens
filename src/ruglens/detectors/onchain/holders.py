"""Top-holder concentration detector with bounded, JIT Transfer-log replay."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Sequence

from eth_utils.address import is_address, to_checksum_address

from ruglens.chains.evm.abi import (
    BURN_ADDRESSES,
    TRANSFER_EVENT_TOPIC,
    ZERO_ADDRESS,
    Selectors,
    decode_uint,
    encode_call,
    hex_data_to_bytes,
    topic_to_address,
)
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import RpcError
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, HolderBalance, RpcCall, TokenContext


class HolderDistributionDetector(BaseDetector):
    """Reconstruct recent holder balances and flag supply concentration."""

    detector_id = "holder_distribution"
    category = DetectorCategory.HOLDERS
    coverage_area = CoverageArea.HOLDERS
    description = (
        "Bounded Transfer-event replay, actual balanceOf verification, pair/burn "
        "exclusion, and top-10 holder concentration thresholds."
    )
    required = True

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        limitations: list[str] = []
        total_supply = context.total_supply
        if total_supply is None:
            try:
                raw = await dependencies.chain.eth_call(
                    context.token_address, Selectors.TOTAL_SUPPLY, context.block_number
                )
                total_supply = decode_uint(raw)
            except (RpcError, ValueError) as exc:
                return self.make_outcome(
                    status=DetectorStatus.FAILED,
                    error=f"Total supply is unavailable: {exc}",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
        if total_supply <= 0:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Token reports zero total supply",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        excluded = {address.lower() for address in BURN_ADDRESSES}
        if context.pair_address and is_address(context.pair_address):
            excluded.add(context.pair_address.lower())
        if context.router and is_address(context.router):
            excluded.add(context.router.lower())
        excluded.add(context.token_address.lower())

        partial = False
        truncated = False
        event_count = 0
        window_from = max(0, context.block_number - self.settings.holder_log_lookback_blocks)

        tentative: dict[str, int]
        if context.holders:
            tentative = {
                str(to_checksum_address(holder.address)): holder.balance
                for holder in context.holders
            }
            limitations.append("Holder snapshot was supplied in the token context.")
        else:
            try:
                tentative, window_from, truncated, event_count = await self._replay_transfers(
                    context, dependencies
                )
            except RpcError as exc:
                return self.make_outcome(
                    status=DetectorStatus.FAILED,
                    error=f"Transfer-log replay failed: {exc}",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            if truncated:
                limitations.append(
                    "Holder analysis used a truncated Transfer-log window or event cap; "
                    "very old holders may be missing."
                )

        candidates = [
            (address, balance)
            for address, balance in tentative.items()
            if balance > 0 and address.lower() not in excluded
        ]
        candidates.sort(key=lambda item: (-item[1], item[0]))
        query_limit = max(self.settings.top_holder_count * 3, 25)
        candidates = candidates[:query_limit]

        verified: dict[str, int] = {}
        pair_balance = 0
        burn_balance = 0
        if context.holders:
            verified = dict(candidates)
            burn_lower = {address.lower() for address in BURN_ADDRESSES}
            pair_balance = sum(
                holder.balance
                for holder in context.holders
                if context.pair_address and holder.address.lower() == context.pair_address.lower()
            )
            burn_balance = sum(
                holder.balance for holder in context.holders if holder.address.lower() in burn_lower
            )
        else:
            targets = [address for address, _ in candidates]
            aux = [ZERO_ADDRESS, BURN_ADDRESSES[1]]
            if context.pair_address and is_address(context.pair_address):
                aux.append(to_checksum_address(context.pair_address))
            else:
                partial = True
                limitations.append("Pair address is unknown; pair-held supply was not excluded.")
            calls = [
                RpcCall(
                    to=context.token_address,
                    data=encode_call("balanceOf(address)", ["address"], [address]),
                )
                for address in [*targets, *aux]
            ]
            try:
                results = await dependencies.chain.multicall(calls, context.block_number)
            except RpcError as exc:
                return self.make_outcome(
                    status=DetectorStatus.FAILED,
                    error=f"Holder balance reads failed: {exc}",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            for index, result in enumerate(results):
                if not result.success:
                    partial = True
                    continue
                try:
                    balance = decode_uint(result.return_data)
                except ValueError:
                    partial = True
                    continue
                if index < len(targets):
                    verified[targets[index]] = balance
                elif index == len(targets) or index == len(targets) + 1:
                    burn_balance += balance
                else:
                    pair_balance = balance

        circulating = total_supply - pair_balance - burn_balance
        if circulating <= 0:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Circulating supply is zero after excluding pair and burn balances",
                limitations=limitations,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        holders = [
            HolderBalance(address=address, balance=balance)
            for address, balance in verified.items()
            if balance > 0 and address.lower() not in excluded
        ]
        holders.sort(key=lambda item: (-item.balance, item.address))
        top_holders = holders[: self.settings.top_holder_count]
        top_share = min(1.0, sum(holder.balance for holder in top_holders) / circulating)
        top1_share = min(1.0, top_holders[0].balance / circulating) if top_holders else 0.0

        findings: list[Finding] = []
        if not top_holders:
            limitations.append("No positive holder balances were found in the analysis window.")
        elif (
            top_share >= self.settings.holders_top10_high_share
            or top1_share >= self.settings.holders_top1_high_share
        ):
            findings.append(
                self._finding(
                    context,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    top_share=top_share,
                    top1_share=top1_share,
                    top_holders=top_holders,
                    circulating=circulating,
                    total_supply=total_supply,
                    excluded=excluded,
                    window_from=window_from,
                    truncated=truncated,
                    partial=partial,
                    event_count=event_count,
                )
            )
        elif (
            top_share >= self.settings.holders_top10_medium_share
            or top1_share >= self.settings.holders_top1_medium_share
        ):
            findings.append(
                self._finding(
                    context,
                    severity=Severity.MEDIUM,
                    confidence=0.72,
                    top_share=top_share,
                    top1_share=top1_share,
                    top_holders=top_holders,
                    circulating=circulating,
                    total_supply=total_supply,
                    excluded=excluded,
                    window_from=window_from,
                    truncated=truncated,
                    partial=partial,
                    event_count=event_count,
                )
            )

        coverage_fraction = 1.0
        if not top_holders:
            coverage_fraction = 0.5
        if truncated:
            coverage_fraction = min(coverage_fraction, 0.7)
        if partial:
            coverage_fraction = min(coverage_fraction, 0.6)
            limitations.append("Some holder balance reads failed; concentration is approximate.")

        return self.make_outcome(
            findings=findings[: self.settings.max_findings_per_detector],
            coverage_fraction=coverage_fraction,
            limitations=limitations,
            details={
                "holder_count": len(holders),
                "top_holders": [holder.model_dump() for holder in top_holders],
                "top_share": top_share,
                "top1_share": top1_share,
                "circulating_supply": str(circulating),
                "event_count": event_count,
                "truncated": truncated,
                "partial": partial,
            },
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    async def _replay_transfers(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> tuple[dict[str, int], int, bool, int]:
        lookback = min(context.block_number, self.settings.holder_log_lookback_blocks)
        max_span = self.settings.holder_log_chunk_blocks * self.settings.max_log_range_chunks
        truncated = lookback > max_span
        effective_lookback = min(lookback, max_span)
        start = max(0, context.block_number - effective_lookback)
        balances: defaultdict[str, int] = defaultdict(int)
        events = 0
        cursor = start
        while cursor <= context.block_number:
            end = min(cursor + self.settings.holder_log_chunk_blocks - 1, context.block_number)
            logs = await dependencies.chain.get_logs(
                context.token_address,
                [TRANSFER_EVENT_TOPIC],
                cursor,
                end,
            )
            for log in logs:
                if events >= self.settings.holder_log_max_events:
                    truncated = True
                    break
                topics = log.get("topics", [])
                if not isinstance(topics, list) or len(topics) < 3:
                    continue
                try:
                    from_address = topic_to_address(str(topics[1]))
                    to_address = topic_to_address(str(topics[2]))
                    value = decode_uint(hex_data_to_bytes(log.get("data", "0x")))
                except (ValueError, TypeError):
                    continue
                if from_address != ZERO_ADDRESS:
                    balances[from_address] -= value
                if to_address != ZERO_ADDRESS:
                    balances[to_address] += value
                events += 1
            if events >= self.settings.holder_log_max_events:
                truncated = True
                break
            cursor = end + 1
        return dict(balances.items()), start, truncated, events

    def _finding(
        self,
        context: TokenContext,
        *,
        severity: Severity,
        confidence: float,
        top_share: float,
        top1_share: float,
        top_holders: Sequence[HolderBalance],
        circulating: int,
        total_supply: int,
        excluded: set[str],
        window_from: int,
        truncated: bool,
        partial: bool,
        event_count: int,
    ) -> Finding:
        level = "high" if severity is Severity.HIGH else "moderate"
        return Finding.create(
            rule_id="HOLDER-CONC-001",
            detector_id=self.detector_id,
            category=DetectorCategory.HOLDERS,
            severity=severity,
            confidence=confidence,
            title=f"{level.capitalize()} supply concentration",
            description=(
                f"The top {len(top_holders)} non-pair, non-burn holders control "
                f"{top_share:.1%} of circulating supply; the largest holds {top1_share:.1%}. "
                "Concentrated supply enables insider dumping and governance capture."
            ),
            evidence={
                "top_holders": [
                    {
                        "address": holder.address,
                        "balance": str(holder.balance),
                        "share": (holder.balance / circulating) if circulating else 0.0,
                    }
                    for holder in top_holders
                ],
                "top_holder_share": top_share,
                "top1_share": top1_share,
                "circulating_supply": str(circulating),
                "total_supply": str(total_supply),
                "excluded_addresses": sorted(excluded),
                "window_from_block": window_from,
                "window_truncated": truncated,
                "partial_balance_data": partial,
                "transfer_events": event_count,
            },
            target=context.token_address,
            block_number=context.block_number,
        )
