"""DEX V2 liquidity depth and LP lock/burn inspection."""

from __future__ import annotations

import time
from collections.abc import Sequence

from eth_utils.address import is_address, to_checksum_address

from ruglens.chains.evm.abi import (
    BURN_ADDRESSES,
    TRANSFER_EVENT_TOPIC,
    ZERO_ADDRESS,
    Selectors,
    decode_address,
    decode_reserves,
    decode_uint,
    encode_call,
    hex_data_to_bytes,
    topic_to_address,
)
from ruglens.chains.evm.registry import normalize_chain
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import RpcError
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, RpcCall, TokenContext


def _balance_for(address: str) -> bytes:
    return encode_call("balanceOf(address)", ["address"], [to_checksum_address(address)])


class LiquidityDetector(BaseDetector):
    """Measure V2 reserves and verify LP burn/lock status."""

    detector_id = "liquidity"
    category = DetectorCategory.LIQUIDITY
    coverage_area = CoverageArea.LIQUIDITY
    description = (
        "Uniswap/PancakeSwap V2 pair discovery, native reserve depth in WETH/BNB, "
        "and LP supply held by burn addresses or recognized lockers."
    )
    required = True

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        limitations: list[str] = []
        findings: list[Finding] = []
        chain = normalize_chain(context.chain_id)
        weth = to_checksum_address(context.weth or chain.weth)

        pair = context.pair_address
        if pair is None:
            try:
                pair = await self._discover_pair(context, dependencies, weth)
            except RpcError as exc:
                return self.make_outcome(
                    status=DetectorStatus.FAILED,
                    error=f"V2 pair discovery failed: {exc}",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            if pair is None:
                findings.append(
                    Finding.create(
                        rule_id="LIQ-NO-V2-PAIR-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.LIQUIDITY,
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        title="No Uniswap/PancakeSwap V2 pair found",
                        description=(
                            "The configured V2 factory has no pair for this token and the "
                            "wrapped native token. Liquidity may be on another venue, so "
                            "depth and LP lock status cannot be verified by this detector."
                        ),
                        evidence={
                            "factory": chain.v2_factory,
                            "token": context.token_address,
                            "weth": weth,
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
                return self.make_outcome(
                    findings=findings,
                    limitations=("V2 liquidity is absent or deployed on a non-V2 venue.",),
                    details={"pair": None},
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
        pair = to_checksum_address(pair)

        token0 = context.pair_token0
        token1 = context.pair_token1
        raw_reserves = context.pair_reserves
        lp_total = context.lp_total_supply
        balances: dict[str, int] = {}
        for address, value in context.lp_balances.items():
            if is_address(address):
                balances[to_checksum_address(address)] = value

        lockers = self._lockers(chain.known_lp_lockers)
        needed_balances = list(dict.fromkeys([*BURN_ADDRESSES, *lockers]))
        missing_balances = [addr for addr in needed_balances if addr not in balances]

        calls: list[RpcCall] = []
        kinds: list[tuple[str, str]] = []
        if token0 is None:
            calls.append(RpcCall(to=pair, data=Selectors.TOKEN0))
            kinds.append(("token0", pair))
        if token1 is None:
            calls.append(RpcCall(to=pair, data=Selectors.TOKEN1))
            kinds.append(("token1", pair))
        if raw_reserves is None:
            calls.append(RpcCall(to=pair, data=Selectors.GET_RESERVES))
            kinds.append(("reserves", pair))
        if lp_total is None:
            calls.append(RpcCall(to=pair, data=Selectors.TOTAL_SUPPLY))
            kinds.append(("lp_total", pair))
        for address in missing_balances:
            calls.append(RpcCall(to=pair, data=_balance_for(address)))
            kinds.append(("balance", address))

        failed_kinds: set[tuple[str, str]] = set()
        if calls:
            try:
                results = await dependencies.chain.multicall(calls, context.block_number)
            except RpcError as exc:
                return self.make_outcome(
                    status=DetectorStatus.FAILED,
                    error=f"Liquidity state could not be read: {exc}",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            for (kind, address), result in zip(kinds, results, strict=False):
                if not result.success:
                    failed_kinds.add((kind, address))
                    continue
                try:
                    if kind == "token0":
                        token0 = decode_address(result.return_data)
                    elif kind == "token1":
                        token1 = decode_address(result.return_data)
                    elif kind == "reserves":
                        raw_reserves = decode_reserves(result.return_data)[:2]
                    elif kind == "lp_total":
                        lp_total = decode_uint(result.return_data)
                    elif kind == "balance":
                        balances[to_checksum_address(address)] = decode_uint(result.return_data)
                except ValueError:
                    failed_kinds.add((kind, address))
                    limitations.append(f"Malformed {kind} result for {address}.")

        depth_known = False
        native_reserve: int | None = None
        if token0 is not None and token1 is not None and raw_reserves is not None:
            if token0.lower() == weth.lower():
                native_reserve = raw_reserves[0]
                depth_known = True
            elif token1.lower() == weth.lower():
                native_reserve = raw_reserves[1]
                depth_known = True
            else:
                limitations.append(
                    "The V2 pair does not contain the configured wrapped native token."
                )
        else:
            limitations.append("Pair token ordering or reserves are unavailable.")

        if depth_known and native_reserve is not None:
            native_units = native_reserve / 10**18
            if native_units < self.settings.liquidity_weth_high_threshold:
                findings.append(
                    Finding.create(
                        rule_id="LIQ-LOW-DEPTH-HIGH-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.LIQUIDITY,
                        severity=Severity.HIGH,
                        confidence=0.82,
                        title="Critically low DEX liquidity",
                        description=(
                            f"The V2 pair holds only {native_units:,.6f} wrapped native tokens. "
                            "Portfolio-sized sells will suffer extreme slippage or fail."
                        ),
                        evidence={
                            "pair": pair,
                            "native_reserve_wei": str(native_reserve),
                            "native_reserve": native_units,
                            "threshold": self.settings.liquidity_weth_high_threshold,
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
            elif native_units < self.settings.liquidity_weth_medium_threshold:
                findings.append(
                    Finding.create(
                        rule_id="LIQ-LOW-DEPTH-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.LIQUIDITY,
                        severity=Severity.MEDIUM,
                        confidence=0.78,
                        title="Low DEX liquidity depth",
                        description=(
                            f"The V2 pair holds {native_units:,.6f} wrapped native tokens, "
                            "below the configured minimum depth. Thin pools amplify exits "
                            "and enable price manipulation."
                        ),
                        evidence={
                            "pair": pair,
                            "native_reserve_wei": str(native_reserve),
                            "native_reserve": native_units,
                            "threshold": self.settings.liquidity_weth_medium_threshold,
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
        elif not findings:
            limitations.append("Liquidity depth could not be assessed.")

        lp_known = lp_total is not None and lp_total > 0
        balances_complete = not any(kind == "balance" for kind, _ in failed_kinds)
        lock_fraction: float | None = None
        if lp_known:
            assert lp_total is not None
            if balances_complete:
                burned = sum(balances.get(address, 0) for address in BURN_ADDRESSES)
                locked = sum(balances.get(address, 0) for address in lockers)
                lock_fraction = min(1.0, max(0.0, (burned + locked) / lp_total))
                unlocked = 1.0 - lock_fraction
                if unlocked >= self.settings.lp_unlocked_high_threshold:
                    (
                        holder,
                        holder_is_eoa,
                        holder_balance,
                        holder_notes,
                    ) = await self._prove_eoa_lp_holder(
                        context,
                        dependencies,
                        pair,
                        lp_total,
                        excluded={address.lower() for address in [*BURN_ADDRESSES, *lockers]},
                    )
                    limitations.extend(holder_notes)
                    evidence = {
                        "pair": pair,
                        "lp_total_supply": str(lp_total),
                        "burned": str(burned),
                        "known_locked": str(locked),
                        "lock_fraction": lock_fraction,
                        "unlocked_fraction": unlocked,
                        "lockers_checked": list(lockers),
                        "top_lp_holder": holder,
                        "top_lp_holder_balance": str(holder_balance)
                        if holder_balance is not None
                        else None,
                        "top_lp_holder_is_eoa": holder_is_eoa,
                    }
                    if (
                        holder_is_eoa
                        and holder_balance is not None
                        and holder_balance / lp_total >= self.settings.lp_unlocked_high_threshold
                    ):
                        findings.append(
                            Finding.create(
                                rule_id="LIQ-UNLOCKED-HIGH-001",
                                detector_id=self.detector_id,
                                category=DetectorCategory.LIQUIDITY,
                                severity=Severity.HIGH,
                                confidence=0.85,
                                title="Most LP tokens are held by a single EOA",
                                description=(
                                    f"{holder_balance / lp_total:.1%} of the pair's LP supply "
                                    "is held by one externally owned account that is neither a "
                                    "burn address nor a recognized locker. That wallet can "
                                    "remove liquidity at any time."
                                ),
                                evidence=evidence,
                                target=context.token_address,
                                block_number=context.block_number,
                            )
                        )
                    else:
                        if holder_is_eoa is None:
                            limitations.append(
                                "Majority LP ownership could not be attributed; the unlocked "
                                "liquidity finding remains MEDIUM rather than HIGH."
                            )
                        findings.append(
                            Finding.create(
                                rule_id="LIQ-UNLOCKED-001",
                                detector_id=self.detector_id,
                                category=DetectorCategory.LIQUIDITY,
                                severity=Severity.MEDIUM,
                                confidence=0.75,
                                title="Most LP tokens are not verifiably burned or locked",
                                description=(
                                    f"{unlocked:.1%} of the pair's LP supply is not burned or "
                                    "held by a recognized locker, but an EOA majority holder "
                                    "could not be proven. The liquidity-withdrawal path is "
                                    "material and unverified."
                                ),
                                evidence=evidence,
                                target=context.token_address,
                                block_number=context.block_number,
                            )
                        )
                elif unlocked > self.settings.lp_unlocked_medium_threshold:
                    findings.append(
                        Finding.create(
                            rule_id="LIQ-UNLOCKED-001",
                            detector_id=self.detector_id,
                            category=DetectorCategory.LIQUIDITY,
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            title="Significant LP supply is unlocked",
                            description=(
                                f"{unlocked:.1%} of the pair's LP supply is not verifiably "
                                "burned or locked, leaving a material liquidity-withdrawal path."
                            ),
                            evidence={
                                "pair": pair,
                                "lp_total_supply": str(lp_total),
                                "burned": str(burned),
                                "known_locked": str(locked),
                                "lock_fraction": lock_fraction,
                                "unlocked_fraction": unlocked,
                                "lockers_checked": list(lockers),
                            },
                            target=context.token_address,
                            block_number=context.block_number,
                        )
                    )
            else:
                limitations.append(
                    "One or more LP holder balances could not be read; lock status is incomplete."
                )
                findings.append(
                    Finding.create(
                        rule_id="LIQ-LOCK-UNVERIFIED-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.LIQUIDITY,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        title="LP lock status could not be fully verified",
                        description=(
                            "The pair's LP supply exists, but one or more balance reads for "
                            "burn addresses or recognized lockers failed. Unlocked supply "
                            "cannot be ruled out."
                        ),
                        evidence={
                            "pair": pair,
                            "lp_total_supply": str(lp_total),
                            "failed_balance_reads": sorted(
                                address for kind, address in failed_kinds if kind == "balance"
                            ),
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
        else:
            lp_known = False
            limitations.append("Pair LP total supply is zero or unavailable.")

        if not depth_known and not lp_known:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Neither liquidity depth nor LP lock status could be assessed",
                limitations=limitations,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        components: list[float] = []
        components.append(1.0 if depth_known else 0.0)
        if lp_known:
            components.append(1.0 if balances_complete else 0.5)
        else:
            components.append(0.0)
        coverage_fraction = sum(components) / len(components)
        findings = findings[: self.settings.max_findings_per_detector]
        return self.make_outcome(
            findings=findings,
            coverage_fraction=coverage_fraction,
            limitations=limitations,
            details={
                "pair": pair,
                "token0": token0,
                "token1": token1,
                "depth_known": depth_known,
                "native_reserve_wei": str(native_reserve) if native_reserve is not None else None,
                "lp_total_supply": str(lp_total) if lp_total is not None else None,
                "lp_lock_fraction": lock_fraction,
                "lockers_checked": list(lockers),
            },
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    async def _discover_pair(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
        weth: str,
    ) -> str | None:
        chain = normalize_chain(context.chain_id)
        data = encode_call(
            "getPair(address,address)",
            ["address", "address"],
            [context.token_address, weth],
        )
        raw = await dependencies.chain.eth_call(
            to_checksum_address(chain.v2_factory), data, context.block_number
        )
        if not raw or int.from_bytes(raw, "big") == 0:
            return None
        try:
            pair = decode_address(raw)
        except ValueError as exc:
            raise RpcError("V2 factory returned a malformed pair address") from exc
        return pair if pair.lower() != ZERO_ADDRESS.lower() else None

    async def _prove_eoa_lp_holder(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
        pair: str,
        lp_total: int,
        *,
        excluded: set[str],
    ) -> tuple[str | None, bool | None, int | None, list[str]]:
        """Identify the top LP holder and prove whether it is an EOA.

        HIGH severity for unlocked LP requires executable evidence that a single
        EOA controls at least the high threshold of LP supply. Log failures or
        truncation deliberately downgrade the result to MEDIUM.
        """
        notes: list[str] = []
        lookback = min(context.block_number, self.settings.holder_log_lookback_blocks)
        max_span = self.settings.holder_log_chunk_blocks * self.settings.max_log_range_chunks
        truncated = lookback > max_span
        start = max(0, context.block_number - min(lookback, max_span))
        balances: dict[str, int] = {}
        events = 0
        cursor = start
        try:
            while cursor <= context.block_number:
                end = min(
                    cursor + self.settings.holder_log_chunk_blocks - 1,
                    context.block_number,
                )
                logs = await dependencies.chain.get_logs(
                    pair,
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
                    except (TypeError, ValueError):
                        continue
                    if from_address.lower() not in excluded:
                        balances[from_address] = balances.get(from_address, 0) - value
                    if to_address.lower() not in excluded:
                        balances[to_address] = balances.get(to_address, 0) + value
                    events += 1
                if events >= self.settings.holder_log_max_events:
                    truncated = True
                    break
                cursor = end + 1
        except RpcError as exc:
            return None, None, None, [f"LP holder logs could not be read: {exc}"]

        candidates = [
            (address, balance)
            for address, balance in balances.items()
            if balance > 0 and address.lower() not in excluded
        ]
        if not candidates:
            return None, None, None, [*notes, "No LP holder activity was found in the window."]
        candidates.sort(key=lambda item: (-item[1], item[0]))
        top = candidates[0][0]
        try:
            results = await dependencies.chain.multicall(
                [RpcCall(to=pair, data=_balance_for(top))],
                context.block_number,
            )
        except RpcError as exc:
            return top, None, None, [f"Top LP holder balance could not be verified: {exc}"]
        if not results or not results[0].success:
            return top, None, None, ["Top LP holder balance could not be decoded."]
        try:
            holder_balance = decode_uint(results[0].return_data)
        except ValueError:
            return top, None, None, ["Top LP holder balance could not be decoded."]
        try:
            holder_code = await dependencies.chain.get_code(top, context.block_number)
        except RpcError as exc:
            return top, None, holder_balance, [f"Top LP holder bytecode could not be read: {exc}"]
        holder_is_eoa: bool | None = holder_code == b""
        if truncated:
            notes.append(
                "LP holder replay was truncated; the top holder may be incomplete, so EOA "
                "majority ownership is not proven."
            )
            holder_is_eoa = None
        if holder_balance > lp_total:
            notes.append("Top LP holder balance exceeds total supply; data is inconsistent.")
            holder_is_eoa = None
        return top, holder_is_eoa, holder_balance, notes

    def _lockers(self, chain_lockers: Sequence[str]) -> tuple[str, ...]:
        candidates: Sequence[str] = (*chain_lockers, *self.settings.extra_lp_lockers)
        valid = [to_checksum_address(address) for address in candidates if is_address(address)]
        return tuple(dict.fromkeys(valid))
