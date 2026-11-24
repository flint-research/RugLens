"""Funding-source cluster analysis for top Solana holders."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from ruglens.chains.solana.base58 import decode_pubkey, is_valid_pubkey
from ruglens.chains.solana.parsers import parse_funding_source
from ruglens.chains.solana.pda import is_on_curve
from ruglens.chains.solana.registry import BURN_ADDRESSES, KNOWN_PROGRAMS, SYSTEM_PROGRAM_ID
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import RpcError
from ruglens.core.interfaces import BaseSolanaDetector, SolanaDetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.core.solana_models import SolanaTokenContext

_REFERENCES = (
    "https://github.com/karidasd/find-the-insiders",
    "https://blog.bubblemaps.io/how-to-spot-a-rug-pull-using-bubblemaps-before-it-happens/",
    "https://www.solanatracker.io/",
)


class SolanaClusterDetector(BaseSolanaDetector):
    """Trace common funding sources of top holders and estimate cluster share."""

    detector_id = "solana_clusters"
    category = DetectorCategory.CLUSTERS
    coverage_area = CoverageArea.SOLANA_CLUSTERS
    description = (
        "Bounded earliest-transaction funding trace for top retail holders, common-funder "
        "clustering, largest-cluster supply share, and a heuristic cluster probability."
    )
    required = True

    async def detect(
        self,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        limitations: list[str] = []
        retail: dict[str, int] = {}
        for holder in context.top_holders:
            if holder.is_burn or holder.program_controlled:
                continue
            retail[holder.owner] = retail.get(holder.owner, 0) + holder.amount
        if context.creator and context.creator not in retail:
            retail[context.creator] = context.creator_holdings
        ordered = sorted(retail.items(), key=lambda item: (-item[1], item[0]))
        candidates = ordered[: self.settings.solana_cluster_max_wallets]
        if len(candidates) < 2:
            return self.make_outcome(
                coverage_fraction=1.0,
                limitations=("Fewer than two retail holder wallets were available.",),
                details={
                    "metrics": {
                        "cluster_probability": 0.0,
                        "largest_cluster_size": 0,
                        "largest_cluster_share_pct": 0.0,
                        "cluster_wallets": [],
                        "cluster_methods": [],
                    }
                },
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        denominator = context.circulating_supply or context.mint.supply
        if denominator <= 0:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Supply is zero; cluster share is undefined",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        traces: list[dict[str, Any]] = []
        successful_traces = 0
        for wallet, amount in candidates:
            trace: dict[str, Any] = {
                "wallet": wallet,
                "amount": str(amount),
                "share": amount / denominator,
                "is_creator": wallet == context.creator,
                "funder": None,
                "funding_tx": None,
                "truncated": False,
                "error": None,
            }
            try:
                signatures = await dependencies.chain.get_signatures_for_address(
                    wallet,
                    limit=self.settings.solana_cluster_signature_limit,
                )
                if signatures:
                    oldest = signatures[-1].get("signature")
                    if isinstance(oldest, str):
                        trace["funding_tx"] = oldest
                        transaction = await dependencies.chain.get_transaction(oldest)
                        if transaction is not None:
                            trace["funder"] = parse_funding_source(transaction, wallet)
                            successful_traces += 1
                        else:
                            trace["error"] = "funding transaction unavailable"
                    else:
                        trace["error"] = "malformed signature entry"
                else:
                    successful_traces += 1
                if len(signatures) >= self.settings.solana_cluster_signature_limit:
                    trace["truncated"] = True
            except RpcError as exc:
                trace["error"] = str(exc)
            traces.append(trace)

        if successful_traces < max(2, (len(candidates) + 1) // 2):
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error=(
                    "Funding traces completed for fewer than half of the candidate wallets "
                    f"({successful_traces}/{len(candidates)})"
                ),
                limitations=tuple(limitations),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        funders = list(
            dict.fromkeys(
                trace["funder"] for trace in traces if isinstance(trace.get("funder"), str)
            )
        )
        funder_info: dict[str, dict[str, Any] | None] = {}
        if funders:
            try:
                fetched = await dependencies.chain.get_multiple_accounts(funders)
                funder_info = dict(zip(funders, fetched, strict=False))
            except RpcError as exc:
                limitations.append(f"Funder accounts could not be classified: {exc}")

        groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for trace in traces:
            funder = trace.get("funder")
            if not isinstance(funder, str) or not is_valid_pubkey(funder):
                continue
            if funder in BURN_ADDRESSES or funder in KNOWN_PROGRAMS or funder == trace["wallet"]:
                continue
            info = funder_info.get(funder)
            owner_program = str(info.get("owner")) if isinstance(info, dict) else None
            executable = bool(info.get("executable", False)) if isinstance(info, dict) else False
            try:
                funder_on_curve = is_on_curve(decode_pubkey(funder))
            except ValueError:
                funder_on_curve = False
            if (
                executable
                or not funder_on_curve
                or (owner_program and owner_program != SYSTEM_PROGRAM_ID)
            ):
                limitations.append(f"Excluded program-controlled funder {funder}.")
                continue
            groups[funder].append(trace)

        largest_funder: str | None = None
        largest_group: list[dict[str, Any]] = []
        largest_share = 0.0
        for funder, group in groups.items():
            share = min(1.0, sum(float(trace["share"]) for trace in group))
            if len(group) > len(largest_group) or (
                len(group) == len(largest_group) and share > largest_share
            ):
                largest_funder = funder
                largest_group = group
                largest_share = share

        creator_linked = bool(
            largest_group
            and (
                largest_funder == context.creator
                or any(trace.get("is_creator") for trace in largest_group)
                or any(trace["wallet"] == context.creator for trace in largest_group)
            )
        )
        size = len(largest_group)
        if size >= 2:
            probability = 0.20 + 0.15 * (size - 1) + 0.60 * largest_share
            if creator_linked:
                probability += 0.10
            probability = round(min(0.95, max(0.0, probability)), 4)
        else:
            probability = 0.05

        findings: list[Finding] = []
        min_wallets = self.settings.solana_cluster_min_wallets
        if size >= 2:
            severity: Severity | None = None
            if size >= min_wallets and largest_share >= self.settings.solana_cluster_high_pct:
                severity = Severity.HIGH
            elif (
                (size >= min_wallets and largest_share >= self.settings.solana_cluster_medium_pct)
                or (creator_linked and size >= 2 and largest_share >= 0.05)
                or largest_share >= self.settings.solana_cluster_high_pct
            ):
                severity = Severity.MEDIUM
            if severity is not None:
                findings.append(
                    Finding.create(
                        rule_id="SOL-CLUSTER-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.CLUSTERS,
                        severity=severity,
                        confidence=0.78 if severity is Severity.HIGH else 0.68,
                        title=(
                            f"Funding-linked holder cluster controls {largest_share:.1%} "
                            "of circulating supply"
                        ),
                        description=(
                            f"{size} of the analyzed top holders share the same earliest "
                            f"funding source ({largest_funder}). Combined they hold "
                            f"{largest_share:.1%} of circulating supply. Common funding is "
                            "correlation, not proof of common control; exchange-funded wallets "
                            "can create false clusters."
                        ),
                        evidence=self._evidence(
                            context,
                            traces,
                            largest_funder,
                            largest_group,
                            largest_share,
                            creator_linked,
                            probability,
                        ),
                        target=context.token_address,
                        block_number=context.slot,
                        references=list(_REFERENCES),
                    )
                )

        traced_ratio = successful_traces / len(candidates)
        coverage = max(0.2, traced_ratio)
        if traced_ratio < 1.0:
            limitations.append(
                f"Funding traces completed for {successful_traces}/{len(candidates)} "
                "candidate wallets; cluster probability is partial."
            )
        if any(trace.get("truncated") for trace in traces):
            limitations.append(
                "At least one wallet had more signatures than the bounded trace window; "
                "the true original funder may be older."
            )
        limitations.append(
            "Cluster probability is a transparent heuristic, not a calibrated statistical "
            "probability. It combines linked-wallet count and held share."
        )
        metrics = {
            "cluster_probability": probability,
            "largest_cluster_size": size,
            "largest_cluster_share_pct": round(largest_share * 100, 4),
            "largest_cluster_funder": largest_funder,
            "cluster_creator_linked": creator_linked,
            "cluster_wallets": [trace["wallet"] for trace in largest_group],
            "cluster_methods": ["common_earliest_funding_source"] if size >= 2 else [],
            "cluster_traced_wallets": successful_traces,
            "cluster_candidate_wallets": len(candidates),
        }
        return self.make_outcome(
            findings=findings[: self.settings.max_findings_per_detector],
            coverage_fraction=coverage,
            limitations=limitations,
            details={"metrics": metrics, "traces": traces},
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _evidence(
        self,
        context: SolanaTokenContext,
        traces: list[dict[str, Any]],
        funder: str | None,
        group: list[dict[str, Any]],
        share: float,
        creator_linked: bool,
        probability: float,
    ) -> dict[str, Any]:
        return {
            "shared_funder": funder,
            "cluster_wallets": [
                {
                    "wallet": trace["wallet"],
                    "amount": trace["amount"],
                    "share_pct": round(float(trace["share"]) * 100, 4),
                    "is_creator": trace["is_creator"],
                    "funding_tx": trace["funding_tx"],
                }
                for trace in group
            ],
            "cluster_share": share,
            "cluster_share_pct": round(share * 100, 4),
            "cluster_probability": probability,
            "creator_linked": creator_linked,
            "creator": context.creator,
            "traced_wallets": len(traces),
            "holder_denominator": str(context.circulating_supply or context.mint.supply),
        }
