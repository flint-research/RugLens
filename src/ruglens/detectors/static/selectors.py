"""Curated EVM selector and opcode signatures.

Selectors are derived from canonical ABI signatures at import time. Detection
requires either a PUSH4+EQ dispatch pattern or an exact match against this
curated table, which keeps false positives from arbitrary PUSH4 constants low.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyevmasm import disassemble_all

from ruglens.chains.evm.abi import selector
from ruglens.core.enums import DetectorCategory, Severity


@dataclass(frozen=True, slots=True)
class FunctionSignature:
    """A risky function signature and its group."""

    signature: str
    name: str
    group: str
    selector: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "selector", "0x" + selector(self.signature).hex())


@dataclass(frozen=True, slots=True)
class RiskGroup:
    """Rule metadata for a family of risky selectors."""

    name: str
    rule_id: str
    severity: Severity
    confidence: float
    title: str
    description: str
    category: DetectorCategory
    references: tuple[str, ...] = ()


RISK_GROUPS: dict[str, RiskGroup] = {
    "mint": RiskGroup(
        name="mint",
        rule_id="STATIC-MINT-001",
        severity=Severity.MEDIUM,
        confidence=0.72,
        title="Minting capability present",
        description=(
            "The bytecode dispatches to one or more mint-like functions. A live owner "
            "with this capability can dilute holders without a market transaction. "
            "Ownership context determines whether this remains a capability or becomes "
            "a high-severity control risk."
        ),
        category=DetectorCategory.OWNERSHIP,
        references=("https://eips.ethereum.org/EIPS/eip-20",),
    ),
    "blacklist": RiskGroup(
        name="blacklist",
        rule_id="STATIC-BLACKLIST-001",
        severity=Severity.MEDIUM,
        confidence=0.78,
        title="Address restriction controls present",
        description=(
            "The contract exposes blacklist, freeze, or bot-control functions. These "
            "can prevent specific wallets from transferring or selling tokens."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
    "pause": RiskGroup(
        name="pause",
        rule_id="STATIC-PAUSE-001",
        severity=Severity.MEDIUM,
        confidence=0.72,
        title="Trading pause/toggle controls present",
        description=(
            "The contract can globally pause transfers or toggle trading. An active "
            "controller can freeze all holders at will."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
    "tax": RiskGroup(
        name="tax",
        rule_id="STATIC-TAX-CONTROL-001",
        severity=Severity.MEDIUM,
        confidence=0.68,
        title="Mutable fee/tax controls present",
        description=(
            "The contract exposes functions that change buy, sell, or transfer fees. "
            "A dynamic simulation measures the current tax; this finding records the "
            "capability to raise it later."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
    "upgrade": RiskGroup(
        name="upgrade",
        rule_id="STATIC-UPGRADE-001",
        severity=Severity.MEDIUM,
        confidence=0.76,
        title="Implementation upgrade functions present",
        description=(
            "Upgrade-like selectors were found. If paired with an active proxy slot, "
            "the code backing the token can be replaced after launch."
        ),
        category=DetectorCategory.PROXY,
        references=("https://eips.ethereum.org/EIPS/eip-1967",),
    ),
    "withdraw": RiskGroup(
        name="withdraw",
        rule_id="STATIC-WITHDRAW-001",
        severity=Severity.LOW,
        confidence=0.55,
        title="Privileged withdrawal functions present",
        description=(
            "The contract exposes functions that can withdraw native currency or "
            "tokens. This is common in legitimate treasury designs but also enables "
            "liquidity or fee extraction."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
    "limits": RiskGroup(
        name="limits",
        rule_id="STATIC-LIMITS-001",
        severity=Severity.LOW,
        confidence=0.5,
        title="Transaction/wallet limit controls present",
        description=(
            "The contract can change maximum transaction or wallet sizes. Limits may "
            "be legitimate anti-whale controls or a mechanism to block large sells."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
    "router": RiskGroup(
        name="router",
        rule_id="STATIC-ROUTER-001",
        severity=Severity.LOW,
        confidence=0.45,
        title="Router/pair configuration functions present",
        description=(
            "The contract can update DEX router, pair, or fee-wallet configuration. "
            "Misconfiguration or malicious reassignment can redirect trading."
        ),
        category=DetectorCategory.OWNERSHIP,
    ),
}

_SIGNATURES: tuple[FunctionSignature, ...] = (
    # Minting
    FunctionSignature("mint(address,uint256)", "mint", "mint"),
    FunctionSignature("mint(uint256)", "mint", "mint"),
    FunctionSignature("mint(address,uint256,bytes)", "mint", "mint"),
    FunctionSignature("mintTo(address,uint256)", "mintTo", "mint"),
    FunctionSignature("issue(uint256)", "issue", "mint"),
    # Blacklist / freeze / bot controls
    FunctionSignature("blacklist(address)", "blacklist", "blacklist"),
    FunctionSignature("addBlackList(address)", "addBlackList", "blacklist"),
    FunctionSignature("addToBlacklist(address)", "addToBlacklist", "blacklist"),
    FunctionSignature("setBlacklist(address,bool)", "setBlacklist", "blacklist"),
    FunctionSignature("setBlackList(address,bool)", "setBlackList", "blacklist"),
    FunctionSignature("freeze(address)", "freeze", "blacklist"),
    FunctionSignature("setBot(address,bool)", "setBot", "blacklist"),
    FunctionSignature("setBots(address,bool)", "setBots", "blacklist"),
    # Pause / trading toggles
    FunctionSignature("pause()", "pause", "pause"),
    FunctionSignature("pause(bool)", "pause", "pause"),
    FunctionSignature("setPaused(bool)", "setPaused", "pause"),
    FunctionSignature("setTradingEnabled(bool)", "setTradingEnabled", "pause"),
    FunctionSignature("setTrading(bool)", "setTrading", "pause"),
    FunctionSignature("enableTrading()", "enableTrading", "pause"),
    FunctionSignature("disableTrading()", "disableTrading", "pause"),
    # Tax/fee mutation
    FunctionSignature("setTax(uint256)", "setTax", "tax"),
    FunctionSignature("setTaxes(uint256,uint256)", "setTaxes", "tax"),
    FunctionSignature("setBuyTax(uint256)", "setBuyTax", "tax"),
    FunctionSignature("setSellTax(uint256)", "setSellTax", "tax"),
    FunctionSignature("setFee(uint256)", "setFee", "tax"),
    FunctionSignature("setFees(uint256,uint256)", "setFees", "tax"),
    FunctionSignature("updateTax(uint256)", "updateTax", "tax"),
    FunctionSignature("setTransferTax(uint256)", "setTransferTax", "tax"),
    # Upgradeability
    FunctionSignature("upgradeTo(address)", "upgradeTo", "upgrade"),
    FunctionSignature("upgradeToAndCall(address,bytes)", "upgradeToAndCall", "upgrade"),
    FunctionSignature("setImplementation(address)", "setImplementation", "upgrade"),
    FunctionSignature("changeImplementation(address)", "changeImplementation", "upgrade"),
    # Privileged withdrawals
    FunctionSignature("withdrawETH()", "withdrawETH", "withdraw"),
    FunctionSignature("withdrawAll()", "withdrawAll", "withdraw"),
    FunctionSignature("rescueETH()", "rescueETH", "withdraw"),
    FunctionSignature("emergencyWithdraw()", "emergencyWithdraw", "withdraw"),
    # Limits
    FunctionSignature("setMaxTxAmount(uint256)", "setMaxTxAmount", "limits"),
    FunctionSignature("setMaxWalletSize(uint256)", "setMaxWalletSize", "limits"),
    FunctionSignature("setMaxWallet(uint256)", "setMaxWallet", "limits"),
    FunctionSignature("setSwapThreshold(uint256)", "setSwapThreshold", "limits"),
    FunctionSignature("setSwapEnabled(bool)", "setSwapEnabled", "limits"),
    # Router / pair configuration
    FunctionSignature("setRouter(address)", "setRouter", "router"),
    FunctionSignature("setPair(address)", "setPair", "router"),
    FunctionSignature("setMarketingWallet(address)", "setMarketingWallet", "router"),
    FunctionSignature("setTaxWallet(address)", "setTaxWallet", "router"),
)

SIGNATURE_BY_SELECTOR: dict[str, FunctionSignature] = {
    signature.selector: signature for signature in _SIGNATURES
}

OPCODES_OF_INTEREST = ("DELEGATECALL", "SELFDESTRUCT", "CREATE2")


@dataclass(frozen=True, slots=True)
class SelectorScan:
    """Result of a pyevmasm disassembly pass."""

    selector_count: int
    selectors: tuple[str, ...]
    matched_groups: dict[str, tuple[FunctionSignature, ...]]
    opcode_counts: dict[str, int]
    opcode_pcs: dict[str, tuple[int, ...]]
    instruction_count: int


def scan_bytecode(bytecode: bytes) -> SelectorScan:
    """Disassemble runtime bytecode and extract selectors and critical opcodes."""
    if not bytecode:
        raise ValueError("Cannot disassemble empty bytecode")
    instructions = list(disassemble_all(bytecode))
    if not instructions:
        raise ValueError("Disassembler returned no instructions")

    dispatch_selectors: set[str] = set()
    all_push4: set[str] = set()
    opcode_counts: dict[str, int] = dict.fromkeys(OPCODES_OF_INTEREST, 0)
    opcode_pcs: dict[str, list[int]] = {name: [] for name in OPCODES_OF_INTEREST}

    for index, instruction in enumerate(instructions):
        name = instruction.name
        if name in opcode_counts:
            opcode_counts[name] += 1
            if len(opcode_pcs[name]) < 16:
                opcode_pcs[name].append(instruction.pc)
        if name != "PUSH4":
            continue
        operand = instruction.operand
        if not isinstance(operand, int):
            continue
        selector_hex = f"0x{operand:08x}"
        all_push4.add(selector_hex)
        window = instructions[index + 1 : index + 7]
        if any(candidate.name == "EQ" for candidate in window):
            dispatch_selectors.add(selector_hex)

    matched: dict[str, list[FunctionSignature]] = {}
    for selector_hex in sorted(all_push4):
        signature = SIGNATURE_BY_SELECTOR.get(selector_hex)
        if signature is not None:
            matched.setdefault(signature.group, []).append(signature)

    all_selectors = dispatch_selectors | {
        item.selector for group in matched.values() for item in group
    }
    return SelectorScan(
        selector_count=len(all_selectors),
        selectors=tuple(sorted(all_selectors)),
        matched_groups={
            group: tuple(sorted(items, key=lambda item: item.selector))
            for group, items in sorted(matched.items())
        },
        opcode_counts=opcode_counts,
        opcode_pcs={name: tuple(pcs) for name, pcs in opcode_pcs.items()},
        instruction_count=len(instructions),
    )
