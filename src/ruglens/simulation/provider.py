"""Trade simulator provider bound to chain configuration and RPC endpoints."""

from __future__ import annotations

from collections.abc import Sequence

from ruglens.chains.evm.registry import normalize_chain, resolve_rpc_urls
from ruglens.core.config import RugLensSettings
from ruglens.core.interfaces import TradeSimulator
from ruglens.simulation.anvil import AnvilManager
from ruglens.simulation.trade_sim import TradeSimulator as EvmTradeSimulator


class TradeSimulatorProvider:
    """Create and cache one fork simulator per chain/RPC pair."""

    def __init__(self, settings: RugLensSettings) -> None:
        self._settings = settings
        self._manager = AnvilManager(settings)
        self._simulators: dict[tuple[int, str], TradeSimulator] = {}

    def get_simulator(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> TradeSimulator | None:
        """Return a simulator, or ``None`` when simulation is disabled."""
        if not self._settings.simulation_enabled:
            return None
        chain = normalize_chain(chain_id)
        urls = resolve_rpc_urls(chain, rpc_urls)
        if not urls:
            return None
        key = (int(chain.chain_id), urls[0])
        existing = self._simulators.get(key)
        if existing is not None:
            return existing
        simulator = EvmTradeSimulator(
            self._manager,
            chain,
            self._settings,
            fork_rpc_url=urls[0],
        )
        self._simulators[key] = simulator
        return simulator

    @property
    def manager(self) -> AnvilManager:
        """The shared Anvil lifecycle manager (useful for diagnostics)."""
        return self._manager
