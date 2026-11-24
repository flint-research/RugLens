"""Runtime configuration and resource limits.

Configuration is loaded from ``RUGLENS_*`` environment variables and can be
overridden programmatically. Paths are resolved lazily and directories are
only created by an explicit :meth:`RugLensSettings.ensure_directories` call.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, field_validator

from ruglens.core.exceptions import ConfigurationError

DEFAULT_DATA_DIR = Path.home() / ".ruglens"


def _read_str(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _read_int(env: Mapping[str, str], name: str) -> int | None:
    raw = _read_str(env, name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc


def _read_float(env: Mapping[str, str], name: str) -> float | None:
    raw = _read_str(env, name)
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc


def _read_bool(env: Mapping[str, str], name: str) -> bool | None:
    raw = _read_str(env, name)
    if raw is None:
        return None
    normalized = raw.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean, got {raw!r}")


class RugLensSettings(BaseModel):
    """Immutable engine configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # --- Paths / persistence -------------------------------------------------
    data_dir: Path = DEFAULT_DATA_DIR
    cache_path: Path | None = None
    database_url: str | None = None
    plugin_dir: Path | None = None
    cache_max_bytes: int = 1_073_741_824  # 1 GiB
    persist_reports: bool = True
    load_cached_reports: bool = True

    # --- RPC ------------------------------------------------------------------
    rpc_timeout: float = 10.0
    rpc_connect_timeout: float = 5.0
    rpc_max_retries: int = 3
    rpc_backoff_base: float = 0.35
    rpc_rate_limit_per_second: float = 20.0
    rpc_max_concurrency: int = 8
    rpc_max_response_bytes: int = 5_000_000
    max_bytecode_bytes: int = 50_000
    max_log_range_chunks: int = 8

    # --- Detector execution ---------------------------------------------------
    anomaly_detector_timeout: float = 90.0
    max_findings_per_detector: int = 64

    # --- Simulation -----------------------------------------------------------
    simulation_enabled: bool = True
    simulation_concurrency: int = 2
    simulation_timeout: float = 60.0
    anvil_binary: str = "anvil"
    anvil_startup_timeout: float = 25.0
    anvil_shutdown_timeout: float = 5.0
    trade_wallet: str = ""  # empty = derive a clean deterministic wallet per token
    trade_native_amount_wei: int = 100_000_000_000_000_000  # 0.1 native
    trade_gas_limit: int = 2_000_000
    gas_griefing_threshold: int = 1_000_000
    buy_tax_medium_threshold: float = 0.10
    buy_tax_high_threshold: float = 0.25
    buy_tax_critical_threshold: float = 0.50
    sell_tax_medium_threshold: float = 0.10
    sell_tax_high_threshold: float = 0.25
    sell_tax_critical_threshold: float = 0.50

    # --- On-chain detectors ---------------------------------------------------
    liquidity_weth_medium_threshold: float = 1.0
    liquidity_weth_high_threshold: float = 0.1
    lp_unlocked_medium_threshold: float = 0.50
    lp_unlocked_high_threshold: float = 0.80
    extra_lp_lockers: tuple[str, ...] = ()
    top_holder_count: int = 10
    holders_top10_medium_share: float = 0.50
    holders_top10_high_share: float = 0.80
    holders_top1_medium_share: float = 0.25
    holders_top1_high_share: float = 0.50
    holder_log_lookback_blocks: int = 1_000_000
    holder_log_chunk_blocks: int = 100_000
    holder_log_max_events: int = 5_000

    # --- Solana ---------------------------------------------------------------
    solana_enabled: bool = True
    solana_cluster_max_wallets: int = 8
    solana_cluster_signature_limit: int = 1_000
    solana_cluster_min_wallets: int = 3
    solana_liquidity_min_custody_pct: float = 0.005
    solana_creator_medium_pct: float = 0.10
    solana_creator_high_pct: float = 0.20
    solana_top1_medium_pct: float = 0.10
    solana_top1_high_pct: float = 0.20
    solana_top10_medium_pct: float = 0.30
    solana_top10_high_pct: float = 0.50
    solana_cluster_medium_pct: float = 0.10
    solana_cluster_high_pct: float = 0.30

    # --- Optional Slither source analysis ------------------------------------
    slither_enabled: bool = False
    slither_binary: str = "slither"
    slither_timeout: float = 15.0

    # --- Plugins --------------------------------------------------------------
    plugins_enabled: bool = True

    # --- API ------------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_max_concurrent_assessments: int = 2
    api_allow_custom_rpc: bool = False
    api_allow_private_rpc: bool = False
    api_max_body_bytes: int = 32_768
    api_queue_timeout: float = 1.0

    # --- Logging --------------------------------------------------------------
    log_level: str = "INFO"

    @field_validator(
        "anomaly_detector_timeout",
        "simulation_timeout",
        "anvil_startup_timeout",
        "anvil_shutdown_timeout",
        "rpc_timeout",
        "rpc_connect_timeout",
        "slither_timeout",
        "api_queue_timeout",
    )
    @classmethod
    def _positive_timeouts(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("timeouts must be positive")
        return value

    @field_validator(
        "rpc_max_concurrency",
        "simulation_concurrency",
        "trade_native_amount_wei",
        "trade_gas_limit",
        "gas_griefing_threshold",
        "top_holder_count",
        "holder_log_lookback_blocks",
        "holder_log_chunk_blocks",
        "holder_log_max_events",
        "solana_cluster_max_wallets",
        "solana_cluster_signature_limit",
        "solana_cluster_min_wallets",
        "cache_max_bytes",
        "max_bytecode_bytes",
        "rpc_max_response_bytes",
        "api_max_concurrent_assessments",
        "api_max_body_bytes",
        "max_log_range_chunks",
        "max_findings_per_detector",
    )
    @classmethod
    def _positive_ints(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("value must be a positive integer")
        return value

    @field_validator("rpc_max_retries")
    @classmethod
    def _non_negative_retries(cls, value: int) -> int:
        if value < 0:
            raise ValueError("rpc_max_retries must be non-negative")
        return value

    @field_validator(
        "buy_tax_medium_threshold",
        "buy_tax_high_threshold",
        "buy_tax_critical_threshold",
        "sell_tax_medium_threshold",
        "sell_tax_high_threshold",
        "sell_tax_critical_threshold",
        "lp_unlocked_medium_threshold",
        "lp_unlocked_high_threshold",
        "holders_top10_medium_share",
        "holders_top10_high_share",
        "holders_top1_medium_share",
        "holders_top1_high_share",
        "solana_liquidity_min_custody_pct",
        "solana_creator_medium_pct",
        "solana_creator_high_pct",
        "solana_top1_medium_pct",
        "solana_top1_high_pct",
        "solana_top10_medium_pct",
        "solana_top10_high_pct",
        "solana_cluster_medium_pct",
        "solana_cluster_high_pct",
    )
    @classmethod
    def _fraction(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("fractional thresholds must be between 0 and 1")
        return value

    @classmethod
    def from_env(cls, overrides: Mapping[str, Any] | None = None) -> Self:
        """Build settings from ``RUGLENS_*`` variables plus explicit overrides."""
        env = os.environ
        values: dict[str, Any] = {}

        data_dir = _read_str(env, "RUGLENS_DATA_DIR")
        if data_dir:
            values["data_dir"] = Path(data_dir).expanduser()

        for field_name, env_name in (
            ("cache_path", "RUGLENS_CACHE_PATH"),
            ("plugin_dir", "RUGLENS_PLUGIN_DIR"),
        ):
            raw = _read_str(env, env_name)
            if raw:
                values[field_name] = Path(raw).expanduser()

        database_url = _read_str(env, "RUGLENS_DATABASE_URL")
        if database_url:
            values["database_url"] = database_url

        int_fields = {
            "cache_max_bytes": "RUGLENS_CACHE_MAX_BYTES",
            "rpc_max_retries": "RUGLENS_RPC_MAX_RETRIES",
            "rpc_max_concurrency": "RUGLENS_RPC_MAX_CONCURRENCY",
            "rpc_max_response_bytes": "RUGLENS_RPC_MAX_RESPONSE_BYTES",
            "max_bytecode_bytes": "RUGLENS_MAX_BYTECODE_BYTES",
            "simulation_concurrency": "RUGLENS_SIMULATION_CONCURRENCY",
            "trade_native_amount_wei": "RUGLENS_TRADE_NATIVE_WEI",
            "trade_gas_limit": "RUGLENS_TRADE_GAS_LIMIT",
            "gas_griefing_threshold": "RUGLENS_GAS_GRIEFING_THRESHOLD",
            "holder_log_lookback_blocks": "RUGLENS_HOLDER_LOOKBACK_BLOCKS",
            "holder_log_chunk_blocks": "RUGLENS_HOLDER_CHUNK_BLOCKS",
            "holder_log_max_events": "RUGLENS_HOLDER_MAX_EVENTS",
            "top_holder_count": "RUGLENS_TOP_HOLDER_COUNT",
            "solana_cluster_max_wallets": "RUGLENS_SOLANA_CLUSTER_MAX_WALLETS",
            "solana_cluster_signature_limit": "RUGLENS_SOLANA_CLUSTER_SIGNATURE_LIMIT",
            "solana_cluster_min_wallets": "RUGLENS_SOLANA_CLUSTER_MIN_WALLETS",
            "api_port": "RUGLENS_API_PORT",
            "api_max_concurrent_assessments": "RUGLENS_API_MAX_CONCURRENT",
            "api_max_body_bytes": "RUGLENS_API_MAX_BODY_BYTES",
            "max_log_range_chunks": "RUGLENS_MAX_LOG_RANGE_CHUNKS",
        }
        for field_name, env_name in int_fields.items():
            parsed_int = _read_int(env, env_name)
            if parsed_int is not None:
                values[field_name] = parsed_int

        float_fields = {
            "rpc_timeout": "RUGLENS_RPC_TIMEOUT",
            "rpc_connect_timeout": "RUGLENS_RPC_CONNECT_TIMEOUT",
            "rpc_backoff_base": "RUGLENS_RPC_BACKOFF_BASE",
            "rpc_rate_limit_per_second": "RUGLENS_RPC_RATE_LIMIT",
            "anomaly_detector_timeout": "RUGLENS_DETECTOR_TIMEOUT",
            "simulation_timeout": "RUGLENS_SIMULATION_TIMEOUT",
            "anvil_startup_timeout": "RUGLENS_ANVIL_STARTUP_TIMEOUT",
            "anvil_shutdown_timeout": "RUGLENS_ANVIL_SHUTDOWN_TIMEOUT",
            "slither_timeout": "RUGLENS_SLITHER_TIMEOUT",
            "api_queue_timeout": "RUGLENS_API_QUEUE_TIMEOUT",
            "solana_liquidity_min_custody_pct": "RUGLENS_SOLANA_LIQUIDITY_MIN_CUSTODY_PCT",
            "solana_creator_medium_pct": "RUGLENS_SOLANA_CREATOR_MEDIUM_PCT",
            "solana_creator_high_pct": "RUGLENS_SOLANA_CREATOR_HIGH_PCT",
            "solana_top1_medium_pct": "RUGLENS_SOLANA_TOP1_MEDIUM_PCT",
            "solana_top1_high_pct": "RUGLENS_SOLANA_TOP1_HIGH_PCT",
            "solana_top10_medium_pct": "RUGLENS_SOLANA_TOP10_MEDIUM_PCT",
            "solana_top10_high_pct": "RUGLENS_SOLANA_TOP10_HIGH_PCT",
            "solana_cluster_medium_pct": "RUGLENS_SOLANA_CLUSTER_MEDIUM_PCT",
            "solana_cluster_high_pct": "RUGLENS_SOLANA_CLUSTER_HIGH_PCT",
        }
        for field_name, env_name in float_fields.items():
            parsed_float = _read_float(env, env_name)
            if parsed_float is not None:
                values[field_name] = parsed_float

        bool_fields = {
            "simulation_enabled": "RUGLENS_SIMULATION_ENABLED",
            "persist_reports": "RUGLENS_PERSIST_REPORTS",
            "load_cached_reports": "RUGLENS_LOAD_CACHED_REPORTS",
            "plugins_enabled": "RUGLENS_PLUGINS_ENABLED",
            "slither_enabled": "RUGLENS_SLITHER_ENABLED",
            "api_allow_custom_rpc": "RUGLENS_API_ALLOW_CUSTOM_RPC",
            "api_allow_private_rpc": "RUGLENS_API_ALLOW_PRIVATE_RPC",
            "solana_enabled": "RUGLENS_SOLANA_ENABLED",
        }
        for field_name, env_name in bool_fields.items():
            parsed_bool = _read_bool(env, env_name)
            if parsed_bool is not None:
                values[field_name] = parsed_bool

        str_fields = {
            "anvil_binary": "RUGLENS_ANVIL_BINARY",
            "slither_binary": "RUGLENS_SLITHER_BINARY",
            "api_host": "RUGLENS_API_HOST",
            "log_level": "RUGLENS_LOG_LEVEL",
        }
        for field_name, env_name in str_fields.items():
            raw = _read_str(env, env_name)
            if raw is not None:
                values[field_name] = raw

        lockers = _read_str(env, "RUGLENS_EXTRA_LP_LOCKERS")
        if lockers:
            values["extra_lp_lockers"] = tuple(
                item.strip() for item in lockers.split(",") if item.strip()
            )

        if overrides:
            values.update(overrides)
        return cls.model_validate(values)

    def resolved_cache_path(self) -> Path:
        """Absolute path of the SQLite bytecode cache."""
        return (self.cache_path or (self.data_dir / "cache.sqlite3")).expanduser()

    def resolved_plugin_dir(self) -> Path:
        """Absolute path of the user plugin directory."""
        return (self.plugin_dir or (self.data_dir / "plugins")).expanduser()

    def resolved_database_url(self) -> str:
        """Async SQLAlchemy database URL for assessment persistence."""
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{(self.data_dir / 'assessments.sqlite3').as_posix()}"

    def ensure_directories(self) -> None:
        """Create local data, cache, and plugin directories."""
        self.data_dir.expanduser().mkdir(parents=True, exist_ok=True)
        self.resolved_cache_path().parent.mkdir(parents=True, exist_ok=True)
        if self.plugins_enabled:
            self.resolved_plugin_dir().mkdir(parents=True, exist_ok=True)
