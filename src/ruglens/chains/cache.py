"""Block-aware, immutable SQLite bytecode cache."""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

import aiosqlite

from ruglens.core.exceptions import CacheError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bytecode_cache (
    chain_id     INTEGER NOT NULL,
    address      TEXT    NOT NULL,
    block_number INTEGER NOT NULL,
    code         BLOB    NOT NULL,
    code_hash    TEXT    NOT NULL,
    fetched_at   INTEGER NOT NULL,
    PRIMARY KEY (chain_id, address, block_number)
);
CREATE INDEX IF NOT EXISTS idx_bytecode_fetched_at ON bytecode_cache(fetched_at);
"""


class BytecodeCache:
    """Persistent cache for immutable runtime bytecode.

    Contract code at a given block can never change, so entries are kept until
    explicit LRU eviction keeps the database below ``max_bytes``.
    """

    def __init__(self, path: Path | str, *, max_bytes: int = 1_073_741_824) -> None:
        self._path = str(path)
        self._max_bytes = max_bytes
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._initialized = False

    @property
    def path(self) -> str:
        """Filesystem location of the cache database."""
        return self._path

    async def initialize(self) -> None:
        """Open the database and create the schema exactly once."""
        if self._initialized:
            return
        async with self._lock:
            if self._conn is not None:
                return
            if self._path != ":memory:":
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            try:
                self._conn = await aiosqlite.connect(self._path)
                self._conn.row_factory = aiosqlite.Row
                await self._conn.execute("PRAGMA journal_mode=WAL")
                await self._conn.execute("PRAGMA synchronous=NORMAL")
                await self._conn.executescript(_SCHEMA)
                await self._conn.commit()
            except (aiosqlite.Error, OSError) as exc:
                raise CacheError(f"Could not initialize bytecode cache: {exc}") from exc
            self._initialized = True

    async def _ensure_initialized(self) -> aiosqlite.Connection:
        if not self._initialized:
            await self.initialize()
        if self._conn is None:  # pragma: no cover - defensive
            raise CacheError("Bytecode cache connection is unavailable")
        return self._conn

    async def get(self, chain_id: int, address: str, block_number: int) -> bytes | None:
        """Return cached bytecode for an exact chain/address/block, if present."""
        conn = await self._ensure_initialized()
        try:
            async with conn.execute(
                "SELECT code FROM bytecode_cache WHERE chain_id=? AND address=? AND block_number=?",
                (chain_id, address.lower(), block_number),
            ) as cursor:
                row = await cursor.fetchone()
        except aiosqlite.Error as exc:
            raise CacheError(f"Could not read bytecode cache: {exc}") from exc
        if row is None:
            return None
        return bytes(row["code"])

    async def put(
        self,
        chain_id: int,
        address: str,
        block_number: int,
        code: bytes,
    ) -> None:
        """Insert or replace a block-pinned bytecode entry and enforce the size cap."""
        conn = await self._ensure_initialized()
        code_hash = hashlib.sha256(code).hexdigest()
        try:
            async with self._lock:
                await conn.execute(
                    """
                    INSERT OR REPLACE INTO bytecode_cache
                        (chain_id, address, block_number, code, code_hash, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (chain_id, address.lower(), block_number, code, code_hash, int(time.time())),
                )
                await conn.commit()
                await self._prune_locked(conn)
        except aiosqlite.Error as exc:
            raise CacheError(f"Could not write bytecode cache: {exc}") from exc

    async def _prune_locked(self, conn: aiosqlite.Connection) -> None:
        async with conn.execute(
            "SELECT COALESCE(SUM(LENGTH(code)), 0) AS total FROM bytecode_cache"
        ) as cursor:
            row = await cursor.fetchone()
        total = int(row["total"]) if row is not None else 0
        if total <= self._max_bytes:
            return
        target = int(self._max_bytes * 0.8)
        async with conn.execute(
            "SELECT rowid, LENGTH(code) AS size FROM bytecode_cache "
            "ORDER BY fetched_at ASC, rowid ASC"
        ) as cursor:
            rows = await cursor.fetchall()
        to_delete: list[int] = []
        current = total
        for row in rows:
            if current <= target:
                break
            to_delete.append(int(row["rowid"]))
            current -= int(row["size"])
        if to_delete:
            placeholders = ",".join("?" for _ in to_delete)
            await conn.execute(
                f"DELETE FROM bytecode_cache WHERE rowid IN ({placeholders})", to_delete
            )
            await conn.commit()

    async def stats(self) -> dict[str, Any]:
        """Return entry count, byte size, and the configured ceiling."""
        conn = await self._ensure_initialized()
        async with conn.execute(
            "SELECT COUNT(*) AS entries, COALESCE(SUM(LENGTH(code)), 0) AS total FROM bytecode_cache"
        ) as cursor:
            row = await cursor.fetchone()
        return {
            "entries": int(row["entries"]) if row is not None else 0,
            "bytes": int(row["total"]) if row is not None else 0,
            "max_bytes": self._max_bytes,
        }

    async def clear(self) -> None:
        """Delete all cached bytecode (used by maintenance tooling)."""
        conn = await self._ensure_initialized()
        try:
            await conn.execute("DELETE FROM bytecode_cache")
            await conn.commit()
        except aiosqlite.Error as exc:
            raise CacheError(f"Could not clear bytecode cache: {exc}") from exc

    async def close(self) -> None:
        """Close the underlying SQLite connection."""
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None
            self._initialized = False
