"""Anvil subprocess lifecycle management.

Every fork is gated by a semaphore (default 2), has a hard startup timeout, and
is terminated in a ``finally`` block. No simulation can leave a zombie Anvil
process behind.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import socket
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

import httpx

from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import AnvilUnavailableError, SimulationTimeoutError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AnvilInstance:
    """A live, ready-to-use Anvil fork."""

    url: str
    port: int
    chain_id: int
    fork_block_number: int | None
    work_dir: Path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class AnvilManager:
    """Spawns and deterministically tears down ephemeral Anvil instances."""

    def __init__(self, settings: RugLensSettings) -> None:
        self._settings = settings
        self._semaphore: asyncio.Semaphore | None = None
        self._active = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._settings.simulation_concurrency)
        return self._semaphore

    @property
    def active_instances(self) -> int:
        """Number of forks currently held by callers."""
        return self._active

    @staticmethod
    def is_available(binary: str = "anvil") -> bool:
        """Whether the configured Anvil executable can be found."""
        return shutil.which(binary) is not None

    def _resolve_binary(self) -> str:
        binary = shutil.which(self._settings.anvil_binary)
        if binary is None:
            raise AnvilUnavailableError(
                f"Foundry Anvil executable {self._settings.anvil_binary!r} not found. "
                "Install Foundry (https://book.getfoundry.sh/getting-started/installation) "
                "or set RUGLENS_ANVIL_BINARY."
            )
        return binary

    @contextlib.asynccontextmanager
    async def fork(
        self,
        fork_url: str | None,
        block_number: int | None,
        chain_id: int,
    ) -> AsyncIterator[AnvilInstance]:
        """Spawn an isolated fork and guarantee process cleanup."""
        semaphore = self._get_semaphore()
        await semaphore.acquire()
        process: asyncio.subprocess.Process | None = None
        work_dir = Path(tempfile.mkdtemp(prefix="ruglens-anvil-"))
        stdout_file: IO[bytes] | None = None
        stderr_file: IO[bytes] | None = None
        self._active += 1
        try:
            binary = self._resolve_binary()
            port = _free_port()
            command = [
                binary,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--chain-id",
                str(chain_id),
                "--gas-limit",
                "30000000",
                "--silent",
            ]
            if fork_url:
                command.extend(["--fork-url", fork_url])
                if block_number is not None:
                    command.extend(["--fork-block-number", str(block_number)])
            logger.debug("Starting Anvil: %s", " ".join(command))
            stdout_path = work_dir / "anvil.stdout.log"
            stderr_path = work_dir / "anvil.stderr.log"
            stdout_file = stdout_path.open("wb")
            stderr_file = stderr_path.open("wb")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=stdout_file,
                stderr=stderr_file,
            )
            url = f"http://127.0.0.1:{port}"
            await self._wait_until_ready(process, url, stderr_path)
            instance = AnvilInstance(
                url=url,
                port=port,
                chain_id=chain_id,
                fork_block_number=block_number,
                work_dir=work_dir,
            )
            yield instance
        finally:
            self._active = max(0, self._active - 1)
            await self._terminate(process)
            for handle in (stdout_file, stderr_file):
                if handle is not None:
                    with contextlib.suppress(OSError):
                        handle.close()
            shutil.rmtree(work_dir, ignore_errors=True)
            semaphore.release()

    async def _wait_until_ready(
        self,
        process: asyncio.subprocess.Process,
        url: str,
        stderr_path: Path,
    ) -> None:
        deadline = time.monotonic() + self._settings.anvil_startup_timeout
        async with httpx.AsyncClient(timeout=1.0) as client:
            while time.monotonic() < deadline:
                if process.returncode is not None:
                    raise AnvilUnavailableError(
                        f"Anvil exited during startup with code {process.returncode}: "
                        f"{_tail(stderr_path)}"
                    )
                try:
                    response = await client.post(
                        url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "web3_clientVersion",
                            "params": [],
                        },
                    )
                    if response.status_code == 200 and "result" in response.json():
                        return
                except (httpx.HTTPError, ValueError):
                    pass
                await asyncio.sleep(0.1)
        raise SimulationTimeoutError(
            f"Anvil did not become ready within {self._settings.anvil_startup_timeout}s: "
            f"{_tail(stderr_path)}"
        )

    async def _terminate(self, process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=self._settings.anvil_shutdown_timeout,
            )
        except TimeoutError:
            logger.warning("Anvil did not terminate gracefully; killing pid %s", process.pid)
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=2.0)


def _tail(path: Path, max_chars: int = 600) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[-max_chars:].strip()
