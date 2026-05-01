"""Persistent SSH connection management using asyncssh.

Each remote host gets exactly one long-lived connection for the duration of
the orchestrator. This eliminates per-poll SSH+sudo startup variance, which
was the root cause of the V1 wire-counter sawtooth artifact.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
from dataclasses import dataclass
from typing import Self

import asyncssh

from config import Config, HostConfig

log = logging.getLogger(__name__)


class SshError(RuntimeError):
    """Raised when an SSH command fails."""


@dataclass(slots=True)
class _Conn:
    host: HostConfig
    name: str
    client: asyncssh.SSHClientConnection | None = None

    async def connect(self) -> None:
        if self.client is not None:
            return
        password = self.host.resolve_password()
        connect_kwargs: dict = {
            "host": self.host.mgmt_ip,
            "username": self.host.ssh_user,
            "known_hosts": None,  # lab-only; replace with strict known_hosts in prod
            "keepalive_interval": 15,
            "keepalive_count_max": 3,
        }
        if self.host.ssh_key_path:
            connect_kwargs["client_keys"] = [self.host.ssh_key_path]
        if password:
            connect_kwargs["password"] = password
        log.info(
            "Connecting to %s (%s) as %s",
            self.name, self.host.mgmt_ip, self.host.ssh_user,
        )
        try:
            self.client = await asyncio.wait_for(
                asyncssh.connect(**connect_kwargs), timeout=15.0
            )
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            raise SshError(
                f"Failed to connect to {self.name} ({self.host.mgmt_ip}): {exc}"
            ) from exc

    async def close(self) -> None:
        if self.client is not None:
            self.client.close()
            await self.client.wait_closed()
            self.client = None

    async def run(
        self, cmd: str, *, timeout: float = 30.0, check: bool = True,
    ) -> asyncssh.SSHCompletedProcess:
        if self.client is None:
            raise SshError(f"{self.name}: not connected")
        try:
            result = await asyncio.wait_for(
                self.client.run(cmd, check=False), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            raise SshError(
                f"{self.name}: command timed out after {timeout}s: {cmd!r}"
            ) from exc
        if check and result.exit_status != 0:
            raise SshError(
                f"{self.name}: exit={result.exit_status} cmd={cmd!r} "
                f"stderr={(result.stderr or '').strip()!r}"
            )
        return result

    async def read_proc_net_dev(self) -> str:
        """Single atomic read of /proc/net/dev."""
        result = await self.run("cat /proc/net/dev", timeout=5.0)
        return result.stdout or ""

    async def detect_iface_for_ip(self, ip: str) -> str:
        """Find the interface that owns `ip` via `ip -4 -o addr show`."""
        result = await self.run("ip -4 -o addr show", timeout=5.0)
        for line in (result.stdout or "").splitlines():
            parts = line.split()
            # "2: ens160    inet 10.1.1.3/24 brd ..."
            if (
                len(parts) >= 4
                and parts[2] == "inet"
                and parts[3].split("/")[0] == ip
            ):
                return parts[1]
        raise SshError(f"{self.name}: no interface found owning {ip}")


def detect_local_iface_for_ip(ip: str) -> str:
    """Find the local interface that owns `ip` via `ip -4 -o addr show`."""
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"],
        capture_output=True, text=True, check=False, timeout=5.0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ip addr show failed: {result.stderr.strip()}")
    for line in result.stdout.splitlines():
        parts = line.split()
        if (
            len(parts) >= 4
            and parts[2] == "inet"
            and parts[3].split("/")[0] == ip
        ):
            return parts[1]
    raise RuntimeError(f"No local interface found owning {ip}")


class FrrSession:
    """Convenience wrapper around the FRR connection."""

    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    async def read_proc_net_dev(self) -> str:
        return await self._conn.read_proc_net_dev()

    async def detect_iface_for_ip(self, ip: str) -> str:
        return await self._conn.detect_iface_for_ip(ip)


class ServerSession:
    """SSH wrapper for the iperf3 server host."""

    def __init__(self, conn: _Conn, iperf3_path: str = "iperf3") -> None:
        self._conn = conn
        self._iperf3 = iperf3_path

    async def read_proc_net_dev(self) -> str:
        return await self._conn.read_proc_net_dev()

    async def detect_iface_for_ip(self, ip: str) -> str:
        return await self._conn.detect_iface_for_ip(ip)

    async def ensure_iperf3_server(self, port: int) -> None:
        """Start (or restart) the iperf3 server in daemon mode on `port`."""
        log.info("Ensuring iperf3 server on %s:%d", self._conn.host.mgmt_ip, port)
        # pkill against the exact path we'll start with — avoids killing other
        # iperf3 invocations on the box.
        iperf3 = shlex.quote(self._iperf3)
        await self._conn.run(
            f"pkill -f {iperf3} || true",
            timeout=5.0, check=False,
        )
        await asyncio.sleep(0.5)
        cmd = (
            f"{iperf3} -s -p {port} -D "
            f"--logfile /tmp/iperf3_{port}.log"
        )
        await self._conn.run(cmd, timeout=10.0)
        await asyncio.sleep(0.5)
        check = await self._conn.run(
            f"pgrep -f {shlex.quote(f'{self._iperf3} -s -p {port}')} | wc -l",
            timeout=5.0, check=False,
        )
        running = (check.stdout or "0").strip()
        if running == "0":
            tail = await self._conn.run(
                f"tail -20 /tmp/iperf3_{port}.log",
                timeout=5.0, check=False,
            )
            raise SshError(
                f"iperf3 server failed to start on port {port}. "
                f"Tail: {(tail.stdout or '').strip()}"
            )
        log.info("iperf3 server is running")

    async def stop_iperf3_server(self) -> None:
        log.info("Stopping iperf3 server")
        try:
            await self._conn.run(
                f"pkill -f {shlex.quote(self._iperf3)} || true",
                timeout=5.0, check=False,
            )
        except SshError as exc:
            log.warning("iperf3 server stop failed (non-fatal): %s", exc)


class SshPool:
    """Async context manager that owns persistent SSH sessions."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._frr_conn = _Conn(config.hosts.frr, name="frr")
        self._server_conn = _Conn(config.hosts.server, name="server")
        self.frr = FrrSession(self._frr_conn)
        self.server = ServerSession(
            self._server_conn,
            iperf3_path=config.hosts.server.iperf3_path,
        )

    async def __aenter__(self) -> Self:
        await self._frr_conn.connect()
        await self._server_conn.connect()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._server_conn.close()
        await self._frr_conn.close()

    async def preflight(self) -> None:
        """Cheap sanity checks: both hosts respond, /proc/net/dev readable."""
        echo = await self._frr_conn.run("echo ok", timeout=5.0)
        if "ok" not in (echo.stdout or ""):
            raise SshError("FRR did not echo correctly")
        await self.frr.read_proc_net_dev()

        echo2 = await self._server_conn.run("echo ok", timeout=5.0)
        if "ok" not in (echo2.stdout or ""):
            raise SshError("Server did not echo correctly")

        which = await self._server_conn.run(
            f"command -v {shlex.quote(self._config.hosts.server.iperf3_path)}",
            timeout=5.0, check=False,
        )
        if which.exit_status != 0:
            raise SshError(
                f"iperf3 not found on server "
                f"(looked for: {self._config.hosts.server.iperf3_path}). "
                f"Install with: sudo apt install -y iperf3"
            )
        log.info("Pre-flight OK")
