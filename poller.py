"""Continuous /proc/net/dev poller with a time-windowed ring buffer.

Each WirePoller owns one source — the local host, the remote FRR, or the
remote server — and reads its /proc/net/dev once per second. iperf3 windows
are correlated to the sample streams from all three pollers after the fact.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Iterable

log = logging.getLogger(__name__)


# An async callable that returns the contents of /proc/net/dev as text.
ProcNetDevReader = Callable[[], Awaitable[str]]


async def read_local_proc_net_dev() -> str:
    """Local read of /proc/net/dev. /proc is a virtual FS — no real disk IO."""
    return Path("/proc/net/dev").read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class CounterSample:
    """One snapshot of /proc/net/dev for a set of interfaces."""
    t: float                        # monotonic seconds
    rx_bytes: dict[str, int]
    tx_bytes: dict[str, int]


@dataclass(frozen=True, slots=True)
class WireDelta:
    """Per-interface byte delta over a time window."""
    iface: str
    rx_bytes: int
    tx_bytes: int
    duration_s: float

    @property
    def rx_mbps(self) -> float:
        return (self.rx_bytes * 8) / (self.duration_s * 1e6) if self.duration_s > 0 else 0.0

    @property
    def tx_mbps(self) -> float:
        return (self.tx_bytes * 8) / (self.duration_s * 1e6) if self.duration_s > 0 else 0.0


def parse_proc_net_dev(
    text: str, ifaces: Iterable[str]
) -> tuple[dict[str, int], dict[str, int]]:
    """Parse /proc/net/dev output into rx/tx byte dicts for `ifaces`."""
    wanted = set(ifaces)
    rx: dict[str, int] = {}
    tx: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name_part, _, stats_part = line.partition(":")
        iface = name_part.strip()
        if iface not in wanted:
            continue
        cols = stats_part.split()
        if len(cols) < 16:
            log.warning("Malformed /proc/net/dev line for %s: %r", iface, line)
            continue
        try:
            rx[iface] = int(cols[0])    # bytes received
            tx[iface] = int(cols[8])    # bytes transmitted
        except ValueError:
            log.warning("Non-integer counter on %s: %r", iface, line)
            continue
    missing = wanted - rx.keys()
    if missing:
        log.warning("Interfaces not found in /proc/net/dev: %s", sorted(missing))
    return rx, tx


class WirePoller:
    """Background task that fills a ring buffer of CounterSample tuples."""

    def __init__(
        self,
        name: str,
        reader: ProcNetDevReader,
        interfaces: list[str],
        interval: float = 1.0,
        buffer_size: int = 3600,
    ) -> None:
        self.name = name
        self._reader = reader
        self._interfaces = list(interfaces)
        self._interval = interval
        self._samples: deque[CounterSample] = deque(maxlen=buffer_size)
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._consecutive_errors = 0
        self._max_consecutive_errors = 10

    @property
    def interfaces(self) -> list[str]:
        return list(self._interfaces)

    @staticmethod
    def now() -> float:
        return time.monotonic()

    async def start(self) -> None:
        if self._task is not None:
            return
        # Take one sample immediately so window() works even before the first interval.
        await self._sample_once()
        self._task = asyncio.create_task(self._run(), name=f"poller-{self.name}")
        log.info(
            "Poller [%s] started: interfaces=%s interval=%.2fs",
            self.name, self._interfaces, self._interval,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _sample_once(self) -> None:
        try:
            text = await self._reader()
        except Exception as exc:  # noqa: BLE001
            self._consecutive_errors += 1
            log.warning(
                "Poller [%s] read failed (%d): %s",
                self.name, self._consecutive_errors, exc,
            )
            if self._consecutive_errors >= self._max_consecutive_errors:
                raise
            return
        rx, tx = parse_proc_net_dev(text, self._interfaces)
        self._samples.append(
            CounterSample(t=self.now(), rx_bytes=rx, tx_bytes=tx)
        )
        self._consecutive_errors = 0

    async def _run(self) -> None:
        next_t = self.now() + self._interval
        while not self._stop.is_set():
            sleep_for = max(0.0, next_t - self.now())
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
                return  # stop set during sleep
            except asyncio.TimeoutError:
                pass
            await self._sample_once()
            next_t += self._interval
            if next_t < self.now():
                next_t = self.now() + self._interval

    def window(self, t_start: float, t_end: float) -> list[WireDelta]:
        """Compute per-interface byte deltas for samples in [t_start, t_end].

        Uses the latest sample at-or-before t_start and at-or-before t_end to
        bracket. If t_start preceded the buffer, falls back to the earliest
        sample we have.
        """
        if t_end <= t_start or not self._samples:
            return []
        first: CounterSample | None = None
        last: CounterSample | None = None
        for s in self._samples:
            if s.t <= t_start:
                first = s
            if s.t <= t_end:
                last = s
            if s.t > t_end:
                break
        if first is None:
            first = self._samples[0]
        if last is None or last.t <= first.t:
            return []
        duration = last.t - first.t
        deltas: list[WireDelta] = []
        for iface in self._interfaces:
            if iface not in first.rx_bytes or iface not in last.rx_bytes:
                continue
            rx_delta = last.rx_bytes[iface] - first.rx_bytes[iface]
            tx_delta = last.tx_bytes[iface] - first.tx_bytes[iface]
            deltas.append(WireDelta(
                iface=iface,
                rx_bytes=max(0, rx_delta),
                tx_bytes=max(0, tx_delta),
                duration_s=duration,
            ))
        return deltas

    def recent_series(self, seconds: int = 600) -> list[dict]:
        """Return a JSON-serialisable view of recent samples for the dashboard."""
        if len(self._samples) < 2:
            return []
        cutoff = self.now() - seconds
        relevant = [s for s in self._samples if s.t >= cutoff]
        if len(relevant) < 2:
            return []
        out: list[dict] = []
        prev = relevant[0]
        for cur in relevant[1:]:
            dt = cur.t - prev.t
            if dt <= 0:
                prev = cur
                continue
            rates: dict[str, dict[str, float]] = {}
            for iface in self._interfaces:
                if iface in cur.rx_bytes and iface in prev.rx_bytes:
                    rx_d = max(0, cur.rx_bytes[iface] - prev.rx_bytes[iface])
                    tx_d = max(0, cur.tx_bytes[iface] - prev.tx_bytes[iface])
                    rates[iface] = {
                        "rx_mbps": (rx_d * 8) / (dt * 1e6),
                        "tx_mbps": (tx_d * 8) / (dt * 1e6),
                    }
            out.append({"t": cur.t, "rates": rates})
            prev = cur
        return out
