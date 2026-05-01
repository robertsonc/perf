"""iperf3 client wrapper with structured result parsing.

Runs the local iperf3 binary against the remote daemon. Captures full JSON
output and synthesises a typed result dataclass with goodput, retransmits,
jitter, packet loss, and the wallclock window the run actually occupied.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

from config import Config
from poller import WireDelta

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Iperf3Result:
    """Parsed result of one iperf3 run."""
    started: bool = False
    success: bool = False
    error: str = ""

    t_start_mono: float = 0.0
    t_end_mono: float = 0.0
    duration_s: float = 0.0

    protocol: str = "tcp"
    parallel_streams: int = 0
    reverse: bool = False

    payload_bytes: int = 0
    goodput_mbps: float = 0.0

    retransmits: int = 0

    lost_packets: int = 0
    total_packets: int = 0
    jitter_ms: float = 0.0

    streams: list[dict[str, Any]] = field(default_factory=list)

    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class HopMetrics:
    """Roll-up of one vantage point's wire counters for one iperf3 window."""
    name: str                       # 'client' | 'frr' | 'server'
    interfaces: list[str] = field(default_factory=list)
    bulk_bytes: int = 0             # bytes in the iperf3 data direction
    return_bytes: int = 0           # bytes in the opposite direction (ACKs)
    duration_s: float = 0.0

    @property
    def bulk_mbps(self) -> float:
        return (self.bulk_bytes * 8) / (self.duration_s * 1e6) if self.duration_s > 0 else 0.0

    @property
    def return_mbps(self) -> float:
        return (self.return_bytes * 8) / (self.duration_s * 1e6) if self.duration_s > 0 else 0.0


@dataclass(slots=True)
class RunAnalysis:
    """Full analysis of one iperf3 run + correlated wire counters."""
    run_n: int
    timestamp: str
    iperf3: Iperf3Result

    # One per vantage point. May be missing if the corresponding poller failed.
    client: HopMetrics | None = None
    frr: HopMetrics | None = None
    server: HopMetrics | None = None

    # Per-hop deltas, computed against payload
    tcp_ip_overhead_pct: float = 0.0   # (client TX − payload) / payload
    tunnel_overhead_pct: float = 0.0   # (frr − client TX) / client TX
    e2e_loss_pct: float = 0.0          # (client TX − server RX) / client TX


class Iperf3Runner:
    """Builds and executes iperf3 commands against the remote server."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._verify_local_iperf3()

    @staticmethod
    def _verify_local_iperf3() -> None:
        if shutil.which("iperf3") is None:
            raise RuntimeError(
                "iperf3 not found in PATH on the client. "
                "Install with: sudo apt install -y iperf3"
            )

    def _build_cmd(self) -> list[str]:
        cfg = self._config
        ic = cfg.iperf3
        target = cfg.hosts.server.data_ip
        if not target:
            raise RuntimeError("hosts.server.data_ip is required")
        cmd: list[str] = [
            "iperf3",
            "-c", target,
            "-p", str(ic.port),
            "-t", str(ic.duration_s),
            "-P", str(ic.parallel_streams),
            "-J",
            "--connect-timeout", "5000",
        ]
        if ic.reverse:
            cmd.append("-R")
        if ic.protocol == "udp":
            cmd.append("-u")
            cmd += ["-b", ic.udp_bandwidth or "0"]
            if ic.udp_length:
                cmd += ["-l", str(ic.udp_length)]
        else:
            if ic.window_kib:
                cmd += ["-w", f"{ic.window_kib}K"]
            if ic.mss_bytes:
                cmd += ["-M", str(ic.mss_bytes)]
        return cmd

    async def run_one(self) -> Iperf3Result:
        cmd = self._build_cmd()
        log.debug("iperf3 cmd: %s", " ".join(cmd))
        result = Iperf3Result(
            protocol=self._config.iperf3.protocol,
            parallel_streams=self._config.iperf3.parallel_streams,
            reverse=self._config.iperf3.reverse,
            started=True,
        )
        result.t_start_mono = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._config.iperf3.duration_s + 60,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.t_end_mono = time.monotonic()
                result.duration_s = result.t_end_mono - result.t_start_mono
                result.error = "iperf3 timed out"
                log.error("iperf3 timed out after %.1fs", result.duration_s)
                return result
        except FileNotFoundError as exc:
            result.error = f"iperf3 binary not found: {exc}"
            return result
        except OSError as exc:
            result.error = f"iperf3 launch failed: {exc}"
            return result

        result.t_end_mono = time.monotonic()
        result.duration_s = result.t_end_mono - result.t_start_mono

        if proc.returncode != 0 and not stdout_b:
            result.error = (stderr_b.decode("utf-8", "replace").strip()
                            or f"iperf3 exited {proc.returncode}")
            log.warning("iperf3 failed: %s", result.error)
            return result

        try:
            data = json.loads(stdout_b)
        except json.JSONDecodeError as exc:
            result.error = f"iperf3 JSON parse failed: {exc}"
            log.warning("%s", result.error)
            return result

        result.raw = data
        self._parse_iperf3_json(data, result)
        result.success = result.goodput_mbps > 0.0
        return result

    @staticmethod
    def _parse_iperf3_json(data: dict[str, Any], result: Iperf3Result) -> None:
        end = data.get("end", {})
        if result.protocol == "udp":
            sum_data = end.get("sum", {})
            result.payload_bytes = int(sum_data.get("bytes", 0) or 0)
            result.lost_packets = int(sum_data.get("lost_packets", 0) or 0)
            result.total_packets = int(sum_data.get("packets", 0) or 0)
            result.jitter_ms = float(sum_data.get("jitter_ms", 0.0) or 0.0)
        else:
            if result.reverse:
                sum_data = end.get("sum_received", end.get("sum_sent", {}))
            else:
                sum_data = end.get("sum_sent", {})
            result.payload_bytes = int(sum_data.get("bytes", 0) or 0)
            result.retransmits = int(
                end.get("sum_sent", {}).get("retransmits", 0) or 0
            )

        sum_block = end.get("sum_sent") or end.get("sum") or {}
        seconds = float(sum_block.get("seconds", 0.0) or 0.0)
        if seconds > 0:
            result.goodput_mbps = (result.payload_bytes * 8) / (seconds * 1e6)

        for s in end.get("streams", []):
            sender = s.get("sender") or {}
            receiver = s.get("receiver") or {}
            udp = s.get("udp") or {}
            result.streams.append({
                "sender_mbps": (
                    (int(sender.get("bytes", 0) or 0) * 8)
                    / (float(sender.get("seconds", 1) or 1) * 1e6)
                ),
                "receiver_mbps": (
                    (int(receiver.get("bytes", 0) or 0) * 8)
                    / (float(receiver.get("seconds", 1) or 1) * 1e6)
                ),
                "retransmits": int(sender.get("retransmits", 0) or 0),
                "lost_packets": int(udp.get("lost_packets", 0) or 0),
                "jitter_ms": float(udp.get("jitter_ms", 0.0) or 0.0),
            })


def _hop_metrics_endpoint(
    name: str,
    deltas: list[WireDelta],
    iface: str,
    reverse: bool,
) -> HopMetrics:
    """Roll up an endpoint NIC's deltas into bulk vs return-direction bytes.

    For an iperf3 upload (reverse=False), the client's bulk direction is TX
    and the server's bulk direction is RX. For a download (reverse=True), it
    flips: the server sends bulk (TX) and the client receives bulk (RX).
    """
    is_client = (name == "client")
    # Bulk direction:
    #   upload + client   → TX
    #   upload + server   → RX
    #   reverse + client  → RX
    #   reverse + server  → TX
    bulk_is_tx = (is_client and not reverse) or (not is_client and reverse)
    hop = HopMetrics(name=name, interfaces=[iface])
    for d in deltas:
        if d.iface != iface:
            continue
        hop.duration_s = max(hop.duration_s, d.duration_s)
        if bulk_is_tx:
            hop.bulk_bytes += d.tx_bytes
            hop.return_bytes += d.rx_bytes
        else:
            hop.bulk_bytes += d.rx_bytes
            hop.return_bytes += d.tx_bytes
    return hop


def _hop_metrics_frr(
    deltas: list[WireDelta],
    config: Config,
) -> HopMetrics:
    """Roll up FRR underlay deltas into bulk vs return-direction bytes.

    For an upload, bulk traffic enters FRR from the West appliance (rx on
    the ingress_iface) and exits toward the East appliance (tx on the
    egress_iface). For a download, the directions flip.

    We use the egress side (tx on egress_iface) as the authoritative bulk
    counter because it represents what the FRR actually forwarded, after any
    queueing or drop on the FRR itself.
    """
    appliance = config.active_appliance()
    egress_ifaces: list[str] = [appliance.wan0.egress_iface]
    ingress_ifaces: list[str] = [appliance.wan0.ingress_iface]
    if config.active.dual_wan and appliance.wan1 is not None:
        egress_ifaces.append(appliance.wan1.egress_iface)
        ingress_ifaces.append(appliance.wan1.ingress_iface)

    reverse = config.iperf3.reverse
    # Upload bulk flows West→East: tx on egress_iface
    # Reverse bulk flows East→West: rx on egress_iface (same iface, opposite dir)
    hop = HopMetrics(
        name="frr",
        interfaces=sorted(set(egress_ifaces + ingress_ifaces)),
    )
    for d in deltas:
        if d.iface in egress_ifaces:
            hop.duration_s = max(hop.duration_s, d.duration_s)
            if not reverse:
                hop.bulk_bytes += d.tx_bytes
                hop.return_bytes += d.rx_bytes
            else:
                hop.bulk_bytes += d.rx_bytes
                hop.return_bytes += d.tx_bytes
    return hop


def analyze_run(
    run_n: int,
    iperf_result: Iperf3Result,
    client_deltas: list[WireDelta],
    frr_deltas: list[WireDelta],
    server_deltas: list[WireDelta],
    config: Config,
    client_iface: str,
    server_iface: str,
) -> RunAnalysis:
    """Combine iperf3 + 3 wire vantage points; compute per-hop metrics."""
    analysis = RunAnalysis(
        run_n=run_n,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        iperf3=iperf_result,
    )
    reverse = config.iperf3.reverse

    if client_deltas and client_iface:
        analysis.client = _hop_metrics_endpoint(
            "client", client_deltas, client_iface, reverse,
        )
    if server_deltas and server_iface:
        analysis.server = _hop_metrics_endpoint(
            "server", server_deltas, server_iface, reverse,
        )
    if frr_deltas:
        analysis.frr = _hop_metrics_frr(frr_deltas, config)

    payload = iperf_result.payload_bytes

    # TCP/IP overhead = how much the client kernel added on top of payload
    if analysis.client and payload > 0:
        client_bulk = analysis.client.bulk_bytes
        if client_bulk > 0:
            analysis.tcp_ip_overhead_pct = (
                (client_bulk - payload) / payload
            ) * 100.0

    # Tunnel overhead = how much EC-V (or SSR) added on top of the
    # already-headered Ethernet frames the client sent
    if analysis.client and analysis.frr:
        client_bulk = analysis.client.bulk_bytes
        frr_bulk = analysis.frr.bulk_bytes
        if client_bulk > 0:
            analysis.tunnel_overhead_pct = (
                (frr_bulk - client_bulk) / client_bulk
            ) * 100.0

    # End-to-end loss = client sent more than server received
    if analysis.client and analysis.server:
        client_bulk = analysis.client.bulk_bytes
        server_bulk = analysis.server.bulk_bytes
        if client_bulk > 0:
            analysis.e2e_loss_pct = max(
                0.0,
                ((client_bulk - server_bulk) / client_bulk) * 100.0,
            )

    return analysis
