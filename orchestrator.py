#!/usr/bin/env python3
"""SD-WAN performance orchestrator.

Runs continuous iperf3 between client (10.1.1.3) and server (10.2.2.2),
correlating wire counters at three vantage points: client NIC, FRR underlay
interfaces, and server NIC.

Usage:
    python3 orchestrator.py --config config.yaml
    python3 orchestrator.py --config config.yaml --appliance ssr --dual-wan
    python3 orchestrator.py --config config.yaml --protocol udp --streams 8
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from config import Config, load_config
from dashboard import Dashboard
from poller import WirePoller, read_local_proc_net_dev
from runner import Iperf3Runner, analyze_run
from ssh_pool import SshError, SshPool, detect_local_iface_for_ip

log = logging.getLogger("sdwan_perf")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)-5s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sdwan_perf",
        description="SD-WAN performance orchestrator with multi-vantage wire counters",
    )
    p.add_argument("--config", type=Path, default=Path("config.yaml"))
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--appliance", choices=["ecv", "ssr"])
    p.add_argument("--dual-wan", action=argparse.BooleanOptionalAction)
    p.add_argument("--protocol", choices=["tcp", "udp"])
    p.add_argument("--streams", type=int)
    p.add_argument("--duration", type=int)
    p.add_argument("--reverse", action=argparse.BooleanOptionalAction)
    p.add_argument("--udp-bandwidth")
    return p.parse_args()


def _apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    raw = config.model_dump()
    if args.appliance is not None:
        raw["active"]["appliance"] = args.appliance
    if args.dual_wan is not None:
        raw["active"]["dual_wan"] = args.dual_wan
    if args.protocol is not None:
        raw["iperf3"]["protocol"] = args.protocol
    if args.streams is not None:
        raw["iperf3"]["parallel_streams"] = args.streams
    if args.duration is not None:
        raw["iperf3"]["duration_s"] = args.duration
    if args.reverse is not None:
        raw["iperf3"]["reverse"] = args.reverse
    if args.udp_bandwidth is not None:
        raw["iperf3"]["udp_bandwidth"] = args.udp_bandwidth
    return Config.model_validate(raw)


async def _resolve_data_ifaces(
    config: Config, pool: SshPool,
) -> tuple[str, str]:
    """Resolve (client_iface, server_iface), detecting from data IPs if unset."""
    client_iface = config.hosts.client.data_iface
    if not client_iface:
        if not config.hosts.client.data_ip:
            raise RuntimeError(
                "Set hosts.client.data_iface or hosts.client.data_ip in config"
            )
        client_iface = detect_local_iface_for_ip(config.hosts.client.data_ip)
        log.info("Auto-detected client data interface: %s (owns %s)",
                 client_iface, config.hosts.client.data_ip)

    server_iface = config.hosts.server.data_iface
    if not server_iface:
        if not config.hosts.server.data_ip:
            raise RuntimeError(
                "Set hosts.server.data_iface or hosts.server.data_ip in config"
            )
        server_iface = await pool.server.detect_iface_for_ip(
            config.hosts.server.data_ip
        )
        log.info("Auto-detected server data interface: %s (owns %s)",
                 server_iface, config.hosts.server.data_ip)

    return client_iface, server_iface


async def _run(config: Config) -> int:
    stop_event = asyncio.Event()

    def _request_stop() -> None:
        if not stop_event.is_set():
            log.info("Stop requested")
            stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)

    log.info(
        "Active config: appliance=%s dual_wan=%s protocol=%s streams=%d duration=%ds reverse=%s",
        config.active.appliance, config.active.dual_wan,
        config.iperf3.protocol, config.iperf3.parallel_streams,
        config.iperf3.duration_s, config.iperf3.reverse,
    )

    async with SshPool(config) as pool:
        await pool.preflight()
        await pool.server.ensure_iperf3_server(port=config.iperf3.port)

        client_iface, server_iface = await _resolve_data_ifaces(config, pool)

        # Three independent pollers, three independent ring buffers.
        # All three pull samples at the same cadence; iperf3 windows are
        # correlated against each one after the fact.
        client_poller = WirePoller(
            name="client",
            reader=read_local_proc_net_dev,
            interfaces=[client_iface],
            interval=config.poller_interval_s,
            buffer_size=config.poller_buffer_size,
        )
        frr_poller = WirePoller(
            name="frr",
            reader=pool.frr.read_proc_net_dev,
            interfaces=config.frr_wan_interfaces(),
            interval=config.poller_interval_s,
            buffer_size=config.poller_buffer_size,
        )
        server_poller = WirePoller(
            name="server",
            reader=pool.server.read_proc_net_dev,
            interfaces=[server_iface],
            interval=config.poller_interval_s,
            buffer_size=config.poller_buffer_size,
        )
        await client_poller.start()
        await frr_poller.start()
        await server_poller.start()

        dashboard = Dashboard(
            client_poller=client_poller,
            frr_poller=frr_poller,
            server_poller=server_poller,
            config=config,
            client_iface=client_iface,
            server_iface=server_iface,
            stop_callback=_request_stop,
        )
        await dashboard.start()

        runner = Iperf3Runner(config=config)

        try:
            run_n = 0
            while not stop_event.is_set():
                run_n += 1
                log.info(
                    "Run #%d  [%s %s P=%d t=%ds]",
                    run_n,
                    config.iperf3.protocol.upper(),
                    "↓ download" if config.iperf3.reverse else "↑ upload",
                    config.iperf3.parallel_streams,
                    config.iperf3.duration_s,
                )

                t_start = client_poller.now()
                result = await runner.run_one()
                t_end = client_poller.now()

                if not result.success:
                    log.warning("  Run #%d failed: %s", run_n, result.error)

                # Wait one extra poller tick so the post-iperf3 sample lands.
                await asyncio.sleep(config.poller_interval_s + 0.1)

                client_w = client_poller.window(t_start, t_end)
                frr_w = frr_poller.window(t_start, t_end)
                server_w = server_poller.window(t_start, t_end)

                analysis = analyze_run(
                    run_n=run_n,
                    iperf_result=result,
                    client_deltas=client_w,
                    frr_deltas=frr_w,
                    server_deltas=server_w,
                    config=config,
                    client_iface=client_iface,
                    server_iface=server_iface,
                )
                dashboard.publish(analysis)

                if result.success:
                    log.info(
                        "  goodput=%.1f Mbps  client_tx=%.1f  frr=%.1f  server_rx=%.1f  "
                        "tcp/ip=%.1f%%  tunnel=%.1f%%  e2e_loss=%.2f%%  retx=%d",
                        result.goodput_mbps,
                        analysis.client.bulk_mbps if analysis.client else 0,
                        analysis.frr.bulk_mbps if analysis.frr else 0,
                        analysis.server.bulk_mbps if analysis.server else 0,
                        analysis.tcp_ip_overhead_pct,
                        analysis.tunnel_overhead_pct,
                        analysis.e2e_loss_pct,
                        result.retransmits,
                    )

                if config.iperf3.cooldown_s > 0 and not stop_event.is_set():
                    try:
                        await asyncio.wait_for(
                            stop_event.wait(),
                            timeout=config.iperf3.cooldown_s,
                        )
                    except asyncio.TimeoutError:
                        pass
        finally:
            log.info("Shutting down…")
            await client_poller.stop()
            await frr_poller.stop()
            await server_poller.stop()
            await dashboard.stop()
            await pool.server.stop_iperf3_server()
    return 0


def main() -> int:
    args = _parse_args()
    _setup_logging(args.log_level)
    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        log.error("Copy config.example.yaml to config.yaml and edit.")
        return 2
    except Exception as exc:  # noqa: BLE001
        log.error("Config load failed: %s", exc)
        return 2

    config = _apply_overrides(config, args)

    try:
        return asyncio.run(_run(config))
    except SshError as exc:
        log.error("SSH error: %s", exc)
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
