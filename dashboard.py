"""Live dashboard via aiohttp.

GET  /                      → static dashboard.html
GET  /api/state             → current state JSON (polled by the page at 1Hz)
POST /api/stop              → request orchestrator shutdown
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from aiohttp import web

from config import Config
from poller import WirePoller
from runner import RunAnalysis

log = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent


class Dashboard:
    def __init__(
        self,
        client_poller: WirePoller,
        frr_poller: WirePoller,
        server_poller: WirePoller,
        config: Config,
        client_iface: str,
        server_iface: str,
        stop_callback: Callable[[], None] | None = None,
    ) -> None:
        self._client_poller = client_poller
        self._frr_poller = frr_poller
        self._server_poller = server_poller
        self._config = config
        self._client_iface = client_iface
        self._server_iface = server_iface
        self._stop_cb = stop_callback
        self._runs: list[RunAnalysis] = []
        self._app = web.Application()
        self._app.router.add_get("/", self._serve_index)
        self._app.router.add_get("/api/state", self._api_state)
        self._app.router.add_post("/api/stop", self._api_stop)
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(
            self._runner,
            host=self._config.dashboard.bind,
            port=self._config.dashboard.port,
        )
        await self._site.start()
        log.info(
            "Dashboard listening on http://%s:%d/",
            self._config.dashboard.bind, self._config.dashboard.port,
        )

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    def publish(self, analysis: RunAnalysis) -> None:
        self._runs.append(analysis)
        if len(self._runs) > 500:
            self._runs = self._runs[-500:]

    async def _serve_index(self, request: web.Request) -> web.Response:
        index = _STATIC_DIR / "dashboard.html"
        if not index.is_file():
            return web.Response(status=500, text="dashboard.html missing")
        return web.Response(
            body=index.read_bytes(),
            content_type="text/html",
            charset="utf-8",
        )

    async def _api_state(self, request: web.Request) -> web.Response:
        appliance = self._config.active_appliance()
        ingress_ifaces = [appliance.wan0.ingress_iface]
        egress_ifaces = [appliance.wan0.egress_iface]
        if self._config.active.dual_wan and appliance.wan1 is not None:
            ingress_ifaces.append(appliance.wan1.ingress_iface)
            egress_ifaces.append(appliance.wan1.egress_iface)

        runs_payload: list[dict[str, Any]] = []
        for r in self._runs[-200:]:
            runs_payload.append({
                "run_n": r.run_n,
                "t": r.timestamp,
                "goodput_mbps": round(r.iperf3.goodput_mbps, 3),
                "client_bulk_mbps": (
                    round(r.client.bulk_mbps, 3) if r.client else None
                ),
                "frr_bulk_mbps": (
                    round(r.frr.bulk_mbps, 3) if r.frr else None
                ),
                "server_bulk_mbps": (
                    round(r.server.bulk_mbps, 3) if r.server else None
                ),
                "tcp_ip_overhead_pct": round(r.tcp_ip_overhead_pct, 2),
                "tunnel_overhead_pct": round(r.tunnel_overhead_pct, 2),
                "e2e_loss_pct": round(r.e2e_loss_pct, 3),
                "west_loss_pct": round(r.west_loss_pct, 3),
                "east_loss_pct": round(r.east_loss_pct, 3),
                "retransmits": r.iperf3.retransmits,
                "lost_packets": r.iperf3.lost_packets,
                "jitter_ms": round(r.iperf3.jitter_ms, 3),
                "protocol": r.iperf3.protocol,
                "streams": r.iperf3.parallel_streams,
                "reverse": r.iperf3.reverse,
                "success": r.iperf3.success,
                "error": r.iperf3.error,
            })

        state = {
            "meta": {
                "appliance": self._config.active.appliance,
                "appliance_desc": appliance.description,
                "dual_wan": self._config.active.dual_wan,
                "client_data_ip": self._config.hosts.client.data_ip,
                "client_data_iface": self._client_iface,
                "server_data_ip": self._config.hosts.server.data_ip,
                "server_data_iface": self._server_iface,
                "frr_mgmt_ip": self._config.hosts.frr.mgmt_ip,
                "interfaces": {
                    "ingress": ingress_ifaces,
                    "egress": egress_ifaces,
                },
                "iperf3": {
                    "protocol": self._config.iperf3.protocol,
                    "duration_s": self._config.iperf3.duration_s,
                    "parallel_streams": self._config.iperf3.parallel_streams,
                    "reverse": self._config.iperf3.reverse,
                    "port": self._config.iperf3.port,
                },
                "poller_interval_s": self._config.poller_interval_s,
            },
            "wire_series": {
                "client": self._client_poller.recent_series(seconds=600),
                "frr": self._frr_poller.recent_series(seconds=600),
                "server": self._server_poller.recent_series(seconds=600),
            },
            "runs": runs_payload,
        }
        return web.json_response(state)

    async def _api_stop(self, request: web.Request) -> web.Response:
        if self._stop_cb is not None:
            self._stop_cb()
            return web.json_response({"stopping": True})
        return web.json_response(
            {"stopping": False, "reason": "no callback registered"}
        )
