#!/usr/bin/env python3
"""
Network Vitals (netquality.py) - bidirectional network quality probe between
two workstations.

A single, self-contained, dependency-free Python app. Run the SAME program on
both workstations. Each instance continuously sends AND receives:

    * 2 UDP probe streams  (default ports 30201 and 30202)
    * 2 TCP probe streams  (default ports 30101 and 30102)

Every stream is a probe -> echo loop, so round-trip time (and therefore latency,
loss and jitter) is measured without needing the two clocks to be synchronized.
A realtime GUI (Tkinter, ships with Windows Python) shows per-stream loss,
latency and jitter, plus an overall connection quality score (ITU-T E-model
R-factor / MOS). If no display is available it falls back to a console UI.

Typical use
-----------
On workstation A (IP 10.0.0.1):   python netquality.py --peer 10.0.0.2
On workstation B (IP 10.0.0.2):   python netquality.py --peer 10.0.0.1

That is all the configuration required - the protocol is fully symmetric.

Local loopback smoke test (one machine, Linux only - two loopback aliases):
    python netquality.py --bind 127.0.0.1 --peer 127.0.0.2 --no-gui
    python netquality.py --bind 127.0.0.2 --peer 127.0.0.1 --no-gui
"""

import argparse
import math
import socket
import struct
import sys
import threading
import time
from collections import deque

# ---------------------------------------------------------------------------
# Wire protocol
# ---------------------------------------------------------------------------
# Every probe/echo packet has a fixed header. For UDP it is one datagram; for
# TCP every message is exactly `size` bytes so the reader can frame on length.
#
#   magic   : uint32  - identifies our traffic, ignores stray packets
#   ptype   : uint8   - PROBE or ECHO
#   sid     : uint8   - stream id (which port/proto this belongs to)
#   seq     : uint32  - per-stream sequence number
#   ts_ns   : uint64  - originator's monotonic clock at send time (echoed back)
#
# The reflector copies the header back verbatim with ptype flipped to ECHO, so
# the originator computes RTT = now - ts_ns purely against its OWN clock.

MAGIC = 0x4E51_5631  # "NQV1"
HEADER = struct.Struct("!IBBIQ")
HEADER_LEN = HEADER.size  # 18 bytes

TYPE_PROBE = 1
TYPE_ECHO = 2

# Stream catalogue. Order is the display order in the UI; sids stay 0..3 so the
# colour map and chart series are stable regardless of which ports are chosen.
#   (sid, proto, port, label)
#
# Default ports live in the unassigned 30100/30200 block: below every OS
# ephemeral range (Windows 49152+, Linux 32768+) so the OS won't hand them to an
# outbound socket, and with no Wireshark dissector (unlike 5201, iPerf3's default
# port, which made Wireshark misparse our packets as iPerf3 traffic).
DEFAULT_UDP_PORTS = (30201, 30202)
DEFAULT_TCP_PORTS = (30101, 30102)


def build_streams(udp_ports, tcp_ports):
    """Build the stream catalogue from the chosen UDP/TCP port pairs."""
    streams = []
    sid = 0
    for port in udp_ports:
        streams.append((sid, "UDP", port, f"UDP-{port}"))
        sid += 1
    for port in tcp_ports:
        streams.append((sid, "TCP", port, f"TCP-{port}"))
        sid += 1
    return streams


STREAMS = build_streams(DEFAULT_UDP_PORTS, DEFAULT_TCP_PORTS)


def ports_summary():
    """e.g. 'UDP 30201/30202  TCP 30101/30102' from the current STREAMS."""
    udp = "/".join(str(p) for _, proto, p, _ in STREAMS if proto == "UDP")
    tcp = "/".join(str(p) for _, proto, p, _ in STREAMS if proto == "TCP")
    return f"UDP {udp}  TCP {tcp}"


def build_packet(ptype, sid, seq, ts_ns, size):
    """Build a fixed-size packet padded out to `size` bytes."""
    hdr = HEADER.pack(MAGIC, ptype, sid, seq, ts_ns)
    if size < HEADER_LEN:
        size = HEADER_LEN
    return hdr + b"\x00" * (size - HEADER_LEN)


def parse_header(data):
    """Return (ptype, sid, seq, ts_ns) or None if it is not our traffic."""
    if len(data) < HEADER_LEN:
        return None
    magic, ptype, sid, seq, ts_ns = HEADER.unpack(data[:HEADER_LEN])
    if magic != MAGIC:
        return None
    return ptype, sid, seq, ts_ns


# Socket buffer size. Windows defaults to a small (~64 KB) UDP receive buffer.
# Thread-scheduler/timer granularity (~15 ms on Windows) makes probes go out in
# bursts; on a clean, low-jitter path those bursts arrive still bunched and can
# momentarily overrun a small receive buffer, dropping UDP datagrams that then
# look like packet loss. Enlarging the buffer absorbs the microbursts so the
# loss we report reflects the wire, not a local buffer overflow.
SOCK_BUF_BYTES = 4 * 1024 * 1024


def enlarge_socket_buffers(sock):
    """Best-effort enlarge of the send/receive buffers (ignored if capped)."""
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, SOCK_BUF_BYTES)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Per-stream statistics (thread-safe, sliding window)
# ---------------------------------------------------------------------------
class StreamStats:
    """Rolling-window stats for one originated stream.

    Loss accounting distinguishes three terminal outcomes for every probe:

      * recv  - echo returned within `timeout` (on time).
      * lost  - no echo within `timeout` and still none -> a real drop.
      * late  - echo arrived AFTER the timeout deadline (reordered / over-
                buffered). It physically came back, but too late to be useful
                to a real-time stream, so it is reclassified lost -> late.

    Loss% and Late% are computed over the sliding `window`; the quality score
    treats (loss + late) as the effective impairment.
    """

    def __init__(self, window=10.0, timeout=2.0):
        self.lock = threading.Lock()
        self.window = window          # seconds of history kept for rates/loss
        self.timeout = timeout        # an un-echoed probe older than this = lost

        self.rtt_samples = deque()    # (t_wall, rtt_ms) for on-time echoes only
        self.tx_events = deque()      # t_wall of probes sent

        # Windowed per-probe outcomes. `resolved_order` keeps insertion order so
        # we can trim by time; `state` maps seq -> 'recv'|'lost'|'late' and is
        # updated in place when a lost probe is later reclassified as late.
        self.resolved_order = deque() # (resolve_wall, seq)
        self.state = {}               # seq -> outcome

        self.pending = {}             # seq -> (send_wall, send_monotonic_ns)
        self.jitter = 0.0             # RFC-3550 style smoothed jitter (ms)
        self.last_rtt = None
        self.last_echo_t = 0.0        # wallclock of most recent echo (any kind)

        # cumulative session counters (for the footer / totals)
        self.cum_tx = 0
        self.cum_recv = 0
        self.cum_lost = 0
        self.cum_late = 0

    # -- producers (called from network threads) --------------------------
    def on_send(self, seq, send_ns):
        with self.lock:
            self.pending[seq] = (time.time(), send_ns)
            self.tx_events.append(time.time())
            self.cum_tx += 1
            self._trim_locked()

    def on_echo(self, seq, ts_ns, now_ns):
        with self.lock:
            rtt = (now_ns - ts_ns) / 1e6
            if rtt < 0:
                rtt = 0.0
            now_w = time.time()
            p = self.pending.pop(seq, None)
            if p is not None:
                # On-time echo.
                self.state[seq] = "recv"
                self.resolved_order.append((now_w, seq))
                self.rtt_samples.append((now_w, rtt))
                self.cum_recv += 1
                if self.last_rtt is not None:
                    d = abs(rtt - self.last_rtt)
                    # smoothed mean deviation, RFC 3550 J += (|D|-J)/16
                    self.jitter += (d - self.jitter) / 16.0
                self.last_rtt = rtt
                self.last_echo_t = now_w
            elif self.state.get(seq) == "lost":
                # A previously reaped probe finally came back: it was late, not
                # lost. Reclassify so Loss% drops and Late% rises.
                self.state[seq] = "late"
                self.cum_lost -= 1
                self.cum_late += 1
                self.last_echo_t = now_w
            # else: duplicate, or so old it has been trimmed -> ignore.
            self._trim_locked()

    def reap(self):
        """Move probes with no echo within `timeout` into the lost bucket."""
        now_ns = time.monotonic_ns()
        cutoff = self.timeout * 1e9
        with self.lock:
            now_w = time.time()
            dead = [s for s, (w, ns) in self.pending.items() if now_ns - ns > cutoff]
            for s in dead:
                self.pending.pop(s, None)
                self.state[s] = "lost"
                self.resolved_order.append((now_w, s))
                self.cum_lost += 1
            self._trim_locked()

    # -- consumer (called from UI thread) ---------------------------------
    def snapshot(self):
        with self.lock:
            self._trim_locked()
            rtts = [r for _, r in self.rtt_samples]
            recv = lost = late = 0
            for st in self.state.values():
                if st == "recv":
                    recv += 1
                elif st == "lost":
                    lost += 1
                else:
                    late += 1
            decided = recv + lost + late
            loss = (lost / decided * 100.0) if decided else 0.0
            late_pct = (late / decided * 100.0) if decided else 0.0
            connected = (time.time() - self.last_echo_t) < self.timeout if self.last_echo_t else False
            avg = (sum(rtts) / len(rtts)) if rtts else 0.0
            return {
                "connected": connected,
                "rtt_avg": avg,
                "rtt_min": min(rtts) if rtts else 0.0,
                "rtt_max": max(rtts) if rtts else 0.0,
                "latency": avg / 2.0,
                "jitter": self.jitter,
                "loss": loss,
                "late": late_pct,
                "tx_pps": len(self.tx_events) / self.window,
                "rx_pps": recv / self.window,
                "samples": len(rtts),
                "cum_tx": self.cum_tx,
                "cum_recv": self.cum_recv,
                "cum_lost": self.cum_lost,
                "cum_late": self.cum_late,
            }

    def reset(self):
        """Drop all accumulated samples/counters (used by the UI Reset button)."""
        with self.lock:
            self.rtt_samples.clear()
            self.tx_events.clear()
            self.resolved_order.clear()
            self.state.clear()
            self.pending.clear()
            self.jitter = 0.0
            self.last_rtt = None
            self.last_echo_t = 0.0
            self.cum_tx = self.cum_recv = self.cum_lost = self.cum_late = 0

    def _trim_locked(self):
        horizon = time.time() - self.window
        while self.rtt_samples and self.rtt_samples[0][0] < horizon:
            self.rtt_samples.popleft()
        while self.tx_events and self.tx_events[0] < horizon:
            self.tx_events.popleft()
        while self.resolved_order and self.resolved_order[0][0] < horizon:
            _, seq = self.resolved_order.popleft()
            self.state.pop(seq, None)


# ---------------------------------------------------------------------------
# Quality scoring (ITU-T G.107 E-model, simplified)
# ---------------------------------------------------------------------------
def quality_score(latency_ms, loss_pct, jitter_ms):
    """Return (score 0-100, MOS 1-4.5, label) from one-way latency/loss/jitter.

    Uses the ITU-T E-model R-factor. Jitter is folded in as extra effective
    delay (a de-jitter buffer typically costs ~2x the jitter).
    """
    d = latency_ms + 2.0 * jitter_ms
    # Delay impairment (Id)
    Id = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    # Equipment/loss impairment (Ie-eff), common log approximation
    p = max(0.0, min(1.0, loss_pct / 100.0))
    Ie = 30.0 * math.log(1.0 + 15.0 * p)
    R = 93.2 - Id - Ie
    R = max(0.0, min(100.0, R))
    # R -> MOS
    if R <= 0:
        mos = 1.0
    else:
        mos = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7e-6
    mos = max(1.0, min(4.5, mos))
    label = score_label(R)
    return R, mos, label


def score_label(r):
    if r >= 80:
        return "Excellent"
    if r >= 70:
        return "Good"
    if r >= 60:
        return "Fair"
    if r >= 50:
        return "Poor"
    return "Bad"


def score_color(r):
    if r >= 80:
        return "#1a9850"
    if r >= 70:
        return "#66bd63"
    if r >= 60:
        return "#fee08b"
    if r >= 50:
        return "#fc8d59"
    return "#d73027"


# ---------------------------------------------------------------------------
# UDP stream: one bound socket per port, both originates and reflects.
# ---------------------------------------------------------------------------
class UDPStream:
    def __init__(self, cfg, peer, bind, size, interval, stats, stop):
        self.sid, _, self.port, self.name = cfg
        self.peer = peer
        self.bind = bind
        self.size = size
        self.interval = interval
        self.stats = stats
        self.stop = stop
        self.sock = None
        self.threads = []

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        enlarge_socket_buffers(s)  # absorb Windows microbursts -> no phantom UDP loss
        s.bind((self.bind, self.port))
        s.settimeout(0.5)
        self.sock = s
        self.threads = [
            threading.Thread(target=self._recv_loop, name=f"{self.name}-rx", daemon=True),
            threading.Thread(target=self._send_loop, name=f"{self.name}-tx", daemon=True),
        ]
        for t in self.threads:
            t.start()

    def _send_loop(self):
        seq = 0
        peer_addr = (self.peer, self.port)
        next_t = time.monotonic()
        while not self.stop.is_set():
            seq += 1
            ns = time.monotonic_ns()
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, self.size)
            try:
                self.sock.sendto(pkt, peer_addr)
                self.stats.on_send(seq, ns)
            except OSError:
                pass
            self.stats.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _recv_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = parse_header(data)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns = parsed
            if ptype == TYPE_PROBE:
                # Reflect straight back to the originator.
                echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, len(data))
                try:
                    self.sock.sendto(echo, addr)
                except OSError:
                    pass
            elif ptype == TYPE_ECHO:
                self.stats.on_echo(seq, ts_ns, time.monotonic_ns())


# ---------------------------------------------------------------------------
# TCP stream: we run BOTH a server (reflect peer's probes) and a client
# (originate our probes). Our displayed stats come from the client side.
# ---------------------------------------------------------------------------
def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, BlockingIOError):
            continue
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class TCPStream:
    def __init__(self, cfg, peer, bind, size, interval, stats, stop):
        self.sid, _, self.port, self.name = cfg
        self.peer = peer
        self.bind = bind
        self.size = max(size, HEADER_LEN)
        self.interval = interval
        self.stats = stats
        self.stop = stop
        self.listen_sock = None
        self.client_sock = None
        self.threads = []

    def start(self):
        self.threads = [
            threading.Thread(target=self._server_loop, name=f"{self.name}-srv", daemon=True),
            threading.Thread(target=self._client_manager, name=f"{self.name}-cli", daemon=True),
        ]
        for t in self.threads:
            t.start()

    # -- server side: reflect peer probes ---------------------------------
    def _server_loop(self):
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ls.bind((self.bind, self.port))
            ls.listen(8)
        except OSError:
            return
        ls.settimeout(0.5)
        self.listen_sock = ls
        while not self.stop.is_set():
            try:
                conn, _ = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._reflect_conn, args=(conn,), daemon=True).start()

    def _reflect_conn(self, conn):
        conn.settimeout(0.5)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        with conn:
            while not self.stop.is_set():
                msg = _recv_exact(conn, self.size)
                if msg is None:
                    return
                parsed = parse_header(msg)
                if parsed is None:
                    continue
                ptype, sid, seq, ts_ns = parsed
                if ptype == TYPE_PROBE:
                    echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, self.size)
                    try:
                        conn.sendall(echo)
                    except OSError:
                        return

    # -- client side: originate probes ------------------------------------
    def _client_manager(self):
        while not self.stop.is_set():
            try:
                cs = socket.create_connection((self.peer, self.port), timeout=2.0)
            except OSError:
                self.stop.wait(1.0)
                continue
            cs.settimeout(0.5)
            try:
                cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self.client_sock = cs
            rx = threading.Thread(target=self._client_recv, args=(cs,), daemon=True)
            rx.start()
            self._client_send(cs)   # blocks until the connection dies
            try:
                cs.close()
            except OSError:
                pass
            rx.join(timeout=1.0)
            if not self.stop.is_set():
                self.stop.wait(0.5)  # brief backoff before reconnect

    def _client_send(self, cs):
        seq = 0
        next_t = time.monotonic()
        while not self.stop.is_set():
            seq += 1
            ns = time.monotonic_ns()
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, self.size)
            try:
                cs.sendall(pkt)
                self.stats.on_send(seq, ns)
            except OSError:
                return
            self.stats.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _client_recv(self, cs):
        while not self.stop.is_set():
            msg = _recv_exact(cs, self.size)
            if msg is None:
                return
            parsed = parse_header(msg)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns = parsed
            if ptype == TYPE_ECHO:
                self.stats.on_echo(seq, ts_ns, time.monotonic_ns())


# ---------------------------------------------------------------------------
# Engine: owns all streams + their stats
# ---------------------------------------------------------------------------
class Engine:
    def __init__(self, peer, bind, size, pps, window, timeout, history_seconds=300,
                 loss_deadband=0.5):
        self.peer = peer
        self.bind = bind
        self.stop = threading.Event()
        self.start_time = time.time()
        self.history_seconds = history_seconds
        self.loss_deadband = loss_deadband  # combined loss+late below this reads as 0
        interval = 1.0 / pps
        self.stats = {}
        self.streams = []
        # Per-second history ring buffer per stream, for the live/history charts.
        self.history = {cfg[0]: deque(maxlen=history_seconds + 2) for cfg in STREAMS}
        self.history_lock = threading.Lock()
        for cfg in STREAMS:
            sid, proto, port, name = cfg
            st = StreamStats(window=window, timeout=timeout)
            self.stats[sid] = st
            if proto == "UDP":
                self.streams.append(UDPStream(cfg, peer, bind, size, interval, st, self.stop))
            else:
                self.streams.append(TCPStream(cfg, peer, bind, size, interval, st, self.stop))

    def start(self):
        for s in self.streams:
            s.start()
        threading.Thread(target=self._sampler, name="history-sampler", daemon=True).start()

    def shutdown(self):
        self.stop.set()

    def effective_loss(self, loss, late):
        """Combined loss+late, with a deadband so trivial blips read as zero."""
        eff = min(100.0, loss + late)
        return 0.0 if eff < self.loss_deadband else eff

    def _sampler(self):
        """Append one history sample per stream every second."""
        while not self.stop.wait(1.0):
            now = time.time()
            with self.history_lock:
                for sid in self.history:
                    snap = self.stats[sid].snapshot()
                    eff = self.effective_loss(snap["loss"], snap["late"])
                    r, _, _ = quality_score(snap["latency"], eff, snap["jitter"])
                    up = snap["connected"]
                    self.history[sid].append({
                        "t": now,
                        "rtt": snap["rtt_avg"] if up else None,
                        "loss": eff,
                        "jitter": snap["jitter"] if up else None,
                        "score": r if up else None,
                        "up": up,
                    })

    def history_copy(self):
        with self.history_lock:
            return {sid: list(dq) for sid, dq in self.history.items()}

    def snapshot(self):
        """Return per-stream snapshots + overall aggregate quality."""
        rows = []
        scores = []
        moses = []
        tot_tx = tot_recv = tot_lost = tot_late = 0
        for sid, proto, port, name in STREAMS:
            snap = self.stats[sid].snapshot()
            eff = self.effective_loss(snap["loss"], snap["late"])  # deadbanded impairment
            r, mos, label = quality_score(snap["latency"], eff, snap["jitter"])
            snap.update(sid=sid, proto=proto, port=port, name=name,
                        score=r, mos=mos, label=label, eff_loss=eff)
            rows.append(snap)
            tot_tx += snap["cum_tx"]
            tot_recv += snap["cum_recv"]
            tot_lost += snap["cum_lost"]
            tot_late += snap["cum_late"]
            if snap["connected"] and snap["samples"] > 0:
                scores.append(r)
                moses.append(mos)
        if scores:
            overall = sum(scores) / len(scores)
            worst = min(scores)
            overall_mos = sum(moses) / len(moses)   # composite MOS, instant average
        else:
            overall = 0.0
            worst = 0.0
            overall_mos = 0.0
        decided = tot_recv + tot_lost + tot_late
        totals = {
            "tx": tot_tx, "recv": tot_recv, "lost": tot_lost, "late": tot_late,
            "loss_pct": (tot_lost / decided * 100.0) if decided else 0.0,
            "late_pct": (tot_late / decided * 100.0) if decided else 0.0,
        }
        return {
            "rows": rows,
            "overall": overall,
            "overall_mos": overall_mos,
            "worst": worst,
            "overall_label": score_label(overall) if scores else "No link",
            "uptime": time.time() - self.start_time,
            "links_up": len(scores),
            "totals": totals,
        }

    def reset(self):
        """Clear all measurement state and chart history (for a clean demo)."""
        for st in self.stats.values():
            st.reset()
        with self.history_lock:
            for dq in self.history.values():
                dq.clear()


# ---------------------------------------------------------------------------
# HPE-inspired theme + Canvas charts (no external dependencies)
# ---------------------------------------------------------------------------
HPE_GREEN = "#01A982"     # HPE signature green
HPE_GREEN_DK = "#017a5e"
BG = "#1a1d21"            # app background (HPE dark neutral)
PANEL = "#23272e"        # cards / chart panels
PANEL_HI = "#2c313a"
GRID = "#363b44"
TXT = "#f2f4f5"
TXT_DIM = "#9aa3ad"
FONT = "Segoe UI"

# distinct, on-brand line colours per stream
STREAM_COLORS = {0: "#01A982", 1: "#FF8300", 2: "#00B0E6", 3: "#FEC901"}



def _draw_ekg(canvas, color=HPE_GREEN, width=2):
    """Draw a small ECG/EKG heartbeat trace (P-QRS-T) onto a Tk Canvas.

    Coordinates are tuned for a ~52x34 canvas: flat baseline, small P bump, a
    sharp QRS spike, then a T bump back to baseline.
    """
    pts = [
        (2, 18), (12, 18),          # baseline
        (15, 14), (18, 18),         # P wave
        (21, 18), (23, 21),         # flat into Q dip
        (26, 4), (29, 30),          # R spike up, S dip down
        (32, 18), (36, 11),         # back to baseline, T wave
        (40, 18), (51, 18),         # baseline out
    ]
    flat = [c for xy in pts for c in xy]
    canvas.create_line(*flat, fill=color, width=width,
                       capstyle="round", joinstyle="round", smooth=False)


def _nice_ceiling(v):
    """Round a value up to a clean 1/2/2.5/5 * 10^n axis maximum."""
    if v <= 0:
        return 1.0
    exp = math.floor(math.log10(v))
    base = 10 ** exp
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * base:
            return m * base
    return 10 * base


def _draw_chart(canvas, title, key, series, samples_by_sid, view_seconds, now,
                ymin_floor=1.0, unit="", value_fmt=None):
    """Render one time-series chart onto a Tk Canvas.

    series: list of (sid, color, short_label). samples_by_sid: {sid: [sample]}.
    Each sample is {'t', key..., 'up'}; None values break the line (gap = down).
    """
    if value_fmt is None:
        value_fmt = lambda v: f"{v:.0f}"
    w = canvas.winfo_width()
    h = canvas.winfo_height()
    if w < 30 or h < 30:
        return
    canvas.delete("all")
    canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline=GRID)
    pad_l, pad_r, pad_t, pad_b = 46, 12, 30, 20
    pw, ph = w - pad_l - pad_r, h - pad_t - pad_b
    if pw < 10 or ph < 10:
        return
    title_id = canvas.create_text(12, 15, text=title, anchor="w", fill=TXT,
                                  font=(FONT, 10, "bold"))
    legend_x0 = canvas.bbox(title_id)[2] + 18  # start legend after the title

    # autoscale Y
    vmax = ymin_floor
    for sid, _c, _n in series:
        for s in samples_by_sid.get(sid, ()):
            v = s.get(key)
            if v is not None and s["up"]:
                vmax = max(vmax, v)
    vmax = _nice_ceiling(vmax)

    # horizontal gridlines + Y labels
    for i in range(5):
        yy = pad_t + ph * i / 4.0
        canvas.create_line(pad_l, yy, w - pad_r, yy, fill=GRID)
        canvas.create_text(pad_l - 5, yy, text=value_fmt(vmax * (1 - i / 4.0)),
                           anchor="e", fill=TXT_DIM, font=(FONT, 7))

    t0 = now - view_seconds

    def X(t):
        return pad_l + pw * (t - t0) / max(1e-3, view_seconds)

    def Y(v):
        return pad_t + ph * (1 - min(1.0, max(0.0, v) / vmax))

    # X axis time labels
    for frac, lbl in ((0.0, f"-{int(view_seconds)}s"),
                      (0.5, f"-{int(view_seconds / 2)}s"), (1.0, "now")):
        canvas.create_text(pad_l + pw * frac, h - 8, text=lbl, anchor="center",
                           fill=TXT_DIM, font=(FONT, 7))

    # series polylines (break on None = stream down)
    for sid, color, _n in series:
        pts = []
        for s in samples_by_sid.get(sid, ()):
            if s["t"] < t0:
                continue
            v = s.get(key)
            if v is None:
                if len(pts) >= 4:
                    canvas.create_line(*pts, fill=color, width=2)
                pts = []
                continue
            pts.extend((X(s["t"]), Y(v)))
        if len(pts) >= 4:
            canvas.create_line(*pts, fill=color, width=2)

    # legend with current values
    lx = legend_x0
    for sid, color, label in series:
        cur = None
        for s in reversed(samples_by_sid.get(sid, ())):
            if s.get(key) is not None:
                cur = s.get(key)
                break
        canvas.create_rectangle(lx, 11, lx + 9, 19, fill=color, outline="")
        txt = f"{label} {value_fmt(cur)}{unit}" if cur is not None else f"{label} -"
        tid = canvas.create_text(lx + 13, 15, text=txt, anchor="w",
                                 fill=TXT_DIM, font=(FONT, 8))
        lx = canvas.bbox(tid)[2] + 12


# ---------------------------------------------------------------------------
# Tkinter GUI (HPE-themed, with live + history charts)
# ---------------------------------------------------------------------------
def run_gui(engine, args):
    import tkinter as tk
    from tkinter import ttk

    view_seconds = float(args.history)
    series = [(sid, STREAM_COLORS[sid], name.split("-")[1])
              for sid, proto, port, name in STREAMS]

    root = tk.Tk()
    root.title(f"Network Vitals  -  peer {args.peer}")
    root.geometry("1000x600")
    root.minsize(480, 320)
    root.configure(bg=BG)

    # ---- ttk dark theme ---------------------------------------------------
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("NQ.Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TXT, rowheight=30, font=(FONT, 10), borderwidth=0)
    style.configure("NQ.Treeview.Heading", background=PANEL_HI, foreground=HPE_GREEN,
                    font=(FONT, 9, "bold"), relief="flat", borderwidth=0)
    style.map("NQ.Treeview.Heading", background=[("active", PANEL_HI)])
    style.map("NQ.Treeview", background=[("selected", HPE_GREEN_DK)],
              foreground=[("selected", "white")])

    # ---- header bar -------------------------------------------------------
    header = tk.Frame(root, bg=BG, padx=14, pady=10)
    header.pack(fill="x", side="top")

    # EKG/heartbeat glyph (vector, drawn on a canvas)
    ekg = tk.Canvas(header, width=54, height=34, bg=BG, highlightthickness=0)
    ekg.pack(side="left", padx=(0, 10))
    _draw_ekg(ekg)

    tk.Label(header, text="Network Vitals", fg=TXT, bg=BG,
             font=(FONT, 17, "bold")).pack(side="left", anchor="w")

    def do_reset():
        engine.reset()  # charts + stats clear; they repopulate on the next tick

    reset_btn = tk.Button(header, text="↺  Reset / Clear", command=do_reset,
                          bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                          activeforeground="white", relief="flat", bd=0,
                          highlightthickness=0, padx=12, pady=5,
                          font=(FONT, 9, "bold"), cursor="hand2")
    reset_btn.pack(side="left", padx=(18, 6))

    totals_shown = {"on": False}

    def do_toggle_totals():
        totals_shown["on"] = not totals_shown["on"]
        if totals_shown["on"]:
            totals_tree.pack(fill="x")
            totals_btn.configure(text="▴  Totals")
        else:
            totals_tree.pack_forget()
            totals_btn.configure(text="▾  Totals")

    totals_btn = tk.Button(header, text="▾  Totals", command=do_toggle_totals,
                           bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                           activeforeground="white", relief="flat", bd=0,
                           highlightthickness=0, padx=12, pady=5,
                           font=(FONT, 9, "bold"), cursor="hand2")
    totals_btn.pack(side="left")

    # right-hand stat cluster: quality text + experience score + composite MOS
    stats = tk.Frame(header, bg=BG)
    stats.pack(side="right")

    mos_var = tk.StringVar(value="--")
    mos_block = tk.Frame(stats, bg=BG)
    mos_block.pack(side="right", padx=(12, 0))
    mos_num = tk.Label(mos_block, textvariable=mos_var, font=(FONT, 30, "bold"),
                       width=4, fg=TXT, bg=BG)
    mos_num.pack(anchor="center")
    tk.Label(mos_block, text="MOS (avg)", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).pack(anchor="center")

    score_var = tk.StringVar(value="--")
    score_lbl = tk.Label(stats, textvariable=score_var, font=(FONT, 34, "bold"),
                         width=4, fg="white", bg="#555a61")
    score_lbl.pack(side="right")

    label_var = tk.StringVar(value="Starting...")
    sub_var = tk.StringVar(value="")
    txt = tk.Frame(stats, bg=BG)
    txt.pack(side="right", padx=(0, 12))
    tk.Label(txt, text="EXPERIENCE", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).pack(anchor="e")
    tk.Label(txt, textvariable=label_var, fg=TXT, bg=BG,
             font=(FONT, 17, "bold")).pack(anchor="e")
    tk.Label(txt, textvariable=sub_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9)).pack(anchor="e")

    # ---- footer (pinned to the bottom, before charts claim the middle) ----
    footer = tk.Frame(root, bg=BG, padx=14, pady=6)
    footer.pack(fill="x", side="bottom")
    foot_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9)).pack(side="left")

    # ---- totals table (hidden by default; toggled by the Totals button) ----
    totals_cols = ("stream", "sent", "recv", "lost", "late", "lossp")
    totals_head = {"stream": "Stream", "sent": "Sent", "recv": "Received",
                   "lost": "Lost", "late": "Late", "lossp": "Loss %"}
    totals_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    totals_frame.pack(fill="x", side="bottom")
    totals_tree = ttk.Treeview(totals_frame, columns=totals_cols, show="headings",
                               height=len(STREAMS), style="NQ.Treeview")
    for c in totals_cols:
        totals_tree.heading(c, text=totals_head[c])
        totals_tree.column(c, width=120, anchor=("w" if c == "stream" else "e"),
                           stretch=(c == "stream"))
    for sid, proto, port, name in STREAMS:
        totals_tree.insert("", "end", iid=f"t{sid}", values=(name, 0, 0, 0, 0, "0.0"))
    # not packed yet -> hidden until the Totals button is clicked

    # ---- charts: latency (top, full width), loss + jitter (bottom row) ----
    charts = tk.Frame(root, bg=BG, padx=12, pady=6)
    charts.pack(fill="both", expand=True)
    lat_canvas = tk.Canvas(charts, bg=PANEL, highlightthickness=0)
    lat_canvas.pack(fill="both", expand=True, pady=(0, 6))
    bottom = tk.Frame(charts, bg=BG)
    bottom.pack(fill="both", expand=True)
    loss_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0)
    loss_canvas.pack(side="left", fill="both", expand=True, padx=(0, 3))
    jit_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0)
    jit_canvas.pack(side="left", fill="both", expand=True, padx=(3, 0))

    def refresh():
        snap = engine.snapshot()
        if snap["links_up"] == 0:
            score_var.set("--")
            score_lbl.configure(bg="#555a61")
            mos_var.set("--")
            mos_num.configure(fg=TXT_DIM)
            label_var.set("Waiting for peer")
            sub_var.set(f"peer {args.peer} - no streams up yet")
        else:
            o = snap["overall"]
            score_var.set(f"{o:.0f}")
            score_lbl.configure(bg=score_color(o))
            mos_var.set(f"{snap['overall_mos']:.1f}")
            mos_num.configure(fg=score_color(o))
            label_var.set(snap["overall_label"])
            sub_var.set(f"worst {snap['worst']:.0f}  -  "
                        f"{snap['links_up']}/{len(STREAMS)} streams up")

        up_s = int(snap["uptime"])
        t = snap["totals"]
        foot_var.set(
            f"peer {args.peer}    {ports_summary()}    {args.pps} probes/s/stream    "
            f"uptime {up_s // 3600:02d}:{(up_s % 3600) // 60:02d}:{up_s % 60:02d}"
            f"    |  since reset:  sent {t['tx']:,}  recv {t['recv']:,}  "
            f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  late {t['late']:,}")

        if totals_shown["on"]:
            for row in snap["rows"]:
                decided = row["cum_recv"] + row["cum_lost"] + row["cum_late"]
                lossp = (row["cum_lost"] / decided * 100.0) if decided else 0.0
                totals_tree.item(f"t{row['sid']}", values=(
                    row["name"], f"{row['cum_tx']:,}", f"{row['cum_recv']:,}",
                    f"{row['cum_lost']:,}", f"{row['cum_late']:,}", f"{lossp:.2f}"))

        hist = engine.history_copy()
        now = time.time()
        _draw_chart(lat_canvas, "Latency (RTT, ms)", "rtt", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
        _draw_chart(loss_canvas, "Loss + late (%)", "loss", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="%",
                    value_fmt=lambda v: f"{v:.0f}")
        _draw_chart(jit_canvas, "Jitter (ms)", "jitter", series, hist,
                    view_seconds, now, ymin_floor=1.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
        root.after(args.refresh_ms, refresh)

    def on_close():
        engine.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(120, refresh)  # let the window realize its size first
    root.mainloop()


# ---------------------------------------------------------------------------
# Console UI (fallback when no display / --no-gui)
# ---------------------------------------------------------------------------
def run_console(engine, args):
    print(f"Network Vitals  peer={args.peer}  bind={args.bind}  "
          f"{ports_summary()}  {args.pps} probes/s/stream")
    print("Ctrl-C to stop.\n")
    try:
        while not engine.stop.is_set():
            snap = engine.snapshot()
            print("\033[2J\033[H", end="")  # clear screen
            o = snap["overall"]
            print(f"  OVERALL QUALITY: {o:5.1f}/100  {snap['overall_label']:<10}"
                  f"  ({snap['links_up']}/{len(STREAMS)} streams up, worst {snap['worst']:.0f})")
            print("  " + "-" * 100)
            print(f"  {'Stream':<10}{'Status':<8}{'RTT ms':>9}{'1-way':>9}"
                  f"{'Jitter':>9}{'Loss %':>9}{'Late %':>9}{'Score':>7}{'MOS':>6}"
                  f"{'TXpps':>8}{'RXpps':>8}")
            print("  " + "-" * 100)
            for r in snap["rows"]:
                st = "UP" if r["connected"] else "DOWN"
                if r["connected"]:
                    print(f"  {r['name']:<10}{st:<8}{r['rtt_avg']:>9.2f}{r['latency']:>9.2f}"
                          f"{r['jitter']:>9.2f}{r['loss']:>9.1f}{r['late']:>9.1f}{r['score']:>7.0f}"
                          f"{r['mos']:>6.2f}{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
                else:
                    print(f"  {r['name']:<10}{st:<8}{'-':>9}{'-':>9}{'-':>9}"
                          f"{r['loss']:>9.1f}{r['late']:>9.1f}{'-':>7}{'-':>6}"
                          f"{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
            up = int(snap["uptime"])
            t = snap["totals"]
            print("  " + "-" * 100)
            print(f"  totals since reset:  sent {t['tx']:,}  recv {t['recv']:,}  "
                  f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  late {t['late']:,} "
                  f"({t['late_pct']:.2f}%)")
            print(f"  uptime {up//3600:02d}:{(up%3600)//60:02d}:{up%60:02d}")
            time.sleep(args.refresh_ms / 1000.0)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _port_pair(text):
    """Parse 'A,B' into a (A, B) tuple of two valid ports."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("expected exactly two ports, e.g. 30201,30202")
    try:
        ports = tuple(int(p) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError("ports must be integers")
    for p in ports:
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(f"port {p} out of range 1-65535")
    return ports


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Bidirectional UDP/TCP network quality probe between two workstations.")
    p.add_argument("--peer", required=True, help="IP address of the other workstation.")
    p.add_argument("--bind", default="0.0.0.0",
                   help="Local address to bind/listen on (default: all interfaces).")
    p.add_argument("--udp-ports", type=_port_pair, default=DEFAULT_UDP_PORTS,
                   metavar="A,B",
                   help="The two UDP ports (default %d,%d)." % DEFAULT_UDP_PORTS)
    p.add_argument("--tcp-ports", type=_port_pair, default=DEFAULT_TCP_PORTS,
                   metavar="A,B",
                   help="The two TCP ports (default %d,%d)." % DEFAULT_TCP_PORTS)
    p.add_argument("--pps", type=int, default=50,
                   help="Probe packets per second, per stream (default 50).")
    p.add_argument("--size", type=int, default=200,
                   help="Probe packet size in bytes (default 200, min %d)." % HEADER_LEN)
    p.add_argument("--window", type=float, default=10.0,
                   help="Sliding window in seconds for loss/jitter/rates (default 10).")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Seconds before an un-echoed probe counts as lost (default 2).")
    p.add_argument("--loss-deadband", type=float, default=0.5,
                   help="Combined loss+late below this %% reads as 0 (default 0.5; 0 disables).")
    p.add_argument("--history", type=int, default=300,
                   help="Seconds of history shown in the charts (default 300).")
    p.add_argument("--refresh-ms", type=int, default=500,
                   help="UI refresh interval in ms (default 500).")
    p.add_argument("--no-gui", action="store_true",
                   help="Force the console UI even if a display is available.")
    return p.parse_args(argv)


def set_timer_resolution(period_ms):
    """Request a finer Windows scheduler tick (default ~15.6 ms -> period_ms).

    Smooth probe pacing instead of clumpy ~15 ms bursts, which is what causes
    occasional UDP receive-buffer drops on an otherwise-clean path. No-op (and
    harmless) on non-Windows platforms. Returns True if it was applied.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return ctypes.windll.winmm.timeBeginPeriod(int(period_ms)) == 0
    except Exception:
        return False


def clear_timer_resolution(period_ms):
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.winmm.timeEndPeriod(int(period_ms))
    except Exception:
        pass


def main(argv=None):
    args = parse_args(argv)
    if args.size < HEADER_LEN:
        args.size = HEADER_LEN
    if args.pps < 1:
        args.pps = 1

    # Apply chosen ports (read as a module global by the engine and UI).
    global STREAMS
    STREAMS = build_streams(args.udp_ports, args.tcp_ports)

    set_timer_resolution(1)  # smooth pacing on Windows -> fewer microburst drops
    engine = Engine(args.peer, args.bind, args.size, args.pps, args.window,
                    args.timeout, history_seconds=args.history,
                    loss_deadband=args.loss_deadband)
    engine.start()

    use_gui = not args.no_gui
    if use_gui:
        try:
            import tkinter  # noqa: F401
        except Exception:
            use_gui = False
            print("Tkinter not available - falling back to console UI.", file=sys.stderr)

    try:
        if use_gui:
            try:
                run_gui(engine, args)
            except Exception as e:  # e.g. no display on a headless host
                print(f"GUI unavailable ({e}) - falling back to console UI.", file=sys.stderr)
                run_console(engine, args)
        else:
            run_console(engine, args)
    finally:
        engine.shutdown()
        clear_timer_resolution(1)


if __name__ == "__main__":
    main()
