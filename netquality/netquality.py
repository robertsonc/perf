#!/usr/bin/env python3
"""
netquality - bidirectional network quality probe between two workstations.

A single, self-contained, dependency-free Python app. Run the SAME program on
both workstations. Each instance continuously sends AND receives:

    * 2 UDP probe streams  on ports 5201 and 5202
    * 2 TCP probe streams  on ports 5101 and 5102

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

# Stream catalogue. Order is the display order in the UI.
#   (sid, proto, port, label)
STREAMS = [
    (0, "UDP", 5201, "UDP-5201"),
    (1, "UDP", 5202, "UDP-5202"),
    (2, "TCP", 5101, "TCP-5101"),
    (3, "TCP", 5102, "TCP-5102"),
]


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


# ---------------------------------------------------------------------------
# Per-stream statistics (thread-safe, sliding window)
# ---------------------------------------------------------------------------
class StreamStats:
    """Rolling-window stats for one originated stream."""

    def __init__(self, window=10.0, timeout=2.0):
        self.lock = threading.Lock()
        self.window = window          # seconds of history kept for rates/loss
        self.timeout = timeout        # an un-echoed probe older than this = lost

        self.rtt_samples = deque()    # (t_wall, rtt_ms)
        self.recv_events = deque()    # t_wall of echoes received
        self.lost_events = deque()    # t_wall of probes declared lost
        self.tx_events = deque()      # t_wall of probes sent

        self.pending = {}             # seq -> send monotonic_ns
        self.jitter = 0.0             # RFC-3550 style smoothed jitter (ms)
        self.last_rtt = None
        self.last_echo_t = 0.0        # wallclock of most recent echo
        self.total_tx = 0
        self.total_rx = 0
        self.total_lost = 0

    # -- producers (called from network threads) --------------------------
    def on_send(self, seq, send_ns):
        with self.lock:
            self.pending[seq] = send_ns
            self.tx_events.append(time.time())
            self.total_tx += 1
            self._trim_locked()

    def on_echo(self, seq, ts_ns, now_ns):
        with self.lock:
            if self.pending.pop(seq, None) is None:
                return  # duplicate or already-reaped echo
            rtt = (now_ns - ts_ns) / 1e6
            if rtt < 0:
                rtt = 0.0
            now_w = time.time()
            self.rtt_samples.append((now_w, rtt))
            self.recv_events.append(now_w)
            self.total_rx += 1
            if self.last_rtt is not None:
                d = abs(rtt - self.last_rtt)
                # smoothed mean deviation, RFC 3550 J += (|D|-J)/16
                self.jitter += (d - self.jitter) / 16.0
            self.last_rtt = rtt
            self.last_echo_t = now_w
            self._trim_locked()

    def reap(self):
        """Move probes with no echo within `timeout` into the lost bucket."""
        now_ns = time.monotonic_ns()
        cutoff = self.timeout * 1e9
        with self.lock:
            dead = [s for s, ns in self.pending.items() if now_ns - ns > cutoff]
            for s in dead:
                self.pending.pop(s, None)
                self.lost_events.append(time.time())
                self.total_lost += 1
            self._trim_locked()

    # -- consumer (called from UI thread) ---------------------------------
    def snapshot(self):
        with self.lock:
            self._trim_locked()
            rtts = [r for _, r in self.rtt_samples]
            recv = len(self.recv_events)
            lost = len(self.lost_events)
            decided = recv + lost
            loss = (lost / decided * 100.0) if decided else 0.0
            connected = (time.time() - self.last_echo_t) < self.timeout if self.last_echo_t else False
            return {
                "connected": connected,
                "rtt_avg": (sum(rtts) / len(rtts)) if rtts else 0.0,
                "rtt_min": min(rtts) if rtts else 0.0,
                "rtt_max": max(rtts) if rtts else 0.0,
                "latency": ((sum(rtts) / len(rtts)) / 2.0) if rtts else 0.0,
                "jitter": self.jitter,
                "loss": loss,
                "tx_pps": len(self.tx_events) / self.window,
                "rx_pps": len(self.recv_events) / self.window,
                "samples": len(rtts),
            }

    def _trim_locked(self):
        horizon = time.time() - self.window
        for dq in (self.rtt_samples, self.recv_events, self.lost_events, self.tx_events):
            if dq and isinstance(dq[0], tuple):
                while dq and dq[0][0] < horizon:
                    dq.popleft()
            else:
                while dq and dq[0] < horizon:
                    dq.popleft()


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
    def __init__(self, peer, bind, size, pps, window, timeout):
        self.peer = peer
        self.bind = bind
        self.stop = threading.Event()
        self.start_time = time.time()
        interval = 1.0 / pps
        self.stats = {}
        self.streams = []
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

    def shutdown(self):
        self.stop.set()

    def snapshot(self):
        """Return per-stream snapshots + overall aggregate quality."""
        rows = []
        scores = []
        for sid, proto, port, name in STREAMS:
            snap = self.stats[sid].snapshot()
            r, mos, label = quality_score(snap["latency"], snap["loss"], snap["jitter"])
            snap.update(sid=sid, proto=proto, port=port, name=name,
                        score=r, mos=mos, label=label)
            rows.append(snap)
            if snap["connected"] and snap["samples"] > 0:
                scores.append(r)
        if scores:
            overall = sum(scores) / len(scores)
            worst = min(scores)
        else:
            overall = 0.0
            worst = 0.0
        return {
            "rows": rows,
            "overall": overall,
            "worst": worst,
            "overall_label": score_label(overall) if scores else "No link",
            "uptime": time.time() - self.start_time,
            "links_up": len(scores),
        }


# ---------------------------------------------------------------------------
# Tkinter GUI
# ---------------------------------------------------------------------------
def run_gui(engine, args):
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title(f"netquality  -  peer {args.peer}")
    root.geometry("980x430")
    root.minsize(820, 360)

    # ---- header: overall score -------------------------------------------
    header = tk.Frame(root, padx=12, pady=10)
    header.pack(fill="x")

    score_var = tk.StringVar(value="--")
    label_var = tk.StringVar(value="Starting...")
    sub_var = tk.StringVar(value="")

    score_lbl = tk.Label(header, textvariable=score_var, font=("Segoe UI", 40, "bold"),
                         width=4, fg="white", bg="#888888")
    score_lbl.pack(side="left", padx=(0, 16))

    txt = tk.Frame(header)
    txt.pack(side="left", anchor="w")
    tk.Label(txt, text="Connection quality", font=("Segoe UI", 11)).pack(anchor="w")
    tk.Label(txt, textvariable=label_var, font=("Segoe UI", 20, "bold")).pack(anchor="w")
    tk.Label(txt, textvariable=sub_var, font=("Segoe UI", 9), fg="#555").pack(anchor="w")

    # ---- table ------------------------------------------------------------
    cols = ("stream", "status", "rtt", "latency", "jitter", "loss", "score",
            "mos", "txpps", "rxpps")
    headings = {
        "stream": "Stream", "status": "Status", "rtt": "RTT ms",
        "latency": "1-way ms", "jitter": "Jitter ms", "loss": "Loss %",
        "score": "Score", "mos": "MOS", "txpps": "TX pps", "rxpps": "RX pps",
    }
    widths = {
        "stream": 110, "status": 80, "rtt": 90, "latency": 80, "jitter": 80,
        "loss": 80, "score": 70, "mos": 60, "txpps": 70, "rxpps": 70,
    }

    table_frame = tk.Frame(root, padx=12)
    table_frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=len(STREAMS))
    for c in cols:
        tree.heading(c, text=headings[c])
        anchor = "w" if c == "stream" else "center"
        tree.column(c, width=widths[c], anchor=anchor, stretch=(c == "stream"))
    tree.pack(fill="both", expand=True)

    style = ttk.Style()
    try:
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    except tk.TclError:
        pass

    for sid, proto, port, name in STREAMS:
        tree.insert("", "end", iid=str(sid), values=(name, "...", "", "", "", "", "", "", "", ""))

    # tag colours by score band
    for band, col in (("ok", "#e7f4e8"), ("warn", "#fff6da"), ("bad", "#fde3dd"), ("down", "#eeeeee")):
        tree.tag_configure(band, background=col)

    # ---- footer -----------------------------------------------------------
    footer = tk.Frame(root, padx=12, pady=6)
    footer.pack(fill="x")
    foot_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_var, font=("Segoe UI", 9), fg="#555").pack(side="left")

    def fmt(v, nd=1):
        return f"{v:.{nd}f}"

    def refresh():
        snap = engine.snapshot()
        for row in snap["rows"]:
            if not row["connected"]:
                status, band = "DOWN", "down"
            elif row["score"] >= 70 and row["loss"] < 1.0:
                status, band = "UP", "ok"
            elif row["score"] >= 50:
                status, band = "UP", "warn"
            else:
                status, band = "UP", "bad"
            vals = (
                row["name"], status,
                fmt(row["rtt_avg"], 2) if row["connected"] else "-",
                fmt(row["latency"], 2) if row["connected"] else "-",
                fmt(row["jitter"], 2) if row["connected"] else "-",
                fmt(row["loss"], 1),
                fmt(row["score"], 0) if row["connected"] else "-",
                fmt(row["mos"], 2) if row["connected"] else "-",
                fmt(row["tx_pps"], 0),
                fmt(row["rx_pps"], 0),
            )
            tree.item(str(row["sid"]), values=vals, tags=(band,))

        overall = snap["overall"]
        if snap["links_up"] == 0:
            score_var.set("--")
            score_lbl.configure(bg="#888888")
            label_var.set("Waiting for peer")
            sub_var.set(f"peer {args.peer}  -  no streams up yet")
        else:
            score_var.set(f"{overall:.0f}")
            score_lbl.configure(bg=score_color(overall))
            label_var.set(snap["overall_label"])
            sub_var.set(f"worst stream {snap['worst']:.0f}  -  {snap['links_up']}/{len(STREAMS)} streams up")
        up = int(snap["uptime"])
        foot_var.set(f"peer {args.peer}   bind {args.bind}   "
                     f"UDP 5201/5202  TCP 5101/5102   "
                     f"{args.pps} probes/s/stream   uptime {up//3600:02d}:{(up%3600)//60:02d}:{up%60:02d}")
        root.after(args.refresh_ms, refresh)

    def on_close():
        engine.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(args.refresh_ms, refresh)
    root.mainloop()


# ---------------------------------------------------------------------------
# Console UI (fallback when no display / --no-gui)
# ---------------------------------------------------------------------------
def run_console(engine, args):
    print(f"netquality  peer={args.peer}  bind={args.bind}  "
          f"UDP 5201/5202  TCP 5101/5102  {args.pps} probes/s/stream")
    print("Ctrl-C to stop.\n")
    try:
        while not engine.stop.is_set():
            snap = engine.snapshot()
            print("\033[2J\033[H", end="")  # clear screen
            o = snap["overall"]
            print(f"  OVERALL QUALITY: {o:5.1f}/100  {snap['overall_label']:<10}"
                  f"  ({snap['links_up']}/{len(STREAMS)} streams up, worst {snap['worst']:.0f})")
            print("  " + "-" * 92)
            print(f"  {'Stream':<10}{'Status':<8}{'RTT ms':>9}{'1-way':>9}"
                  f"{'Jitter':>9}{'Loss %':>9}{'Score':>7}{'MOS':>6}{'TXpps':>8}{'RXpps':>8}")
            print("  " + "-" * 92)
            for r in snap["rows"]:
                st = "UP" if r["connected"] else "DOWN"
                if r["connected"]:
                    print(f"  {r['name']:<10}{st:<8}{r['rtt_avg']:>9.2f}{r['latency']:>9.2f}"
                          f"{r['jitter']:>9.2f}{r['loss']:>9.1f}{r['score']:>7.0f}{r['mos']:>6.2f}"
                          f"{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
                else:
                    print(f"  {r['name']:<10}{st:<8}{'-':>9}{'-':>9}{'-':>9}"
                          f"{r['loss']:>9.1f}{'-':>7}{'-':>6}{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
            up = int(snap["uptime"])
            print("  " + "-" * 92)
            print(f"  uptime {up//3600:02d}:{(up%3600)//60:02d}:{up%60:02d}")
            time.sleep(args.refresh_ms / 1000.0)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Bidirectional UDP/TCP network quality probe between two workstations.")
    p.add_argument("--peer", required=True, help="IP address of the other workstation.")
    p.add_argument("--bind", default="0.0.0.0",
                   help="Local address to bind/listen on (default: all interfaces).")
    p.add_argument("--pps", type=int, default=50,
                   help="Probe packets per second, per stream (default 50).")
    p.add_argument("--size", type=int, default=200,
                   help="Probe packet size in bytes (default 200, min %d)." % HEADER_LEN)
    p.add_argument("--window", type=float, default=10.0,
                   help="Sliding window in seconds for loss/jitter/rates (default 10).")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Seconds before an un-echoed probe counts as lost (default 2).")
    p.add_argument("--refresh-ms", type=int, default=500,
                   help="UI refresh interval in ms (default 500).")
    p.add_argument("--no-gui", action="store_true",
                   help="Force the console UI even if a display is available.")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.size < HEADER_LEN:
        args.size = HEADER_LEN
    if args.pps < 1:
        args.pps = 1

    engine = Engine(args.peer, args.bind, args.size, args.pps, args.window, args.timeout)
    engine.start()

    use_gui = not args.no_gui
    if use_gui:
        try:
            import tkinter  # noqa: F401
        except Exception:
            use_gui = False
            print("Tkinter not available - falling back to console UI.", file=sys.stderr)

    if use_gui:
        try:
            run_gui(engine, args)
        except Exception as e:  # e.g. no display on a headless host
            print(f"GUI unavailable ({e}) - falling back to console UI.", file=sys.stderr)
            run_console(engine, args)
    else:
        run_console(engine, args)

    engine.shutdown()


if __name__ == "__main__":
    main()
