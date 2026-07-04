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
import os
import re
import socket
import struct
import sys
import threading
import time
import traceback
from collections import deque

__version__ = "1.1.0"

# Where --update / --check-update look for the latest release of this file.
# Override with --update-url (or keep a fork's URL here).
UPDATE_URL = ("https://raw.githubusercontent.com/robertsonc/netvitals/"
              "main/netquality.py")

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
# magic(I) type(B) sid(B) seq(I) ts_ns(Q) psize(H) rxsize(H) rxcount(I)
#   psize   = the total size this packet is meant to be (self-describing; lets
#             the receiver assert it got a full-size datagram - jumbo testing).
#   rxsize  = bytes the reflector actually received (0 in a probe; filled into
#             the echo) so the originator learns the delivered size.
#   rxcount = the reflector's cumulative count of probes received on this stream
#             (0 in a probe; filled into the echo) so the originator can split
#             its round-trip loss into forward (probes that never reached the
#             peer) vs return (echoes that never made it back) - loss isolation.
HEADER = struct.Struct("!IBBIQHHI")
HEADER_LEN = HEADER.size  # 26 bytes
MAX_SIZE = 65535          # psize/rxsize are uint16
MAX_COUNT = 0xFFFF_FFFF   # rxcount is uint32

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


def build_packet(ptype, sid, seq, ts_ns, size, rxsize=0, rxcount=0):
    """Build a fixed-size packet padded out to `size` bytes.

    `size` is stamped into the header (psize) so the receiver can confirm it got
    a full-size datagram; `rxsize`/`rxcount` are the size and cumulative probe
    count the reflector observed (set only on echoes).
    """
    if size < HEADER_LEN:
        size = HEADER_LEN
    if size > MAX_SIZE:
        size = MAX_SIZE
    hdr = HEADER.pack(MAGIC, ptype, sid, seq & MAX_COUNT, ts_ns, size,
                      min(rxsize, MAX_SIZE), rxcount & MAX_COUNT)
    return hdr + b"\x00" * (size - HEADER_LEN)


def parse_header(data):
    """Return (ptype, sid, seq, ts_ns, psize, rxsize, rxcount) or None."""
    if len(data) < HEADER_LEN:
        return None
    fields = HEADER.unpack(data[:HEADER_LEN])
    if fields[0] != MAGIC:
        return None
    return fields[1:]  # ptype, sid, seq, ts_ns, psize, rxsize, rxcount


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


def bind_exclusively(sock):
    """Bind-time socket options, per platform.

    On Windows SO_REUSEADDR lets a SECOND process bind the very same UDP/TCP
    port, after which inbound packets are split between the two processes
    nondeterministically — an accidentally double-launched instance reads as
    huge random packet loss. SO_EXCLUSIVEADDRUSE restores sane semantics.
    Elsewhere SO_REUSEADDR just skips TIME_WAIT on restart.
    """
    if sys.platform == "win32":
        opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if opt is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, 1)
            except OSError:
                pass
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def quench_udp_connreset(sock):
    """Stop Windows from surfacing ICMP Port Unreachable as an error on the
    UDP socket itself.

    When the peer app isn't running yet, our sendto() elicits ICMP Port
    Unreachable and Windows then raises ConnectionResetError (WSAECONNRESET)
    from the NEXT recvfrom() on the same socket. Without this ioctl the
    receive loop would die just because the other workstation was started a
    minute later. No-op on non-Windows platforms.
    """
    if sys.platform != "win32":
        return
    SIO_UDP_CONNRESET = 0x9800000C
    try:
        sock.ioctl(SIO_UDP_CONNRESET, False)
    except (OSError, ValueError, AttributeError):
        pass


def resolve_peer_ip(peer):
    """Resolve the peer to an IP for source-address filtering (None if we
    can't resolve, in which case filtering is skipped)."""
    try:
        return socket.gethostbyname(peer)
    except OSError:
        return None


def set_dont_fragment(sock):
    """Set the IPv4 Don't-Fragment bit so oversized datagrams are dropped, not
    fragmented - required to actually test jumbo frames end to end. Returns
    True if it took effect. Platform-specific; best effort."""
    try:
        if sys.platform == "win32":
            ip_dontfrag = getattr(socket, "IP_DONTFRAGMENT", 14)
            sock.setsockopt(socket.IPPROTO_IP, ip_dontfrag, 1)
        else:
            ip_mtu_discover = getattr(socket, "IP_MTU_DISCOVER", 10)
            pmtudisc_do = getattr(socket, "IP_PMTUDISC_DO", 2)
            sock.setsockopt(socket.IPPROTO_IP, ip_mtu_discover, pmtudisc_do)
        return True
    except (OSError, AttributeError):
        return False


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

    def __init__(self, window=10.0, timeout=2.0, target_pps=None):
        self.lock = threading.Lock()
        self.window = window          # seconds of history kept for rates/loss
        self.timeout = timeout        # an un-echoed probe older than this = lost
        self.target_pps = target_pps  # offered probe rate (for throughput ratio)
        # All window bookkeeping uses time.monotonic(): an NTP step on the
        # wall clock must not empty the window or freeze rate/loss figures.
        self.window_start = time.monotonic()  # for accurate rates before window fills

        self.rtt_samples = deque()    # (t_mono, rtt_ms) for on-time echoes only
        self.tx_events = deque()      # t_mono of probes sent
        self.connect_samples = deque(maxlen=8)  # recent TCP connect times (ms)

        # Windowed per-probe outcomes. `resolved_order` keeps insertion order so
        # we can trim by time; `state` maps seq -> 'recv'|'lost'|'late' and is
        # updated in place when a lost probe is later reclassified as late.
        self.resolved_order = deque() # (resolve_mono, seq)
        self.state = {}               # seq -> outcome

        self.pending = {}             # seq -> (send_mono, send_monotonic_ns)
        self.jitter = 0.0             # RFC-3550 style smoothed jitter (ms)
        self.last_rtt = None
        self.last_echo_t = 0.0        # monotonic time of most recent echo (any kind)

        # cumulative session counters (for the footer / totals)
        self.cum_tx = 0
        self.cum_recv = 0
        self.cum_lost = 0
        self.cum_late = 0

        # packet-size verification (jumbo-frame testing)
        self.rx_echo_max = 0      # largest echo datagram received (return path)
        self.peer_rx_max = 0      # largest size the far end reported receiving
        self.size_mismatch = 0    # echoes whose length != the stamped size

        # Loss localization: the reflector detects forward loss as GAPS in the
        # peer's sequence numbers (epoch-independent, immune to which app started
        # first), and echoes the running gap count back. Forward = those gaps;
        # return = round-trip lost - forward. seq is monotonic for UDP; for TCP
        # it restarts each reconnect, which we detect as a large backward jump.
        self.refl_rx = 0          # probes we received from the peer (reference)
        self.refl_first = 0       # first peer seq seen this run (0 = unset)
        self.refl_max = 0         # highest peer seq seen this run
        self.refl_run = 0         # probes received in the current seq run
        self.refl_gap = 0         # forward-loss gaps finalized from prior runs
        # Candidate peer-restart marker: (seq, counted_into_run). A single
        # large backward seq jump may just be a deeply reordered packet; two
        # in a row with ascending seqs confirm the peer restarted.
        self._reset_pend = None
        self.peer_fwd = 0         # forward-loss count the peer reports (see on_echo)
        self.peer_fwd_seq = 0     # seq of the echo that carried peer_fwd
        # The peer's reflector counter is a LIFETIME total that survives our
        # Reset button and our process restarting. Baseline it against the
        # first echo we see so only gaps accrued during THIS session count.
        self.peer_fwd_base = None

    # -- producers (called from network threads) --------------------------
    def on_probe_rx(self, seq):
        """Reflector side: fold a received probe's seq into gap tracking and
        return the cumulative forward-loss count to stamp into the echo."""
        with self.lock:
            self.refl_rx += 1
            if self.refl_first == 0:
                self.refl_first = self.refl_max = seq
                self.refl_run = 1
            elif seq < self.refl_max - 100:
                # A large backward jump is EITHER the peer's app restarting
                # (its seq begins again near 1) or a packet reordered/delayed
                # by hundreds of positions. Require two such packets in a row
                # with ascending seqs before declaring a restart; a lone one
                # is treated as a very-late member of the current run, so deep
                # reordering can no longer fabricate hundreds of phantom
                # forward losses.
                if self._reset_pend is not None and 0 <= seq - self._reset_pend[0] <= 100:
                    pend_seq, pend_counted = self._reset_pend
                    run = self.refl_run - (1 if pend_counted else 0)
                    self.refl_gap += max(0, (self.refl_max - self.refl_first + 1) - run)
                    self.refl_first = pend_seq
                    self.refl_max = seq
                    self.refl_run = 2  # the candidate probe + this one
                    self._reset_pend = None
                else:
                    counted = seq >= self.refl_first
                    if counted:
                        self.refl_run += 1  # gap-filler within the current run
                    self._reset_pend = (seq, counted)
            else:
                self._reset_pend = None
                if seq > self.refl_max:
                    self.refl_max = seq
                self.refl_run += 1
            live_gap = max(0, (self.refl_max - self.refl_first + 1) - self.refl_run)
            return (self.refl_gap + live_gap) & MAX_COUNT

    def on_send(self, seq, send_ns):
        with self.lock:
            now_m = time.monotonic()
            self.pending[seq] = (now_m, send_ns)
            self.tx_events.append(now_m)
            self.cum_tx += 1
            self._trim_locked()

    def on_echo(self, seq, ts_ns, now_ns, rx_len=0, psize=0, peer_rx=0, peer_fwd=0):
        with self.lock:
            rtt = (now_ns - ts_ns) / 1e6
            if rtt < 0:
                rtt = 0.0
            now_w = time.monotonic()
            # Size verification: rx_len = echo we got back (return path), peer_rx
            # = bytes the reflector reported (forward path). psize = intended.
            if rx_len > self.rx_echo_max:
                self.rx_echo_max = rx_len
            if peer_rx > self.peer_rx_max:
                self.peer_rx_max = peer_rx
            if psize and ((rx_len and rx_len != psize) or (peer_rx and peer_rx != psize)):
                self.size_mismatch += 1
            # Loss localization: peer_fwd = forward-loss gaps the peer's
            # reflector reports. Take the value carried by the highest-seq echo
            # seen (≈ the reflector's most recent count) rather than max-
            # latching, so a transient reorder spike in the peer's live gap
            # heals instead of ratcheting up forever. The first echo after a
            # reset (or process start) baselines the peer's lifetime counter,
            # since the reflector's total survives our Reset button / restart.
            if self.peer_fwd_base is None or peer_fwd < self.peer_fwd_base:
                # First echo of the session, or the peer's counter went
                # backward (its app restarted): re-baseline.
                self.peer_fwd_base = peer_fwd
            if seq >= self.peer_fwd_seq:
                self.peer_fwd_seq = seq
                self.peer_fwd = max(0, peer_fwd - self.peer_fwd_base)
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
            now_w = time.monotonic()
            dead = [s for s, (w, ns) in self.pending.items() if now_ns - ns > cutoff]
            for s in dead:
                self.pending.pop(s, None)
                self.state[s] = "lost"
                self.resolved_order.append((now_w, s))
                self.cum_lost += 1
            self._trim_locked()

    def on_connect(self, dt_ms):
        """Record a TCP connection-establishment time sample (client side)."""
        with self.lock:
            self.connect_samples.append(dt_ms)

    # -- consumer (called from UI thread) ---------------------------------
    def snapshot(self):
        with self.lock:
            self._trim_locked()
            now = time.monotonic()
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
            connected = (now - self.last_echo_t) < self.timeout if self.last_echo_t else False
            avg = (sum(rtts) / len(rtts)) if rtts else 0.0
            # RTT standard deviation over the window (PQI variance term).
            if len(rtts) > 1:
                rtt_std = math.sqrt(sum((r - avg) ** 2 for r in rtts) / len(rtts))
            else:
                rtt_std = 0.0
            # Stall rate: deliveries >= baseline + 200ms are almost certainly TCP
            # retransmissions (RTO / fast-retransmit) - the app-level retrans proxy.
            if rtts:
                stall_thr = min(rtts) + 200.0
                stall_pct = sum(1 for r in rtts if r > stall_thr) / len(rtts) * 100.0
            else:
                stall_pct = 0.0
            # Don't let a partially-filled window understate the packet rates.
            span = max(1e-3, min(self.window, now - self.window_start))
            tx_pps = len(self.tx_events) / span
            rx_pps = recv / span
            # Achieved echo rate vs offered probe rate = effective throughput
            # under backpressure (sendall stalls drag this below 1.0).
            if self.target_pps:
                tput_ratio = max(0.0, min(1.0, rx_pps / self.target_pps))
            else:
                tput_ratio = 1.0
            conn_list = sorted(self.connect_samples)
            connect_ms = conn_list[len(conn_list) // 2] if conn_list else None
            # Loss localization. The true round-trip loss (cum_lost) is split:
            # forward = the gaps the peer's reflector saw in our sequence (probes
            # that never reached it); return = whatever's left (echoes that never
            # made it back). This always reconciles: forward + return = cum_lost.
            fwd_lost = min(self.peer_fwd, self.cum_lost)
            rtn_lost = max(0, self.cum_lost - fwd_lost)
            fwd_pct = (fwd_lost / self.cum_tx * 100.0) if self.cum_tx else 0.0
            rtn_pct = (rtn_lost / self.cum_tx * 100.0) if self.cum_tx else 0.0
            return {
                "connected": connected,
                "rtt_avg": avg,
                "rtt_min": min(rtts) if rtts else 0.0,
                "rtt_max": max(rtts) if rtts else 0.0,
                "latency": avg / 2.0,
                "jitter": self.jitter,
                "rtt_std": rtt_std,
                "stall_pct": stall_pct,
                "tput_ratio": tput_ratio,
                "connect_ms": connect_ms,
                "loss": loss,
                "late": late_pct,
                "tx_pps": tx_pps,
                "rx_pps": rx_pps,
                "samples": len(rtts),
                "cum_tx": self.cum_tx,
                "cum_recv": self.cum_recv,
                "cum_lost": self.cum_lost,
                "cum_late": self.cum_late,
                "rx_echo_max": self.rx_echo_max,
                "peer_rx_max": self.peer_rx_max,
                "size_mismatch": self.size_mismatch,
                "refl_rx": self.refl_rx,
                "peer_fwd": self.peer_fwd,
                "fwd_lost": fwd_lost,
                "rtn_lost": rtn_lost,
                "fwd_pct": fwd_pct,
                "rtn_pct": rtn_pct,
            }

    def reset(self):
        """Drop all accumulated samples/counters (used by the UI Reset button)."""
        with self.lock:
            self.rtt_samples.clear()
            self.tx_events.clear()
            self.resolved_order.clear()
            self.state.clear()
            self.pending.clear()
            self.connect_samples.clear()
            self.jitter = 0.0
            self.last_rtt = None
            self.last_echo_t = 0.0
            self.window_start = time.monotonic()
            self.cum_tx = self.cum_recv = self.cum_lost = self.cum_late = 0
            self.rx_echo_max = self.peer_rx_max = self.size_mismatch = 0
            self.refl_rx = self.peer_fwd = 0
            self.refl_first = self.refl_max = self.refl_run = self.refl_gap = 0
            self._reset_pend = None
            # Re-baseline against the peer's lifetime reflector counter on the
            # next echo; the peer has no notion of our Reset button.
            self.peer_fwd_seq = 0
            self.peer_fwd_base = None

    def _trim_locked(self):
        horizon = time.monotonic() - self.window
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


def pqi_score(latency_ms, rtt_std_ms, retrans_pct, tput_ratio, connect_ms, rtt_ms):
    """Path Quality Index (PQI) for TCP streams, 0-100.

    MOS is a media metric and the wrong lens for TCP, which converts loss into
    delay via retransmission. PQI instead blends what actually shapes
    application experience on a TCP path:

      * RTT             - same delay-impairment curve as the E-model Id term.
      * RTT variance    - stddev over the window; erratic RTT = queue churn.
      * retransmission% - app-level proxy: deliveries stalled >= ~RTO beyond the
                          window's baseline RTT, plus lost/late probes.
      * eff. throughput - achieved echo rate / offered probe rate; TCP
                          backpressure (blocked sends) drags this below 1.
      * connect time    - establishment time beyond ~RTT means SYN loss
                          (each SYN retry costs a full RTO, seconds at worst).

    Returns (pqi, label) with the same 0-100 bands as the R-factor score.
    """
    d = latency_ms
    rtt_pen = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    var_pen = min(20.0, 0.3 * rtt_std_ms)
    p = max(0.0, min(1.0, retrans_pct / 100.0))
    retx_pen = 30.0 * math.log(1.0 + 15.0 * p)
    tput_pen = 25.0 * (1.0 - max(0.0, min(1.0, tput_ratio)))
    conn_pen = 0.0
    if connect_ms is not None:
        excess = max(0.0, connect_ms - (rtt_ms + 50.0))
        conn_pen = min(15.0, excess / 100.0)
    pqi = 100.0 - rtt_pen - var_pen - retx_pen - tput_pen - conn_pen
    pqi = max(0.0, min(100.0, pqi))
    return pqi, score_label(pqi)


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


def loss_verdict(fwd_lost, rtn_lost, inflight=6):
    """Classify where a stream's loss is, from the forward/return split.

    `inflight` is a small allowance for packets legitimately in flight (a few
    per stream); over a long run real loss dwarfs it.
    """
    f = fwd_lost if fwd_lost > inflight else 0
    r = rtn_lost if rtn_lost > inflight else 0
    if f == 0 and r == 0:
        return "clean", "ok"
    if f and r > 3 * max(1, f):
        return "← return", "warn"
    if r and f > 3 * max(1, r):
        return "→ forward", "warn"
    if f and not r:
        return "→ forward", "warn"
    if r and not f:
        return "← return", "warn"
    return "both dirs", "warn"


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
    def __init__(self, cfg, peer, bind, size, interval, stats, stop, dont_fragment=False):
        self.sid, _, self.port, self.name = cfg
        self.peer = peer
        self.bind = bind
        self.size = size
        self.interval = interval
        self.stats = stats
        self.stop = stop
        self.dont_fragment = dont_fragment
        self.sock = None
        self.peer_ip = None
        self.threads = []

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bind_exclusively(s)        # a second accidental instance must fail loudly
        enlarge_socket_buffers(s)  # absorb Windows microbursts -> no phantom UDP loss
        quench_udp_connreset(s)    # peer not started yet must not error the socket
        if self.dont_fragment:
            set_dont_fragment(s)   # jumbo probes that don't fit are dropped, not split
        s.bind((self.bind, self.port))
        s.settimeout(0.5)
        self.sock = s
        self.peer_ip = resolve_peer_ip(self.peer)
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
            except ConnectionResetError:
                # Windows: ICMP Port Unreachable from a prior sendto (peer app
                # not running yet). Not a socket failure — keep receiving.
                continue
            except OSError:
                if self.stop.is_set():
                    break
                time.sleep(0.1)  # unexpected; don't spin, don't die
                continue
            # Only talk to the configured peer: a hostile/chatty LAN must not
            # be able to skew stats or use us as a packet reflector.
            if self.peer_ip is not None and addr[0] != self.peer_ip:
                continue
            parsed = parse_header(data)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns, psize, rxsize, rxcount = parsed
            if ptype == TYPE_PROBE:
                # Reflect back, stamping the bytes and cumulative probe count we
                # received so the originator can verify size and split loss by
                # direction.
                rxlen = len(data)
                fwd = self.stats.on_probe_rx(seq)
                echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, rxlen,
                                    rxsize=rxlen, rxcount=fwd)
                try:
                    self.sock.sendto(echo, addr)
                except OSError:
                    pass
            elif ptype == TYPE_ECHO:
                self.stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                                   rx_len=len(data), psize=psize, peer_rx=rxsize,
                                   peer_fwd=rxcount)


# ---------------------------------------------------------------------------
# TCP stream: we run BOTH a server (reflect peer's probes) and a client
# (originate our probes). Our displayed stats come from the client side.
# ---------------------------------------------------------------------------
def _recv_exact(sock, n, stop=None, idle_timeout=None):
    """Read exactly n bytes. Returns None if the stream dies, `stop` is set,
    or no data arrives for `idle_timeout` seconds (silent peer death — a
    blue-screened / hard-powered-off peer never sends FIN or RST, and without
    a deadline the reader thread would spin on 0.5 s timeouts forever)."""
    buf = bytearray()
    last_data = time.monotonic()
    while len(buf) < n:
        if stop is not None and stop.is_set():
            return None
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, BlockingIOError):
            if (idle_timeout is not None
                    and time.monotonic() - last_data > idle_timeout):
                return None
            continue
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
        last_data = time.monotonic()
    return bytes(buf)


def _recv_msg(sock, stop=None, idle_timeout=None):
    """Read one framed message: the fixed header first, then the padding the
    header's own psize field declares.

    Framing is self-describing, so the two workstations may run different
    --size values without permanently desyncing the byte stream (which used
    to read as 100% phantom TCP loss). A magic mismatch means the stream is
    desynced or foreign; returning None makes the caller drop the connection,
    which is the only reliable way to resync."""
    hdr = _recv_exact(sock, HEADER_LEN, stop=stop, idle_timeout=idle_timeout)
    if hdr is None:
        return None
    fields = HEADER.unpack(hdr)
    if fields[0] != MAGIC:
        return None
    psize = fields[5]
    if psize < HEADER_LEN or psize > MAX_SIZE:
        return None
    if psize == HEADER_LEN:
        return hdr
    rest = _recv_exact(sock, psize - HEADER_LEN, stop=stop, idle_timeout=idle_timeout)
    if rest is None:
        return None
    return hdr + rest


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
        self.peer_ip = None
        self.threads = []
        # Probe seq continues across reconnects (see _client_send).
        self._tx_seq = 0
        # At most one live reflector connection: when the peer reconnects, the
        # old (usually half-dead) connection is closed so its thread exits
        # instead of leaking, and so two connections can't interleave probes
        # into the same StreamStats.
        self._reflect_lock = threading.Lock()
        self._active_reflect = None

    def start(self):
        self.peer_ip = resolve_peer_ip(self.peer)
        self.threads = [
            threading.Thread(target=self._server_loop, name=f"{self.name}-srv", daemon=True),
            threading.Thread(target=self._client_manager, name=f"{self.name}-cli", daemon=True),
            threading.Thread(target=self._connect_sampler, name=f"{self.name}-syn", daemon=True),
        ]
        for t in self.threads:
            t.start()

    # -- server side: reflect peer probes ---------------------------------
    def _server_loop(self):
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_exclusively(ls)
        warned = False
        while not self.stop.is_set():
            try:
                ls.bind((self.bind, self.port))
                ls.listen(8)
                break
            except OSError as e:
                # Port taken (lingering old instance, another app): keep
                # retrying instead of silently never reflecting — the only
                # symptom used to appear on the PEER's screen.
                if not warned:
                    print(f"{self.name}: cannot listen on {self.bind}:{self.port}"
                          f" ({e}) - retrying every 5s; until then the peer "
                          f"will show this stream down.", file=sys.stderr)
                    warned = True
                if self.stop.wait(5.0):
                    return
        if self.stop.is_set():
            return
        if warned:
            print(f"{self.name}: now listening on {self.bind}:{self.port}",
                  file=sys.stderr)
        ls.settimeout(0.5)
        self.listen_sock = ls
        while not self.stop.is_set():
            try:
                conn, addr = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.peer_ip is not None and addr[0] != self.peer_ip:
                # Only reflect for the configured peer (hostile-LAN hardening:
                # no thread-per-connection for arbitrary hosts).
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            with self._reflect_lock:
                old, self._active_reflect = self._active_reflect, conn
            if old is not None:
                try:
                    old.close()  # unblocks the old reflector thread -> exits
                except OSError:
                    pass
            threading.Thread(target=self._reflect_conn, args=(conn,), daemon=True).start()

    def _reflect_conn(self, conn):
        conn.settimeout(0.5)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        with conn:
            while not self.stop.is_set():
                # 30s with no bytes = silently dead peer (no FIN/RST after a
                # crash/power-off); exit rather than leak this thread forever.
                msg = _recv_msg(conn, stop=self.stop, idle_timeout=30.0)
                if msg is None:
                    return
                parsed = parse_header(msg)
                if parsed is None:
                    continue
                ptype, sid, seq, ts_ns, psize, rxsize, rxcount = parsed
                if ptype == TYPE_PROBE:
                    fwd = self.stats.on_probe_rx(seq)
                    # Echo at the PROBE's size (not our local --size) so the
                    # originator's reader frames it correctly even when the
                    # two ends run different sizes.
                    echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, len(msg),
                                        rxsize=len(msg), rxcount=fwd)
                    try:
                        conn.sendall(echo)
                    except OSError:
                        return

    def _source_address(self):
        """Source address for outbound TCP, so the peer's reflector sees us
        arrive from the address it has configured as its --peer (essential on
        multi-homed hosts and the loopback smoke test)."""
        if self.bind in ("", "0.0.0.0"):
            return None
        return (self.bind, 0)

    # -- connection-establishment sampler (PQI input) ----------------------
    def _connect_sampler(self):
        """Every ~15s, time a throwaway TCP handshake to the peer port."""
        while not self.stop.wait(15.0):
            t0 = time.monotonic()
            try:
                s = socket.create_connection((self.peer, self.port), timeout=3.0,
                                             source_address=self._source_address())
                self.stats.on_connect((time.monotonic() - t0) * 1000.0)
                s.close()
            except OSError:
                pass  # peer down; connection health shows via the main stream

    # -- client side: originate probes ------------------------------------
    def _client_manager(self):
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                cs = socket.create_connection((self.peer, self.port), timeout=2.0,
                                              source_address=self._source_address())
            except OSError:
                self.stop.wait(1.0)
                continue
            self.stats.on_connect((time.monotonic() - t0) * 1000.0)
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
        # seq continues across reconnects so the peer's reflector sees ONE
        # monotonic sequence: the gap across a reconnect is exactly the probes
        # that died with the old connection (real forward loss), and pending
        # entries from the old connection are reaped as lost instead of being
        # silently overwritten by a restarted sequence.
        next_t = time.monotonic()
        while not self.stop.is_set():
            self._tx_seq += 1
            seq = self._tx_seq
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
            msg = _recv_msg(cs, stop=self.stop)
            if msg is None:
                return
            parsed = parse_header(msg)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns, psize, rxsize, rxcount = parsed
            if ptype == TYPE_ECHO:
                self.stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                                   rx_len=len(msg), psize=psize, peer_rx=rxsize,
                                   peer_fwd=rxcount)


# ---------------------------------------------------------------------------
# Engine: owns all streams + their stats
# ---------------------------------------------------------------------------
class Engine:
    def __init__(self, peer, bind, size, pps, window, timeout, history_seconds=300,
                 loss_deadband=0.5, dont_fragment=False):
        self.peer = peer
        self.bind = bind
        self.size = size
        self.dont_fragment = dont_fragment
        self.stop = threading.Event()
        self.start_time = time.monotonic()
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
            st = StreamStats(window=window, timeout=timeout, target_pps=pps)
            self.stats[sid] = st
            if proto == "UDP":
                self.streams.append(UDPStream(cfg, peer, bind, size, interval, st,
                                              self.stop, dont_fragment=dont_fragment))
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
            now = time.monotonic()  # chart X axis; immune to NTP steps
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
        proto_mos = {"UDP": [], "TCP": []}
        proto_score = {"UDP": [], "TCP": []}
        tot_tx = tot_recv = tot_lost = tot_late = 0
        tot_fwd = tot_rtn = 0
        for sid, proto, port, name in STREAMS:
            snap = self.stats[sid].snapshot()
            eff = self.effective_loss(snap["loss"], snap["late"])  # deadbanded impairment
            if proto == "TCP":
                # TCP gets a Path Quality Index, not MOS: retransmissions show
                # up as stalls/loss/late at the probe level, plus throughput
                # backpressure and connection-establishment time.
                retrans = min(100.0, snap["stall_pct"] + eff)
                score, label = pqi_score(snap["latency"], snap["rtt_std"], retrans,
                                         snap["tput_ratio"], snap["connect_ms"],
                                         snap["rtt_avg"])
                mos = None
            else:
                score, mos, label = quality_score(snap["latency"], eff, snap["jitter"])
            snap.update(sid=sid, proto=proto, port=port, name=name,
                        score=score, mos=mos, label=label, eff_loss=eff)
            rows.append(snap)
            tot_tx += snap["cum_tx"]
            tot_recv += snap["cum_recv"]
            tot_lost += snap["cum_lost"]
            tot_late += snap["cum_late"]
            tot_fwd += snap["fwd_lost"]
            tot_rtn += snap["rtn_lost"]
            if snap["connected"] and snap["samples"] > 0:
                scores.append(score)
                if mos is not None:
                    proto_mos[proto].append(mos)
                proto_score[proto].append(score)
        # Per-protocol headline numbers: UDP keeps MOS (a media metric), TCP
        # gets the average PQI of its live streams.
        udp_mos = sum(proto_mos["UDP"]) / len(proto_mos["UDP"]) if proto_mos["UDP"] else None
        udp_score = sum(proto_score["UDP"]) / len(proto_score["UDP"]) if proto_score["UDP"] else None
        tcp_pqi = sum(proto_score["TCP"]) / len(proto_score["TCP"]) if proto_score["TCP"] else None
        if scores:
            overall = sum(scores) / len(scores)
            worst = min(scores)
        else:
            overall = 0.0
            worst = 0.0
        decided = tot_recv + tot_lost + tot_late
        totals = {
            "tx": tot_tx, "recv": tot_recv, "lost": tot_lost, "late": tot_late,
            "loss_pct": (tot_lost / decided * 100.0) if decided else 0.0,
            "late_pct": (tot_late / decided * 100.0) if decided else 0.0,
            "fwd_lost": tot_fwd, "rtn_lost": tot_rtn,
            "fwd_pct": (tot_fwd / tot_tx * 100.0) if tot_tx else 0.0,
            "rtn_pct": (tot_rtn / tot_tx * 100.0) if tot_tx else 0.0,
        }
        # Aggregate size verification across the UDP streams (the jumbo-relevant
        # ones): "verified" once full-size datagrams have round-tripped both ways.
        udp_rows = [r for r in rows if r["proto"] == "UDP" and r["connected"]]
        if any(r["size_mismatch"] for r in rows):
            size_status = "mismatch"
        elif udp_rows and all(r["peer_rx_max"] >= self.size and r["rx_echo_max"] >= self.size
                              for r in udp_rows):
            size_status = "verified"
        else:
            size_status = "pending"
        return {
            "rows": rows,
            "overall": overall,
            "udp_mos": udp_mos,
            "udp_score": udp_score,
            "tcp_pqi": tcp_pqi,
            "worst": worst,
            "overall_label": score_label(overall) if scores else "No link",
            "uptime": time.monotonic() - self.start_time,
            "links_up": len(scores),
            "totals": totals,
            "frame_size": self.size,
            "dont_fragment": self.dont_fragment,
            "size_status": size_status,
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
    root.title(f"Network Vitals {__version__}  -  peer {args.peer}")
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
        # Toggle the whole FRAME, not the tree inside it: an emptied,
        # still-packed frame keeps its last requested size, which is what
        # used to leave the bottom charts squeezed after closing the table.
        totals_shown["on"] = not totals_shown["on"]
        if totals_shown["on"]:
            totals_frame.pack(fill="x", side="bottom", before=charts)
            totals_btn.configure(text="▴  Totals")
        else:
            totals_frame.pack_forget()
            totals_btn.configure(text="▾  Totals")

    totals_btn = tk.Button(header, text="▾  Totals", command=do_toggle_totals,
                           bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                           activeforeground="white", relief="flat", bd=0,
                           highlightthickness=0, padx=12, pady=5,
                           font=(FONT, 9, "bold"), cursor="hand2")
    totals_btn.pack(side="left", padx=(0, 6))

    isolate_shown = {"on": False}

    def do_toggle_isolate():
        isolate_shown["on"] = not isolate_shown["on"]
        if isolate_shown["on"]:
            iso_frame.pack(fill="x", side="bottom", before=charts)
            isolate_btn.configure(text="▴  Isolate")
        else:
            iso_frame.pack_forget()
            isolate_btn.configure(text="⇄  Isolate")

    isolate_btn = tk.Button(header, text="⇄  Isolate", command=do_toggle_isolate,
                            bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                            activeforeground="white", relief="flat", bd=0,
                            highlightthickness=0, padx=12, pady=5,
                            font=(FONT, 9, "bold"), cursor="hand2")
    isolate_btn.pack(side="left", padx=(0, 6))

    def do_fit_charts():
        """Collapse the bottom tables and force a fresh geometry pass so the
        charts reclaim the full current window space."""
        if totals_shown["on"]:
            do_toggle_totals()
        if isolate_shown["on"]:
            do_toggle_isolate()
        for c in (lat_canvas, loss_canvas, jit_canvas):
            c.configure(width=100, height=80)
        root.update_idletasks()

    fit_btn = tk.Button(header, text="⤢  Fit charts", command=do_fit_charts,
                        bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                        activeforeground="white", relief="flat", bd=0,
                        highlightthickness=0, padx=12, pady=5,
                        font=(FONT, 9, "bold"), cursor="hand2")
    fit_btn.pack(side="left")

    # right-hand stat cluster: quality text + experience score + composite MOS
    stats = tk.Frame(header, bg=BG)
    stats.pack(side="right")

    # Per-protocol headline metrics: UDP keeps MOS (a media metric); TCP gets
    # a Path Quality Index (RTT, RTT variance, retransmissions, throughput,
    # connection establishment) - MOS is the wrong lens for TCP.
    udp_mos_var = tk.StringVar(value="--")
    tcp_pqi_var = tk.StringVar(value="--")
    mos_block = tk.Frame(stats, bg=BG)
    mos_block.pack(side="right", padx=(14, 0))
    tk.Label(mos_block, text="UDP MOS", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).grid(row=0, column=0, sticky="e", padx=(0, 5))
    udp_mos_num = tk.Label(mos_block, textvariable=udp_mos_var,
                           font=(FONT, 14, "bold"), fg=TXT, bg=BG)
    udp_mos_num.grid(row=0, column=1, sticky="w")
    tk.Label(mos_block, text="TCP PQI", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).grid(row=1, column=0, sticky="e", padx=(0, 5))
    tcp_pqi_num = tk.Label(mos_block, textvariable=tcp_pqi_var,
                           font=(FONT, 14, "bold"), fg=TXT, bg=BG)
    tcp_pqi_num.grid(row=1, column=1, sticky="w")

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
    totals_cols = ("stream", "sent", "recv", "lost", "late", "lossp",
                   "txb", "peerrx", "echorx", "size")
    totals_head = {"stream": "Stream", "sent": "Sent", "recv": "Received",
                   "lost": "Lost", "late": "Late", "lossp": "Loss %",
                   "txb": "TX B", "peerrx": "Peer RX B", "echorx": "My RX B",
                   "size": "Size"}
    totals_w = {"stream": 110, "sent": 78, "recv": 84, "lost": 64, "late": 60,
                "lossp": 64, "txb": 66, "peerrx": 78, "echorx": 72, "size": 80}
    totals_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_totals packs/unpacks the whole frame
    totals_tree = ttk.Treeview(totals_frame, columns=totals_cols, show="headings",
                               height=len(STREAMS), style="NQ.Treeview")
    totals_tree.pack(fill="x")
    for c in totals_cols:
        totals_tree.heading(c, text=totals_head[c])
        totals_tree.column(c, width=totals_w[c], anchor=("w" if c == "stream" else "e"),
                           stretch=(c == "stream"))
    totals_tree.tag_configure("ok", foreground="#7ee2b8")
    totals_tree.tag_configure("bad", foreground="#ffb3a6")
    for sid, proto, port, name in STREAMS:
        totals_tree.insert("", "end", iid=f"t{sid}",
                           values=(name, 0, 0, 0, 0, "0.0", 0, 0, 0, "-"))
    # frame stays unpacked -> hidden until the Totals button is clicked

    # ---- isolate table (hidden; splits loss into forward vs return) --------
    iso_cols = ("stream", "sent", "fwd", "fwdp", "rtn", "rtnp", "where")
    iso_head = {"stream": "Stream", "sent": "Sent",
                "fwd": "Fwd lost (→peer)", "fwdp": "Fwd %",
                "rtn": "Rtn lost (←peer)", "rtnp": "Rtn %", "where": "Where"}
    iso_w = {"stream": 110, "sent": 84, "fwd": 120, "fwdp": 70,
             "rtn": 120, "rtnp": 70, "where": 110}
    iso_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_isolate packs/unpacks the whole frame
    iso_tree = ttk.Treeview(iso_frame, columns=iso_cols, show="headings",
                            height=len(STREAMS), style="NQ.Treeview")
    iso_tree.pack(fill="x")
    for c in iso_cols:
        iso_tree.heading(c, text=iso_head[c])
        iso_tree.column(c, width=iso_w[c], anchor=("w" if c in ("stream", "where") else "e"),
                        stretch=(c == "stream"))
    iso_tree.tag_configure("ok", foreground="#7ee2b8")
    iso_tree.tag_configure("warn", foreground="#ffd27e")
    for sid, proto, port, name in STREAMS:
        iso_tree.insert("", "end", iid=f"i{sid}",
                        values=(name, 0, 0, "0.00", 0, "0.00", "…"))
    # frame stays unpacked -> hidden until the Isolate button is clicked

    # ---- charts: latency (top, full width), loss + jitter (bottom row) ----
    # Laid out with grid + row weights, NOT pack: pack hands the space freed
    # by a collapsing sibling (the Totals/Isolate tables) to the first
    # expandable widget only, so after opening and closing Totals the bottom
    # chart row stayed squeezed to a sliver until the app was restarted.
    # Grid weights re-distribute the space proportionally on every geometry
    # pass, so the charts always track the current window size.
    charts = tk.Frame(root, bg=BG, padx=12, pady=6)
    charts.pack(fill="both", expand=True)
    charts.columnconfigure(0, weight=1)
    charts.rowconfigure(0, weight=3, uniform="charts")
    charts.rowconfigure(1, weight=2, uniform="charts")
    # Small requested sizes: the drawn size is allocation-driven, and modest
    # requests keep the layout solvable at any window size.
    lat_canvas = tk.Canvas(charts, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    lat_canvas.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
    bottom = tk.Frame(charts, bg=BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.rowconfigure(0, weight=1)
    bottom.columnconfigure(0, weight=1, uniform="bottom")
    bottom.columnconfigure(1, weight=1, uniform="bottom")
    loss_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                            width=100, height=80)
    loss_canvas.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
    jit_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    jit_canvas.grid(row=0, column=1, sticky="nsew", padx=(3, 0))

    def refresh_body():
        snap = engine.snapshot()
        def set_metric(var, num, value, fmt, color_score):
            if value is None:
                var.set("--")
                num.configure(fg=TXT_DIM)
            else:
                var.set(fmt.format(value))
                num.configure(fg=score_color(color_score))

        if snap["links_up"] == 0:
            score_var.set("--")
            score_lbl.configure(bg="#555a61")
            set_metric(udp_mos_var, udp_mos_num, None, "", 0)
            set_metric(tcp_pqi_var, tcp_pqi_num, None, "", 0)
            label_var.set("Waiting for peer")
            sub_var.set(f"peer {args.peer} - no streams up yet")
        else:
            o = snap["overall"]
            score_var.set(f"{o:.0f}")
            score_lbl.configure(bg=score_color(o))
            set_metric(udp_mos_var, udp_mos_num, snap["udp_mos"], "{:.1f}",
                       snap["udp_score"] or 0)
            set_metric(tcp_pqi_var, tcp_pqi_num, snap["tcp_pqi"], "{:.0f}",
                       snap["tcp_pqi"] or 0)
            label_var.set(snap["overall_label"])
            sub_var.set(f"worst {snap['worst']:.0f}  -  "
                        f"{snap['links_up']}/{len(STREAMS)} streams up")

        up_s = int(snap["uptime"])
        t = snap["totals"]
        df = "on" if snap["dont_fragment"] else "off"
        size_tag = {"verified": "✓ verified", "mismatch": "⚠ MISMATCH",
                    "pending": "…"}[snap["size_status"]]
        foot_var.set(
            f"peer {args.peer}    {ports_summary()}    "
            f"frame {snap['frame_size']} B  DF {df}  size {size_tag}    "
            f"uptime {up_s // 3600:02d}:{(up_s % 3600) // 60:02d}:{up_s % 60:02d}"
            f"    |  since reset:  sent {t['tx']:,}  recv {t['recv']:,}  "
            f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  "
            f"[fwd→ {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%)  "
            f"rtn← {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%)]")

        if isolate_shown["on"]:
            for row in snap["rows"]:
                where, tag = loss_verdict(row["fwd_lost"], row["rtn_lost"])
                iso_tree.item(f"i{row['sid']}", tags=(tag,), values=(
                    row["name"], f"{row['cum_tx']:,}",
                    f"{row['fwd_lost']:,}", f"{row['fwd_pct']:.2f}",
                    f"{row['rtn_lost']:,}", f"{row['rtn_pct']:.2f}", where))

        if totals_shown["on"]:
            for row in snap["rows"]:
                decided = row["cum_recv"] + row["cum_lost"] + row["cum_late"]
                lossp = (row["cum_lost"] / decided * 100.0) if decided else 0.0
                full = (row["peer_rx_max"] >= snap["frame_size"]
                        and row["rx_echo_max"] >= snap["frame_size"])
                if row["size_mismatch"]:
                    size_cell, tag = f"⚠ {row['size_mismatch']}", "bad"
                elif full:
                    size_cell, tag = "OK", "ok"
                else:
                    size_cell, tag = "…", ""
                totals_tree.item(f"t{row['sid']}", tags=(tag,), values=(
                    row["name"], f"{row['cum_tx']:,}", f"{row['cum_recv']:,}",
                    f"{row['cum_lost']:,}", f"{row['cum_late']:,}", f"{lossp:.2f}",
                    snap["frame_size"], row["peer_rx_max"], row["rx_echo_max"],
                    size_cell))

        hist = engine.history_copy()
        now = time.monotonic()  # history samples are stamped with monotonic time
        _draw_chart(lat_canvas, "Latency (RTT, ms)", "rtt", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
        _draw_chart(loss_canvas, "Loss + late (%)", "loss", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="%",
                    value_fmt=lambda v: f"{v:.0f}")
        _draw_chart(jit_canvas, "Jitter (ms)", "jitter", series, hist,
                    view_seconds, now, ymin_floor=1.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")

    def refresh():
        # One bad tick must not kill the whole update chain: on an unattended
        # demo screen a single swallowed exception used to freeze the UI on
        # stale numbers forever while probing kept running underneath.
        try:
            refresh_body()
        except tk.TclError:
            return  # window is being torn down
        except Exception:
            traceback.print_exc()
        try:
            root.after(args.refresh_ms, refresh)
        except tk.TclError:
            pass

    def on_close():
        engine.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(120, refresh)  # let the window realize its size first
    root.mainloop()


# ---------------------------------------------------------------------------
# Console UI (fallback when no display / --no-gui)
# ---------------------------------------------------------------------------
def enable_vt_mode():
    """Enable ANSI escape processing in the Windows console. Classic
    conhost/cmd.exe ships with it OFF, so without this the console UI prints
    literal '←[2J←[H' garbage instead of clearing the screen. Returns True if
    escapes will render."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(k32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


def run_console(engine, args):
    vt = enable_vt_mode()
    print(f"Network Vitals {__version__}  peer={args.peer}  bind={args.bind}  "
          f"{ports_summary()}  {args.pps} probes/s/stream")
    print("Ctrl-C to stop.\n")
    try:
        while not engine.stop.is_set():
            snap = engine.snapshot()
            if vt:
                print("\033[2J\033[H", end="")  # clear screen
            else:
                os.system("cls" if sys.platform == "win32" else "clear")
            o = snap["overall"]
            um = f"{snap['udp_mos']:.2f}" if snap["udp_mos"] is not None else "-"
            tq = f"{snap['tcp_pqi']:.0f}" if snap["tcp_pqi"] is not None else "-"
            print(f"  OVERALL QUALITY: {o:5.1f}/100  {snap['overall_label']:<10}"
                  f"  ({snap['links_up']}/{len(STREAMS)} streams up, worst {snap['worst']:.0f})"
                  f"   UDP MOS {um}   TCP PQI {tq}")
            print("  " + "-" * 100)
            print(f"  {'Stream':<10}{'Status':<8}{'RTT ms':>9}{'1-way':>9}"
                  f"{'Jitter':>9}{'Loss %':>9}{'Late %':>9}{'Score':>7}{'MOS':>6}"
                  f"{'TXpps':>8}{'RXpps':>8}")
            print("  " + "-" * 100)
            for r in snap["rows"]:
                st = "UP" if r["connected"] else "DOWN"
                mos_s = f"{r['mos']:.2f}" if r["mos"] is not None else "-"
                if r["connected"]:
                    print(f"  {r['name']:<10}{st:<8}{r['rtt_avg']:>9.2f}{r['latency']:>9.2f}"
                          f"{r['jitter']:>9.2f}{r['loss']:>9.1f}{r['late']:>9.1f}{r['score']:>7.0f}"
                          f"{mos_s:>6}{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
                else:
                    print(f"  {r['name']:<10}{st:<8}{'-':>9}{'-':>9}{'-':>9}"
                          f"{r['loss']:>9.1f}{r['late']:>9.1f}{'-':>7}{'-':>6}"
                          f"{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
            up = int(snap["uptime"])
            t = snap["totals"]
            df = "on" if snap["dont_fragment"] else "off"
            size_tag = {"verified": "verified", "mismatch": "MISMATCH",
                        "pending": "pending"}[snap["size_status"]]
            print("  " + "-" * 100)
            print(f"  frame {snap['frame_size']} B   DF {df}   size {size_tag}"
                  f"   (UDP peer-RX / my-RX per stream:"
                  + "".join(f"  {r['name'].split('-')[1]} {r['peer_rx_max']}/{r['rx_echo_max']}"
                            for r in snap["rows"] if r["proto"] == "UDP") + ")")
            print(f"  totals since reset:  sent {t['tx']:,}  recv {t['recv']:,}  "
                  f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  late {t['late']:,} "
                  f"({t['late_pct']:.2f}%)")
            print(f"  loss split:  forward -> {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%)   "
                  f"return <- {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%)"
                  + "".join(f"   {r['name'].split('-')[1]}:{loss_verdict(r['fwd_lost'], r['rtn_lost'])[0]}"
                            for r in snap["rows"] if r["fwd_lost"] > 6 or r["rtn_lost"] > 6))
            print(f"  uptime {up//3600:02d}:{(up%3600)//60:02d}:{up%60:02d}")
            time.sleep(args.refresh_ms / 1000.0)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


# ---------------------------------------------------------------------------
# Self-update: fetch the latest release of this file from UPDATE_URL and
# replace ourselves in place. Only runs when explicitly requested (--update /
# --check-update / update.bat) — a measurement tool must not phone home on
# its own, and a surprise fetch would skew the very numbers it reports.
# ---------------------------------------------------------------------------
def _parse_version(text):
    """Extract __version__ from source text as an int tuple, or None."""
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        return None, None
    nums = tuple(int(x) for x in re.findall(r"\d+", m.group(1))[:3])
    return (nums or None), m.group(1)


def fetch_update(url, timeout=15):
    """Download the candidate source. Returns (source_text, version_tuple,
    version_string). Raises RuntimeError with a friendly message on any
    problem — network, HTTP, or a payload that isn't a plausible newer us."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"download failed: {e}") from e
    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RuntimeError(f"payload is not UTF-8 text: {e}") from e
    # Sanity: it must be valid Python and recognisably this application.
    try:
        compile(src, "netquality.py", "exec")
    except SyntaxError as e:
        raise RuntimeError(f"payload does not compile: {e}") from e
    if "MAGIC" not in src or "Network Vitals" not in src:
        raise RuntimeError("payload doesn't look like Network Vitals — wrong URL?")
    vtuple, vstr = _parse_version(src)
    if vtuple is None:
        raise RuntimeError("payload has no __version__")
    return src, vtuple, vstr


def perform_update(url, apply=True):
    """Check (and optionally install) the latest version. Returns an exit
    code: 0 = up to date / updated, 1 = failed, 3 = update available (check
    mode only, so scripts can branch on it)."""
    local_v, _ = _parse_version(f'__version__ = "{__version__}"')
    print(f"Network Vitals {__version__}")
    print(f"Checking {url} …")
    try:
        src, remote_v, remote_s = fetch_update(url)
    except RuntimeError as e:
        print(f"Update check failed: {e}", file=sys.stderr)
        return 1
    if remote_v <= local_v:
        print(f"Already up to date (latest is {remote_s}).")
        return 0
    print(f"New version available: {remote_s}")
    if not apply:
        return 3
    if getattr(sys, "frozen", False):
        print("This is a packaged .exe — it can't replace itself. Download "
              "the new version (or rebuild with build_exe.bat) from:\n  "
              + url, file=sys.stderr)
        return 1
    target = os.path.abspath(__file__)
    backup = target + ".bak"
    tmp = target + ".new"
    try:
        with open(backup, "w", encoding="utf-8") as fh:
            fh.write(open(target, "r", encoding="utf-8").read())
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(src)
        os.replace(tmp, target)  # atomic on the same filesystem
    except OSError as e:
        print(f"Install failed: {e}", file=sys.stderr)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return 1
    print(f"Updated {os.path.basename(target)} {__version__} -> {remote_s}.")
    print(f"(previous version saved as {os.path.basename(backup)})")
    print("Restart the app to run the new version.")
    return 0


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
    p.add_argument("--version", action="version",
                   version=f"Network Vitals {__version__}")
    p.add_argument("--update", action="store_true",
                   help="Fetch the latest version from the update URL, install "
                        "it in place, and exit.")
    p.add_argument("--check-update", action="store_true",
                   help="Report whether a newer version is available, then exit "
                        "(exit code 3 = update available).")
    p.add_argument("--update-url", default=UPDATE_URL,
                   help="Where --update/--check-update download from "
                        "(default: the netvitals GitHub repo).")
    p.add_argument("--peer", default=None,
                   help="IP address of the other workstation.")
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
                   help="Probe packet size in bytes (default 200, min %d, max %d; "
                        "e.g. 8972 to fill a 9000-byte jumbo frame)."
                        % (HEADER_LEN, MAX_SIZE))
    p.add_argument("--dont-fragment", action="store_true",
                   help="Set the IPv4 Don't-Fragment bit on UDP so oversized probes "
                        "are dropped, not fragmented (required to truly test jumbo).")
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
    p.add_argument("--mtu-sweep", action="store_true",
                   help="One-shot: binary-search the largest UDP payload that reaches "
                        "the peer unfragmented (peer must be running Network Vitals), "
                        "then exit. Honours --dont-fragment (implied on).")
    p.add_argument("--sweep-min", type=int, default=1400,
                   help="MTU sweep lower bound, UDP payload bytes (default 1400).")
    p.add_argument("--sweep-max", type=int, default=9000,
                   help="MTU sweep upper bound, UDP payload bytes (default 9000).")
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


def run_mtu_sweep(args):
    """Binary-search the largest UDP payload that reaches the peer unfragmented.

    Sends probes with DF set to the peer's UDP reflector and watches for echoes.
    Binds an ephemeral source port so it coexists with a normally-running
    instance on either end. Measures the FORWARD path MTU (this host -> peer);
    the return echo may fragment without affecting detection.
    """
    peer, port = args.peer, args.udp_ports[0]
    lo = max(HEADER_LEN, min(args.sweep_min, MAX_SIZE))
    hi = max(lo, min(args.sweep_max, MAX_SIZE))
    print(f"MTU sweep -> {peer}:{port} (UDP, Don't-Fragment). "
          f"Peer must be running Network Vitals.\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    enlarge_socket_buffers(sock)
    quench_udp_connreset(sock)  # peer down must read as 'dropped', not an error
    if not set_dont_fragment(sock):
        print("WARNING: could not set Don't-Fragment - results may reflect "
              "fragmentation, not true path MTU.\n")
    try:
        sock.bind((args.bind, 0))  # ephemeral source port
    except OSError as e:
        print(f"bind failed: {e}")
        return
    sock.settimeout(0.4)
    seq = [0]

    def round_trips(size):
        """True if a probe of `size` bytes gets an echo back (4 tries)."""
        for _ in range(4):
            seq[0] += 1
            s = seq[0]
            pkt = build_packet(TYPE_PROBE, 0, s, time.monotonic_ns(), size, rxsize=size)
            try:
                sock.sendto(pkt, (peer, port))
            except OSError:
                return False  # EMSGSIZE: exceeds the local NIC MTU
            deadline = time.monotonic() + 0.4
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(MAX_SIZE)
                except socket.timeout:
                    break
                except OSError:
                    return False
                p = parse_header(data)
                if p and p[0] == TYPE_ECHO and p[2] == s:
                    return True
        return False

    if not round_trips(lo):
        print(f"  {lo} B payload did not round-trip - peer down, UDP {port} "
              f"blocked, or even the base size is being dropped.")
        sock.close()
        return
    print(f"  {lo:>5} B payload  ...  OK")
    best, blo, bhi = lo, lo + 1, hi
    while blo <= bhi:
        mid = (blo + bhi) // 2
        ok = round_trips(mid)
        print(f"  {mid:>5} B payload  ...  {'OK' if ok else 'dropped'}")
        if ok:
            best, blo = mid, mid + 1
        else:
            bhi = mid - 1
    sock.close()
    frame = best + 28  # + 20 IPv4 + 8 UDP
    print()
    print(f"Largest UDP payload that traverses unfragmented:  {best} bytes")
    print(f"Forward path MTU (this host -> peer):            ~{frame} bytes")
    if frame >= 9000:
        print("=> Jumbo frames (>=9000) confirmed end to end.  ✓")
    elif frame > 1500:
        print(f"=> Larger-than-standard frames supported up to ~{frame} B "
              f"(but short of 9000 jumbo).")
    else:
        print("=> Standard 1500-byte MTU; no jumbo on this path.")


def main(argv=None):
    args = parse_args(argv)

    if args.update or args.check_update:
        return perform_update(args.update_url, apply=args.update)

    if not args.peer:
        print("error: --peer is required (except with --update/--check-update)",
              file=sys.stderr)
        return 2

    args.size = max(HEADER_LEN, min(args.size, MAX_SIZE))
    if args.pps < 1:
        args.pps = 1

    # Apply chosen ports (read as a module global by the engine and UI).
    global STREAMS
    STREAMS = build_streams(args.udp_ports, args.tcp_ports)

    if args.mtu_sweep:
        run_mtu_sweep(args)
        return

    set_timer_resolution(1)  # smooth pacing on Windows -> fewer microburst drops
    engine = Engine(args.peer, args.bind, args.size, args.pps, args.window,
                    args.timeout, history_seconds=args.history,
                    loss_deadband=args.loss_deadband,
                    dont_fragment=args.dont_fragment)
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
    sys.exit(main())
