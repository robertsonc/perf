# Network Vitals

A single, self-contained Python app (`netquality.py`) that precisely measures
**loss, latency and jitter** between two Windows workstations and rates the
connection with a **quality score**.

You run the *exact same program* on both machines. Each instance continuously
**sends and receives** four probe streams at once:

| Stream    | Protocol | Port |
|-----------|----------|------|
| UDP-5201  | UDP      | 5201 |
| UDP-5202  | UDP      | 5202 |
| TCP-5101  | TCP      | 5101 |
| TCP-5102  | TCP      | 5102 |

Traffic flows **bi-directionally on every stream, all the time**. The UI updates
in realtime and shows the connection's overall experience at a glance.

The dashboard shows **three live + history charts** with one line per stream:

- **Latency (RTT, ms)**
- **Loss + late (%)**
- **Jitter (ms)**

plus, in the header:

- a big colour-coded **Experience score** (0–100, green = excellent → red = bad),
- a composite **MOS (avg)** — the average MOS across the active streams,
- a **Reset / Clear** button that wipes the charts and all accumulated
  loss/latency/jitter stats so a demo can start from a clean slate.

Charts keep a rolling history (default 5 minutes, `--history`). The window
resizes freely; the charts grow and shrink with it.

> Loss is still measured per stream and folded into the score (as `loss + late`,
> see below) — it's just not shown as its own chart/table anymore.

## Requirements

- **Python 3.8+** (tested on 3.11). Nothing to `pip install` — it uses only the
  standard library. The GUI uses Tkinter, which is included with the standard
  Python installer for Windows.
- No clock synchronization between the two machines is required (latency is
  measured by round-trip, so both clocks are irrelevant).

## Running it

On **workstation A** (say its peer is `10.0.0.2`):

```
python netquality.py --peer 10.0.0.2
```

On **workstation B** (peer is `10.0.0.1`):

```
python netquality.py --peer 10.0.0.1
```

That's the entire configuration. Or just double-click **`run.bat`** and type the
peer's IP when prompted.

### Console mode (no GUI)

```
python netquality.py --peer 10.0.0.2 --no-gui
```

The app also falls back to the console UI automatically if no display / Tkinter
is available.

### Single-machine smoke test (Linux loopback aliases)

```
python netquality.py --bind 127.0.0.1 --peer 127.0.0.2 --no-gui
python netquality.py --bind 127.0.0.2 --peer 127.0.0.1 --no-gui
```

## How it works

Every packet is a fixed-size **probe** carrying a stream id, a sequence number,
and the sender's monotonic timestamp. The receiving side reflects it straight
back as an **echo** with the timestamp untouched. The originator then computes:

- **RTT** = `now − echoed_timestamp` (measured entirely on its own clock, so no
  time sync needed). **One-way latency** is reported as RTT/2.
- **Jitter** — RFC 3550 style smoothed mean deviation of successive RTTs.

### Loss vs. late — how a frame is judged "lost"

Every probe ends in exactly one of three outcomes, tallied over the sliding
`--window` (default 10s):

| Outcome | Meaning |
|---|---|
| **received** | echo came back within `--timeout` (default 2s) |
| **lost** | no echo within `--timeout`, and none since — a real drop |
| **late** | echo arrived **after** the `--timeout` deadline (reordered or over-buffered) |

So a frame is declared *lost* when its echo hasn't returned within `--timeout`.
**But what if it arrives after that?** It is *not* silently dropped: when the
late echo eventually appears, the probe is reclassified `lost → late`, so
**Loss %** reflects frames that *truly never came back* and **Late %** reflects
frames that *came back too late to be useful*. This separates a dead path from a
recoverable jitter/reorder event — they look identical if you only track "loss".

For the **quality score**, `loss + late` is treated as the effective impairment
(a real-time stream can't use a frame that misses its playout deadline either
way), but the two are reported separately so you can see which is happening.
Raise `--timeout` if you want to tolerate slower paths before counting late/lost;
lower it to be stricter about latency deadlines.

#### Why a *clean* link can show a little UDP loss (and impairment makes it vanish)

A counterintuitive thing you may see: a low-jitter path shows a small amount of
**UDP** loss, while adding jitter/delay impairment drives it to ~0. TCP streams
never show it. The cause is **microbursts**, not the wire:

- The OS thread scheduler / timer granularity (≈15 ms on Windows) makes the
  paced probes actually leave in small bursts rather than evenly spaced.
- On a clean, low-jitter path those bursts arrive **still bunched**, and a burst
  can momentarily overrun the socket receive buffer — a dropped datagram that
  looks like loss. (TCP can't show this; the kernel retransmits invisibly.)
- A jitter/delay impairment box **spreads packets out in time** (and buffers
  rather than drops), which *de-bursts* the arrivals — so the buffer never
  overruns and loss falls to zero.

To keep this local artifact out of the measurement, netquality (a) enlarges the
UDP socket send/receive buffers to a few MB (`SOCK_BUF_BYTES`) so microbursts are
absorbed, and (b) on Windows requests a 1 ms scheduler tick
(`timeBeginPeriod(1)`) so the probe pacing is smooth instead of clumping into
~15 ms bursts in the first place. Reported loss then reflects the path, not a
local buffer overflow.

If you still see a little UDP loss on a path you believe is clean, confirm
whether it's on the wire with a two-ended packet capture (e.g. Wireshark): on
each host capture `udp port 5201`, then compare how many probe datagrams one
host **sent** against how many the other host **received**. If sent > received,
the loss is real and on the network; if the counts match, it isn't leaving/
arriving as loss at all.

Because both instances originate probes *and* reflect the peer's probes on the
same ports, every stream carries traffic in both directions continuously. For
TCP, each instance runs both a listener (to reflect the peer) and a client
connection (to originate its own probes), with automatic reconnect.

### Quality score

The score (0–100) and MOS (1–4.5) come from the **ITU-T G.107 E-model**
R-factor, fed by one-way latency, loss, and jitter (jitter is folded in as
extra effective delay). The header shows the *average* across streams and calls
out the *worst* stream. Bands: Excellent ≥80, Good ≥70, Fair ≥60, Poor ≥50,
Bad below.

## Options

```
--peer IP          (required) the other workstation's IP
--bind ADDR        local address to bind/listen on (default 0.0.0.0)
--pps N            probes per second per stream (default 50)
--size N           probe packet size in bytes (default 200)
--window SECONDS   sliding window for loss/jitter/rate (default 10)
--timeout SECONDS  un-echoed probe -> lost after this (default 2)
--history SECONDS  span of the live/history charts (default 300)
--refresh-ms N     UI refresh interval (default 500)
--no-gui           force console UI
```

At the defaults each stream is ~50 packets/s × 200 B ≈ 10 KB/s each way, i.e.
~80 KB/s total for the box — light enough to leave running, dense enough to
resolve loss and jitter well. Bump `--pps` / `--size` for a heavier load test.

## Windows firewall

The first time you run it, Windows may prompt to allow Python through the
firewall — allow it on the relevant networks. If it was dismissed, add inbound
rules for **UDP 5201–5202** and **TCP 5101–5102**, or allow `python.exe`.

## Building a standalone .exe (optional)

If you'd rather hand someone a single executable with no Python install, run
**`build_exe.bat`** (needs `pip install pyinstaller`). It produces
`dist\netquality.exe`, which you launch as:

```
netquality.exe --peer 10.0.0.2
```
