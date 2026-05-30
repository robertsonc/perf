# netquality

A single, self-contained Python app that precisely measures **loss, latency and
jitter** between two Windows workstations and rates the connection with a
**quality score**.

You run the *exact same program* on both machines. Each instance continuously
**sends and receives** four probe streams at once:

| Stream    | Protocol | Port |
|-----------|----------|------|
| UDP-5201  | UDP      | 5201 |
| UDP-5202  | UDP      | 5202 |
| TCP-5101  | TCP      | 5101 |
| TCP-5102  | TCP      | 5102 |

Traffic flows **bi-directionally on every stream, all the time**. The UI updates
in realtime with per-stream loss / RTT / one-way latency / jitter, plus an
overall connection quality score and MOS estimate.

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
- **Loss** — a probe with no echo within `--timeout` (default 2s) is counted as
  lost; loss % is computed over a sliding `--window` (default 10s).
- **Jitter** — RFC 3550 style smoothed mean deviation of successive RTTs.

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
