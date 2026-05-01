# sdwan_perf — SD-WAN performance orchestrator

Multi-vantage measurement harness for EC-V / SSR. iperf3 client/server with
wire counters at three independent points — client NIC, FRR underlay, server
NIC — all correlated to the iperf3 wallclock window.

## Why three vantage points

A single wire reading on the FRR can't distinguish between:

- a real drop in the EC-V tunnel,
- a measurement skew between two unsynchronized samples,
- an asymmetric path that bypasses the interface you're watching.

With client TX, FRR wire, and server RX captured for the same window:

| Quantity | Computed as | Healthy range | Tells you |
|---|---|---|---|
| TCP/IP overhead | (client TX − payload) / payload | ~3% | Client-side framing only |
| Tunnel overhead | (FRR wire − client TX) / client TX | ~10% (EC-V) | Encap is doing what it should |
| End-to-end loss | (client TX − server RX) / client TX | ~0% | Drops anywhere in the path |

If FRR ingress ≈ FRR egress but server RX < client TX, the drop is in the
appliance after de-encapsulation (East-side EC-V, NIC, kernel). If FRR
ingress ≠ FRR egress, the drop is on the FRR itself. If client TX ≪ payload,
your iperf3 numbers are wrong (TSO/GSO accounting, etc.).

## Topology

```
   Client                 EC-V          FRR            EC-V               Server
   10.1.1.3 ────────► West ──────► 192.168.2.102 ──► East ────────► 10.2.2.2
   (orchestrator)                  (counter source)                (iperf3 -s)
       │                                  │                              │
       │                                  │                              │
       └────────── 192.168.2.0/24 OOB management network ────────────────┘

   Pollers:
     client  → /proc/net/dev locally (no SSH)
     frr     → SSH to 192.168.2.102, cat /proc/net/dev
     server  → SSH to 192.168.2.123, cat /proc/net/dev
```

## Setup

```bash
# 1. Deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. SSH key auth (drop the hardcoded password from V1)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
ssh-copy-id aruba@192.168.2.102        # FRR
ssh-copy-id aruba@192.168.2.123        # server
ssh -i ~/.ssh/id_ed25519 aruba@192.168.2.102 'cat /proc/net/dev | head -3'
ssh -i ~/.ssh/id_ed25519 aruba@192.168.2.123 'iperf3 --version'

# 3. Config
cp config.example.yaml config.yaml
$EDITOR config.yaml

# 4. Run
python3 orchestrator.py --config config.yaml
```

Dashboard: `http://10.1.1.3:8080/`

## CLI overrides

```bash
# SSR dual-WAN, 8 streams, 20s runs
python3 orchestrator.py --config config.yaml --appliance ssr --dual-wan --streams 8 --duration 20

# UDP at near line rate
python3 orchestrator.py --config config.yaml --protocol udp --udp-bandwidth 950M

# Reverse direction (server → client) — bulk flips, all overhead math still works
python3 orchestrator.py --config config.yaml --reverse
```

## Architecture

```
orchestrator.py    main asyncio loop, signal handling, three pollers
config.py          pydantic models + YAML loader
ssh_pool.py        asyncssh persistent sessions, iface auto-detection
poller.py          /proc/net/dev poller + ring buffer + windowing
runner.py          iperf3 client wrapper + multi-vantage analysis
dashboard.py       aiohttp app
dashboard.html     Chart.js frontend
```

The poller is generic — it takes any async callable that returns
/proc/net/dev text. The orchestrator instantiates three:

```python
client_poller = WirePoller(name="client", reader=read_local_proc_net_dev,  ifaces=[client_iface])
frr_poller    = WirePoller(name="frr",    reader=pool.frr.read_proc_net_dev,    ifaces=frr_wan_ifaces)
server_poller = WirePoller(name="server", reader=pool.server.read_proc_net_dev, ifaces=[server_iface])
```

Each owns its own ring buffer. After every iperf3 run, the orchestrator
captures `(t_start, t_end)` and queries all three pollers for that exact
window. Per-hop deltas go to `analyze_run()` which does the overhead math.

## Diagnostic patterns to watch for

| Pattern | Likely cause |
|---|---|
| Tunnel overhead is much higher than ~10% | EC-V is hitting fragmentation or PMTUD; check tunnel MTU |
| Tunnel overhead is much lower than ~10% | Wire counters undersampling; or compression is on |
| FRR ingress ≠ FRR egress in single-WAN mode | EC-V is silently using WAN1 — run with `--dual-wan` to see |
| E2E loss > 0.5% with steady goodput | UDP loss tolerated; server-side EC-V or NIC dropping |
| TCP/IP overhead > 5% | TSO/GSO disabled, or many small TCP segments (check MSS) |
| Goodput stable, all wire steady | Healthy. The thing's working. |

## What's not in this build (future)

- EC-V Orchestrator API counters (would replace the FRR vantage with the
  appliance's own pre-encrypt / post-decrypt byte counts — much more
  accurate for tunnel overhead than the FRR vantage)
- SQLite persistence (dashboard memory loses history on restart)
- WebSocket push (currently 1 Hz HTTP poll — fine for this scale)
- Per-stream retransmit chart (data is in `iperf3.streams` already, just
  not plotted)
