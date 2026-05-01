#!/usr/bin/env python3
"""One-shot SSH key setup for sdwan_perf.

Reads hosts from config.yaml, generates an ed25519 key if needed, copies it
to each remote host (one password prompt per host), and verifies passwordless
auth works using the exact same options the orchestrator will use.

Idempotent: if passwordless auth already works for a host, it skips that host.

Usage:
    python3 setup_ssh.py                       # uses ./config.yaml
    python3 setup_ssh.py --config /path/to.yaml
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from config import HostConfig, load_config

# Minimal ANSI for clarity. Disable with --no-color if needed.
class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _check_tools() -> None:
    for tool in ("ssh-keygen", "ssh-copy-id", "ssh"):
        if not shutil.which(tool):
            print(f"{C.RED}✗ Missing required tool: {tool}{C.RESET}", file=sys.stderr)
            print("  Install with: sudo apt install -y openssh-client", file=sys.stderr)
            sys.exit(1)


def _ensure_key(key_path: Path) -> None:
    """Generate an ed25519 key at key_path if it doesn't exist."""
    if key_path.exists():
        print(f"  {C.DIM}Key already exists: {key_path}{C.RESET}")
        return
    print(f"  Generating ed25519 key: {key_path}")
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    subprocess.run(
        [
            "ssh-keygen", "-t", "ed25519",
            "-f", str(key_path),
            "-N", "",                         # no passphrase
            "-C", f"sdwan_perf@{Path.home().name or 'host'}",
        ],
        check=True,
    )


def _verify_passwordless(key_path: Path, user: str, host: str) -> bool:
    """Test passwordless auth using the EXACT options asyncssh will use.

    IdentitiesOnly=yes ensures we test the configured key, not a different
    one that happens to be in ssh-agent.
    """
    if not key_path.exists():
        return False
    result = subprocess.run(
        [
            "ssh",
            "-i", str(key_path),
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}",
            "echo ok",
        ],
        capture_output=True, text=True, check=False, timeout=15,
    )
    return result.returncode == 0 and "ok" in result.stdout


def _copy_key(key_path: Path, user: str, host: str) -> bool:
    """Run ssh-copy-id. This is the only step that prompts for the password."""
    print(f"  Copying key to {user}@{host}…")
    print(f"  {C.YELLOW}You will be prompted for the SSH password ONCE.{C.RESET}")
    result = subprocess.run(
        [
            "ssh-copy-id",
            "-i", f"{key_path}.pub",
            "-o", "StrictHostKeyChecking=accept-new",
            f"{user}@{host}",
        ],
        check=False,
    )
    return result.returncode == 0


def _process_host(name: str, host: HostConfig) -> tuple[bool, str]:
    """Configure one host. Returns (success, message)."""
    print(f"\n{C.BOLD}[{name}]{C.RESET} {host.ssh_user}@{host.mgmt_ip}")
    if not host.ssh_user or not host.ssh_key_path:
        return False, "missing ssh_user or ssh_key_path in config"

    key_path = Path(host.ssh_key_path).expanduser()

    if _verify_passwordless(key_path, host.ssh_user, host.mgmt_ip):
        print(f"  {C.GREEN}✓ Already configured{C.RESET}")
        return True, "already-configured"

    _ensure_key(key_path)

    if not _copy_key(key_path, host.ssh_user, host.mgmt_ip):
        return False, "ssh-copy-id failed"

    if not _verify_passwordless(key_path, host.ssh_user, host.mgmt_ip):
        return False, "auth verify failed after copy"

    print(f"  {C.GREEN}✓ Passwordless auth confirmed{C.RESET}")
    return True, "configured"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--config", type=Path, default=Path("config.yaml"),
        help="Path to YAML config (default: config.yaml)",
    )
    args = parser.parse_args()

    _check_tools()

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"{C.RED}✗ {exc}{C.RESET}", file=sys.stderr)
        print("  Copy config.example.yaml to config.yaml and edit first.", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"{C.RED}✗ Config load failed: {exc}{C.RESET}", file=sys.stderr)
        return 2

    targets = [
        ("server", config.hosts.server),
        ("frr", config.hosts.frr),
    ]

    failed: list[tuple[str, str]] = []
    for name, host in targets:
        try:
            ok, msg = _process_host(name, host)
        except subprocess.TimeoutExpired:
            ok, msg = False, "ssh timed out — host unreachable?"
            print(f"  {C.RED}✗ {msg}{C.RESET}")
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}Interrupted.{C.RESET}")
            return 130
        if not ok:
            failed.append((name, msg))
            print(f"  {C.RED}✗ {msg}{C.RESET}")

    print()
    if failed:
        print(f"{C.RED}{C.BOLD}Failed:{C.RESET}")
        for name, msg in failed:
            print(f"  {name}: {msg}")
        print(f"\n{C.DIM}Common fixes:{C.RESET}")
        print(f"  - Wrong password during ssh-copy-id → re-run this script")
        print(f"  - Host unreachable → check mgmt_ip in config.yaml")
        print(f"  - SSH disabled on host → check sshd is running")
        return 1

    print(f"{C.GREEN}{C.BOLD}All hosts ready.{C.RESET}")
    print(f"\nNext: {C.BOLD}python3 orchestrator.py --config {args.config}{C.RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())