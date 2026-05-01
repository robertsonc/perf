"""Configuration models for the SD-WAN performance orchestrator."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class DashboardConfig(BaseModel):
    bind: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)


class Iperf3Config(BaseModel):
    port: int = Field(default=5201, ge=1, le=65535)
    duration_s: int = Field(default=10, ge=1, le=3600)
    parallel_streams: int = Field(default=4, ge=1, le=128)
    protocol: Literal["tcp", "udp"] = "tcp"
    reverse: bool = False
    cooldown_s: float = Field(default=1.0, ge=0.0, le=300.0)
    window_kib: int | None = Field(default=None, ge=1)
    mss_bytes: int | None = Field(default=None, ge=88, le=9000)
    udp_bandwidth: str | None = None
    udp_length: int | None = Field(default=None, ge=64, le=65507)


class HostConfig(BaseModel):
    mgmt_ip: str
    data_ip: str | None = None
    # Auto-detected from data_ip if not set. Override only if you have
    # multiple interfaces on the same subnet.
    data_iface: str | None = None
    ssh_user: str | None = None
    ssh_key_path: str | None = None
    ssh_password_env: str | None = None
    iperf3_path: str = "iperf3"

    @field_validator("ssh_key_path")
    @classmethod
    def expand_key_path(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return str(Path(v).expanduser().resolve())

    def resolve_password(self) -> str | None:
        """Read password from env var if configured; never store in YAML."""
        if not self.ssh_password_env:
            return None
        pw = os.environ.get(self.ssh_password_env)
        if not pw:
            raise RuntimeError(
                f"ssh_password_env={self.ssh_password_env} is set in config "
                f"but the environment variable is empty"
            )
        return pw


class HostsConfig(BaseModel):
    client: HostConfig
    server: HostConfig
    frr: HostConfig


class WanInterfaces(BaseModel):
    ingress_iface: str
    egress_iface: str


class ApplianceConfig(BaseModel):
    description: str = ""
    wan0: WanInterfaces
    wan1: WanInterfaces | None = None


class ActiveConfig(BaseModel):
    appliance: str
    dual_wan: bool = False


class Config(BaseModel):
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    iperf3: Iperf3Config = Field(default_factory=Iperf3Config)
    poller_interval_s: float = Field(default=1.0, gt=0.0, le=60.0)
    poller_buffer_size: int = Field(default=3600, ge=60, le=86400)
    hosts: HostsConfig
    appliances: dict[str, ApplianceConfig]
    active: ActiveConfig

    @model_validator(mode="after")
    def _validate_active_appliance(self) -> "Config":
        if self.active.appliance not in self.appliances:
            raise ValueError(
                f"active.appliance='{self.active.appliance}' not found in "
                f"appliances (have: {list(self.appliances)})"
            )
        appliance = self.appliances[self.active.appliance]
        if self.active.dual_wan and appliance.wan1 is None:
            raise ValueError(
                f"active.dual_wan=true but appliance '{self.active.appliance}' "
                f"has no wan1 configured"
            )
        return self

    def active_appliance(self) -> ApplianceConfig:
        return self.appliances[self.active.appliance]

    def frr_wan_interfaces(self) -> list[str]:
        """Distinct list of FRR interfaces to poll for the active config."""
        appliance = self.active_appliance()
        ifaces = [appliance.wan0.ingress_iface, appliance.wan0.egress_iface]
        if self.active.dual_wan and appliance.wan1 is not None:
            ifaces.extend(
                [appliance.wan1.ingress_iface, appliance.wan1.egress_iface]
            )
        seen: set[str] = set()
        out: list[str] = []
        for i in ifaces:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out


def load_config(path: str | Path) -> Config:
    """Parse and validate a YAML config file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return Config.model_validate(raw)
