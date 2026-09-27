"""Typed access to the Phase 1 attack catalogue (`attacks.toml`)."""

import tomllib
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Literal

type IPAddress = IPv4Address | IPv6Address
type Layer = Literal["inbound", "egress"]
type Vector = Literal["literal", "dns", "redirect", "scheme", "parser"]

LAYERS: tuple[Layer, ...] = ("inbound", "egress")
VECTORS: tuple[Vector, ...] = ("literal", "dns", "redirect", "scheme", "parser")


@dataclass(frozen=True, slots=True)
class Asset:
    name: str
    description: str
    networks: tuple[IPv4Network | IPv6Network, ...]

    def contains(self, ip: IPAddress) -> bool:
        return any(ip.version == net.version and ip in net for net in self.networks)


@dataclass(frozen=True, slots=True)
class Attack:
    id: str
    technique: str
    vector: Vector
    payload: str
    asset: str
    layers: tuple[Layer, ...]
    resolves_to: IPAddress | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class Catalogue:
    assets: dict[str, Asset]
    attacks: tuple[Attack, ...]


@cache
def load() -> Catalogue:
    raw = tomllib.loads(files("mlwsg").joinpath("attacks.toml").read_text())
    assets = {
        name: Asset(name, a["description"], tuple(ip_network(n) for n in a["networks"]))
        for name, a in raw["assets"].items()
    }
    attacks = tuple(
        Attack(
            **{k: v for k, v in a.items() if k not in ("layers", "resolves_to")},
            layers=tuple(a["layers"]),
            resolves_to=ip_address(a["resolves_to"]) if "resolves_to" in a else None,
        )
        for a in raw["attacks"]
    )
    return Catalogue(assets, attacks)
