"""Ensembles d'adresses IPv4 et de services (protocole + plages de ports),
avec inclusion et intersection : base du calcul des règles masquées,
redondantes, trop larges et de l'exposition.

Les objets non résolubles (FQDN, géolocalisation, objets dynamiques,
utilisateurs…) sont gardés comme « opaques » : ils ne sont égaux qu'à
eux-mêmes, et une règle qui en contient n'est jamais déclarée « couverte »
sauf par une règle « any » — on ne conclut jamais sans certitude.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

MAX_IP = 2**32 - 1


def _merge(iv: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def _covers(big: list[tuple[int, int]], small: list[tuple[int, int]]) -> bool:
    i = 0
    for lo, hi in small:
        while i < len(big) and big[i][1] < lo:
            i += 1
        if i >= len(big) or big[i][0] > lo or big[i][1] < hi:
            return False
    return True


def _intersects(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i][1] < b[j][0]:
            i += 1
        elif b[j][1] < a[i][0]:
            j += 1
        else:
            return True
    return False


@dataclass
class AddrSet:
    iv: list[tuple[int, int]] = field(default_factory=list)
    opaque: frozenset = frozenset()          # noms non résolus (FQDN, géo, dynamiques…)
    negate: bool = False                     # « tout sauf » (Forti srcaddr-negate, MikroTik !)

    @staticmethod
    def any() -> "AddrSet":
        return AddrSet([(0, MAX_IP)])

    @staticmethod
    def parse(items) -> "AddrSet":
        iv, op = [], set()
        for it in items:
            r = parse_addr(it)
            if r is None:
                op.add(str(it))
            else:
                iv.append(r)
        return AddrSet(_merge(iv), frozenset(op))

    def union(self, other: "AddrSet") -> "AddrSet":
        return AddrSet(_merge(self.iv + other.iv), self.opaque | other.opaque, self.negate and other.negate)

    @property
    def is_any(self) -> bool:
        return not self.negate and self.iv == [(0, MAX_IP)]

    @property
    def size(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.iv)

    def covers(self, other: "AddrSet") -> bool:
        if self.is_any:
            return True
        if self.negate or other.negate:
            return self == other
        return other.opaque <= self.opaque and _covers(self.iv, other.iv)

    def intersects(self, other: "AddrSet") -> bool:
        if self.is_any or other.is_any or self.negate or other.negate:
            return True
        return bool(self.opaque & other.opaque) or _intersects(self.iv, other.iv) or bool(self.opaque or other.opaque)

    def contains_ip(self, ip: str) -> bool:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return False
        inside = any(lo <= n <= hi for lo, hi in self.iv)
        return inside != self.negate

    def describe(self, limit: int = 4) -> str:
        if self.is_any:
            return "tout"
        parts = []
        for lo, hi in self.iv[:limit]:
            parts.append(_fmt(lo, hi))
        parts += sorted(self.opaque)[:max(0, limit - len(parts))]
        more = len(self.iv) + len(self.opaque) - len(parts)
        return ("tout sauf " if self.negate else "") + ", ".join(parts) + (f" (+{more})" if more > 0 else "")

    def is_public(self) -> bool:
        """Contient des adresses publiques (Internet) ?"""
        if self.is_any or self.negate:
            return True
        priv = [(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))) for a, b in PRIVATE]
        rest = self.iv
        for lo, hi in rest:
            n = lo
            while n <= hi:
                blk = next(((pl, ph) for pl, ph in priv if pl <= n <= ph), None)
                if not blk:
                    return True
                n = blk[1] + 1
        return False


PRIVATE = [("0.0.0.0", "0.255.255.255"), ("10.0.0.0", "10.255.255.255"), ("100.64.0.0", "100.127.255.255"),
           ("127.0.0.0", "127.255.255.255"), ("169.254.0.0", "169.254.255.255"), ("172.16.0.0", "172.31.255.255"),
           ("192.168.0.0", "192.168.255.255"), ("224.0.0.0", "255.255.255.255")]


def _fmt(lo: int, hi: int) -> str:
    if lo == hi:
        return str(ipaddress.IPv4Address(lo))
    try:
        nets = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)))
        if len(nets) == 1:
            return str(nets[0])
    except ValueError:
        pass
    return f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}"


def parse_addr(s) -> tuple[int, int] | None:
    """« 10.0.0.0/8 », « 10.0.0.0 255.0.0.0 », « 10.0.0.1-10.0.0.9 », « 10.0.0.5 », « 0.0.0.0/0 » ; None si non IP."""
    s = str(s).strip().strip('"')
    if not s:
        return None
    if s.lower() in ("any", "all", "*", "0.0.0.0/0", "0.0.0.0 0.0.0.0"):
        return (0, MAX_IP)
    try:
        if "-" in s and "/" not in s:
            a, b = (x.strip() for x in s.split("-", 1))
            ia = int(ipaddress.IPv4Address(a))
            ib = int(ipaddress.IPv4Address(b)) if "." in b else int(ipaddress.IPv4Address(".".join(a.split(".")[:3] + [b])))
            return (min(ia, ib), max(ia, ib))
        if " " in s:
            a, m = s.split()[:2]
            n = ipaddress.IPv4Network(f"{a}/{m}", strict=False)
        else:
            n = ipaddress.IPv4Network(s, strict=False)
        return (int(n.network_address), int(n.broadcast_address))
    except ValueError:
        return None


# ------------------------------------------------------------------ services
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "sctp": 132, "ipv6-icmp": 58, "ospf": 89,
             "igmp": 2, "vrrp": 112, "l2tp": 115, "ipip": 4, "pim": 103}


@dataclass
class SvcSet:
    """{protocole: intervalles de ports} ; protocole 0 = tous ; ports (0, 65535) = tous."""
    m: dict[int, list[tuple[int, int]]] = field(default_factory=dict)
    opaque: frozenset = frozenset()          # applications / services non résolus

    @staticmethod
    def any() -> "SvcSet":
        return SvcSet({0: [(0, 65535)]})

    def add(self, proto, lo: int = 0, hi: int = 65535) -> "SvcSet":
        p = proto if isinstance(proto, int) else PROTO_NUM.get(str(proto).lower(), None)
        if p is None:
            try:
                p = int(proto)
            except (TypeError, ValueError):
                self.opaque = self.opaque | {str(proto)}
                return self
        self.m.setdefault(p, [])
        self.m[p] = _merge(self.m[p] + [(min(lo, hi), max(lo, hi))])
        return self

    def union(self, other: "SvcSet") -> "SvcSet":
        out = SvcSet({k: list(v) for k, v in self.m.items()}, self.opaque | other.opaque)
        for p, ivs in other.m.items():
            for lo, hi in ivs:
                out.add(p, lo, hi)
        return out

    @property
    def is_any(self) -> bool:
        return self.m.get(0) == [(0, 65535)]

    def covers(self, other: "SvcSet") -> bool:
        if self.is_any:
            return True
        if not other.opaque <= self.opaque:
            return False
        for p, ivs in other.m.items():
            if p == 0:
                return False
            mine = self.m.get(p)
            if not mine or not _covers(mine, ivs):
                return False
        return True

    def intersects(self, other: "SvcSet") -> bool:
        if self.is_any or other.is_any or (self.opaque and other.opaque):
            return True
        for p, ivs in other.m.items():
            if p in self.m and _intersects(self.m[p], ivs):
                return True
        return bool(self.opaque or other.opaque)

    def has_port(self, port: int, proto: int = 6) -> bool:
        if self.is_any:
            return True
        return any(lo <= port <= hi for lo, hi in self.m.get(proto, [])) or any(lo <= port <= hi for lo, hi in self.m.get(0, []))

    def ports(self, proto: int = 6) -> list[tuple[int, int]]:
        if self.is_any:
            return [(0, 65535)]
        return self.m.get(proto, []) + self.m.get(0, [])

    def describe(self, limit: int = 6) -> str:
        if self.is_any:
            return "tous services"
        names = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}
        parts = []
        for p, ivs in sorted(self.m.items()):
            pn = names.get(p, f"proto {p}")
            if ivs == [(0, 65535)]:
                parts.append(f"{pn} (tous)")
            else:
                parts.append(f"{pn} " + ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ivs[:limit]))
        parts += sorted(self.opaque)[:limit]
        return " · ".join(parts) or "—"


def svc_port(proto: str, port: int) -> SvcSet:
    return SvcSet().add(proto, port, port)
