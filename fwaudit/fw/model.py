"""Configuration de pare-feu NORMALISÉE : chaque lecteur (FortiGate, Sophos,
Stormshield, WatchGuard, UniFi, MikroTik, Windows) produit cette même
structure ; toutes les règles d'analyse travaillent dessus.

Sérialisable en JSON (to_dict / from_dict) pour l'historique et la ré-analyse.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .sets import AddrSet, SvcSet

ALLOW, DENY = "allow", "deny"

# rôles de zone / interface
WAN, LAN, DMZ, GUEST, IOT, VPN, MGMT, LOCAL, ANY, OTHER = "wan", "lan", "dmz", "guest", "iot", "vpn", "mgmt", "local", "any", "other"
ROLE_LABELS = {WAN: "Internet (WAN)", LAN: "Réseau interne", DMZ: "DMZ", GUEST: "Invités", IOT: "Objets connectés / caméras",
               VPN: "VPN", MGMT: "Administration", LOCAL: "Le pare-feu lui-même", ANY: "Toutes zones", OTHER: "Autre"}


@dataclass
class Interface:
    name: str
    role: str = OTHER
    zone: str = ""
    ips: list[str] = field(default_factory=list)          # « 10.0.0.1/24 »
    admin: list[str] = field(default_factory=list)        # services d'administration ouverts sur l'interface (https, ssh, telnet, http, ping, snmp…)
    vlan: int | None = None
    enabled: bool = True
    description: str = ""


@dataclass
class Rule:
    id: str                                  # identifiant / numéro chez le constructeur
    position: int                            # ordre d'évaluation (0 = première)
    name: str = ""
    enabled: bool = True
    action: str = ALLOW
    src_zones: list[str] = field(default_factory=list)   # [] = toutes
    dst_zones: list[str] = field(default_factory=list)
    src: dict = field(default_factory=lambda: {"iv": [], "opaque": [], "negate": False})
    dst: dict = field(default_factory=lambda: {"iv": [], "opaque": [], "negate": False})
    svc: dict = field(default_factory=dict)
    src_names: list[str] = field(default_factory=list)   # libellés d'origine (objets)
    dst_names: list[str] = field(default_factory=list)
    svc_names: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)       # conditions supplémentaires (utilisateurs, applications, horaires)
    apps: list[str] = field(default_factory=list)
    schedule: str = ""
    log: bool | None = None
    profiles: list[str] = field(default_factory=list)    # inspections : antivirus, IPS, filtrage web, contrôle applicatif…
    hits: int | None = None
    last_hit: str = ""
    comment: str = ""
    layer: str = "filter"                    # filter / input (vers le pare-feu) / forward / local-in / windows-in / windows-out
    chain: str = ""
    nat: bool = False                        # règle qui porte aussi une translation (Sophos, UniFi…)
    raw: str = ""                            # extrait de la configuration d'origine (preuve)

    # ----------------------------------------------------------- ensembles
    @property
    def src_set(self) -> AddrSet:
        return _aset(self.src)

    @property
    def dst_set(self) -> AddrSet:
        return _aset(self.dst)

    @property
    def svc_set(self) -> SvcSet:
        return _sset(self.svc)

    def set_src(self, a: AddrSet):
        self.src = _adict(a)

    def set_dst(self, a: AddrSet):
        self.dst = _adict(a)

    def set_svc(self, s: SvcSet):
        self.svc = {"m": {str(k): v for k, v in s.m.items()}, "opaque": sorted(s.opaque)}

    @property
    def extra_conditions(self) -> bool:
        return bool(self.users or self.apps or self.schedule)

    def label(self) -> str:
        return f"#{self.id}" + (f" « {self.name} »" if self.name and self.name != str(self.id) else "")


@dataclass
class Nat:
    """Redirection / publication vers l'intérieur (DNAT, VIP, port forwarding)."""
    id: str
    name: str = ""
    enabled: bool = True
    ext_ip: str = ""                         # IP publique (vide = IP de l'interface WAN)
    ext_ports: str = ""                      # « 3389 », « 8000-8010 », « » = tous
    proto: str = "tcp"
    int_ip: str = ""
    int_port: str = ""
    src_restrict: list[str] = field(default_factory=list)   # [] = depuis tout Internet
    interface: str = ""
    raw: str = ""


@dataclass
class Admin:
    name: str
    profile: str = ""                        # super_admin, read-only…
    trusted: list[str] = field(default_factory=list)   # hôtes de confiance (vide = partout)
    mfa: bool | None = None
    enabled: bool = True
    default_name: bool = False               # « admin », « root »… (nom prévisible)


@dataclass
class VpnTunnel:
    name: str
    kind: str = "ipsec"                      # ipsec / ssl / pptp / l2tp / openvpn / wireguard
    ike: int | None = None                   # 1 ou 2
    enc: list[str] = field(default_factory=list)
    auth: list[str] = field(default_factory=list)
    dh: list[int] = field(default_factory=list)
    psk: bool | None = None
    peer: str = ""
    enabled: bool = True
    mode: str = ""                           # main / aggressive


@dataclass
class FwConfig:
    vendor: str
    model: str = ""
    hostname: str = ""
    version: str = ""                        # version du système (« 7.2.8 », « 4.7.3 », « 7.15.2 »…)
    serial: str = ""
    source: str = ""                         # fichier ou « API 10.0.0.1 »
    interfaces: list[Interface] = field(default_factory=list)
    zones: dict[str, str] = field(default_factory=dict)          # zone -> rôle
    rules: list[Rule] = field(default_factory=list)
    nat: list[Nat] = field(default_factory=list)
    admins: list[Admin] = field(default_factory=list)
    vpn: list[VpnTunnel] = field(default_factory=list)
    services: dict = field(default_factory=dict)     # paramètres système : admin_ports, admin_https_only, ntp, dns, syslog, snmp, ha, upnp…
    objects_unused: list[str] = field(default_factory=list)
    default_action: str = DENY               # politique implicite en fin de règles
    notes: list[str] = field(default_factory=list)  # avertissements du lecteur (éléments non interprétés)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "FwConfig":
        c = FwConfig(**{k: v for k, v in d.items() if k in FwConfig.__dataclass_fields__ and k not in
                        ("interfaces", "rules", "nat", "admins", "vpn")})
        c.interfaces = [Interface(**x) for x in d.get("interfaces", [])]
        c.rules = [Rule(**x) for x in d.get("rules", [])]
        c.nat = [Nat(**x) for x in d.get("nat", [])]
        c.admins = [Admin(**x) for x in d.get("admins", [])]
        c.vpn = [VpnTunnel(**x) for x in d.get("vpn", [])]
        return c

    def zone_role(self, zone: str) -> str:
        if not zone:
            return ANY
        if zone in self.zones:
            return self.zones[zone]
        for i in self.interfaces:
            if i.name == zone or i.zone == zone:
                return i.role
        return guess_role(zone)


def guess_role(name: str) -> str:
    n = (name or "").lower()
    if n in ("any", "all", "*", ""):
        return ANY
    for role, keys in ((WAN, ("wan", "internet", "outside", "untrust", "ppp", "pppoe", "external", "out", "lte", "4g", "fibre",
                               "fiber", "adsl", "vdsl", "sdwan", "virtual-wan", "isp", "uplink")),
                       (GUEST, ("guest", "invit", "hotspot", "visiteur", "public-wifi")),
                       (IOT, ("iot", "camera", "camera", "cctv", "video", "domotique", "objets", "printer", "imprim")),
                       (DMZ, ("dmz",)), (VPN, ("vpn", "ipsec", "ssl", "tun", "wg", "ovpn", "l2tp", "sslvpn")),
                       (MGMT, ("mgmt", "management", "admin", "oob")),
                       (LAN, ("lan", "internal", "inside", "trust", "local", "bureau", "office", "users", "servers", "serveurs",
                              "vlan", "bridge", "port", "switch", "ether", "eth", "in"))):
        if any(k in n for k in keys):
            return role
    return OTHER


def _adict(a: AddrSet) -> dict:
    return {"iv": [list(x) for x in a.iv], "opaque": sorted(a.opaque), "negate": a.negate}


def _aset(d: dict) -> AddrSet:
    if not d:
        return AddrSet.any()
    return AddrSet([tuple(x) for x in d.get("iv", [])], frozenset(d.get("opaque", [])), bool(d.get("negate")))


def _sset(d: dict) -> SvcSet:
    if not d:
        return SvcSet.any()
    return SvcSet({int(k): [tuple(x) for x in v] for k, v in (d.get("m") or {}).items()}, frozenset(d.get("opaque", [])))


addr_dict = _adict
