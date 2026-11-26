"""Contexte des règles d'analyse : configuration normalisée, résultats des
tests réels, aides (rôles de zones, couverture de règles, ports sensibles)."""
from __future__ import annotations

from ..fw.model import ANY, DMZ, GUEST, IOT, LAN, LOCAL, MGMT, VPN, WAN, FwConfig, Rule
from .model import NOT_CHECKED, OK, Finding

# ports sensibles : (port, proto, libellé, gravité si exposé à Internet sans restriction)
SENSITIVE = {
    3389: ("Bureau à distance (RDP)", 4), 445: ("Partage Windows (SMB)", 4), 139: ("NetBIOS / SMB", 4),
    135: ("RPC Microsoft", 4), 23: ("Telnet", 4), 21: ("FTP", 3), 22: ("SSH", 3), 5900: ("VNC", 4),
    1433: ("SQL Server", 4), 3306: ("MySQL / MariaDB", 4), 5432: ("PostgreSQL", 4), 1521: ("Oracle", 4),
    27017: ("MongoDB", 4), 6379: ("Redis", 4), 9200: ("Elasticsearch", 4), 11211: ("Memcached", 4),
    5985: ("WinRM", 4), 5986: ("WinRM (HTTPS)", 3), 2375: ("API Docker", 4), 161: ("SNMP", 3), 623: ("IPMI", 4),
    389: ("LDAP", 4), 636: ("LDAPS", 3), 88: ("Kerberos", 4), 53: ("DNS", 2), 8291: ("Winbox MikroTik", 4),
    8728: ("API MikroTik", 4), 10000: ("Webmin", 3), 5000: ("port 5000 (interface NAS ou web)", 3), 5001: ("port 5001 (interface NAS ou web)", 3),
    8006: ("Proxmox", 3), 9100: ("Impression RAW", 3), 502: ("Modbus", 4), 47808: ("BACnet", 4), 1883: ("MQTT", 3),
    25: ("SMTP", 2), 110: ("POP3", 2), 143: ("IMAP", 2), 80: ("HTTP", 1), 8080: ("HTTP", 1), 8443: ("HTTPS (admin ?)", 1),
}
INTERNAL_ROLES = (LAN, DMZ, GUEST, IOT, MGMT, VPN)
UTM_VENDORS = ("Fortinet", "Sophos", "WatchGuard", "Stormshield")


class Ctx:
    def __init__(self, snap: dict, prev: dict | None = None):
        self.snap = snap
        self.prev = prev
        self.cfg: FwConfig = FwConfig.from_dict(snap.get("config") or {"vendor": "?"})
        raw = (snap.get("meta") or {}).get("raw_api")
        if raw and self.cfg.vendor.startswith("UniFi"):
            # données brutes conservées : la ré-analyse profite des corrections du lecteur
            from ..fw import unifi
            try:
                src = self.cfg.source
                self.cfg = unifi.to_model(raw, src)
            except Exception:
                pass
        self.meta: dict = snap.get("meta") or {}
        self.tests: dict = snap.get("tests") or {}
        self.findings: list[Finding] = []
        self.active = [r for r in self.cfg.rules if r.enabled]

    def add(self, fid, domain, sev, title, detail="", impact="", fix="", evidence=None, predictive=False):
        self.findings.append(Finding(fid, domain, sev, title, detail, impact, fix, [str(e) for e in (evidence or [])][:40], predictive))

    def ok(self, fid, domain, title, detail=""):
        self.findings.append(Finding(fid, domain, OK, title, detail))

    def nc(self, fid, domain, title, why):
        self.findings.append(Finding(fid, domain, NOT_CHECKED, title, why))

    # ----------------------------------------------------------------- zones
    def roles(self, zones: list[str]) -> set[str]:
        if not zones:
            return {ANY}
        return {self.cfg.zone_role(z) for z in zones}

    def from_wan(self, r: Rule) -> bool:
        ro = self.roles(r.src_zones)
        return WAN in ro or (ANY in ro and r.src_set.is_public())

    def to_internal(self, r: Rule) -> bool:
        ro = self.roles(r.dst_zones)
        return bool(ro & set(INTERNAL_ROLES)) or (ANY in ro) or r.nat

    def to_firewall(self, r: Rule) -> bool:
        return r.layer in ("input", "local-in") or LOCAL in self.roles(r.dst_zones)

    @staticmethod
    def is_return(r: Rule) -> bool:
        """Règle qui ne laisse passer que le RETOUR de connexions déjà établies (pas une ouverture)."""
        return any(a.startswith("état retour") or (a.startswith("état ") and "new" not in a and
                                                  ("established" in a or "related" in a)) for a in r.apps)

    @staticmethod
    def is_default(r: Rule) -> bool:
        """Règle prédéfinie par le constructeur (politique par défaut d'une paire de zones, portail invités…)."""
        return r.comment == "prédéfinie"

    def nets_by_role(self, roles: tuple) -> list[tuple[str, str, "AddrSet"]]:
        from ..fw.sets import AddrSet
        out = []
        for i in self.cfg.interfaces:
            if i.role in roles and i.ips:
                a = AddrSet.parse(i.ips)
                if a.iv:
                    out.append((i.name, i.role, a))
        return out

    def is_final_drop(self, r: Rule) -> bool:
        """Blocage de tout ce qui vient du WAN (ou de tout ce qui n'est pas interne : « !LAN »), les seules
        conditions tolérées étant l'état de connexion (configuration par défaut RouterOS)."""
        if r.action != "deny" or not r.src_set.is_any or not r.svc_set.is_any or r.users or r.schedule:
            return False
        if any(not (a.startswith("état") or a.startswith("NAT")) for a in r.apps):
            return False
        return all(str(z).startswith("!") or self.cfg.zone_role(z) == WAN for z in r.src_zones)

    def has_final_drop(self, layer: str) -> bool:
        return any(self.is_final_drop(r) for r in self.active if r.layer == layer)

    @property
    def is_windows(self) -> bool:
        return self.cfg.vendor.startswith("Pare-feu Windows")

    @property
    def is_utm(self) -> bool:
        return any(v in self.cfg.vendor for v in UTM_VENDORS)

    def rlabel(self, r: Rule) -> str:
        z = ""
        if r.src_zones or r.dst_zones:
            z = f" [{', '.join(r.src_zones) or 'toutes'} → {', '.join(r.dst_zones) or 'toutes'}]"
        return f"{r.label()}{z}"

    def describe(self, r: Rule) -> str:
        return (f"{self.rlabel(r)} : {'AUTORISE' if r.action == 'allow' else 'BLOQUE'} de {r.src_set.describe(3)} vers "
                f"{r.dst_set.describe(3)}, {r.svc_set.describe(4)}"
                + "".join(f" ({a})" for a in r.apps if a.startswith("géolocalisation")))


def zones_cover(big: list[str], small: list[str]) -> bool:
    if not big:
        return True
    if not small:
        return False
    return set(small) <= set(big)


def covers(a: Rule, b: Rule) -> bool:
    """La règle a (placée avant) englobe-t-elle entièrement la règle b ?"""
    if a.layer != b.layer or (a.chain or "") != (b.chain or ""):
        return False
    if a.extra_conditions and (a.users != b.users or a.apps != b.apps or a.schedule != b.schedule):
        return False
    return (zones_cover(a.src_zones, b.src_zones) and zones_cover(a.dst_zones, b.dst_zones)
            and a.src_set.covers(b.src_set) and a.dst_set.covers(b.dst_set) and a.svc_set.covers(b.svc_set))


_ = (LAN, LOCAL, NOT_CHECKED)
