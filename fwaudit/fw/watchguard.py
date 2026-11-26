"""Lecteur WatchGuard Firebox (Fireware 12.x) : fichier de configuration XML
de Policy Manager (File › Save › As File) ou sauvegarde XML de Fireware Web UI.

Structure lue (tolérante aux variantes de version) : interfaces, alias,
groupes d'adresses, services, politiques (ordre d'évaluation = ordre du
fichier), NAT statique (SNAT) utilisé par les politiques.
Lecteur À VALIDER sur de vraies configurations.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .model import ALLOW, DENY, LAN, WAN, Admin, FwConfig, Interface, Nat, Rule, VpnTunnel, guess_role
from .sets import AddrSet, SvcSet, parse_addr


def _t(el, path: str, default: str = "") -> str:
    x = el.find(path) if el is not None else None
    return (x.text or "").strip() if x is not None and x.text is not None else default


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


# politiques créées par Fireware lui-même (trafic du boîtier, VPN mobiles, paquets non gérés)
_DEFAULT_RE = re.compile(r"^(any from firebox|allow-ike-to-firebox|unhandled (internal|external) packet|watchguard sslvpn|"
                         r"watchguard certificate portal|watchguard authentication|allow-ike|ike-to-firebox)(-\d+)?$", re.I)


def to_model(raw: bytes, source: str = "") -> FwConfig:
    root = _strip_ns(ET.fromstring(raw))
    cfg = FwConfig(vendor="WatchGuard Firebox", source=source)
    cfg.hostname = _t(root, ".//system-parameters/device-conf/system-name") or _t(root, ".//system-name")
    cfg.model = _t(root, ".//base-model") or _t(root, ".//model")
    cfg.version = _t(root, ".//for-version") or _t(root, ".//version")

    # interfaces. Le type (External / Trusted / Optional) se lit de façon fiable dans les alias système
    # Any-External / Any-Trusted / Any-Optional (leurs membres = les interfaces de ce type) ; les codes numériques
    # de <if-property> varient selon les versions, on ne s'y fie que sous forme textuelle.
    import ipaddress
    sys_alias: dict[str, str] = {}
    for a in root.iter("alias"):
        an = _t(a, "name")
        role = {"Any-External": WAN, "Any-Trusted": LAN, "Any-Optional": "dmz"}.get(an)
        if role:
            for m in a.iter("alias-member"):
                itf_name = _t(m, "interface")
                if itf_name and itf_name.lower() != "any":
                    sys_alias[itf_name] = role
    for itf in root.iter("interface"):
        name = _t(itf, "name")
        if not name:
            continue
        ips = []
        for ipel in itf.iter("ip"):
            ip = (ipel.text or "").strip()
            if not ip or ip.startswith("0.") or ip == "0.0.0.0":
                continue                       # interface non configurée
            par = next((x for x in itf.iter() if ipel in list(x)), None)
            mask = _t(par, "netmask") if par is not None else ""
            try:
                ips.append(str(ipaddress.IPv4Interface(f"{ip}/{mask}" if mask else ip)))
            except ValueError:
                continue
        typ = (_t(itf, ".//if-property") or _t(itf, ".//interface-type") or _t(itf, ".//if-type")).lower()
        named = guess_role(name)
        role = sys_alias.get(name)
        if role is None:
            role = WAN if typ == "external" else LAN if typ == "trusted" else "dmz" if typ == "optional" else None
        if role is None:
            pub = False
            for c in ips:
                try:
                    pub = pub or ipaddress.IPv4Interface(c).ip.is_global
                except ValueError:
                    pass
            role = WAN if pub else named
        elif role in (LAN, "dmz") and named in ("guest", "iot", "mgmt", "vpn"):
            role = named                       # « vlan-invite » de type Trusted reste un réseau invités
        en = _t(itf, ".//enabled", "1") != "0"
        cfg.interfaces.append(Interface(name=name, role=role, ips=ips, enabled=en))
    for i in cfg.interfaces:
        cfg.zones[i.name] = i.role
    for z, role in (("Any-External", WAN), ("Any-Trusted", LAN), ("Any-Optional", "dmz"), ("Firebox", "local"),
                    ("Any-BOVPN", "vpn"), ("Any-MUVPN", "vpn"), ("SSL-VPN", "vpn"), ("Any", "any"), ("External", WAN),
                    ("Trusted", LAN), ("Optional", "dmz")):
        cfg.zones.setdefault(z, role)
    cfg.zones["publication (NAT)"] = LAN
    for tag in ("tunnel", "bovpn-tunnel", "gateway", "bovpn-gateway", "ike-policy"):
        for el in root.iter(tag):
            if _t(el, "name"):
                cfg.zones.setdefault(_t(el, "name"), "vpn")

    # groupes d'adresses
    agroups: dict[str, AddrSet] = {}
    for g in root.iter("address-group"):
        name = _t(g, "name")
        s = AddrSet()
        for mbr in g.iter("member"):
            typ = _t(mbr, "type")
            host, net, mask = _t(mbr, "host-ip-addr"), _t(mbr, "ip-network-addr"), _t(mbr, "ip-mask")
            st, en = _t(mbr, "start-ip-addr"), _t(mbr, "end-ip-addr")
            r = parse_addr(host) if host else parse_addr(f"{net} {mask}") if net else parse_addr(f"{st}-{en}") if st else None
            if r:
                s = s.union(AddrSet([r]))
            elif _t(mbr, "domain") or typ:
                s = s.union(AddrSet(opaque=frozenset([_t(mbr, "domain") or f"{name}:{typ}"])))
        agroups[name] = s
    # alias : membres = groupe d'adresses et/ou interface (zone)
    aliases: dict[str, list[tuple[str, str]]] = {}
    for a in root.iter("alias"):
        name = _t(a, "name")
        if not name:
            continue
        mem = []
        for m in a.iter("alias-member"):
            mem.append((_t(m, "address") or _t(m, "alias-name"), _t(m, "interface")))
        aliases[name] = mem

    def resolve(alias: str, depth=0) -> tuple[AddrSet, list[str]]:
        if alias in ("Any", "Any-External", "Any-Trusted", "Any-Optional") or alias.lower() == "any":
            return AddrSet.any(), [alias] if alias != "Any" else []
        if depth > 8:
            return AddrSet(opaque=frozenset([alias])), []
        if alias in agroups:
            return agroups[alias], []
        if alias in aliases:
            s, zones = AddrSet(), []
            for addr, itf in aliases[alias]:
                if addr and addr.lower() not in ("any", ""):
                    a2, z2 = resolve(addr, depth + 1)
                    s = s.union(a2)
                    zones += z2
                elif itf and itf.lower() != "any":
                    zones.append(itf)
                    s = s.union(AddrSet.any())
                else:
                    s = s.union(AddrSet.any())
            return s, zones
        r = parse_addr(alias)
        return (AddrSet([r]) if r else AddrSet(opaque=frozenset([alias]))), []

    services: dict[str, SvcSet] = {}
    for s in root.iter("service"):
        name = _t(s, "name")
        if not name or s.find("service-item") is None and s.find(".//member") is None:
            continue
        ss = SvcSet()
        for m in s.iter("member"):
            proto = _t(m, "protocol")
            port = _t(m, "server-port")
            lo, hi = _t(m, "start-server-port"), _t(m, "end-server-port")
            p = int(proto) if proto.isdigit() else proto or 0
            if port and port.isdigit() and port != "0":
                ss.add(p, int(port), int(port))
            elif lo.isdigit() and hi.isdigit():
                ss.add(p, int(lo), int(hi))
            elif p in (0, "0", ""):
                ss = SvcSet.any()
            else:
                ss.add(p)
        services[name] = ss
    snat: dict[str, tuple[str, str, str]] = {}
    for n in root.iter("nat"):
        name = _t(n, "name")
        ext = _t(n, ".//ext-addr-name") or _t(n, ".//external-ip") or _t(n, ".//addr-name")
        intip = _t(n, ".//real-host") or _t(n, ".//internal-ip") or _t(n, ".//dst-host")
        port = _t(n, ".//port")
        if name:
            snat[name] = (ext, intip, port)

    pos = 0
    for p in root.iter("policy"):
        name = _t(p, "name")
        if not name or p.find("from-alias-list") is None:
            continue
        r = Rule(id=str(pos + 1), position=pos, name=name, enabled=_t(p, "enable", "1") not in ("0", "false"))
        pos += 1
        fw = _t(p, "firewall", "1")
        svc_name = _t(p, "service")
        prox = _t(p, "proxy") or _t(p, "proxy-action")
        proxied = bool(prox) or "proxy" in svc_name.lower()
        if fw.lower() in ("1", "allowed", "allow"):
            r.action = ALLOW
        elif proxied and fw.lower() not in ("denied", "denied (send reset)"):
            r.action = ALLOW                   # politique proxy : le trafic passe, analysé par le proxy
        else:
            r.action = DENY
        if _DEFAULT_RE.match(name):
            r.comment = "prédéfinie"
        frm = [(x.text or "").strip() for x in p.findall("from-alias-list/alias")]
        to = [(x.text or "").strip() for x in p.findall("to-alias-list/alias")]
        sa, sz = AddrSet(), []
        for a in frm or ["Any"]:
            s2, z2 = resolve(a)
            sa, sz = sa.union(s2), sz + z2
        da, dz = AddrSet(), []
        nat_used = []
        for a in to or ["Any"]:
            key = a[:-5] if a.lower().endswith(".snat") and a[:-5] in snat else a
            if key not in snat and a.lower().endswith(".snat"):
                s2, _z = resolve(a)            # alias « .snat » sans objet NAT lisible : publication quand même
                snat[a] = ("", s2.describe(2) if not s2.is_any else "", "")
                key = a
            if key in snat:
                a = key
                nat_used.append(a)
                ext, intip, port = snat[a]
                r2 = parse_addr(intip)
                da = da.union(AddrSet([r2]) if r2 else AddrSet(opaque=frozenset([intip or a])))
                dz.append("publication (NAT)")
                continue
            s2, z2 = resolve(a)
            da, dz = da.union(s2), dz + z2
        r.src_zones, r.dst_zones = sorted(set(sz)), sorted(set(dz))
        if any(a == "Firebox" for a in to):                # le pare-feu lui-même
            r.layer = "input"
            r.dst_zones = ["Firebox"]
            da = AddrSet(opaque=frozenset(["Firebox"]))
        r.set_src(sa)
        r.set_dst(da)
        r.src_names, r.dst_names = frm or ["Any"], to or ["Any"]
        r.svc_names = [svc_name or "Any"]
        r.set_svc(services.get(svc_name, SvcSet.any() if svc_name in ("", "Any") else SvcSet(opaque=frozenset([svc_name]))))
        r.log = _t(p, "log", "0") in ("1", "true")
        r.profiles = [f"proxy:{prox or svc_name}"] if proxied and r.action == ALLOW else []
        for tag, lab in (("ips", "IPS"), ("app-control", "contrôle applicatif"), ("webblocker", "WebBlocker"),
                         ("gateway-av", "antivirus")):
            v = _t(p, f".//{tag}") or _t(p, f".//{tag}-enabled")
            if v and v not in ("0", "false", "None"):
                r.profiles.append(lab)
        sch = _t(p, "schedule")
        r.schedule = "" if sch in ("", "Always On") else sch
        if nat_used and r.action == ALLOW:
            r.nat = True
            for a in nat_used:
                ext, intip, port = snat[a]
                cfg.nat.append(Nat(id=a, name=f"{name} ({a})", ext_ip=ext, ext_ports=port or ", ".join(
                    f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in r.svc_set.ports(6)[:6]), int_ip=intip,
                    src_restrict=[] if sa.is_any else [sa.describe(3)], enabled=r.enabled))
        r.raw = ET.tostring(p, encoding="unicode")[:1200]
        cfg.rules.append(r)
    for u in root.iter("user"):
        nm = _t(u, "name")
        if nm and (_t(u, "role") or _t(u, "access-level")):
            cfg.admins.append(Admin(name=nm, profile=_t(u, "role") or _t(u, "access-level"), default_name=nm == "admin"))
    for g in root.iter("ike-policy"):
        cfg.vpn.append(VpnTunnel(name=_t(g, "name") or "BOVPN", kind="ipsec", ike=_ike_version(_t(g, "version") or _t(g, "ike-version")),
                                 enc=[x.text for x in g.iter("encryption-algorithm") if x.text],
                                 auth=[x.text for x in g.iter("authentication-algorithm") if x.text],
                                 dh=[int(x.text) for x in g.iter("dh-group") if (x.text or "").isdigit()]))
    if any(True for _ in root.iter("pptp")) and _t(root, ".//pptp/enabled", "0") == "1":
        cfg.vpn.append(VpnTunnel(name="PPTP", kind="pptp"))
    cfg.services = {"snmp_communities": [x.text for x in root.iter("community") if x.text],
                    # collecteur reconnu -> True ; sinon inconnu (Fireware a plusieurs emplacements selon les versions :
                    # syslog, Dimension, WatchGuard Cloud) : on ne conclut pas à l'absence
                    "log_remote": True if any(_t(root, f".//{t}") for t in (
                        "syslog-server", "log-server", "syslog-server-ip", "dimension-server", "wsm-log-server")) else None,
                    "ntp": _t(root, ".//ntp/enabled", "1") != "0"}
    cfg.default_action = DENY
    return cfg


def _ike_version(v: str) -> int | None:
    v = (v or "").lower().replace("ikev", "")
    return 2 if v == "2" else 1 if v == "1" else None


def detect(raw: bytes) -> bool:
    head = raw[:20000]
    return b"<profile" in head and (b"policy-list" in raw[:3_000_000] or b"alias-list" in raw[:3_000_000])

