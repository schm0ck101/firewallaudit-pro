"""Lecteur WatchGuard Firebox : fichier de configuration XML de Policy Manager
(File › Save › As File) ou sauvegarde XML de Fireware Web UI.

Validé sur un vrai config.xml (Fireware 2026.4, 57 politiques) : politiques
(ordre du fichier ; firewall 1 = autorisée, 2 = refusée, 4 = proxy ; property
32 = politique système), alias enveloppés « X.1.from / X.1.to » et imbriqués,
NAT statique porté par la politique (<nat>), géolocalisation, interfaces
physiques / VLAN / BOVPN, VPN IKE (<ike-policy> + <ike-action>), journaux
distants (syslog, serveur de journaux WatchGuard).
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

    # interfaces (relevé sur Fireware 2026.4) : <interface-list>/<interface> ; property 4 = zones intégrées (Any,
    # Any-External…) ; type par <if-property> (interface physique) ou <vif-property> (VLAN) : 1 Trusted, 2 External,
    # 3 Optional, 7 membre d'agrégat ; item-type 4 = interface virtuelle BOVPN, 5 = SSL-VPN.
    import ipaddress
    il = root.find("interface-list")
    kind_nets: dict[str, AddrSet] = {}           # réseaux par type d'interface (Any-Trusted / Any-Optional)
    for itf in (il.findall("interface") if il is not None else root.iter("interface")):
        name = _t(itf, "name")
        if not name or _t(itf, "property") == "4":
            continue
        ips = []
        for holder in itf.iter():
            ipel = holder.find("ip")
            if ipel is None or holder.tag == "secondary-ip":
                continue
            ip = (ipel.text or "").strip()
            if not ip or ip.startswith("0."):
                continue                       # interface non configurée
            mask = _t(holder, "netmask")
            try:
                ips.append(str(ipaddress.IPv4Interface(f"{ip}/{mask}" if mask else ip)))
            except ValueError:
                continue
        typ = (_t(itf, ".//if-property") or _t(itf, ".//vif-property") or _t(itf, ".//interface-type")).lower()
        itype = _t(itf, ".//item-type")
        named = guess_role(name)
        role = {"external": WAN, "2": WAN, "trusted": LAN, "1": LAN, "optional": "dmz", "3": "dmz"}.get(typ)
        kind = {"trusted": "Any-Trusted", "1": "Any-Trusted", "optional": "Any-Optional", "3": "Any-Optional"}.get(typ)
        if kind and itype not in ("4", "5"):
            for c in ips:
                r0 = parse_addr(str(ipaddress.IPv4Interface(c).network))
                if r0:
                    kind_nets[kind] = kind_nets.get(kind, AddrSet()).union(AddrSet([r0]))
        if itype in ("4", "5"):
            role = "vpn"
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
        if alias == "Firebox":
            return AddrSet(opaque=frozenset(["Firebox"])), ["Firebox"]
        if alias in kind_nets:                 # zone interne : ses réseaux réels (plus précis que « tout »)
            return kind_nets[alias], [alias]
        if alias in ("Any", "Any-External", "Any-Trusted", "Any-Optional") or alias.lower() == "any":
            return AddrSet.any(), [alias] if alias != "Any" else []
        if depth > 8:
            return AddrSet(opaque=frozenset([alias])), []
        if alias in agroups:
            return agroups[alias], []
        if alias in aliases:
            s, zones, zoneless = AddrSet(), [], False
            for addr, itf in aliases[alias]:
                before = len(zones)
                if addr and addr.lower() not in ("any", ""):
                    a2, z2 = resolve(addr, depth + 1)
                    s = s.union(a2)
                    zones += z2 + ([itf] if itf and itf.lower() != "any" and addr != "Firebox" else [])
                elif itf and itf.lower() != "any":
                    zones.append(itf)
                    s = s.union(AddrSet.any())
                else:
                    s = s.union(AddrSet.any())
                zoneless = zoneless or len(zones) == before
            if zones and zoneless:
                zones.append("Any")            # des adresses sans zone (ex. IP publique d'un prestataire) : toutes zones
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
    # NAT statique : <nat-list>/<nat> ; membre addr-name = groupe d'adresses interne (« NOM.1.snat »)
    snat: dict[str, tuple[str, str, str]] = {}
    nl = root.find("nat-list")
    for n in (nl.findall("nat") if nl is not None else []):
        name = _t(n, "name")
        if not name:
            continue
        ints, ports, ext = [], [], ""
        for m in n.iter("member"):
            ext = ext or _t(m, "ext-addr-name") or _t(m, "interface")
            an = _t(m, "addr-name") or _t(m, "real-host")
            if an:
                grp = agroups.get(an)
                ints.append(grp.describe(2) if grp is not None else an)
            if _t(m, "port") not in ("", "0"):
                ports.append(_t(m, "port"))
        snat[name] = (ext if ext not in ("Firebox", "Any-External") else "", ", ".join(ints), ", ".join(ports))
    # géolocalisation : actions autres que l'action système « Global » = restriction des pays autorisés
    geo_restrict = {_t(g, "name") for g in root.iter("geo-action") if _t(g, "name") and _t(g, "name") != "Global"
                    and g.find("geo-list") is not None and len(g.find("geo-list"))}

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
        if _t(p, "property") == "32" or _DEFAULT_RE.match(name):
            r.comment = "prédéfinie"           # politique créée par Fireware
        geo = _t(p, "geo-action")
        if geo in geo_restrict:
            r.apps = [f"géolocalisation : {geo}"]
        frm = [(x.text or "").strip() for x in p.findall("from-alias-list/alias")]
        to = [(x.text or "").strip() for x in p.findall("to-alias-list/alias")]
        sa, sz = AddrSet(), []
        for a in frm or ["Any"]:
            s2, z2 = resolve(a)
            sa, sz = sa.union(s2), sz + z2
        da, dz = AddrSet(), []
        nat_used = []
        pol_nat = _t(p, "nat")
        if pol_nat in snat:
            nat_used.append(pol_nat)
            ext, intip, port = snat[pol_nat]
            r2 = parse_addr(intip)
            da = AddrSet([r2]) if r2 else AddrSet(opaque=frozenset([intip or pol_nat]))
            dz.append("publication (NAT)")
        for a in [] if pol_nat in snat else (to or ["Any"]):
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
        if not nat_used and (any(a == "Firebox" for a in to) or "Firebox" in dz):   # le pare-feu lui-même
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
        if _t(p, "ips-monitor-enabled") == "1":
            r.profiles.append("IPS")
        if _t(p, "app-action") not in ("", "None", "Global"):
            r.profiles.append("contrôle applicatif")
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
                cfg.nat.append(Nat(id=a, name=f"{name} ({a})", ext_ip=ext, ext_ports=", ".join(
                    f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in (r.svc_set.ports(6) or r.svc_set.ports(17))[:6]) or port,
                    proto="tcp" if r.svc_set.ports(6) else "udp", int_ip=intip, int_port=port,
                    src_restrict=([] if sa.is_any else [sa.describe(3)]) + [a.replace("géolocalisation : ", "pays autorisés : ") for a in r.apps],
                    enabled=r.enabled))
        r.raw = ET.tostring(p, encoding="unicode")[:1200]
        cfg.rules.append(r)
    for u in root.iter("user"):
        nm = _t(u, "name")
        if nm and (_t(u, "role") or _t(u, "access-level")):
            cfg.admins.append(Admin(name=nm, profile=_t(u, "role") or _t(u, "access-level"), default_name=nm == "admin"))
    # VPN site à site : <ike-policy-list>/<ike-policy> -> <ike-action> (transformations de phase 1)
    actions = {_t(x, "name"): x for x in root.iter("ike-action")}
    ipl = root.find("ike-policy-list")
    for g in (ipl.findall("ike-policy") if ipl is not None else []):
        if not _t(g, "name") or _t(g, "enabled", "1") == "0":
            continue
        act = actions.get(_t(g, "ike-action"))
        enc, auth, dh = [], [], []
        for m in (act.iter("member") if act is not None else []):
            ea, kl = _t(m, "encryp-algm"), _t(m, "encryp-key-len")
            enc.append(f"AES-{int(kl) * 8}" if ea == "7" and kl.isdigit() else _ENC.get(ea, f"algo {ea}"))
            auth.append(_AUTH.get(_t(m, "auth-algm"), "algo " + _t(m, "auth-algm")))
            if _t(m, "dh-group").isdigit():
                dh.append(int(_t(m, "dh-group")))
        cfg.vpn.append(VpnTunnel(name=_t(g, "name"), kind="ipsec", ike=_ike_version(_t(g, "version")),
                                 enc=enc, auth=auth, dh=dh, peer=_t(g, "peer-addr"),
                                 mode="aggressive" if act is not None and _t(act, "mode") == "1" else "main"))
    if any(True for _ in root.iter("pptp")) and _t(root, ".//pptp/enabled", "0") == "1":
        cfg.vpn.append(VpnTunnel(name="PPTP", kind="pptp"))
    cfg.services = {"snmp_communities": [x.text for x in root.iter("community") if x.text],
                    # collecteur reconnu -> True ; sinon inconnu (Fireware a plusieurs emplacements selon les versions :
                    # syslog, Dimension, WatchGuard Cloud) : on ne conclut pas à l'absence
                    "log_remote": _log_remote(root),
                    "ntp": _t(root, ".//ntp/enabled", "1") != "0"}
    cfg.default_action = DENY
    return cfg


_ENC = {"1": "DES", "2": "3DES", "7": "AES"}
_AUTH = {"1": "MD5", "2": "SHA1", "4": "SHA2-256", "5": "SHA2-384", "6": "SHA2-512"}


def _log_remote(root) -> bool | None:
    """Syslog (log-conf/remote-logging) ou serveur de journaux WatchGuard (common-logging) ; inconnu si absent."""
    sp = root.find("system-parameters")
    if sp is None:
        return None
    sl, cl = _t(sp, "log-conf/remote-logging/enabled"), _t(sp, "common-logging/enabled")
    if "1" in (sl, cl):
        return True
    if sl == "0" and cl == "0":
        return False
    return None


def _ike_version(v: str) -> int | None:
    v = (v or "").lower().replace("ikev", "")
    return 2 if v == "2" else 1 if v == "1" else None


def detect(raw: bytes) -> bool:
    head = raw[:20000]
    return b"<profile" in head and (b"policy-list" in raw[:3_000_000] or b"alias-list" in raw[:3_000_000])

