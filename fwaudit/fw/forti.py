"""Lecteur FortiGate (FortiOS 6.x / 7.x) : fichier de sauvegarde texte (.conf)
ou API REST en lecture (jeton API d'un profil en lecture seule).

La syntaxe « config / edit / set / next / end » est lue en arbre générique,
puis traduite vers le modèle normalisé. Multi-VDOM : chaque VDOM est lu,
les règles sont préfixées par le nom du VDOM.
"""
from __future__ import annotations

import re
import shlex

from .model import ALLOW, DENY, LAN, WAN, Admin, FwConfig, Interface, Nat, Rule, VpnTunnel, guess_role
from .sets import AddrSet, SvcSet, parse_addr

# objets prédéfinis (absents de certaines sauvegardes partielles)
BUILTIN_SVC = {"ALL": [("ip", 0, 65535)], "ALL_TCP": [("tcp", 1, 65535)], "ALL_UDP": [("udp", 1, 65535)],
               "ALL_ICMP": [("icmp", 0, 65535)], "PING": [("icmp", 0, 65535)], "HTTP": [("tcp", 80, 80)],
               "HTTPS": [("tcp", 443, 443)], "DNS": [("tcp", 53, 53), ("udp", 53, 53)], "SSH": [("tcp", 22, 22)],
               "TELNET": [("tcp", 23, 23)], "FTP": [("tcp", 21, 21)], "SMTP": [("tcp", 25, 25)], "SMTPS": [("tcp", 465, 465)],
               "RDP": [("tcp", 3389, 3389)], "SMB": [("tcp", 445, 445)], "SAMBA": [("tcp", 139, 139)],
               "NTP": [("udp", 123, 123), ("tcp", 123, 123)], "SNMP": [("udp", 161, 162)], "MS-SQL": [("tcp", 1433, 1434)],
               "MYSQL": [("tcp", 3306, 3306)], "IMAP": [("tcp", 143, 143)], "IMAPS": [("tcp", 993, 993)],
               "POP3": [("tcp", 110, 110)], "POP3S": [("tcp", 995, 995)], "LDAP": [("tcp", 389, 389)], "VNC": [("tcp", 5900, 5900)],
               "SIP": [("udp", 5060, 5060)], "KERBEROS": [("tcp", 88, 88), ("udp", 88, 88)], "NONE": []}


def tokenize(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse_tree(text: str) -> dict:
    """Arbre : {"config system interface": {"wan1": {"ip": [...], ...}}, "config system global": {"hostname": [...]}}."""
    root: dict = {}
    stack: list[tuple[str, dict]] = [("", root)]      # (type, noeud) : type = config | edit
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tok = tokenize(line)
        if not tok:
            continue
        kw = tok[0]
        cur = stack[-1][1]
        if kw == "config":
            key = "config " + " ".join(tok[1:])
            node = cur.setdefault(key, {})
            stack.append(("config", node))
        elif kw == "edit":
            name = " ".join(tok[1:])
            node = cur.setdefault(name, {})
            stack.append(("edit", node))
        elif kw == "next":
            if stack[-1][0] == "edit":
                stack.pop()
        elif kw == "end":
            if stack[-1][0] == "edit":       # « end » sans « next » (rare)
                stack.pop()
            if len(stack) > 1:
                stack.pop()
        elif kw in ("set", "append"):
            if len(tok) >= 2:
                vals = tok[2:]
                if kw == "append" and tok[1] in cur:
                    cur[tok[1]] = cur[tok[1]] + vals
                else:
                    cur[tok[1]] = vals
        elif kw == "unset":
            if len(tok) >= 2:
                cur.pop(tok[1], None)
    return root


def _v(node: dict, key: str, default: str = "") -> str:
    v = node.get(key)
    return " ".join(v) if isinstance(v, list) else (default if v is None else str(v))


def _l(node: dict, key: str) -> list[str]:
    v = node.get(key)
    return v if isinstance(v, list) else ([] if v is None else [str(v)])


def header_info(text: str) -> dict:
    m = re.search(r"#config-version=([A-Z0-9]+)-(\d+\.\d+\.\d+)[^:]*", text)
    out = {}
    if m:
        out["model"], out["version"] = m.group(1), m.group(2)
    b = re.search(r"build(\d+)", text[:500])
    if b:
        out["build"] = b.group(1)
    return out


class _Vdom:
    def __init__(self, tree: dict, glob: dict):
        self.t = tree
        self.g = glob

    def sec(self, name: str) -> dict:
        return self.t.get(name) or self.g.get(name) or {}


def _addr_of(name: str, addrs: dict, groups: dict, depth: int = 0) -> AddrSet:
    if name.lower() in ("all", "any", "0.0.0.0/0"):
        return AddrSet.any()
    if name.lower() == "none":
        return AddrSet()
    if depth > 10:
        return AddrSet(opaque=frozenset([name]))
    if name in groups:
        s = AddrSet()
        for m in _l(groups[name], "member"):
            s = s.union(_addr_of(m, addrs, groups, depth + 1))
        return s
    a = addrs.get(name)
    if a is None:
        r = parse_addr(name)
        return AddrSet([r]) if r else AddrSet(opaque=frozenset([name]))
    typ = _v(a, "type", "ipmask")
    if typ in ("ipmask", "interface-subnet", "") and a.get("subnet"):
        r = parse_addr(" ".join(_l(a, "subnet")[:2]))
        return AddrSet([r]) if r else AddrSet(opaque=frozenset([name]))
    if typ == "iprange":
        r = parse_addr(f"{_v(a, 'start-ip')}-{_v(a, 'end-ip')}")
        return AddrSet([r]) if r else AddrSet(opaque=frozenset([name]))
    return AddrSet(opaque=frozenset([f"{name} ({typ}: {_v(a, 'fqdn') or _v(a, 'country') or ''})".replace(": )", ")")]))


def _svc_of(name: str, svcs: dict, groups: dict, depth: int = 0) -> SvcSet:
    if depth > 10:
        return SvcSet(opaque=frozenset([name]))
    if name in groups:
        s = SvcSet()
        for m in _l(groups[name], "member"):
            s = s.union(_svc_of(m, svcs, groups, depth + 1))
        return s
    d = svcs.get(name)
    s = SvcSet()
    if d is None:
        b = BUILTIN_SVC.get(name.upper())
        if b is None:
            return SvcSet(opaque=frozenset([name]))
        for proto, lo, hi in b:
            s.add(0 if proto == "ip" else proto, lo, hi)
        return s
    proto = _v(d, "protocol", "TCP/UDP/SCTP").upper()
    if proto == "IP":
        pn = _v(d, "protocol-number", "0")
        return SvcSet.any() if pn in ("0", "") else s.add(int(pn))
    if proto in ("ICMP", "ICMP6"):
        return s.add("icmp")
    found = False
    for key, p in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
        for rng in _l(d, key):
            dst = rng.split(":")[0]
            lo, _, hi = dst.partition("-")
            try:
                s.add(p, int(lo), int(hi or lo))
                found = True
            except ValueError:
                pass
    if not found and name.upper() in BUILTIN_SVC:
        for p, lo, hi in BUILTIN_SVC[name.upper()]:
            s.add(0 if p == "ip" else p, lo, hi)
    return s


def to_model(text: str, source: str = "") -> FwConfig:
    tree = parse_tree(text)
    hi = header_info(text)
    glob = tree.get("config global", {}) or tree
    cfg = FwConfig(vendor="Fortinet FortiGate", model=hi.get("model", ""), version=hi.get("version", ""), source=source)
    g = glob.get("config system global", {})
    cfg.hostname = _v(g, "hostname")
    vdoms: list[tuple[str, dict]] = []
    if "config vdom" in tree:
        for name, node in tree["config vdom"].items():
            if any(k.startswith("config firewall") for k in node):
                vdoms.append((name, node))
    if not vdoms:
        vdoms = [("", tree)]
    multi = len(vdoms) > 1

    # ------------------------------------------------------------ interfaces
    ifaces = glob.get("config system interface", {}) or tree.get("config system interface", {})
    zone_of = {}
    for _vn, vt in vdoms:
        for zname, z in (vt.get("config system zone") or {}).items():
            for m in _l(z, "interface"):
                zone_of[m] = zname
        sdw = vt.get("config system sdwan") or glob.get("config system sdwan") or {}
        for _mid, m in ((sdw.get("config members") if isinstance(sdw, dict) else None) or {}).items():
            if isinstance(m, dict) and _v(m, "interface") and _v(m, "zone"):
                zone_of[_v(m, "interface")] = _v(m, "zone")
    for name, d in ifaces.items():
        role = _v(d, "role") or ""
        role = {"wan": WAN, "lan": LAN, "dmz": "dmz", "undefined": ""}.get(role, "") or guess_role(name + " " + _v(d, "alias"))
        named_role = guess_role(name + " " + _v(d, "alias"))
        if role == LAN and named_role in ("guest", "iot", "mgmt"):
            role = named_role                              # « lan » côté FortiGate mais réseau invités / objets d'après son nom
        ip = _l(d, "ip")
        cidr = []
        if len(ip) >= 2:
            r = parse_addr(" ".join(ip[:2]))
            if r:
                import ipaddress
                cidr.append(f"{ip[0]}/{ipaddress.IPv4Network(f'0.0.0.0/{ip[1]}').prefixlen}")
        if _v(d, "mode") in ("dhcp", "pppoe") and role != LAN:
            role = WAN if role in ("", "other") else role
        cfg.interfaces.append(Interface(name=name, role=role, zone=zone_of.get(name, ""), ips=cidr,
                                        admin=[x.lower() for x in _l(d, "allowaccess")],
                                        vlan=int(_v(d, "vlanid")) if _v(d, "vlanid").isdigit() else None,
                                        enabled=_v(d, "status", "up") != "down", description=_v(d, "alias") or _v(d, "description")))
    for zname, iname in {z: i for i, z in zone_of.items()}.items():
        cfg.zones[zname] = next((i.role for i in cfg.interfaces if i.name == iname), guess_role(zname))
    for i in cfg.interfaces:
        cfg.zones.setdefault(i.name, i.role)

    # ------------------------------------------------------------- règles
    pos = 0
    for vname, vt in vdoms:
        V = _Vdom(vt, glob)
        addrs = dict(V.sec("config firewall address"))
        agrp = dict(V.sec("config firewall addrgrp"))
        svcs = dict(V.sec("config firewall service custom"))
        sgrp = dict(V.sec("config firewall service group"))
        used = set()
        for pid, p in V.sec("config firewall policy").items():
            r = Rule(id=f"{vname}:{pid}" if multi else str(pid), position=pos, name=_v(p, "name"))
            pos += 1
            r.enabled = _v(p, "status", "enable") != "disable"
            act = _v(p, "action", "deny")
            r.action = ALLOW if act in ("accept", "ipsec") else DENY
            r.src_zones = _l(p, "srcintf")
            r.dst_zones = _l(p, "dstintf")
            if "any" in r.src_zones:
                r.src_zones = []
            if "any" in r.dst_zones:
                r.dst_zones = []
            r.src_names, r.dst_names, r.svc_names = _l(p, "srcaddr"), _l(p, "dstaddr"), _l(p, "service") or ["ALL"]
            used.update(r.src_names + r.dst_names + r.svc_names)
            sa = AddrSet()
            for n in r.src_names:
                sa = sa.union(_addr_of(n, addrs, agrp))
            # destination = objet VIP : la règle publie un service interne -> adresse réelle (mappedip)
            vips = V.sec("config firewall vip")
            vgrps = V.sec("config firewall vipgrp")
            da = AddrSet()
            for n in r.dst_names:
                members = _l(vgrps[n], "member") if n in vgrps else [n]
                for mname in members:
                    if mname in vips:
                        r.nat = True
                        da = da.union(AddrSet.parse([x for x in _l(vips[mname], "mappedip")]) or AddrSet(opaque=frozenset([mname])))
                    else:
                        da = da.union(_addr_of(mname, addrs, agrp))
            if _v(p, "srcaddr-negate") == "enable":
                sa.negate = True
            if _v(p, "dstaddr-negate") == "enable":
                da.negate = True
            isdb_dst = _l(p, "internet-service-name") + _l(p, "internet-service-group") + _l(p, "internet-service-custom")
            if _v(p, "internet-service") == "enable" and not da.iv and not da.opaque:
                da = AddrSet(opaque=frozenset(isdb_dst or ["Internet Service"]))
            isdb_src = _l(p, "internet-service-src-name") + _l(p, "internet-service-src-group") + _l(p, "internet-service-src-custom")
            if _v(p, "internet-service-src") == "enable" and not sa.iv and not sa.opaque:
                sa = AddrSet(opaque=frozenset(isdb_src or ["Internet Service"]))
            r.set_src(sa)
            r.set_dst(da)
            sv = SvcSet()
            for n in r.svc_names:
                sv = sv.union(_svc_of(n, svcs, sgrp))
            if _v(p, "service-negate") == "enable":
                sv = SvcSet(opaque=frozenset(["tout sauf " + ", ".join(r.svc_names)]))
            r.set_svc(sv)
            r.users = _l(p, "users") + _l(p, "groups")
            r.apps = _l(p, "application") + _l(p, "internet-service-name") + _l(p, "internet-service-src-name")
            if _v(p, "internet-service") == "enable" or _v(p, "internet-service-src") == "enable":
                r.apps = r.apps or ["Internet Service"]
            sch = _v(p, "schedule", "always")
            r.schedule = "" if sch == "always" else sch
            lt = _v(p, "logtraffic", "utm")
            r.log = lt in ("all", "utm") if r.action == ALLOW else lt != "disable"
            r.profiles = [f"{k}:{_v(p, k)}" for k in ("av-profile", "ips-sensor", "webfilter-profile", "application-list",
                                                     "dnsfilter-profile", "file-filter-profile", "ssl-ssh-profile") if _v(p, k)]
            if _v(p, "profile-group"):
                r.profiles.append(f"group:{_v(p, 'profile-group')}")
            r.comment = _v(p, "comments")
            r.raw = _raw_block(text, "config firewall policy", pid)
            cfg.rules.append(r)
        # local-in : accès au pare-feu lui-même
        for pid, p in V.sec("config firewall local-in-policy").items():
            r = Rule(id=f"local-in {pid}", position=pos, name=f"local-in {pid}", layer="input")
            pos += 1
            r.action = ALLOW if _v(p, "action", "deny") == "accept" else DENY
            r.src_zones = [x for x in _l(p, "intf") if x != "any"]
            sa = AddrSet()
            for n in _l(p, "srcaddr"):
                sa = sa.union(_addr_of(n, addrs, agrp))
            if _v(p, "srcaddr-negate") == "enable":
                sa.negate = True                 # « tout sauf ces adresses » : typiquement un refus sauf prestataire
            r.set_src(sa)
            r.src_names = _l(p, "srcaddr")
            r.set_dst(AddrSet(opaque=frozenset(["le pare-feu"])))
            r.dst_names = _l(p, "dstaddr") or ["le pare-feu"]
            r.comment = _v(p, "comments")
            sv = SvcSet()
            for n in _l(p, "service") or ["ALL"]:
                sv = sv.union(_svc_of(n, svcs, sgrp))
            r.set_svc(sv)
            r.enabled = _v(p, "status", "enable") != "disable"
            cfg.rules.append(r)
        # ------------------------------------------------------------ VIP (interfaces inutilisées retirées plus bas)
        for vid, v in V.sec("config firewall vip").items():
            ext = _v(v, "extip")
            mapped = _l(v, "mappedip")
            n = Nat(id=vid, name=vid, ext_ip=ext.split("-")[0] if ext not in ("0.0.0.0", "") else "",
                    ext_ports=_v(v, "extport") if _v(v, "portforward") == "enable" else "",
                    proto=_v(v, "protocol", "tcp"), int_ip=mapped[0].split("-")[0] if mapped else "",
                    int_port=_v(v, "mappedport"), interface=_v(v, "extintf"),
                    src_restrict=_l(v, "src-filter"), enabled=_v(v, "status", "enable") != "disable")
            # une VIP n'est réellement exposée que si une règle autorise son trafic
            n.raw = _raw_block(text, "config firewall vip", vid)
            cfg.nat.append(n)
            used.add(vid)
        for name in list(addrs) + list(agrp):
            if name not in used and name not in ("all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE",
                                                 "SSLVPN_TUNNEL_ADDR1", "login.microsoftonline.com", "login.microsoft.com",
                                                 "login.windows.net", "gmail.com", "wildcard.google.com", "wildcard.dropbox.com"):
                cfg.objects_unused.append(name)

    # ------------------------------------------------------------- admins
    for name, a in (glob.get("config system admin") or {}).items():
        trusted = []
        for k in [f"trusthost{i}" for i in range(1, 11)]:
            t = " ".join(_l(a, k)[:2])
            if t and t not in ("0.0.0.0 0.0.0.0",):
                trusted.append(t)
        mfa = _v(a, "two-factor", "disable") != "disable" or bool(_v(a, "remote-auth") == "enable")
        cfg.admins.append(Admin(name=name, profile=_v(a, "accprofile"), trusted=trusted, mfa=mfa,
                                default_name=name.lower() in ("admin", "administrator", "root", "fortinet")))

    # --------------------------------------------------------------- VPN
    for _vn, vt in vdoms:
        V = _Vdom(vt, glob)
        for name, p in {**V.sec("config vpn ipsec phase1-interface"), **V.sec("config vpn ipsec phase1")}.items():
            props = _l(p, "proposal")
            enc = sorted({x.split("-")[0] for x in props})
            auth = sorted({x.split("-")[1] for x in props if "-" in x})
            cfg.vpn.append(VpnTunnel(name=name, kind="ipsec", ike=int(_v(p, "ike-version", "1")), enc=enc, auth=auth,
                                     dh=[int(x) for x in _l(p, "dhgrp") if x.isdigit()] or [14, 5],
                                     psk=_v(p, "authmethod", "psk") == "psk", peer=_v(p, "remote-gw"),
                                     mode=_v(p, "mode", "main")))
        ssl = V.sec("config vpn ssl settings")
        if ssl and (_l(ssl, "source-interface") or _v(ssl, "status") == "enable") and _v(ssl, "status") != "disable":
            cfg.vpn.append(VpnTunnel(name="SSL-VPN", kind="ssl", peer=f"port {_v(ssl, 'port', '443')}",
                                     enc=[_v(ssl, "ssl-min-proto-ver", "tls1-2")]))
    pptp = glob.get("config vpn pptp") or {}
    if _v(pptp, "status") == "enable":
        cfg.vpn.append(VpnTunnel(name="PPTP", kind="pptp"))

    # ------------------------------------------------------------- système
    snmp = [_v(c, "name") for c in (glob.get("config system snmp community") or {}).values()]
    snmpv3 = list((glob.get("config system snmp user") or {}).keys())
    log_remote = any(_v(glob.get(k) or {}, "status") == "enable" for k in
                     ("config log syslogd setting", "config log fortianalyzer setting", "config log fortiguard setting",
                      "config log syslogd2 setting", "config log fortianalyzer-cloud setting"))
    ntp = glob.get("config system ntp") or {}
    ha = glob.get("config system ha") or {}
    cfg.services = {
        "admin_https_port": _v(g, "admin-sport", "443"), "admin_ssh_port": _v(g, "admin-ssh-port", "22"),
        "admin_telnet": _v(g, "admin-telnet", "") == "enable",
        "admin_https_redirect": _v(g, "admin-https-redirect", "enable") == "enable",
        "admin_timeout_min": int(_v(g, "admintimeout", "5") or 5),
        "admin_lockout": _v(g, "admin-lockout-threshold", "3"),
        "strong_crypto": _v(g, "strong-crypto", "enable") == "enable",
        "snmp_communities": snmp, "snmp_v3_users": snmpv3,
        "log_remote": log_remote, "ntp": _v(ntp, "ntpsync", "enable") == "enable",
        "ha": _v(ha, "mode", "standalone"), "upnp": None,
        "admin_maintainer": _v(g, "admin-maintainer", "enable") == "enable",
        "admin_lockout_duration": _v(g, "admin-lockout-duration", "60"),
    }
    # interfaces sans adresse ni usage (ports physiques d'un switch, naf.root, l2t.root…) : retirées de la fiche
    used_itf = {z for r in cfg.rules for z in r.src_zones + r.dst_zones}
    used_itf |= {_v(d, "interface") for d in ifaces.values() if isinstance(d, dict)}
    cfg.interfaces = [i for i in cfg.interfaces if i.ips or i.role in (WAN, "vpn") or i.name in used_itf
                      or (i.zone and i.zone in used_itf)]
    return cfg


def _raw_block(text: str, section: str, edit: str, limit: int = 1200) -> str:
    i = text.find(section)
    if i < 0:
        return ""
    m = re.search(r"^\s*edit " + re.escape(f'"{edit}"' if not str(edit).isdigit() else str(edit)) + r"\s*$", text[i:], re.M)
    if not m:
        m = re.search(r"^\s*edit " + re.escape(str(edit)) + r"\s*$", text[i:], re.M)
    if not m:
        return ""
    j = i + m.start()
    k = text.find("next", j)
    return text[j:k + 4 if k > 0 else j + limit][:limit]


def detect(text: str) -> bool:
    return "#config-version=FG" in text[:300] or ("config firewall policy" in text and "config system interface" in text)
