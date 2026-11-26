"""Lecteur MikroTik RouterOS (v6 / v7) : sortie de « /export » (fichier .rsc
ou lecture SSH en lecture seule).

Attention à la sémantique RouterOS : une chaîne SANS règle « drop » finale
ACCEPTE tout (action par défaut = accept). Les règles « input » protègent
le routeur lui-même, « forward » le trafic qui le traverse.
"""
from __future__ import annotations

import re
import shlex

from .model import ALLOW, DENY, LAN, WAN, FwConfig, Interface, Nat, Rule, VpnTunnel, guess_role
from .sets import AddrSet, SvcSet, parse_addr

SERVICE_PORTS = {"telnet": 23, "ftp": 21, "www": 80, "ssh": 22, "www-ssl": 443, "api": 8728, "winbox": 8291, "api-ssl": 8729}
# services actifs par défaut sur RouterOS (si l'export ne dit rien)
SERVICE_DEFAULT_ON = {"telnet": True, "ftp": True, "www": True, "ssh": True, "www-ssl": False, "api": True, "winbox": True,
                      "api-ssl": True}
PORT_NAMES = {"http": 80, "https": 443, "ssh": 22, "telnet": 23, "ftp": 21, "smtp": 25, "dns": 53, "winbox": 8291,
              "rdp": 3389, "smb": 445, "ntp": 123, "snmp": 161}


def _join_lines(text: str) -> list[str]:
    out, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        buf += line.strip()
        if buf:
            out.append(buf)
        buf = ""
    return out


def _kv(line: str) -> tuple[str, dict]:
    """« add action=drop chain=input comment="x y" » -> ("add", {...})."""
    line = re.sub(r"\[\s*find[^\]]*\]", "", line)
    try:
        tok = shlex.split(line, posix=True)
    except ValueError:
        tok = line.split()
    verb = tok[0] if tok else ""
    d = {}
    target = ""
    for t in tok[1:]:
        if "=" in t:
            k, _, v = t.partition("=")
            d[k] = v
        elif not target:
            target = t
    if target:
        d["_target"] = target
    return verb, d


def parse_sections(text: str) -> dict[str, list[tuple[str, dict]]]:
    secs: dict[str, list] = {}
    cur = ""
    for line in _join_lines(text):
        if line.startswith("#"):
            continue
        if line.startswith("/"):
            # « /ip firewall filter » seul, ou « /ip service set telnet disabled=yes » sur une ligne
            tok = line.split()
            k = next((i for i, t in enumerate(tok) if t in ("add", "set", "remove", "print", "export", "enable", "disable")), len(tok))
            cur = " ".join(tok[:k])
            if k < len(tok):
                secs.setdefault(cur, []).append(_kv(" ".join(tok[k:])))
            continue
        if cur:
            secs.setdefault(cur, []).append(_kv(line))
    return secs


def _ports(spec: str, proto: str) -> SvcSet:
    s = SvcSet()
    neg = spec.startswith("!")
    spec = spec.lstrip("!")
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            lo_i = int(lo) if lo.isdigit() else PORT_NAMES[lo]
            hi_i = int(hi) if hi else lo_i
            s.add(proto or "tcp", lo_i, hi_i)
            if not proto:
                s.add("udp", lo_i, hi_i)
        except (KeyError, ValueError):
            s.opaque = s.opaque | {part}
    if neg:
        return SvcSet(opaque=frozenset([f"!{spec}"]))
    return s


def to_model(text: str, source: str = "") -> FwConfig:
    secs = parse_sections(text)
    cfg = FwConfig(vendor="MikroTik RouterOS", source=source, default_action=ALLOW)
    m = re.search(r"by RouterOS ([\d.]+\w*)", text)
    cfg.version = m.group(1) if m else ""
    m = re.search(r"#\s*model\s*=\s*(\S+)", text)
    cfg.model = m.group(1) if m else ""
    m = re.search(r"#\s*serial number\s*=\s*(\S+)", text)
    cfg.serial = m.group(1) if m else ""
    for _v, d in secs.get("/system", []):
        pass
    for _v, d in secs.get("/system identity", []):
        cfg.hostname = d.get("name", cfg.hostname)

    # --------------------------------------------------- interfaces / listes
    lists: dict[str, list[str]] = {}
    for _v, d in secs.get("/interface list member", []):
        lists.setdefault(d.get("list", ""), []).append(d.get("interface", ""))
    list_role = {}
    for name in lists:
        list_role[name] = guess_role(name)
    if_role = {}
    for lname, members in lists.items():
        for mbr in members:
            if list_role.get(lname) in (WAN, LAN) or mbr not in if_role:
                if_role[mbr] = list_role.get(lname, "other")
    addrs: dict[str, list[str]] = {}
    for _v, d in secs.get("/ip address", []):
        addrs.setdefault(d.get("interface", ""), []).append(d.get("address", ""))
    dhcp_client = {d.get("interface") for _v, d in secs.get("/ip dhcp-client", [])}
    pppoe = {d.get("name") for _v, d in secs.get("/interface pppoe-client", [])}
    names = set(addrs) | set(if_role) | dhcp_client | pppoe
    for _v, d in secs.get("/interface vlan", []):
        names.add(d.get("name", ""))
    for n in sorted(x for x in names if x):
        role = if_role.get(n) or (WAN if n in dhcp_client or n in pppoe else guess_role(n))
        vid = next((int(d.get("vlan-id")) for _v, d in secs.get("/interface vlan", []) if d.get("name") == n and
                    str(d.get("vlan-id", "")).isdigit()), None)
        cfg.interfaces.append(Interface(name=n, role=role, ips=addrs.get(n, []), vlan=vid))
    for lname, role in list_role.items():
        cfg.zones[lname] = role
    for i in cfg.interfaces:
        cfg.zones[i.name] = i.role

    # ------------------------------------------------------- listes d'adresses
    alist: dict[str, AddrSet] = {}
    for _v, d in secs.get("/ip firewall address-list", []):
        if d.get("disabled") == "yes":
            continue
        a = d.get("address", "")
        r = parse_addr(a)
        cur = alist.get(d.get("list", ""), AddrSet())
        alist[d.get("list", "")] = cur.union(AddrSet([r]) if r else AddrSet(opaque=frozenset([a])))

    def aset(d: dict, which: str) -> tuple[AddrSet, list[str]]:
        s = AddrSet.any()
        label = []
        if d.get(f"{which}-address"):
            v = d[f"{which}-address"]
            neg = v.startswith("!")
            r = parse_addr(v.lstrip("!"))
            s = AddrSet([r]) if r else AddrSet(opaque=frozenset([v]))
            s.negate = neg
            label.append(v)
        if d.get(f"{which}-address-list"):
            v = d[f"{which}-address-list"]
            neg = v.startswith("!")
            base = alist.get(v.lstrip("!"), AddrSet(opaque=frozenset([v.lstrip("!")])))
            s2 = AddrSet(base.iv, base.opaque, neg)
            s = s2 if s.is_any else s
            label.append(f"liste {v}")
        return s, label

    def zones(d: dict, which: str) -> list[str]:
        z = []
        if d.get(f"{which}-interface"):
            z.append(d[f"{which}-interface"])
        if d.get(f"{which}-interface-list"):
            z.append(d[f"{which}-interface-list"])
        return z

    # -------------------------------------------------------------- filtre
    pos = 0
    has_jump = False
    for idx, (verb, d) in enumerate(secs.get("/ip firewall filter", [])):
        if verb != "add":
            continue
        chain = d.get("chain", "")
        action = d.get("action", "accept")
        if action in ("jump", "return", "passthrough", "log", "add-src-to-address-list", "add-dst-to-address-list"):
            has_jump = has_jump or action == "jump"
            if action != "log":
                cfg.notes.append(f"Règle {idx} ({chain}) : action « {action} » non simulée")
            continue
        if action == "fasttrack-connection":
            action = "accept"
        r = Rule(id=str(idx), position=pos, name=d.get("comment", ""), chain=chain,
                 layer="input" if chain == "input" else "filter" if chain == "forward" else chain)
        pos += 1
        r.enabled = d.get("disabled") != "yes"
        r.action = ALLOW if action == "accept" else DENY
        r.src_zones = zones(d, "in")
        r.dst_zones = zones(d, "out")
        sa, sl = aset(d, "src")
        da, dl = aset(d, "dst")
        r.set_src(sa)
        r.set_dst(da)
        r.src_names, r.dst_names = sl or ["any"], dl or ["any"]
        proto = d.get("protocol", "")
        if d.get("dst-port"):
            sv = _ports(d["dst-port"], proto)
            r.svc_names = [f"{proto or 'tcp/udp'}/{d['dst-port']}"]
        elif proto:
            sv = SvcSet().add(proto.lstrip("!")) if not proto.startswith("!") else SvcSet(opaque=frozenset([proto]))
            r.svc_names = [proto]
        else:
            sv = SvcSet.any()
            r.svc_names = ["tout"]
        r.set_svc(sv)
        cs = d.get("connection-state", "")
        extra = []
        if cs:
            extra.append(f"état {cs}")
        if d.get("connection-nat-state"):
            extra.append(f"NAT {d['connection-nat-state']}")
        for k in ("src-mac-address", "layer7-protocol", "content", "tls-host", "connection-mark", "packet-mark",
                  "connection-limit", "limit", "dst-limit", "src-address-type", "dst-address-type", "ipsec-policy", "time",
                  "icmp-options", "tcp-flags", "connection-type", "psd"):
            if d.get(k):
                extra.append(f"{k}={d[k]}")
        r.apps = extra
        r.log = d.get("log") == "yes"
        r.comment = d.get("comment", "")
        r.raw = "add " + " ".join(f"{k}={v}" for k, v in d.items() if not k.startswith("_"))
        cfg.rules.append(r)
    if has_jump:
        cfg.notes.append("Chaînes personnalisées (jump) présentes : leur effet n'est pas simulé, vérifier manuellement.")

    # ---------------------------------------------------------------- NAT
    for idx, (verb, d) in enumerate(secs.get("/ip firewall nat", [])):
        if verb != "add" or d.get("action") not in ("dst-nat", "netmap") or d.get("chain") != "dstnat":
            continue
        cfg.nat.append(Nat(id=str(idx), name=d.get("comment", ""), enabled=d.get("disabled") != "yes",
                           ext_ip=d.get("dst-address", "").lstrip("!"), ext_ports=d.get("dst-port", ""),
                           proto=d.get("protocol", "tcp"), int_ip=d.get("to-addresses", ""), int_port=d.get("to-ports", ""),
                           src_restrict=[x for x in (d.get("src-address"), d.get("src-address-list")) if x],
                           interface=d.get("in-interface") or d.get("in-interface-list", ""),
                           raw="add " + " ".join(f"{k}={v}" for k, v in d.items() if not k.startswith("_"))))

    # ----------------------------------------------------------- services
    svc_state = dict(SERVICE_DEFAULT_ON)
    svc_addr: dict[str, str] = {}
    svc_port: dict[str, int] = {}
    for _v, d in secs.get("/ip service", []):
        name = d.get("_target", "")
        if name in svc_state:
            if "disabled" in d:
                svc_state[name] = d["disabled"] != "yes"
            if d.get("address"):
                svc_addr[name] = d["address"]
            if str(d.get("port", "")).isdigit():
                svc_port[name] = int(d["port"])
    admin = [f"{n}:{svc_port.get(n, SERVICE_PORTS[n])}" + (f" (limité à {svc_addr[n]})" if n in svc_addr else "")
             for n, on in svc_state.items() if on]
    for i in cfg.interfaces:
        i.admin = [n for n, on in svc_state.items() if on and n not in svc_addr]
    snmp_on = any(d.get("enabled") == "yes" for _v, d in secs.get("/snmp", []))
    comms = [d.get("name", "public") for _v, d in secs.get("/snmp community", [])] or (["public"] if snmp_on else [])
    upnp = any(d.get("enabled") == "yes" for _v, d in secs.get("/ip upnp", []))
    dns_remote = any(d.get("allow-remote-requests") == "yes" for _v, d in secs.get("/ip dns", []))
    cfg.services = {"mikrotik_services": admin, "mikrotik_services_state": svc_state, "mikrotik_services_addr": svc_addr,
                    "snmp_communities": comms if snmp_on else [], "upnp": upnp, "dns_open_resolver": dns_remote,
                    "ntp": any(d.get("enabled") == "yes" for _v, d in secs.get("/system ntp client", [])),
                    "log_remote": any(d.get("target") == "remote" for _v, d in secs.get("/system logging action", [])),
                    "mac_server": not any("allowed-interface-list" in d for _v, d in secs.get("/tool mac-server", [])),
                    "neighbor_discovery_all": not any(d.get("discover-interface-list") not in (None, "all")
                                                      for _v, d in secs.get("/ip neighbor discovery-settings", []))}

    # ---------------------------------------------------------------- VPN
    prof = {d.get("name", "default") if d.get("name") else "default": d for _v, d in secs.get("/ip ipsec profile", [])}
    for _v, d in secs.get("/ip ipsec peer", []):
        p = prof.get(d.get("profile", "default"), {})
        cfg.vpn.append(VpnTunnel(name=d.get("name", d.get("address", "peer")), kind="ipsec",
                                 ike=2 if d.get("exchange-mode") == "ike2" else 1,
                                 enc=(p.get("enc-algorithm") or "aes-128,3des").split(","),
                                 auth=(p.get("hash-algorithm") or "sha1").split(","),
                                 dh=[{"modp768": 1, "modp1024": 2, "modp1536": 5, "modp2048": 14, "modp3072": 15, "modp4096": 16,
                                      "ecp256": 19, "ecp384": 20, "ecp521": 21}.get(x, 0) for x in (p.get("dh-group") or "modp2048,modp1024").split(",")],
                                 peer=d.get("address", ""), mode=d.get("exchange-mode", "main")))
    for sect, kind in (("/interface pptp-server server", "pptp"), ("/interface l2tp-server server", "l2tp"),
                       ("/interface sstp-server server", "sstp"), ("/interface ovpn-server server", "openvpn")):
        for _v, d in secs.get(sect, []):
            if d.get("enabled") == "yes":
                cfg.vpn.append(VpnTunnel(name=kind.upper(), kind=kind,
                                         psk=bool(d.get("use-ipsec")) if kind == "l2tp" else None))
    for _v, d in secs.get("/interface wireguard", []):
        cfg.vpn.append(VpnTunnel(name=d.get("name", "wireguard"), kind="wireguard", peer=f"port {d.get('listen-port', '')}"))
    # utilisateurs (présents seulement dans un export « show-sensitive » ou via /user print)
    from .model import Admin
    for _v, d in secs.get("/user", []):
        if d.get("name"):
            cfg.admins.append(Admin(name=d["name"], profile=d.get("group", ""), trusted=[x for x in [d.get("address")] if x],
                                    enabled=d.get("disabled") != "yes", default_name=d["name"] == "admin"))
    return cfg


def detect(text: str) -> bool:
    return "by RouterOS" in text[:400] or ("/ip firewall filter" in text and "/interface" in text)


_ = (DENY, LAN, WAN)
