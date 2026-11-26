"""Lecteur Stormshield Network Security (SNS v3 / v4) : sauvegarde « .na »
NON chiffrée par mot de passe (archive des fichiers ConfigFiles), archive .zip
/ .tar(.gz) du dossier ConfigFiles, ou texte collé des fichiers Filter/object.

Fichiers lus : network (interfaces, « Protected=1 » = interne), object
(machines, réseaux, plages, services), objectgroup / servicegroup, Filter/NN
(politique active d'après Filter/slotinfo) : sections [Filter] et [NAT].

Lecteur écrit d'après la syntaxe documentée des ConfigFiles : À VALIDER sur
de vraies sauvegardes (les éléments non reconnus sont listés en remarque).
"""
from __future__ import annotations

import bz2
import configparser
import gzip
import io
import re
import tarfile
import zipfile

from .model import ALLOW, DENY, LAN, WAN, FwConfig, Interface, Nat, Rule, guess_role
from .sets import AddrSet, SvcSet, parse_addr

BUILTIN_SVC = {"http": ("tcp", 80), "https": ("tcp", 443), "ssh": ("tcp", 22), "telnet": ("tcp", 23), "ftp": ("tcp", 21),
               "smtp": ("tcp", 25), "dns_udp": ("udp", 53), "dns": ("tcp", 53), "rdp": ("tcp", 3389), "microsoft-ds": ("tcp", 445),
               "netbios-ssn": ("tcp", 139), "ntp": ("udp", 123), "snmp": ("udp", 161), "imap": ("tcp", 143),
               "imaps": ("tcp", 993), "pop3": ("tcp", 110), "pop3s": ("tcp", 995), "smtps": ("tcp", 465), "mssql": ("tcp", 1433),
               "mysql": ("tcp", 3306), "ldap": ("tcp", 389), "ldaps": ("tcp", 636), "firewall_srv": ("tcp", 1300),
               "firewall_admin": ("tcp", 443), "vnc": ("tcp", 5900), "sip": ("udp", 5060)}
NETWORK_ALIASES = {"any": None, "internet": "internet", "network_internals": "internes", "network_bridge": "internes",
                   "firewall_all": "pare-feu", "firewall_out": "pare-feu", "firewall_in": "pare-feu"}


def load_files(raw: bytes) -> dict[str, str]:
    """{chemin relatif dans ConfigFiles : texte}."""
    files: dict[str, str] = {}
    data = raw
    for dec in (gzip.decompress, bz2.decompress):
        try:
            data = dec(raw)
            break
        except (OSError, ValueError, EOFError):
            continue
    bio = io.BytesIO(data)
    try:
        with tarfile.open(fileobj=bio) as t:
            for m in t.getmembers():
                if m.isfile() and "ConfigFiles" in m.name:
                    files[m.name.split("ConfigFiles/", 1)[1]] = t.extractfile(m).read().decode("utf-8", "replace")
    except tarfile.TarError:
        pass
    if not files:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for n in z.namelist():
                    if "ConfigFiles/" in n and not n.endswith("/"):
                        files[n.split("ConfigFiles/", 1)[1]] = z.read(n).decode("utf-8", "replace")
        except zipfile.BadZipFile:
            pass
    if not files:
        txt = raw.decode("utf-8", "replace")
        if "[Filter]" in txt or "[Host]" in txt or "[ethernet" in txt:
            # texte collé : on répartit par sections connues
            files["pasted"] = txt
        else:
            raise ValueError("Sauvegarde Stormshield illisible : sauvegarde chiffrée par mot de passe ? "
                             "Refaire la sauvegarde sans mot de passe, ou exporter le dossier ConfigFiles.")
    return files


def _ini(text: str) -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser(strict=False, allow_no_value=True, delimiters=("=",))
    cp.optionxform = str
    try:
        cp.read_string(text)
    except configparser.Error:
        pass
    return cp


def _sections_raw(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = ""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        elif cur and s and not s.startswith(";"):
            out[cur].append(s)
    return out


def to_model(raw: bytes, source: str = "") -> FwConfig:
    files = load_files(raw)
    cfg = FwConfig(vendor="Stormshield SNS", source=source)
    alltxt = "\n".join(files.values())

    # interfaces
    net_txt = files.get("network") or alltxt
    for sec, lines in _sections_raw(net_txt).items():
        if not re.match(r"^(ethernet|vlan|agg|bridge|wifi|dialup|loopback)", sec, re.I):
            continue
        kv = dict(line.split("=", 1) for line in lines if "=" in line)
        name = kv.get("Name", sec)
        prot = kv.get("Protected", "")
        g = guess_role(name)
        role = (g if g in ("dmz", "guest", "iot", "mgmt") else LAN) if prot == "1" else \
            WAN if prot == "0" and ("out" in name.lower() or sec.lower() == "ethernet0" or g == WAN) else g
        ips = []
        if kv.get("Address") and kv.get("Mask"):
            import ipaddress
            try:
                ips.append(str(ipaddress.IPv4Interface(f"{kv['Address']}/{kv['Mask']}")))
            except ValueError:
                pass
        cfg.interfaces.append(Interface(name=name, role=role, ips=ips, enabled=kv.get("State", "1") != "0",
                                        vlan=int(kv["Tag"]) if kv.get("Tag", "").isdigit() else None, description=kv.get("Comment", "")))
    for i in cfg.interfaces:
        cfg.zones[i.name] = i.role
    m = re.search(r"(?:Version|FirmwareVersion)\s*=\s*([\d.]+)", alltxt)
    cfg.version = m.group(1) if m else ""
    m = re.search(r"^(?:Model|model)\s*=\s*(\S+)", alltxt, re.M)
    cfg.model = m.group(1) if m else ""
    m = re.search(r"^(?:Name|SystemName|FirewallName)\s*=\s*(\S+)", files.get("system", ""), re.M)
    cfg.hostname = m.group(1) if m else ""

    # objets
    obj = _sections_raw(files.get("object") or alltxt)
    hosts: dict[str, AddrSet] = {}
    for sec in ("Host", "Network", "Range", "Fqdn", "Hosts", "Networks", "Ranges"):
        for line in obj.get(sec, []):
            if "=" not in line:
                continue
            name, rest = line.split("=", 1)
            val = rest.split(",")[0]
            r = parse_addr(val.replace(" ", ""))
            hosts[name.lower()] = AddrSet([r]) if r else AddrSet(opaque=frozenset([name]))
    internal = AddrSet.parse([ip for i in cfg.interfaces if i.role == LAN for ip in i.ips])
    hosts.setdefault("network_internals", internal if internal.iv else AddrSet(opaque=frozenset(["Network_internals"])))
    hosts["internet"] = AddrSet(opaque=frozenset(["Internet (hors réseaux internes)"]))
    svcs: dict[str, SvcSet] = {}
    for line in obj.get("Service", []) + obj.get("Services", []):
        if "=" not in line:
            continue
        name, rest = line.split("=", 1)
        parts = rest.split(",")
        port = parts[0]
        proto = next((p.split("=", 1)[1] for p in parts if p.startswith("proto=")), "tcp")
        lo, _, hi = port.partition("-")
        s = SvcSet()
        if lo.isdigit():
            s.add(proto, int(lo), int(hi) if hi.isdigit() else int(lo))
        else:
            s.add(proto)
        svcs[name.lower()] = s
    groups = {k.lower(): v for k, v in _sections_raw(files.get("objectgroup", "")).items()}
    sgroups = {k.lower(): v for k, v in _sections_raw(files.get("servicegroup", "")).items()}

    def addr(spec: str) -> AddrSet:
        out = AddrSet()
        neg = spec.startswith("!") or spec.startswith("~")
        for n in re.split(r"[|,]", spec.lstrip("!~")):
            k = n.strip().lower()
            if k in ("any", "all", ""):
                return AddrSet.any()
            if k in groups:
                for m in groups[k]:
                    out = out.union(hosts.get(m.strip().lower(), AddrSet(opaque=frozenset([m]))))
            elif k.startswith("firewall_"):
                out = out.union(AddrSet(opaque=frozenset(["le pare-feu"])))
            else:
                out = out.union(hosts.get(k, AddrSet.parse([n]) if parse_addr(n) else AddrSet(opaque=frozenset([n]))))
        out.negate = neg
        return out

    def svc(spec: str, proto: str = "") -> SvcSet:
        out = SvcSet()
        for n in re.split(r"[|,]", spec):
            k = n.strip().lower()
            if k in ("any", ""):
                return SvcSet.any()
            if k in sgroups:
                for m in sgroups[k]:
                    out = out.union(svcs.get(m.lower(), SvcSet(opaque=frozenset([m]))))
            elif k in svcs:
                out = out.union(svcs[k])
            elif k in BUILTIN_SVC:
                p, port = BUILTIN_SVC[k]
                out.add(proto or p, port, port)
            elif k.isdigit():
                out.add(proto or "tcp", int(k), int(k))
            else:
                out.opaque = out.opaque | {n}
        return out

    # politique active
    slot = ""
    m = re.search(r"Active\s*=\s*(\d+)", files.get("Filter/slotinfo", ""))
    if m:
        slot = f"Filter/{int(m.group(1)):02d}"
    ftxt = files.get(slot) or next((v for k, v in sorted(files.items()) if k.startswith("Filter/") and "[Filter]" in v), "") \
        or (alltxt if "[Filter]" in alltxt else "")
    secs = _sections_raw(ftxt)
    pos = 0
    for line in secs.get("Filter", []):
        if line.startswith("separator"):
            continue
        comment = ""
        if "#" in line:
            line, comment = line.split("#", 1)
        tok = line.split()
        if not tok:
            continue
        enabled = True
        if tok[0] == "off":
            enabled = False
            tok = tok[1:]
        if not tok or tok[0] not in ("pass", "block", "reset", "drop", "decrypt"):
            cfg.notes.append(f"Ligne de filtre non interprétée : {line.strip()[:120]}")
            continue
        action = ALLOW if tok[0] in ("pass", "decrypt") else DENY
        r = Rule(id=str(pos + 1), position=pos, enabled=enabled, action=action, comment=comment.strip(), name=comment.strip()[:60])
        pos += 1
        rest = tok[1:]
        proto = ""
        if "ipproto" in rest:
            proto = rest[rest.index("ipproto") + 1]
        prof = [t for t in rest[:rest.index("from")] if t not in ("ipproto", proto)] if "from" in rest else []
        if rest == ["all"]:
            r.set_src(AddrSet.any())
            r.set_dst(AddrSet.any())
            r.set_svc(SvcSet.any())
            r.src_names = r.dst_names = ["any"]
            r.svc_names = ["any"]
        else:
            def after(word):
                return rest[rest.index(word) + 1] if word in rest and rest.index(word) + 1 < len(rest) else ""
            src, dst, port = after("from") or "any", after("to") or "any", after("port")
            ons = [rest[i + 1] for i, t in enumerate(rest) if t == "on" and i + 1 < len(rest)]
            fi, ti = rest.index("from") if "from" in rest else 0, rest.index("to") if "to" in rest else len(rest)
            r.src_zones = [o for i, o in enumerate(ons) if fi < rest.index("on") < ti] if ons else []
            r.set_src(addr(src))
            r.set_dst(addr(dst))
            r.src_names, r.dst_names = [src], [dst]
            if port:
                r.set_svc(svc(port, proto))
                r.svc_names = [port]
            elif proto and proto not in ("any",):
                r.set_svc(SvcSet().add(proto))
                r.svc_names = [proto]
            else:
                r.set_svc(SvcSet.any())
                r.svc_names = ["any"]
            for k in ("auth", "user", "srcuser", "time", "schedule"):
                if k in rest:
                    r.users.append(f"{k} {after(k)}")
            if "firewall" in dst.lower() or dst.lower().startswith("firewall_"):
                r.layer = "input"
            if "on" in rest and rest.index("on") > ti:
                r.dst_zones = [rest[rest.index("on", ti) + 1]]
        r.log = not any(t in prof for t in ("nolog", "noconnlog")) if action == ALLOW else "log" in prof
        r.profiles = [f"inspection:{prof[prof.index('inspection') + 1]}" for _ in [0] if "inspection" in prof and
                      prof.index("inspection") + 1 < len(prof)] + [t for t in prof if t in ("antivirus", "antispam", "urlfiltering", "sslfiltering")]
        r.raw = line.strip()
        cfg.rules.append(r)
    for i, line in enumerate(secs.get("NAT", [])):
        if "->" not in line or line.startswith("separator"):
            continue
        enabled = not line.startswith("off")
        left, right = line.split("->", 1)
        lt, rt = left.split(), right.split("#")[0].split()

        def get(tok, w):
            return tok[tok.index(w) + 1] if w in tok and tok.index(w) + 1 < len(tok) else ""
        to_l, to_r = get(lt, "to"), get(rt, "to")
        def ports_of(name):
            s = svc(name) if name else SvcSet()
            iv = s.ports(6) + s.ports(17)
            return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in iv) or name

        def ip_of(name):
            a = addr(name) if name else AddrSet()
            return str(__import__("ipaddress").IPv4Address(a.iv[0][0])) if a.iv and not a.is_any else name
        if to_l.lower().startswith("firewall_") or "out" in get(lt, "on").lower():     # publication vers l'intérieur
            cfg.nat.append(Nat(id=str(i), enabled=enabled, ext_ip=to_l, ext_ports=ports_of(get(lt, "port")), int_ip=ip_of(to_r),
                               int_port=ports_of(get(rt, "port") or get(lt, "port")),
                               src_restrict=[] if get(lt, "from") in ("any", "") else [get(lt, "from")],
                               interface=get(lt, "on"), raw=line[:300], name=line.split("#", 1)[1].strip() if "#" in line else ""))
    cfg.default_action = DENY
    snmp = re.findall(r"^\s*Community\s*=\s*(\S+)", files.get("snmp", ""), re.M)
    cfg.services = {"snmp_communities": snmp, "log_remote": bool(re.search(r"\[Syslog", alltxt) and "Server=" in alltxt),
                    "ntp": "[NTP" in alltxt or "NTPServer" in alltxt}
    if not cfg.rules:
        cfg.notes.append("Aucune règle de filtrage trouvée dans la sauvegarde (politique active introuvable).")
    return cfg


def detect(raw: bytes) -> bool:
    return raw[:4] in (b"BZh9", b"BZh8") or b"ConfigFiles" in raw[:200000] or b"[Filter]" in raw[:200000]


_ = _ini
