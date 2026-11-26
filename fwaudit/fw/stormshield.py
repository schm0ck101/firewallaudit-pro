"""Lecteur Stormshield Network Security (SNS v3 / v4) : sauvegarde « .na »
NON chiffrée par mot de passe (archive des fichiers ConfigFiles), archive .zip
/ .tar(.gz) du dossier ConfigFiles, ou texte collé des fichiers Filter/object.

Fichiers lus : network (interfaces, « Protected=1 » = interne), object
(machines, réseaux, plages, services), objectgroup / servicegroup, Filter/NN
(politique active d'après Filter/slotinfo) : sections [Filter] et [NAT].

Validé sur une vraie sauvegarde SNS 4.8 (SN210W) : .na chiffrée « sans mot de
passe » (AES-128-CBC, clé PBKDF2-SHA256 du mot de passe vide), règles avec
redirection intégrée (« -> to hôte port … »), objets Network_/Firewall_<interface>,
groupes imbriqués, services « port/proto », VPN (peer + ph1profile), syslog
(Communication/config). Les éléments non reconnus sont listés en remarque.
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


def decrypt_na(raw: bytes, password: str = "") -> bytes:
    """Sauvegarde .na SNS v4 : en-tête texte « [BACKUP] » (iv, salt, pbkdf_iterations) sur 1 Ko, signature PKCS#7
    (longueur sur 4 octets), puis données (longueur sur 4 octets) chiffrées AES-128-CBC, clé PBKDF2-SHA256 du mot de
    passe — mot de passe VIDE quand la sauvegarde est faite « sans mot de passe ». Résultat : archive tar.gz."""
    import hashlib

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    head = raw[:0x400].split(b"\x00")[0].decode("utf-8", "replace")
    kv = dict(line.split("=", 1) for line in head.splitlines() if "=" in line)
    try:
        iv, salt, it = bytes.fromhex(kv["iv"]), bytes.fromhex(kv["salt"]), int(kv.get("pbkdf_iterations", "10000"))
    except (KeyError, ValueError) as e:
        raise ValueError("Sauvegarde Stormshield : en-tête illisible.") from e
    siglen = int.from_bytes(raw[0x400:0x404], "big")
    start = 0x404 + siglen
    n = int.from_bytes(raw[start:start + 4], "big")
    ct = raw[start + 4:start + 4 + n]
    if not ct or len(ct) % 16:
        raise ValueError("Sauvegarde Stormshield : format de chiffrement non reconnu.")
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, it, 16)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    pt = pt[:-pad] if 1 <= pad <= 16 else pt
    if pt[:2] != b"\x1f\x8b":
        raise ValueError("Sauvegarde Stormshield protégée par un mot de passe : refaire la sauvegarde sans mot de passe "
                         "(Configuration › Système › Maintenance › Sauvegarder), ou exporter le dossier ConfigFiles.")
    return pt


def load_files(raw: bytes) -> dict[str, str]:
    """{chemin relatif dans ConfigFiles : texte}."""
    files: dict[str, str] = {}
    header = ""
    if raw[:8] == b"[BACKUP]":
        header = raw[:0x400].split(b"\x00")[0].decode("utf-8", "replace")
        raw = decrypt_na(raw)
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
    if header:
        files["__header__"] = header
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
    """Sections « [Nom] » (commentaire « # … » toléré après le nom) -> lignes (commentaires de fin retirés)."""
    out: dict[str, list[str]] = {}
    cur = ""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^\[([^\]]+)\]\s*(?:#.*)?$", s)
        if m:
            cur = m.group(1).strip()
            out.setdefault(cur, [])
        elif cur and s and not s.startswith((";", "#")):
            out[cur].append(s)
    return out


def _strip_comment(line: str) -> tuple[str, str]:
    """Sépare « règle # commentaire » (le « # » hors guillemets)."""
    q = False
    for i, ch in enumerate(line):
        if ch == '"':
            q = not q
        elif ch == "#" and not q and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip(), line[i + 1:].strip()
    return line.rstrip(), ""


def _tokens(line: str) -> list[str]:
    import shlex
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def _public_set() -> AddrSet:
    """« internet » de Stormshield = tout sauf les réseaux privés / réservés."""
    from .sets import PRIVATE
    import ipaddress
    priv = sorted((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))) for a, b in PRIVATE)
    iv, cur = [], 0
    for lo, hi in priv:
        if lo > cur:
            iv.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= 2**32 - 1:
        iv.append((cur, 2**32 - 1))
    return AddrSet(iv)


# mots-clés des règles suivis d'une valeur (ignorés ou traités à part)
_KV = {"inspection", "level", "ipproto", "proto", "type", "code", "route", "iprep", "on", "from", "to", "port", "rulename",
       "via", "srcport", "tos", "settos", "qos", "count", "rate", "ipstate", "srcif", "dstif", "user", "auth", "time",
       "schedule", "hostrep", "geo", "dscp", "loadbalancing", "nat", "redirect", "srcportlist", "antispoof", "domain"}


def to_model(raw: bytes, source: str = "") -> FwConfig:
    import ipaddress
    files = load_files(raw)
    cfg = FwConfig(vendor="Stormshield SNS", source=source)
    alltxt = "\n".join(v for k, v in files.items() if k != "__header__")
    head = dict(line.split("=", 1) for line in files.get("__header__", "").splitlines() if "=" in line)
    cfg.model = head.get("model", "")
    cfg.version = head.get("version", "")
    cfg.serial = head.get("serial", "")
    cfg.hostname = head.get("serial", "")
    if not cfg.version:
        m = re.search(r"(?:Version|FirmwareVersion)\s*=\s*([\d.]+)", alltxt)
        cfg.version = m.group(1) if m else ""

    # interfaces (fichier network) : sans « Address » = port non configuré (ignoré) ; « Protected » absent = externe
    net_txt = files.get("network") or alltxt
    itf_nets: dict[str, AddrSet] = {}
    itf_ips: dict[str, AddrSet] = {}
    for sec, lines in _sections_raw(net_txt).items():
        if not re.match(r"^(ethernet|vlan|agg|bridge|wifi|dialup|loopback|usbethernet)", sec, re.I):
            continue
        kv = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = _strip_comment(v)[0].strip().strip('"')
        name = kv.get("Name", sec)
        if "Address" not in kv and not sec.lower().startswith(("dialup", "vlan")):
            continue
        prot = kv.get("Protected", "0")
        g = guess_role(name)
        role = (g if g in ("dmz", "guest", "iot", "mgmt", "vpn") else LAN) if prot == "1" else \
            ("other" if sec.lower().startswith("loopback") else WAN)
        ips = []
        if kv.get("Address") and kv.get("Mask"):
            try:
                itf = ipaddress.IPv4Interface(f"{kv['Address']}/{kv['Mask']}")
                ips.append(str(itf))
                itf_nets[name.lower()] = AddrSet([parse_addr(str(itf.network))])
                itf_ips[name.lower()] = AddrSet([parse_addr(str(itf.ip))])
            except ValueError:
                pass
        cfg.interfaces.append(Interface(name=name, role=role, ips=ips, enabled=kv.get("State", "1") != "0",
                                        vlan=int(kv["Tag"]) if kv.get("Tag", "").isdigit() else None, description=kv.get("Comment", "")))
    for i in cfg.interfaces:
        cfg.zones[i.name] = i.role
    cfg.zones.update({"ipsec": "vpn", "sslvpn": "vpn", "publication (NAT)": LAN})

    # objets : machines « nom=ip[,resolve=…] », réseaux « nom=cidr », plages, FQDN, services « nom=port[-port]/proto »
    obj = _sections_raw(files.get("object") or alltxt)
    hosts: dict[str, AddrSet] = {}
    for sec in ("Host", "Network", "Range", "Fqdn", "Hosts", "Networks", "Ranges"):
        for line in obj.get(sec, []):
            line = _strip_comment(line)[0]
            if "=" not in line:
                continue
            name, rest = line.split("=", 1)
            val = rest.split(",")[0].strip()
            r = parse_addr(val.replace(" ", ""))
            hosts[name.strip().lower()] = AddrSet([r]) if r else AddrSet(opaque=frozenset([name.strip()]))
    internal = AddrSet()
    for i in cfg.interfaces:
        if i.role != WAN and i.name.lower() in itf_nets and not i.name.lower().startswith("loopback"):
            internal = internal.union(itf_nets[i.name.lower()])
    hosts.setdefault("network_internals", internal if internal.iv else AddrSet(opaque=frozenset(["Network_internals"])))
    internet = _public_set()
    svcs: dict[str, SvcSet] = {}
    for line in obj.get("Service", []) + obj.get("Services", []):
        line = _strip_comment(line)[0]
        if "=" not in line:
            continue
        name, rest = line.split("=", 1)
        spec = rest.split(",")[0].strip()
        port, _, proto = spec.partition("/")
        proto = proto or next((p.split("=", 1)[1] for p in rest.split(",") if p.startswith("proto=")), "tcp")
        lo, _, hi = port.partition("-")
        s = SvcSet()
        for pr in (("tcp", "udp") if proto in ("any", "") else (proto,)):
            if lo.isdigit():
                s.add(pr, int(lo), int(hi) if hi.isdigit() else int(lo))
            else:
                s.add(pr)
        svcs[name.strip().lower()] = s
    groups = {k.lower(): [_strip_comment(m)[0].strip() for m in v] for k, v in _sections_raw(files.get("objectgroup", "")).items()}
    sgroups = {k.lower(): [_strip_comment(m)[0].strip() for m in v] for k, v in _sections_raw(files.get("servicegroup", "")).items()}

    def addr(spec: str, depth: int = 0) -> AddrSet:
        out = AddrSet()
        neg = spec.startswith(("!", "~"))
        for n in re.split(r"[|,]", spec.lstrip("!~")):
            k = n.strip().lower()
            if k in ("any", "all", ""):
                return AddrSet.any()
            if k == "internet":
                out = out.union(internet)
            elif k.startswith("firewall_"):
                out = out.union(AddrSet(opaque=frozenset(["le pare-feu"])))
            elif k.startswith("network_") and k[8:] in itf_nets:
                out = out.union(itf_nets[k[8:]])
            elif k in groups and depth < 8:
                for m in groups[k]:
                    out = out.union(addr(m, depth + 1))
            elif k in hosts:
                out = out.union(hosts[k])
            else:
                r = parse_addr(n)
                out = out.union(AddrSet([r]) if r else AddrSet(opaque=frozenset([n.strip()])))
        out.negate = neg
        return out

    def svc(spec: str, proto: str = "", depth: int = 0) -> SvcSet:
        out = SvcSet()
        for n in re.split(r"[|,]", spec):
            k = n.strip().lower()
            if k in ("any", ""):
                return SvcSet.any()
            if k in sgroups and depth < 8:
                for m in sgroups[k]:
                    out = out.union(svc(m, proto, depth + 1))
            elif k in svcs:
                out = out.union(svcs[k])
            elif k in BUILTIN_SVC:
                p, port = BUILTIN_SVC[k]
                out.add(proto or p, port, port)
            elif k.isdigit():
                out.add(proto or "tcp", int(k), int(k))
            else:
                out.opaque = out.opaque | {n.strip()}
        return out

    def ports_txt(s: SvcSet) -> str:
        iv = s.ports(6) or s.ports(17)
        return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in iv[:6])

    def first_ip(a: AddrSet, name: str) -> str:
        return str(ipaddress.IPv4Address(a.iv[0][0])) if a.iv and not a.is_any and a.size <= 256 else name

    # politique de filtrage active (Filter/slotinfo -> Filter/NN) : section [Filter] ; [NAT] = translations
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
        body, comment = _strip_comment(line)
        tok = _tokens(body)
        if not tok:
            continue
        enabled = True
        if tok[0] == "off":
            enabled, tok = False, tok[1:]
        if not tok or tok[0] not in ("pass", "block", "reset", "drop", "decrypt"):
            cfg.notes.append(f"Ligne de filtre non interprétée : {body.strip()[:120]}")
            continue
        action = ALLOW if tok[0] in ("pass", "decrypt") else DENY
        left, right = (tok[1:tok.index("->")], tok[tok.index("->") + 1:]) if "->" in tok else (tok[1:], [])
        f: dict = {"from": "any", "to": "any", "port": "", "src_on": "", "dst_on": "", "via": "", "ipproto": "",
                   "iprep_src": "", "iprep_dst": "", "rulename": "", "profiles": [], "log": False, "users": []}
        side = ""
        i = 0
        while i < len(left):
            t = left[i]
            v = left[i + 1] if i + 1 < len(left) else ""
            if t in ("from", "to"):
                side = "src" if t == "from" else "dst"
                f[t] = v
                i += 2
                continue
            if t == "on":
                f["src_on" if side == "src" else "dst_on"] = v
            elif t == "iprep":
                f["iprep_src" if side == "src" else "iprep_dst"] = v
            elif t == "inspection":
                f["profiles"].append(f"inspection:{v}")
            elif t in ("port", "via", "ipproto", "rulename"):
                f[t] = v
            elif t in ("user", "auth", "time", "schedule"):
                f["users"].append(f"{t} {v}")
            elif t == "log":
                f["log"] = True
                i += 1
                continue
            elif t in _KV:
                pass
            else:
                if any(x in t for x in ("antivirus", "antispam", "urlfiltering", "sslfiltering", "ftpfiltering", "smtpfiltering")):
                    f["profiles"] += [x.split(":")[0] for x in t.split(",")]
                i += 1
                continue
            i += 2
        red = {"to": "", "port": ""}
        for j, t in enumerate(right):
            if t in ("to", "port") and j + 1 < len(right):
                red[t] = right[j + 1]
        auto = re.match(r"^(created|updated|cr[ée]{2}e?|cr[ée]e|mise? à jour)\b", comment, re.I)
        r = Rule(id=str(pos + 1), position=pos, enabled=enabled, action=action, comment=comment,
                 name="" if auto else comment[:60])
        pos += 1
        src = addr(f["from"])
        r.set_src(src)
        r.src_names = [f["from"]]
        if f["src_on"]:
            r.src_zones = [f["src_on"]]
        elif f["via"] in ("ipsec", "sslvpn"):
            r.src_zones = [f["via"]]
        elif f["via"]:
            r.apps.append(f"via {f['via']}")             # ex. « via sslproxy » : trafic déchiffré par le proxy SSL
        if f["dst_on"]:
            r.dst_zones = [f["dst_on"]]
        if f["iprep_src"]:
            r.apps.append(f"réputation IP source : {f['iprep_src']}")
        if f["iprep_dst"]:
            r.apps.append(f"réputation IP destination : {f['iprep_dst']}")
        r.users = f["users"]
        if tok[0] == "decrypt":
            r.apps.append("déchiffrement SSL (puis règles « via sslproxy »)")
        pub_svc = svc(f["port"], f["ipproto"]) if f["port"] else (SvcSet().add(f["ipproto"]) if f["ipproto"] not in ("", "any") else SvcSet.any())
        if red["to"]:                                      # redirection intégrée à la règle : publication vers l'intérieur
            dst = addr(red["to"])
            real_svc = svc(red["port"], f["ipproto"]) if red["port"] else pub_svc
            r.set_dst(dst)
            r.set_svc(real_svc)
            r.dst_names, r.svc_names = [red["to"]], [red["port"] or f["port"] or "any"]
            r.dst_zones = ["publication (NAT)"]
            r.nat = action == ALLOW
            if r.nat:
                cfg.nat.append(Nat(id=f["rulename"] or str(pos), name=comment or f["rulename"], enabled=enabled,
                                   ext_ip=f["to"], ext_ports=ports_txt(pub_svc) or f["port"],
                                   proto="tcp" if pub_svc.ports(6) else "udp", int_ip=first_ip(dst, red["to"]),
                                   int_port=ports_txt(real_svc), src_restrict=[] if src.is_any or src == internet else [src.describe(3)],
                                   interface=f["src_on"], raw=body[:300]))
        else:
            dst = addr(f["to"])
            r.set_dst(dst)
            r.set_svc(pub_svc)
            r.dst_names, r.svc_names = [f["to"]], [f["port"] or f["ipproto"] or "any"]
            if f["to"].lower().startswith("firewall_"):
                r.layer = "input"
        r.log = f["log"] if action == DENY else True
        r.profiles = f["profiles"]
        r.raw = body.strip()
        cfg.rules.append(r)

    # [NAT] : translations de destination explicites (« nat … to Firewall_X port P -> … to hôte »)
    for line in secs.get("NAT", []):
        if "->" not in line or line.startswith("separator"):
            continue
        body, comment = _strip_comment(line)
        tok = _tokens(body)
        enabled = tok[0] != "off"
        left, right = tok[:tok.index("->")], tok[tok.index("->") + 1:]

        def get(ts, w):
            return ts[ts.index(w) + 1] if w in ts and ts.index(w) + 1 < len(ts) else ""
        to_l, to_r = get(left, "to"), get(right, "to")
        if to_r and to_l.lower().startswith("firewall_"):
            src = addr(get(left, "from") or "any")
            ps = svc(get(left, "port")) if get(left, "port") else SvcSet.any()
            cfg.nat.append(Nat(id=get(left, "rulename") or f"nat{len(cfg.nat)}", name=comment, enabled=enabled, ext_ip=to_l,
                               ext_ports=ports_txt(ps), int_ip=first_ip(addr(to_r), to_r),
                               int_port=ports_txt(svc(get(right, "port"))) if get(right, "port") else ports_txt(ps),
                               src_restrict=[] if src.is_any or src == internet else [src.describe(3)],
                               interface=get(left, "on"), raw=body[:300]))

    # VPN IPsec (VPN/peer + VPN/ph1profile)
    ph1 = _sections_raw(files.get("VPN/ph1profile", ""))
    for name, lines in _sections_raw(files.get("VPN/peer", "")).items():
        kv = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = _strip_comment(v)[0].strip()
        prof = ph1.get(kv.get("conf", ""), [])
        enc, auth, dh = [], [], []
        for line in prof:
            line = _strip_comment(line)[0]
            if line.startswith("enc="):
                for part in line.split():
                    k, _, v = part.partition("=")
                    if k == "enc" and v:
                        enc.append(v.replace("aes_gcm_16", "AES-GCM").replace("aes", "AES").replace("/", "-").replace("3des", "3DES").replace("des", "DES"))
                    elif k == "auth" and v:
                        auth.append(v.replace("sha2_", "SHA2-").replace("sha1", "SHA1").replace("md5", "MD5"))
            elif line.startswith("defaultdh=") and line[10:].strip().isdigit():
                dh.append(int(line[10:].strip()))
        from .model import VpnTunnel
        cfg.vpn.append(VpnTunnel(name=name, kind="ipsec", ike=int(kv["ikeversion"]) if kv.get("ikeversion", "").isdigit() else None,
                                 enc=enc, auth=sorted(set(auth)), dh=dh, peer=kv.get("dst", ""),
                                 mode="aggressive" if kv.get("mode", "").lower().startswith("aggr") else "main"))

    cfg.default_action = DENY
    snmp = re.findall(r"^\s*Community\s*=\s*(\S+)", files.get("snmp", ""), re.M)
    comm = _sections_raw(files.get("Communication/config", ""))
    syslog = [s for s, ls in comm.items() if s.lower().startswith("syslog") and "State=1" in [x.split("#")[0].strip() for x in ls]
              and any(x.startswith("Server=") and x.split("=", 1)[1].split("#")[0].strip() for x in ls)]
    has_sys = any(s.lower().startswith("syslog") for s in comm)
    cfg.services = {"snmp_communities": [c.strip('"') for c in snmp],
                    "log_remote": True if syslog else (False if has_sys else None),
                    "ntp": (re.search(r"^\s*State\s*=\s*1", files["ntp"], re.M) is not None) if "ntp" in files
                    else ("[NTP" in alltxt or "NTPServer" in alltxt)}
    if not cfg.rules:
        cfg.notes.append("Aucune règle de filtrage trouvée dans la sauvegarde (politique active introuvable).")
    return cfg


def detect(raw: bytes) -> bool:
    return raw[:8] == b"[BACKUP]" or raw[:4] in (b"BZh9", b"BZh8") or b"ConfigFiles" in raw[:200000] or b"[Filter]" in raw[:200000]


_ = _ini
