"""Lecteur UniFi (UniFi OS : UDM, UCG, UXG, Cloud Key…) par l'API locale de la
console, avec un compte LOCAL en lecture seule (rôle « View Only »).

Lit : réseaux (VLAN), zones et politiques du pare-feu par zones (Network 9+)
ou anciennes règles (LAN_IN, WAN_IN…), groupes, redirections de ports,
réglages (IPS, UPnP, SSH, SNMP, NTP, syslog), VPN, Wi-Fi invités.
Aucune écriture : uniquement des requêtes GET (et la connexion).
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import urllib.request

from .model import ALLOW, DENY, DMZ, GUEST, LAN, LOCAL, VPN, WAN, Admin, FwConfig, Interface, Nat, Rule, VpnTunnel
from .sets import AddrSet, SvcSet, parse_addr

ZONE_ROLE = {"internal": LAN, "external": WAN, "gateway": LOCAL, "vpn": VPN, "hotspot": GUEST, "dmz": DMZ}
LEGACY_RULESETS = {"WAN_IN": ("wan", "lan"), "WAN_LOCAL": ("wan", "local"), "WAN_OUT": ("lan", "wan"),
                   "LAN_IN": ("lan", "any"), "LAN_LOCAL": ("lan", "local"), "LAN_OUT": ("any", "lan"),
                   "GUEST_IN": ("guest", "any"), "GUEST_LOCAL": ("guest", "local"), "GUEST_OUT": ("any", "guest")}


class Api:
    def __init__(self, host: str, user: str, password: str, site: str = "default", timeout: float = 15):
        self.base = f"https://{host}"
        self.site = site
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # certificat auto-signé de la console
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar))
        self.timeout = timeout
        self.csrf = ""
        body = json.dumps({"username": user, "password": password, "rememberMe": False}).encode()
        req = urllib.request.Request(self.base + "/api/auth/login", data=body, headers={"Content-Type": "application/json"})
        with self.op.open(req, timeout=timeout) as r:
            self.csrf = r.headers.get("x-csrf-token") or r.headers.get("X-Updated-Csrf-Token") or ""
            self.me = json.loads(r.read() or b"{}")

    def get(self, path: str):
        p = path.replace("{site}", self.site)
        req = urllib.request.Request(self.base + p, headers={"x-csrf-token": self.csrf, "Accept": "application/json"})
        try:
            with self.op.open(req, timeout=self.timeout) as r:
                d = json.loads(r.read() or b"null")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404):
                return None
            raise
        return d.get("data") if isinstance(d, dict) and "data" in d and "meta" in d else d

    def logout(self):
        try:
            req = urllib.request.Request(self.base + "/api/auth/logout", data=b"", headers={"x-csrf-token": self.csrf}, method="POST")
            self.op.open(req, timeout=5).close()
        except Exception:
            pass


ENDPOINTS = {
    "sysinfo": "/proxy/network/api/s/{site}/stat/sysinfo",
    "devices": "/proxy/network/api/s/{site}/stat/device",
    "networks": "/proxy/network/api/s/{site}/rest/networkconf",
    "portforward": "/proxy/network/api/s/{site}/rest/portforward",
    "legacy_rules": "/proxy/network/api/s/{site}/rest/firewallrule",
    "groups": "/proxy/network/api/s/{site}/rest/firewallgroup",
    "settings": "/proxy/network/api/s/{site}/rest/setting",
    "wlans": "/proxy/network/api/s/{site}/rest/wlanconf",
    "zones": "/proxy/network/v2/api/site/{site}/firewall/zone",
    "policies": "/proxy/network/v2/api/site/{site}/firewall-policies",
    "traffic_rules": "/proxy/network/v2/api/site/{site}/trafficrules",
    "admins": "/proxy/network/api/s/{site}/stat/admin",
}


def fetch(host: str, user: str, password: str, site: str = "default") -> dict:
    api = Api(host, user, password, site)
    out = {"host": host}
    try:
        for k, p in ENDPOINTS.items():
            try:
                out[k] = api.get(p)
            except Exception as exc:
                out[k] = None
                out.setdefault("_errors", []).append(f"{k} : {exc}")
    finally:
        api.logout()
    return out


SECRET_KEYS = ("passphrase", "password", "secret", "psk", "private_key", "privatekey", "token", "preshared", "pre_shared",
               "wpa_key", "auth_key", "api_key")


def sanitize(obj):
    """Copie des données de l'API sans aucun secret (phrases Wi-Fi, clés VPN, mots de passe, champs x_…) :
    conservée dans l'audit pour pouvoir RÉ-ANALYSER avec une version plus récente du lecteur."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            keep = kl in ("x_ssh_enabled", "x_ssh_password_auth")          # réglages, pas des secrets
            if not keep and (kl.startswith("x_") or any(s in kl for s in SECRET_KEYS)):
                continue
            out[k] = sanitize(v)
        return out
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    return obj


def _net_by_id(data: dict) -> dict:
    return {n.get("_id"): n for n in (data.get("networks") or [])}


def to_model(data: dict, source: str = "") -> FwConfig:
    nets = _net_by_id(data)
    gw = next((d for d in (data.get("devices") or []) if d.get("type") in ("udm", "ugw", "uxg") or d.get("is_gateway")), {})
    si = (data.get("sysinfo") or [{}])[0] if isinstance(data.get("sysinfo"), list) else (data.get("sysinfo") or {})
    cfg = FwConfig(vendor="UniFi", model=gw.get("model") or "", hostname=gw.get("name") or si.get("name", ""),
                   version=f"UniFi OS {gw.get('version', '?')} · Network {si.get('version', '?')}", serial=gw.get("serial", ""),
                   source=source or f"API {data.get('host')}")
    groups = {g.get("_id"): g for g in (data.get("groups") or [])}

    # réseaux -> interfaces
    for n in nets.values():
        purpose = n.get("purpose", "")
        role = WAN if purpose == "wan" else GUEST if purpose == "guest" or n.get("is_guest") else \
            VPN if "vpn" in purpose else LAN
        name = n.get("name", "")
        low = name.lower()
        if role == LAN and any(k in low for k in ("iot", "internet of things", "camera", "caméra", "domot", "objet", "cctv",
                                                  "video", "vidéo", "surveillance")):
            role = "iot"
        cfg.interfaces.append(Interface(name=name, role=role, ips=[n["ip_subnet"]] if n.get("ip_subnet") else [],
                                        vlan=n.get("vlan") if n.get("vlan_enabled") else None, enabled=n.get("enabled", True),
                                        zone=n.get("_id", "")))
    for i in cfg.interfaces:
        cfg.zones[i.name] = i.role

    def net_set(ids) -> tuple[AddrSet, list[str]]:
        s, names = AddrSet(), []
        for nid in ids or []:
            n = nets.get(nid)
            if n and n.get("ip_subnet"):
                r = parse_addr(n["ip_subnet"])
                if r:
                    s = s.union(AddrSet([r]))
                names.append(n.get("name", nid))
        return s, names

    zones = {z.get("_id"): z for z in (data.get("zones") or [])}
    for z in zones.values():
        cfg.zones[z.get("name", "")] = ZONE_ROLE.get(z.get("zone_key", ""), guess_zone(z.get("name", "")))

    def endpoint(e: dict) -> tuple[list[str], AddrSet, list[str], SvcSet | None]:
        z = zones.get(e.get("zone_id"), {})
        zname = z.get("name", "")
        mt = (e.get("matching_target") or "ANY").upper()
        if mt == "ANY":
            a, names = net_set(z.get("network_ids")) if z.get("network_ids") and ZONE_ROLE.get(z.get("zone_key")) in (LAN, GUEST, DMZ) else (AddrSet.any(), ["toute la zone"])
            if not z.get("network_ids") or ZONE_ROLE.get(z.get("zone_key")) in (WAN, VPN, LOCAL, None):
                a, names = AddrSet.any(), [f"toute la zone {zname}"]
        elif mt == "NETWORK":
            a, names = net_set(e.get("network_ids"))
        elif mt == "IP":
            a = AddrSet.parse(e.get("ips") or [])
            names = e.get("ips") or []
            if e.get("ip_group_id") and e["ip_group_id"] in groups:
                g = groups[e["ip_group_id"]]
                a = a.union(AddrSet.parse(g.get("group_members") or []))
                names = names + [f"groupe {g.get('name')}"]
        elif mt == "REGION":
            a, names = AddrSet(opaque=frozenset(["pays : " + ",".join(e.get("regions") or [])])), ["pays " + ",".join(e.get("regions") or [])]
        else:                                             # CLIENT, MAC, DEVICE, APP, WEB… : identifiants précis (deux
            ids = []                                      # règles « client » ne se couvrent que pour les MÊMES clients)
            for k in ("client_macs", "mac_addresses", "device_ids", "app_ids", "app_category_ids", "web_domains", "macs"):
                ids += [str(x) for x in (e.get(k) or [])]
            lab = f"{mt.lower()} {', '.join(sorted(ids))}".strip() if ids else f"{mt.lower()} (non détaillé)"
            a, names = AddrSet(opaque=frozenset([lab])), [lab]
        if e.get("match_opposite_ips") or e.get("match_opposite_networks"):
            a = AddrSet(a.iv, a.opaque, True)
        svc = None
        pm = (e.get("port_matching_type") or "ANY").upper()
        if pm == "SPECIFIC" and e.get("port"):
            svc = SvcSet()
            for part in str(e["port"]).split(","):
                lo, _, hi = part.strip().partition("-")
                if lo.isdigit():
                    svc.add("tcp", int(lo), int(hi or lo))
                    svc.add("udp", int(lo), int(hi or lo))
        elif pm == "OBJECT" and e.get("port_group_id") in groups:
            svc = SvcSet()
            for part in groups[e["port_group_id"]].get("group_members") or []:
                lo, _, hi = str(part).partition("-")
                if lo.isdigit():
                    svc.add("tcp", int(lo), int(hi or lo))
                    svc.add("udp", int(lo), int(hi or lo))
        return [zname] if zname else [], a, names, svc

    pols = data.get("policies") or []
    pols = sorted(pols, key=lambda p: (p.get("index") or 0))
    pos = 0
    for p in pols:
        if p.get("predefined") and p.get("action") == "ALLOW" and "established" in (p.get("name") or "").lower():
            continue
        r = Rule(id=str(p.get("index") or p.get("_id")), position=pos, name=p.get("name") or "", enabled=p.get("enabled", True))
        pos += 1
        r.action = ALLOW if p.get("action") == "ALLOW" else DENY
        sz, sa, sn, _ss = endpoint(p.get("source") or {})
        dz, da, dn, dsvc = endpoint(p.get("destination") or {})
        r.src_zones, r.dst_zones = sz, dz
        r.set_src(sa)
        r.set_dst(da)
        r.src_names, r.dst_names = sn, dn
        proto = (p.get("protocol") or "all").lower()
        if dsvc is not None:
            sv = SvcSet()
            for pn, ivs in dsvc.m.items():
                if proto in ("all", "tcp_udp") or (pn == 6 and proto == "tcp") or (pn == 17 and proto == "udp"):
                    for lo, hi in ivs:
                        sv.add(pn, lo, hi)
        elif proto == "all":
            sv = SvcSet.any()
        elif proto == "tcp_udp":
            sv = SvcSet().add("tcp").add("udp")
        else:
            sv = SvcSet().add(proto)
        r.set_svc(sv)
        r.svc_names = [f"{proto} {(p.get('destination') or {}).get('port') or ''}".strip()]
        cst = (p.get("connection_state_type") or "ALL").upper()
        states = [str(s).lower() for s in (p.get("connection_states") or [])]
        nm = (p.get("name") or "").lower()
        # règles de RETOUR (trafic d'une connexion déjà établie) : prédéfinies « Allow Return Traffic » et règles
        # « … (Return) » créées automatiquement pour chaque autorisation : ce ne sont pas des ouvertures
        if cst in ("RESPOND_ONLY", "RETURN") or nm.endswith("(return)") or "return traffic" in nm or \
                (states and "new" not in states and set(states) <= {"established", "related"}):
            r.apps = ["état retour (connexions établies)"]
        elif cst not in ("ALL", ""):
            r.apps = [f"état {','.join(states or [cst.lower()])}"]
        sch = (p.get("schedule") or {}).get("mode", "ALWAYS")
        r.schedule = "" if sch in ("ALWAYS", None) else sch.lower()
        r.log = bool(p.get("logging"))
        r.layer = "input" if ZONE_ROLE.get((zones.get((p.get("destination") or {}).get("zone_id")) or {}).get("zone_key")) == LOCAL else "filter"
        r.comment = "prédéfinie" if p.get("predefined") else ""
        r.raw = json.dumps({k: p.get(k) for k in ("name", "action", "index", "protocol", "predefined", "connection_state_type",
                                                  "connection_states", "source", "destination", "enabled")},
                           ensure_ascii=False)[:1400]
        cfg.rules.append(r)

    # UniFi réutilise le même numéro (index) dans chaque paire de zones : identifiant rendu unique
    from collections import Counter
    dup = Counter(r.id for r in cfg.rules)
    for r in cfg.rules:
        if dup[r.id] > 1:
            r.id = f"{r.id} {'/'.join(r.src_zones) or '*'}→{'/'.join(r.dst_zones) or '*'}"
    seen_ids: Counter = Counter()
    for r in cfg.rules:                      # même numéro ET même paire de zones (règle et son « Return »)
        seen_ids[r.id] += 1
        if seen_ids[r.id] > 1:
            r.id = f"{r.id} ({seen_ids[r.id]})"

    # anciennes règles (avant le pare-feu par zones)
    if not pols:
        for p in sorted(data.get("legacy_rules") or [], key=lambda x: (x.get("ruleset", ""), x.get("rule_index") or 0)):
            rs = p.get("ruleset", "")
            sz, dz = LEGACY_RULESETS.get(rs, ("any", "any"))
            r = Rule(id=f"{rs}/{p.get('rule_index')}", position=pos, name=p.get("name", ""), enabled=p.get("enabled", True))
            pos += 1
            r.action = ALLOW if p.get("action") == "accept" else DENY
            r.src_zones, r.dst_zones = ([sz] if sz != "any" else []), ([dz] if dz != "any" else [])
            s = AddrSet.parse([p["src_address"]]) if p.get("src_address") else AddrSet.any()
            for gid in p.get("src_firewallgroup_ids") or []:
                g = groups.get(gid, {})
                s = AddrSet.parse(g.get("group_members") or []) if g.get("group_type") == "address-group" else s
            if p.get("src_networkconf_id"):
                s, _n = net_set([p["src_networkconf_id"]])
            d = AddrSet.parse([p["dst_address"]]) if p.get("dst_address") else AddrSet.any()
            if p.get("dst_networkconf_id"):
                d, _n = net_set([p["dst_networkconf_id"]])
            r.set_src(s)
            r.set_dst(d)
            sv = SvcSet.any() if p.get("protocol", "all") == "all" else SvcSet()
            if p.get("dst_port"):
                sv = SvcSet()
                for part in str(p["dst_port"]).split(","):
                    lo, _, hi = part.partition("-")
                    if lo.isdigit():
                        for pr in (("tcp", "udp") if p.get("protocol") in ("tcp_udp", "all") else (p.get("protocol"),)):
                            sv.add(pr, int(lo), int(hi or lo))
            r.set_svc(sv)
            r.log = bool(p.get("logging"))
            r.layer = "input" if rs.endswith("_LOCAL") else "filter"
            cfg.rules.append(r)
        cfg.notes.append("Ancien pare-feu UniFi (règles par jeu LAN_IN / WAN_IN…) : migrer vers le pare-feu par zones est recommandé.")

    # redirections de ports
    for f in data.get("portforward") or []:
        src = f.get("src") or "any"
        restrict = [] if src in ("any", "") else [src]
        gid = f.get("src_firewall_group_id") or f.get("src_firewallgroup_id")     # nom selon la version de Network
        if gid:
            restrict = (groups.get(gid) or {}).get("group_members") or [f"groupe d'adresses {(groups.get(gid) or {}).get('name') or gid}"]
        # Network 9+ : la redirection crée une politique « Allow Port Forward <nom> » qui porte la restriction de source
        if not restrict:
            pol = next((r for r in cfg.rules if r.name.lower() == f"allow port forward {f.get('name', '')}".lower()), None)
            if pol and not pol.src_set.is_any:
                restrict = [pol.src_set.describe(6)]
        cfg.nat.append(Nat(id=f.get("_id", ""), name=f.get("name", ""), enabled=f.get("enabled", True),
                           ext_ip=f.get("destination_ip") if f.get("destination_ip") not in (None, "any") else "",
                           ext_ports=str(f.get("dst_port", "")), proto=f.get("proto", "tcp_udp"), int_ip=f.get("fwd", ""),
                           int_port=str(f.get("fwd_port", "")), src_restrict=restrict, interface=f.get("pfwd_interface", "wan"),
                           raw=json.dumps({k: f.get(k) for k in ("name", "dst_port", "fwd", "fwd_port", "src", "proto")}, ensure_ascii=False)))

    # réglages
    st = {s.get("key"): s for s in (data.get("settings") or [])}
    mgmt, ips, usg, snmp, ntp, rsys = (st.get(k, {}) for k in ("mgmt", "ips", "usg", "snmp", "ntp", "rsyslogd"))
    cfg.services = {
        "ips_mode": ips.get("ips_mode", ""), "ips_categories": len(ips.get("enabled_categories") or []),
        "honeypot": bool(ips.get("honeypot_enabled")), "upnp": bool(usg.get("upnp_enabled")),
        "ssh": bool(mgmt.get("x_ssh_enabled")), "ssh_password_auth": bool(mgmt.get("x_ssh_password_auth", mgmt.get("x_ssh_enabled"))),
        "snmp_communities": [snmp.get("community", "public")] if snmp.get("enabled") else [],
        "snmp_v3": bool(snmp.get("enabledV3")), "ntp": True, "log_remote": bool(rsys.get("enabled") or rsys.get("ip")),
        "dpi": bool(st.get("dpi", {}).get("enabled")), "geo_block": bool(st.get("country", {}).get("enabled")),
        "teleport": bool(st.get("teleport", {}).get("enabled")),
        "auto_upgrade": mgmt.get("auto_upgrade") if "auto_upgrade" in mgmt else None,
    }
    # Wi-Fi
    wl = []
    for w in data.get("wlans") or []:
        wl.append({"name": w.get("name"), "security": w.get("security"), "wpa_mode": w.get("wpa_mode"),
                   "wpa3": bool(w.get("wpa3_support")), "pmf": w.get("pmf_mode"), "guest": bool(w.get("is_guest")),
                   "enabled": w.get("enabled", True), "l2_isolation": bool(w.get("l2_isolation"))})
    cfg.services["wlans"] = wl
    # VPN
    for n in nets.values():
        pur = n.get("purpose", "")
        if pur == "site-vpn":
            cfg.vpn.append(VpnTunnel(name=n.get("name", ""), kind="ipsec",
                                     ike=2 if n.get("ipsec_key_exchange") == "ikev2" else 1,
                                     enc=[n.get("ipsec_encryption", "aes256")], auth=[n.get("ipsec_hash", "sha1")],
                                     dh=[int(n.get("ipsec_dh_group") or 14)], peer=n.get("ipsec_peer_ip", ""),
                                     enabled=n.get("enabled", True)))
        elif pur == "remote-user-vpn":
            cfg.vpn.append(VpnTunnel(name=n.get("name", ""), kind=n.get("vpn_type", "l2tp").replace("-server", ""),
                                     enabled=n.get("enabled", True)))
    for a in data.get("admins") or []:
        cfg.admins.append(Admin(name=a.get("name") or a.get("email", "?"), profile=a.get("role", ""),
                                mfa=bool(a.get("ui_mfa") or a.get("mfa")), default_name=(a.get("name") or "") in ("admin", "ubnt", "root")))
    return cfg


def guess_zone(name: str) -> str:
    from .model import guess_role
    return guess_role(name)


_ = DENY
