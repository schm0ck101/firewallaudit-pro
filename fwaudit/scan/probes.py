"""Tests réels du pare-feu, depuis le PC d'audit :

* filtrage SORTANT : connexions TCP vers portquiz.net (serveur public qui
  écoute sur tous les ports), DNS direct vers des résolveurs publics, DNS
  chiffré (DoT 853, DoH), NTP, ping ;
* CLOISONNEMENT : depuis le réseau où le PC est branché, ce qui est
  joignable dans les autres réseaux connus du pare-feu ;
* EXPOSITION EXTERNE : scan des IP publiques du client depuis une connexion
  extérieure (partage 4G du technicien), bannières, pages et certificats.

Uniquement des connexions et requêtes ordinaires : aucun paquet forgé, aucune
tentative d'authentification.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from ..net import dnsmsg, icmp, ports, tests

PORTQUIZ = "portquiz.net"
EGRESS_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP (envoi direct de courriels)", 53: "DNS (TCP)", 80: "HTTP",
                110: "POP3", 135: "RPC Microsoft", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB (partages Windows)",
                465: "SMTPS", 587: "Soumission de courriels", 853: "DNS chiffré (DoT)", 993: "IMAPS", 995: "POP3S",
                1080: "Proxy SOCKS", 1194: "OpenVPN", 1433: "SQL Server", 1723: "PPTP", 3306: "MySQL", 3389: "Bureau à distance",
                4444: "Port de « reverse shell »", 5060: "SIP", 5222: "Messagerie XMPP", 5900: "VNC", 6667: "IRC (botnets)",
                6881: "BitTorrent", 8080: "HTTP alternatif", 8443: "HTTPS alternatif", 9001: "Tor", 25565: "Minecraft",
                31337: "port élevé quelconque", 50000: "port élevé quelconque", 51413: "BitTorrent"}
PUBLIC_DNS = {"8.8.8.8": "Google", "1.1.1.1": "Cloudflare", "9.9.9.9": "Quad9", "208.67.222.222": "OpenDNS"}

EXTERNAL_TCP = sorted(set(ports.PORTS_DEEP) | {500, 1194, 1701, 1723, 4433, 4443, 4444, 8000, 8001, 8008, 8081, 8088, 8291, 8443,
                                                8728, 8729, 8888, 9443, 10000, 10443, 11443, 2222, 2200, 3390, 33890, 5800, 6443,
                                                7443, 8006, 8880, 9000, 9090, 9999, 50443, 60443, 32400})


# --------------------------------------------------------------- sortant
# serveurs publics qui répondent sur TOUS les ports TCP, et la réponse attendue (vérifiée : une simple connexion
# ne suffit pas, un équipement intermédiaire peut répondre à la place du serveur)
ECHO_SERVERS = [("letmeoutofyour.net", b"w00tw00t"), ("portquiz.net", b"Port test successful")]


def _probe_port(host: str, ip: str, port: int, expect: bytes, timeout: float = 4.0) -> str:
    """'open' (le serveur de test a répondu), 'intercepted' (connexion acceptée, réponse étrangère),
    'closed' (refus ou délai)."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return "closed"
    try:
        s.settimeout(timeout)
        s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: FirewallAuditPro\r\n\r\n".encode())
        data = b""
        t0 = time.monotonic()
        while len(data) < 8192 and time.monotonic() - t0 < timeout:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            data += chunk
            if expect in data:
                return "open"
        return "open" if expect in data else "intercepted"
    finally:
        s.close()


def egress(cancel: threading.Event | None = None, progress=None) -> dict:
    out: dict = {"tcp": {}, "dns_direct": {}, "dot": None, "doh": None, "ntp": None, "icmp": None}
    fallback = None
    for host, expect in ECHO_SERVERS:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            continue
        # le serveur de test répond-il sur un port très courant ? (80 / 443 / 8080)
        states = []
        for p0 in (80, 443, 8080):
            st = _probe_port(host, ip, p0, expect)
            states.append(st)
            if st == "open":
                break
        if "open" in states:
            out["target"], out["target_ip"] = host, ip
            break
        if "intercepted" in states and not fallback:
            fallback = (host, ip)             # joignable, mais réponses modifiées (proxy web, déchiffrement SSL)
    else:
        if fallback:
            out["target"], out["target_ip"] = fallback
            out["proxied"] = True
        else:
            out["error"] = ("Aucun serveur de test des ports sortants joignable (Internet coupé, résolution DNS impossible, "
                            "ou ports 80/443/8080 sortants bloqués).")
            return out

    def one(p):
        if cancel and cancel.is_set():
            return p, None
        return p, _probe_port(out["target"], out["target_ip"], p, dict(ECHO_SERVERS)[out["target"]])
    # Critère retenu : la connexion TCP aboutit (un pare-feu qui bloque la refuse ou la laisse expirer).
    # Le contenu de la réponse n'est qu'une indication (le serveur de test limite les connexions simultanées ;
    # une réponse étrangère répétée peut aussi signaler un proxy transparent).
    with ThreadPoolExecutor(2) as ex:
        for p, st in ex.map(one, sorted(EGRESS_PORTS)):
            if st:
                out["tcp"][str(p)] = {"open": st != "closed", "verified": st == "open"}
    for p, st in list(out["tcp"].items()):
        if not st["open"] and not (cancel and cancel.is_set()):       # 2e essai, plus patient, avant de conclure « bloqué »
            st2 = _probe_port(out["target"], out["target_ip"], int(p), dict(ECHO_SERVERS)[out["target"]], 8.0)
            out["tcp"][p] = {"open": st2 != "closed", "verified": st2 == "open"}
    for srv, name in PUBLIC_DNS.items():
        r = dnsmsg.query(srv, "www.wikipedia.org", "A", timeout=2.5)
        out["dns_direct"][srv] = {"provider": name, "ok": r["ok"] and r.get("rcode") == "OK"}
    out["dot"] = tests.tcp_connect_ms("1.1.1.1", 853, 3.0) is not None
    try:
        req = urllib.request.Request("https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                                     headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            out["doh"] = "Answer" in r.read(4000).decode("utf-8", "replace")
    except Exception:
        out["doh"] = False
    out["ntp"] = tests.sntp_offset("pool.ntp.org").get("ok")
    out["icmp"] = icmp.probe("1.1.1.1", timeout_ms=1500).reached
    return out


# ---------------------------------------------------------- cloisonnement
SEG_PORTS = [22, 23, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443, 9100, 554, 1433, 5985]


def segmentation(targets: list[dict], local_nets: list[str], cancel: threading.Event | None = None,
                 max_hosts: int = 254, progress=None) -> dict:
    """targets : [{name, network, role, gateway}] = autres réseaux du pare-feu.
    Pour chacun : passerelle (interface du pare-feu) et hôtes joignables (ping + ports courants)."""
    own = [ipaddress.IPv4Network(n) for n in local_nets]
    res = {}
    for t in targets:
        if cancel and cancel.is_set():
            break
        try:
            net = ipaddress.IPv4Network(t["network"], strict=False)
        except ValueError:
            continue
        if any(net.overlaps(o) for o in own) or net.num_addresses > 4096 or net.prefixlen >= 31:
            continue
        if progress:
            progress(f"{t['network']} ({t.get('name', '')})")
        hosts = [str(h) for h in net.hosts()][:max_hosts]
        alive: dict[str, dict] = {}
        lock = threading.Lock()

        def ping(h):
            if cancel and cancel.is_set():
                return
            r = icmp.probe(h, timeout_ms=600)
            if r.reached:
                with lock:
                    alive.setdefault(h, {"icmp": True, "ports": []})
        with ThreadPoolExecutor(96) as ex:
            list(ex.map(ping, hosts))
        # sans réponse au ping : quelques ports courants sur tout le réseau
        rest = [h for h in hosts if h not in alive]
        quick = ports.scan(rest, [445, 3389, 80, 443, 22, 9100, 554], timeout=0.5, workers=256, cancel=cancel)
        for h, ps in quick.items():
            if ps:
                alive.setdefault(h, {"icmp": False, "ports": []})
        if alive:
            sc = ports.scan(sorted(alive), SEG_PORTS, timeout=0.8, workers=256, cancel=cancel)
            for h, ps in sc.items():
                alive[h]["ports"] = ps
        intercepted: list[int] = []
        dead = [h for h in reversed(hosts) if h not in alive and h != t.get("gateway")][:3]
        if alive and dead and not (cancel and cancel.is_set()):
            canary = ports.scan(dead, SEG_PORTS, timeout=0.8, workers=64, cancel=cancel)
            intercepted = sorted({pt for ps in canary.values() for pt in ps})
        if intercepted:
            for h in list(alive):
                alive[h]["ports"] = [pt for pt in alive[h]["ports"] if pt not in intercepted]
                if not alive[h]["ports"] and not alive[h]["icmp"]:
                    alive.pop(h)
        gw = t.get("gateway") or ""
        alive.pop(gw, None)                 # l'interface du pare-feu est rapportée à part
        gw_ports = ports.scan([gw], [22, 23, 80, 443, 8443, 4444, 10443, 8291, 161], 0.8)[gw] if gw else []
        res[t["network"]] = {"name": t.get("name", ""), "role": t.get("role", ""), "scanned": len(hosts),
                             "reachable": len(alive), "hosts": alive, "gateway": gw, "gateway_ports": gw_ports,
                             "intercepted_ports": intercepted}
    return res


# ------------------------------------------------------------- externe
def current_public_ip() -> str:
    r = tests.public_ip()
    return r.get("ip", "") if r.get("ok") else ""


def external_scan(targets: list[str], extra_ports: list[int] | None = None, cancel: threading.Event | None = None,
                  progress=None) -> dict:
    plist = sorted(set(EXTERNAL_TCP) | set(extra_ports or []))
    out = {"from_ip": current_public_ip(), "targets": {}, "ports_tested": len(plist), "t": time.time()}
    for ip in targets:
        if cancel and cancel.is_set():
            break
        if progress:
            progress(ip)
        res = ports.scan([ip], plist, timeout=2.0, workers=200, cancel=cancel)
        open_ = res.get(ip, [])
        info = ports.enrich({ip: open_}, True, cancel).get(ip, {}) if open_ else {}
        udp = {}
        r = dnsmsg.query(ip, "www.google.com", "A", timeout=2.0, tries=1)
        udp["dns_53"] = bool(r.get("ok")) and bool(r.get("answers"))
        udp["ntp_123"] = tests.sntp_offset(ip, 2.0).get("ok", False)
        from ..net import snmp
        udp["snmp_public"] = bool(snmp.probe(ip, [snmp.Credential("2c", "public")], timeout=2.0))
        reach = icmp.probe(ip, timeout_ms=1500).reached
        out["targets"][ip] = {"open": open_, "web": info.get("web", []), "banners": info.get("banners", {}),
                              "smb1": info.get("smb1"), "udp": udp, "icmp": reach}
    return out


def tls_cert_brand(web: list[dict]) -> list[str]:
    """Reconnaît une page d'administration / VPN de pare-feu à son titre, son serveur ou son certificat."""
    hits = []
    for w in web or []:
        blob = " ".join(str(x) for x in (w.get("title"), w.get("server"), (w.get("cert") or {}).get("subject"),
                                         (w.get("cert") or {}).get("issuer"), w.get("location"))).lower()
        for key, label in (("fortigate", "FortiGate"), ("fortinet", "FortiGate"), ("/remote/login", "VPN SSL FortiGate"),
                           ("sophos", "Sophos"), ("stormshield", "Stormshield"), ("watchguard", "WatchGuard"),
                           ("unifi", "UniFi"), ("routeros", "MikroTik"), ("mikrotik", "MikroTik"), ("pfsense", "pfSense"),
                           ("opnsense", "OPNsense"), ("sonicwall", "SonicWall"), ("globalprotect", "Palo Alto GlobalProtect"),
                           ("synology", "Synology DSM"), ("qnap", "QNAP"), ("outlook", "Exchange / OWA"),
                           ("remote desktop", "Passerelle RDS"), ("rdweb", "Passerelle RDS"), ("citrix", "Citrix"),
                           ("idrac", "iDRAC"), ("ilo", "HPE iLO"), ("proxmox", "Proxmox")):
            if key in blob:
                hits.append(f"port {w.get('port')} : {label} « {w.get('title') or ''} »")
                break
    return hits


_ = (json, ssl)
