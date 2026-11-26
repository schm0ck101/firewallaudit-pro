"""Règles d'analyse : chaque défaut piégé dans les configurations de test est
détecté, sans faux positif sur une configuration saine ; logique des tests
réels (sortie, cloisonnement, exposition externe)."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("FWAUDIT_DATA_DIR", str(Path(os.environ.get("TEMP", "/tmp")) / "fwaudit-tests"))

from fwaudit.analyze.engine import analyze  # noqa: E402
from fwaudit.analyze.model import CRIT, MAJOR, MINOR  # noqa: E402
from fwaudit.fw import forti, load  # noqa: E402

from test_readers import stormshield_zip  # noqa: E402

CFG = ROOT / "tests" / "configs"


def run(cfg, tests=None):
    a = analyze({"config": cfg.to_dict(), "meta": {}, "tests": tests or {}})
    assert not a.rule_errors, a.rule_errors
    return a


def sev(a, prefix):
    fs = [f for f in a.findings if f.id.startswith(prefix)]
    return max((f.severity for f in fs), default=None)


def test_fortigate_findings():
    a = run(load.from_file(CFG / "forti_siege.conf")[0])
    assert sev(a, "pol.inbound.2") == CRIT                    # RDP publié depuis tout Internet
    assert sev(a, "expo.nat") == CRIT
    assert sev(a, "pol.shadow.6") == MAJOR                    # « Bloquer SMB sortant » masquée par la règle 1
    assert sev(a, "pol.wide.5") == MAJOR                      # caméras -> tout
    assert sev(a, "pol.egress.1") == MINOR
    assert sev(a, "pol.inbound.8") == MINOR                   # RDP/Telnet mais source restreinte (prestataire)
    assert sev(a, "expo.admin") == CRIT                       # HTTP sur wan1
    assert sev(a, "expo.sslvpn") == MAJOR and sev(a, "sys.vpn.VPN-AGENCE") == MAJOR
    assert sev(a, "sys.fw") == MAJOR and sev(a, "sys.admin.trust") == MAJOR and sev(a, "sys.snmp.public") == MAJOR
    assert sev(a, "pol.redundant") == MINOR                   # règle 4 couverte par la règle 1
    assert a.scores["global"] <= 49


def test_mikrotik_findings():
    a = run(load.from_file(CFG / "mikrotik_agence.rsc")[0])
    assert sev(a, "pol.default.input") == CRIT                # pas de drop sur input -> routeur ouvert
    assert sev(a, "pol.default.filter") is None or sev(a, "pol.default.filter") == 0   # forward : drop WAN présent
    titles = " ".join(f.title for f in a.findings)
    assert "Winbox (port 8291) joignable depuis Internet" in titles and "Telnet (port 23)" in titles
    assert sev(a, "sys.vpn.pptp") == CRIT and sev(a, "expo.upnp") == MAJOR and sev(a, "expo.dns") == MAJOR
    assert sev(a, "sys.fw") == MAJOR                          # RouterOS v6


def test_mikrotik_hardened_is_quiet():
    txt = (CFG / "mikrotik_agence.rsc").read_text(encoding="utf-8")
    txt = txt.replace('add action=accept chain=input comment="winbox depuis partout" dst-port=8291 protocol=tcp\n',
                      'add action=drop chain=input in-interface-list=!LAN\n')
    txt = txt.replace("/ip upnp\nset enabled=yes", "/ip upnp\nset enabled=no").replace("set enabled=yes\n/ip ipsec", "set enabled=no\n/ip ipsec")
    from fwaudit.fw import mikrotik
    a = run(mikrotik.to_model(txt))
    assert sev(a, "pol.default.input") == 0
    assert not [f for f in a.findings if f.id.startswith("expo.admin") and f.severity >= MAJOR]
    assert sev(a, "expo.dns") is None


def test_sophos_stormshield_watchguard_unifi(tmp_path):
    s = run(load.from_file(CFG / "sophos_entities.xml")[0])
    assert sev(s, "pol.inbound.3") == CRIT and sev(s, "pol.shadow.4") == MAJOR and sev(s, "pol.wide.2") == MAJOR
    assert sev(s, "sys.fw") == MAJOR and sev(s, "sys.vpn.Agence") == MAJOR
    st = run(load.from_file(stormshield_zip(tmp_path))[0])
    assert sev(st, "pol.inbound.3") == CRIT and [f for f in st.findings if f.id.startswith("expo.admin") and f.severity >= MAJOR]
    assert sev(st, "pol.anyany") is None                       # la règle « tout ouvert » est désactivée
    wg = run(load.from_file(CFG / "watchguard.xml")[0])
    assert sev(wg, "pol.anyany.4") == CRIT and sev(wg, "sys.vpn.BOVPN-Agence") == MAJOR
    assert [f for f in wg.findings if f.id == "sys.admin.clear"]       # Telnet vers le boîtier
    u = run(load.from_file(CFG / "unifi_api.json", "unifi")[0])
    assert sev(u, "expo.nat") == CRIT and sev(u, "expo.upnp") == MAJOR and sev(u, "pol.redundant") == MINOR
    assert [f for f in u.findings if f.id.startswith("expo.admin") and f.severity == MAJOR]


def test_unifi_network11_real_structure():
    """Structure relevée sur une vraie console (UniFi OS 6 / Network 11) : règles prédéfinies, retours, portail invités,
    politiques par défaut des paires de zones, règles par client, redirection limitée par groupe d'adresses."""
    import json

    from fwaudit.fw import unifi
    data = json.loads((CFG / "unifi_network11.json").read_text(encoding="utf-8"))
    cfg = unifi.to_model(data)
    raw = unifi.sanitize(data)
    assert "SECRET" not in json.dumps(raw) and "zone_key" in json.dumps(raw) and "x_ssh_password_auth" in json.dumps(raw)
    assert len({r.id for r in cfg.rules}) == len(cfg.rules)                       # identifiants uniques
    dsm = next(n for n in cfg.nat if n.name.startswith("DSMS"))
    assert dsm.src_restrict and "198.51.100.4" in dsm.src_restrict
    a = analyze({"config": cfg.to_dict(), "meta": {"raw_api": raw}, "tests": {}})
    assert not a.rule_errors
    crit_or_major = [(f.id, f.title) for f in a.findings if f.severity >= MAJOR]
    # seul vrai problème : le réseau Caméras n'est bloqué vers Bureau par aucune règle (IoT, lui, l'est)
    assert len(crit_or_major) == 1 and "Caméras" in crit_or_major[0][1], crit_or_major
    assert not [f for f in a.findings if f.id.startswith(("pol.shadow", "pol.redundant", "pol.anyany", "pol.wide"))]
    assert not [f for f in a.findings if "Return" in f.title or "Guest" in f.title or "10.30.40" in f.title]
    assert sev(a, "expo.nat") != CRIT and sev(a, "sys.unifi.ssh") is None


def test_clean_fortigate_has_no_major():
    txt = '''#config-version=FGT40F-7.4.5-FW-build2702:opmode=0:vdom=0
config system global
    set hostname "FGT-OK"
    set admintimeout 10
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ping
        set role wan
    next
    edit "lan"
        set ip 192.168.1.254 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
end
config system admin
    edit "jdupont"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
        set two-factor fortitoken
    next
end
config log syslogd setting
    set status enable
end
config firewall address
    edit "LAN"
        set subnet 192.168.1.0 255.255.255.0
    next
end
config firewall service group
    edit "Web"
        set member "HTTP" "HTTPS" "DNS"
    next
end
config firewall policy
    edit 1
        set name "Web sortant"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN"
        set dstaddr "all"
        set service "Web"
        set utm-status enable
        set ips-sensor "default"
        set webfilter-profile "default"
        set av-profile "default"
        set logtraffic all
    next
end
'''
    a = run(forti.to_model(txt))
    bad = [(f.id, f.title) for f in a.findings if f.severity >= MAJOR]
    assert not bad, bad
    assert a.scores["global"] >= 85


def test_windows_semantics_no_shadow():
    from fwaudit.fw import windows
    data = {"profiles": [{"name": n, "enabled": "True", "inbound": "Block", "outbound": "Allow", "log_blocked": "True"}
                         for n in ("Domain", "Private", "Public")],
            "rules": [{"n": "Tout", "e": True, "d": 1, "a": 1, "p": 256, "lp": "*", "ra": "*", "pr": 7},
                      {"n": "RDP", "e": True, "d": 1, "a": 1, "p": 6, "lp": "3389", "ra": "*", "pr": 7},
                      {"n": "Python", "e": True, "d": 1, "a": 1, "p": 6, "lp": "*", "ra": "*", "pr": 4, "app": "C:\\python.exe"},
                      {"n": "Store", "e": True, "d": 1, "a": 1, "p": 256, "lp": "*", "ra": "*", "pr": 7, "owner": "S-1-5-21-1-1001"}],
            "host": {"name": "PC1", "os": "Windows 11", "build": "26100", "server": False},
            "connections": {"alias": "Ethernet", "category": "Public"}}
    a = run(windows.to_model(data))
    ids = {f.id: f.severity for f in a.findings}
    assert ids.get("pol.win.anyport") == MAJOR and ids.get("pol.win.3389") == MAJOR and ids.get("pol.win.prog") == MINOR
    assert "pol.redundant" not in ids and not any(i.startswith("pol.shadow") for i in ids)    # pas d'ordre sous Windows
    prog = next(f for f in a.findings if f.id == "pol.win.prog")
    assert len(prog.evidence) == 1                                                            # la règle du Store n'y figure pas
    data["profiles"][2]["enabled"] = "False"
    assert {f.id: f.severity for f in run(windows.to_model(data)).findings}.get("sys.win.off.Public") == CRIT


def test_real_tests_logic():
    cfg = load.from_file(CFG / "forti_siege.conf")[0]
    tests = {"egress": {"tcp": {"445": {"open": True}, "25": {"open": True}, "443": {"open": True}, "22": {"open": False}},
                        "dns_direct": {"8.8.8.8": {"provider": "Google", "ok": True}}, "dot": True, "doh": False},
             "audit_network": {"network": "10.20.40.0/24", "role": "guest"},
             "segmentation": {"192.168.1.0/24": {"name": "internal", "role": "lan", "scanned": 254, "reachable": 3,
                                                 "hosts": {"192.168.1.10": {"ports": [445, 3389]}}, "gateway": "192.168.1.254"}},
             "external": {"from_ip": "198.51.100.200", "ports_tested": 200,
                          "targets": {"203.0.113.3": {"open": [3389, 8443, 5900], "web": [{"port": 8443, "title": "FortiGate", "status": 200}],
                                                      "banners": {}, "udp": {"dns_53": False, "snmp_public": True}}}}}
    a = run(cfg, tests)
    got = {f.id: f.severity for f in a.findings}
    assert got["test.egress.mismatch.445"] == MAJOR          # la règle 6 devait bloquer SMB… mais elle est masquée
    assert got["test.egress.25"] == MAJOR and got["test.dns.direct"] == MINOR
    assert got["test.seg.192.168.1.0/24"] == CRIT            # depuis le réseau invités, un serveur SMB/RDP est joignable
    assert got["test.ext.sens.203.0.113.3"] == CRIT and got["test.ext.admin.203.0.113.3"] == MAJOR
    assert got["test.ext.unexp.203.0.113.3"] == MAJOR        # 5900 n'est prévu nulle part dans la config
    assert got["test.ext.snmp.203.0.113.3"] == CRIT


def test_partial_and_empty_inputs():
    for snap in ({}, {"config": {"vendor": "X"}}, {"config": {"vendor": "X", "rules": [], "interfaces": []}, "tests": {"egress": {"error": "x"}}}):
        a = analyze(snap)
        assert not a.rule_errors, a.rule_errors


def test_watchguard_real_structure():
    """Structure d'un vrai Firebox (Fireware 2026.4) : proxys (firewall 4) qui laissent passer, politiques système
    (property 32), NAT porté par la politique, alias enveloppés et imbriqués, géolocalisation, VLAN, agrégat 0.0.0.0."""
    cfg = load.from_file(CFG / "watchguard_fireware2026.xml")[0]
    roles = {i.name: (i.role, i.ips) for i in cfg.interfaces}
    assert "Any-External" not in roles                                                # zones intégrées : pas des interfaces
    assert roles["OPERATEUR"] == ("wan", ["203.0.113.77/29"]) and roles["vlan-invite"][0] == "guest"
    assert roles["VOIP"][0] == "lan" and roles["TUNNEL-SECOND"][0] == "vpn"
    assert roles["AGGR-LAN"][1] == [] and roles["LA-1"][1] == []                     # 0.0.0.0 : pas de réseau « tout »
    by = {r.name: r for r in cfg.rules}
    assert by["SMTP-proxy Sortant-00"].action == "allow" and "IPS" in by["SMTP-proxy Sortant-00"].profiles
    assert by["Unhandled External Packet-00"].action == "deny" and by["Any From Firebox-00"].comment == "prédéfinie"
    assert by["WatchGuard-00"].layer == "input"
    nat = {n.id: n for n in cfg.nat}
    assert nat["VIP-FTP"].int_ip == "192.168.1.15" and "RESTRICTION_FRANCE" in nat["VIP-FTP"].src_restrict[0]
    assert nat["VIP-RDP"].src_restrict == ["198.51.100.10"]                            # alias enveloppé + imbriqué résolu
    v = cfg.vpn[0]
    assert len(cfg.vpn) == 1 and v.ike == 2 and v.enc == ["AES-256"] and v.auth == ["SHA2-256"] and v.dh == [14]
    assert cfg.services["log_remote"] is False and not cfg.services["snmp_communities"]
    a = run(cfg, {"egress": {"tcp": {"25": {"open": True}, "80": {"open": True}}}})
    got = {f.id: f.severity for f in a.findings}
    assert not [i for i in got if i.startswith("test.egress.mismatch")], got        # le proxy SMTP laisse passer
    assert got.get("pol.inbound.3") == MAJOR                                          # FTP ouvert (France seulement)
    assert got.get("pol.wide.8") == MINOR                                             # tout autorisé dans le tunnel
    assert not [i for i in got if i.endswith(".2") or i.startswith("pol.redundant")], got
    assert [f for f in a.findings if f.id.startswith("expo.admin.") and "#7" in f.title and f.severity == MINOR]
    assert got.get("sys.vpn.SITE-SECOND") == 0 and got.get("sys.log") == MINOR
    # IP publique vue depuis le réseau d'audit hors des interfaces Internet du pare-feu : autre chemin de sortie
    a2 = run(cfg, {"egress": {"tcp": {"25": {"open": True}}}, "public_measured": "198.51.100.225"})
    assert {f.id: f.severity for f in a2.findings}.get("test.path") == MAJOR
    assert "test.path" not in got
    a3 = run(cfg, {"egress": {"tcp": {"25": {"open": True}, "4444": {"open": True}, "22": {"open": False}}},
                   "audit_network": {"network": "192.168.1.0/24", "interface": "LAN", "role": "lan"}})
    assert {f.id: f.severity for f in a3.findings}.get("test.egress.unexpected") == MAJOR   # 4444 sort sans règle
    a4 = run(cfg, {"egress": {"tcp": {"25": {"open": True}, "22": {"open": False}}},
                   "audit_network": {"network": "192.168.1.0/24", "interface": "LAN", "role": "lan"}})
    assert [f for f in a4.findings if f.id == "test.egress.match"]
    eg = next(f for f in a.findings if f.id == "test.egress.25")
    assert eg.severity == MINOR and "#4" in eg.detail                                  # prévu par le proxy SMTP, inspecté
    adm = next(f for f in a.findings if f.id.startswith("expo.admin.") and "#7" in f.title)
    assert "192.168." not in adm.title                                                # seules les sources publiques sont citées
