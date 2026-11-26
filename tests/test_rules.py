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
