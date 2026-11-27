"""Corrections proposées : présentes pour toutes les marques, exactes (bonne règle / bon objet) et
syntaxiquement cohérentes (FortiOS : config/end et edit/next équilibrés ; RouterOS / PowerShell : une commande par ligne)."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fwaudit.analyze.engine import analyze  # noqa: E402
from fwaudit.analyze.model import MINOR  # noqa: E402
from fwaudit.fw import load, unifi, windows  # noqa: E402
from test_readers import stormshield_zip  # noqa: E402

CFG = Path(__file__).parent / "configs"


def run(cfg):
    return analyze({"config": cfg.to_dict(), "meta": {}, "tests": {}})


def fixes(a) -> dict:
    return {f.id: f for f in a.findings if f.remedy}


def forti_balanced(txt: str):
    lines = [ln.strip() for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert sum(ln.startswith("config ") for ln in lines) == sum(ln == "end" for ln in lines), txt
    assert sum(ln.startswith("edit ") for ln in lines) == sum(ln == "next" for ln in lines), txt


def coverage(a, min_ratio=0.75):
    probs = [f for f in a.problems if f.severity >= MINOR]
    done = [f for f in probs if f.remedy]
    assert probs and len(done) / len(probs) >= min_ratio, [f.id for f in probs if not f.remedy]


def test_fortigate_vdom_remedies():
    a = run(load.from_file(CFG / "forti_vdom_mpls.conf")[0])
    fx = fixes(a)
    for f in fx.values():
        assert f.remedy_kind == "cli-fortios"
        forti_balanced(f.remedy)
    cam = fx["pol.inbound.4"].remedy
    assert 'config vdom' in cam and 'edit "CLIENT"' in cam and "edit 4" in cam and 'set srcaddr "SRC-AUTORISEES-4"' in cam
    https = next(f for i, f in fx.items() if i.startswith("expo.admin.administration-web-https")).remedy
    assert "config global" in https and "set allowaccess ping" in https and 'unselect member "France"' in https
    snmp = next(f for i, f in fx.items() if i.startswith("expo.admin.snmp")).remedy
    assert 'edit "SNMP"' in snmp and "set udp-portrange 161-162" in snmp
    assert "set ssl-min-proto-ver tls1-2" in next(f for i, f in fx.items() if i.startswith("expo.ssl.tls")).remedy
    coverage(a)


def test_fortigate_remedies_and_unused_objects():
    cfg = load.from_file(CFG / "forti_siege.conf")[0]
    a = run(cfg)
    fx = fixes(a)
    for f in fx.values():
        forti_balanced(f.remedy)
        assert "config vdom" not in f.remedy                     # sauvegarde sans VDOM : pas d'enveloppe
    assert "set ike-version 2" in fx["sys.vpn.VPN-AGENCE"].remedy
    assert "move 6 before 1" in fx["pol.shadow.6"].remedy
    assert "delete 4" in fx["pol.redundant"].remedy
    coverage(a)


def test_fortigate_unused_object_really_unused():
    txt = (CFG / "forti_vdom_mpls.conf").read_text(encoding="utf-8")
    cfg = load.from_file(CFG / "forti_vdom_mpls.conf")[0]
    assert "GRP-MGMT" not in cfg.objects_unused and "France" not in cfg.objects_unused     # utilisés par local-in / groupe
    assert "IP_PRESTA" not in cfg.objects_unused and "LAN-SITES" not in cfg.objects_unused
    assert "edit" in txt


def test_mikrotik_remedies():
    a = run(load.from_file(CFG / "mikrotik_agence.rsc")[0])
    fx = fixes(a)
    for f in fx.values():
        assert f.remedy_kind == "routeros"
        for ln in f.remedy.splitlines():
            ln = ln.strip()
            assert not ln or ln.startswith("#") or ln.startswith("/") or ln.startswith("add "), ln
            assert "#" not in ln or ln.startswith("#") or "    #" in ln, ln
    assert "add chain=input action=drop in-interface-list=!LAN" in fx["pol.default.input"].remedy
    assert fx["sys.vpn.pptp.PPTP"].remedy == "/interface pptp-server server set enabled=no"
    coverage(a)


def test_windows_remedies():
    data = {"profiles": [{"name": n, "enabled": "True", "inbound": "Block", "outbound": "Allow", "log_blocked": "False"}
                         for n in ("Domain", "Private", "Public")],
            "rules": [{"n": "Tout", "e": True, "d": 1, "a": 1, "p": 256, "lp": "*", "ra": "*", "pr": 7},
                      {"n": "RemoteDesktop-UserMode-In-TCP", "e": True, "d": 1, "a": 1, "p": 6, "lp": "3389", "ra": "*", "pr": 7},
                      {"n": "Appli d'Éric", "e": True, "d": 1, "a": 1, "p": 6, "lp": "*", "ra": "*", "pr": 4, "app": r"C:\a.exe"}],
            "host": {"name": "PC1", "os": "Windows 11", "build": "26100", "server": False},
            "connections": {"alias": "Ethernet", "category": "Public"}}
    a = run(windows.to_model(data))
    fx = fixes(a)
    assert "Disable-NetFirewallRule -Name 'Tout'" in fx["pol.win.anyport"].remedy
    assert "-Name 'RemoteDesktop-UserMode-In-TCP' -Profile Domain,Private -RemoteAddress" in fx["pol.win.3389"].remedy
    assert "-Name 'Appli d''Éric'" in fx["pol.win.prog"].remedy                                  # apostrophe échappée
    assert "Set-NetFirewallProfile -Profile Public -LogBlocked True" in fx["sys.win.log.Public"].remedy
    assert all(f.remedy_kind == "powershell" for f in fx.values())


def test_gui_vendors_remedies(tmp_path):
    ss = run(load.from_file(stormshield_zip(tmp_path))[0])
    fx = fixes(ss)
    assert "règle n° 3" in fx["pol.inbound.3"].remedy and "Filtrage et NAT" in fx["pol.inbound.3"].remedy
    assert "Agent SNMP" in fx["sys.snmp.public"].remedy
    coverage(ss)
    wg = run(load.from_file(CFG / "watchguard_fireware2026.xml")[0])
    fx = fixes(wg)
    assert "Stratégies de pare-feu" in fx["pol.inbound.3"].remedy and "Any-External" in fx["pol.inbound.3"].remedy
    assert "Envoyer un message de journal" in fx["pol.nolog"].remedy                            # pas le texte syslog
    coverage(wg)
    uf = run(unifi.to_model(json.loads((CFG / "unifi_network11.json").read_text(encoding="utf-8"))))
    seg = next(f for f in uf.findings if f.id.startswith("pol.seg."))
    assert "Bloquer" in seg.remedy and "10.30.30.0/27" in seg.remedy and "« Allow All Traffic »" in seg.remedy
    so = run(load.from_file(CFG / "sophos_entities.xml")[0])
    assert "Device access" in fixes(so)[next(i for i in fixes(so) if i.startswith("expo.admin"))].remedy
    coverage(so)
    for a in (ss, wg, uf, so):
        assert all(f.remedy_kind == "gui" for f in a.findings if f.remedy)


def test_egress_test_remedies():
    """Constats « Terrain » : port sortant ouvert -> règle de blocage du port (FortiOS, RouterOS, Windows)."""
    cfg = load.from_file(CFG / "forti_siege.conf")[0]
    a = analyze({"config": cfg.to_dict(), "meta": {}, "tests": {"egress": {"tcp": {"445": True, "443": True, "25": True}}}})
    f = next(x for x in a.findings if x.id == "test.egress.25")
    assert "set tcp-portrange 25" in f.remedy and "set action deny" in f.remedy and "move <n° de la nouvelle règle> before" in f.remedy
    forti_balanced(f.remedy)
    m = next(x for x in a.findings if x.id == "test.egress.mismatch.445")      # bloqué dans la config mais sort : diagnostic
    assert "diagnose debug flow filter dport 445" in m.remedy
    mt = load.from_file(CFG / "mikrotik_agence.rsc")[0]
    a = analyze({"config": mt.to_dict(), "meta": {}, "tests": {"egress": {"tcp": {"445": True, "443": True}}}})
    f = next(x for x in a.findings if x.id == "test.egress.445")
    assert "add chain=forward action=drop protocol=tcp dst-port=445" in f.remedy


def test_remedy_notes():
    """Chaque correction porte ses points d'attention ; le retour arrière reprend les valeurs d'origine."""
    a = run(load.from_file(CFG / "forti_vdom_mpls.conf")[0])
    fx = fixes(a)
    assert all(f.remedy_notes for f in fx.values()), [i for i, f in fx.items() if not f.remedy_notes]
    adm = next(f for i, f in fx.items() if i.startswith("expo.admin.administration-web-https"))
    assert any(n.startswith("Avant : ") and "TESTER" in n for n in adm.remedy_notes)
    assert any(n.startswith("Retour arrière : ") and "ping https ssh snmp http" in n for n in adm.remedy_notes)
    cam = fx["pol.inbound.4"]
    assert any("source France" in n for n in cam.remedy_notes)
