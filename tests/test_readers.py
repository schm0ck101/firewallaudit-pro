"""Lecteurs de configuration (fichiers de test construits d'après les formats
des constructeurs) et arithmétique des ensembles d'adresses / services."""
import io
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("FWAUDIT_DATA_DIR", str(Path(os.environ.get("TEMP", "/tmp")) / "fwaudit-tests"))

from fwaudit.fw import load, mikrotik  # noqa: E402
from fwaudit.fw.sets import AddrSet, SvcSet, parse_addr  # noqa: E402

CFG = ROOT / "tests" / "configs"


def stormshield_zip(tmp_path) -> Path:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        base = CFG / "stormshield"
        for p in base.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(base).as_posix())
    out = tmp_path / "sns.zip"
    out.write_bytes(bio.getvalue())
    return out


def test_sets_cover_intersect_negate():
    lan = AddrSet.parse(["192.168.1.0/24"])
    host = AddrSet.parse(["192.168.1.10"])
    other = AddrSet.parse(["10.0.0.0/8"])
    assert lan.covers(host) and not host.covers(lan) and AddrSet.any().covers(lan)
    assert lan.intersects(host) and not lan.intersects(other)
    neg = AddrSet(lan.iv, frozenset(), True)
    assert not neg.contains_ip("192.168.1.5") and neg.contains_ip("8.8.8.8") and not neg.covers(host)
    fq = AddrSet.parse(["www.exemple.fr"])
    assert fq.opaque and not lan.covers(fq) and AddrSet.any().covers(fq)
    assert parse_addr("10.0.0.0 255.255.255.0") == parse_addr("10.0.0.0/24")
    assert parse_addr("10.0.0.10-20")[1] - parse_addr("10.0.0.10-20")[0] == 10
    assert not lan.is_public() and AddrSet.parse(["8.8.8.0/24"]).is_public() and AddrSet.any().is_public()
    web = SvcSet().add("tcp", 80).add("tcp", 443) if False else SvcSet().add("tcp", 80, 80).add("tcp", 443, 443)
    allt = SvcSet().add("tcp")
    assert allt.covers(web) and not web.covers(allt) and SvcSet.any().covers(allt)
    assert web.has_port(443) and not web.has_port(22) and not web.has_port(443, 17)
    assert AddrSet.parse(["10.0.0.0/25", "10.0.0.128/25"]).iv == AddrSet.parse(["10.0.0.0/24"]).iv     # fusion


def test_fortigate_reader():
    cfg, meta = load.from_file(CFG / "forti_siege.conf")
    assert meta["vendor"] == "forti" and cfg.model == "FGT60F" and cfg.version == "7.0.12" and cfg.hostname == "FGT-SIEGE"
    wan = next(i for i in cfg.interfaces if i.name == "wan1")
    assert wan.role == "wan" and {"http", "https", "ssh"} <= set(wan.admin) and wan.ips == ["203.0.113.2/29"]
    r2 = next(r for r in cfg.rules if r.id == "2")
    assert r2.nat and r2.dst_set.contains_ip("192.168.1.10") and r2.svc_set.has_port(3389) and r2.log is False
    r4 = next(r for r in cfg.rules if r.id == "4")
    assert r4.svc_set.has_port(53, 17) and r4.svc_set.has_port(443) and not r4.svc_set.has_port(22)
    assert not next(r for r in cfg.rules if r.id == "7").enabled
    r8 = next(r for r in cfg.rules if r.id == "8")
    assert r8.src_set.contains_ip("198.51.100.7") and r8.dst_set.contains_ip("10.10.10.20")      # groupe d'adresses résolu
    assert {(n.ext_ip, n.ext_ports, n.int_ip) for n in cfg.nat} == {("203.0.113.3", "3389", "192.168.1.10"), ("203.0.113.4", "443", "10.10.10.20")}
    vpn = next(v for v in cfg.vpn if v.kind == "ipsec")
    assert vpn.ike == 1 and vpn.mode == "aggressive" and "3des" in vpn.enc and "md5" in vpn.auth and 2 in vpn.dh
    assert any(v.kind == "ssl" for v in cfg.vpn)
    assert {a.name for a in cfg.admins} == {"admin", "presta"} and next(a for a in cfg.admins if a.name == "presta").mfa
    assert cfg.services["snmp_communities"] == ["public"] and "OBJET_ORPHELIN" in cfg.objects_unused


def test_fortigate_multi_vdom_and_quotes():
    txt = '''#config-version=FG100F-7.4.4-FW-build2662:opmode=0:vdom=1
config global
config system interface
    edit "port1"
        set vdom "client-a"
        set ip 198.51.100.2 255.255.255.0
        set allowaccess ping
        set role wan
    next
end
end
config vdom
edit client-a
config firewall address
    edit "Serveur web"
        set subnet 10.1.1.5 255.255.255.255
    next
end
config firewall policy
    edit 3
        set name "Web public"
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set dstaddr "Serveur web"
        set service "HTTPS"
    next
end
next
edit client-b
config firewall policy
    edit 1
        set srcintf "port3"
        set dstintf "port1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
next
end
'''
    from fwaudit.fw import forti
    cfg = forti.to_model(txt)
    ids = {r.id for r in cfg.rules}
    assert ids == {"client-a:3", "client-b:1"} and cfg.version == "7.4.4"
    r = next(r for r in cfg.rules if r.id == "client-a:3")
    assert r.dst_set.contains_ip("10.1.1.5") and r.svc_set.has_port(443)


def test_mikrotik_reader_semantics():
    cfg, meta = load.from_file(CFG / "mikrotik_agence.rsc")
    assert meta["vendor"] == "mikrotik" and cfg.version == "6.48.6" and cfg.model == "RB4011iGS+" and cfg.hostname == "RB-AGENCE"
    assert cfg.default_action == "allow"                       # RouterOS accepte par défaut
    assert next(i for i in cfg.interfaces if i.name == "ether1").role == "wan"
    st = cfg.services["mikrotik_services_state"]
    assert st["telnet"] and st["winbox"] and not st["ftp"] and not st["api"]
    est = cfg.rules[0]
    assert est.layer == "input" and est.apps and est.apps[0].startswith("état")
    drop = cfg.rules[-1]
    assert drop.action == "deny" and drop.src_zones == ["WAN"] and drop.layer == "filter"
    assert any(n.ext_ports == "2222" and n.src_restrict == ["203.0.113.99"] for n in cfg.nat)
    assert any(v.kind == "pptp" for v in cfg.vpn) and cfg.services["upnp"] and cfg.services["dns_open_resolver"]
    # une ligne « /ip service set … » sur une seule ligne et les continuations « \\ »
    secs = mikrotik.parse_sections("/ip service set telnet disabled=yes\n/ip firewall filter\nadd action=drop \\\n    chain=input\n")
    assert secs["/ip service"][0][1]["_target"] == "telnet" and secs["/ip firewall filter"][0][1]["chain"] == "input"


def test_sophos_reader(tmp_path):
    cfg, meta = load.from_file(CFG / "sophos_entities.xml")
    assert meta["vendor"] == "sophos" and cfg.version == "SFOS 19.5"
    assert cfg.zones["WAN"] == "wan" and "https" in next(i for i in cfg.interfaces if i.name == "Port2").admin
    r3 = next(r for r in cfg.rules if r.name == "SQL depuis Internet")
    assert r3.src_zones == ["WAN"] and r3.svc_set.has_port(1433) and r3.dst_set.contains_ip("172.16.16.21")
    assert next(r for r in cfg.rules if r.name == "Internet LAN").profiles
    assert cfg.nat[0].int_ip.startswith("172.16.16.20") and cfg.nat[0].ext_ports == "3389"
    v = cfg.vpn[0]
    assert v.ike == 1 and "3DES" in v.enc and 2 in v.dh
    # même XML dans une archive .tar (format de l'export Sophos)
    import tarfile
    tp = tmp_path / "API-export.tar"
    with tarfile.open(tp, "w") as t:
        t.add(CFG / "sophos_entities.xml", arcname="Entities.xml")
    cfg2, meta2 = load.from_file(tp)
    assert meta2["vendor"] == "sophos" and len(cfg2.rules) == len(cfg.rules)


def test_stormshield_reader(tmp_path):
    cfg, meta = load.from_file(stormshield_zip(tmp_path))
    assert meta["vendor"] == "stormshield"
    roles = {i.name: i.role for i in cfg.interfaces}
    assert roles == {"out": "wan", "in": "lan", "dmz1": "dmz"}
    names = [r.name for r in cfg.rules]
    assert names[0].startswith("Admin") and cfg.rules[0].layer == "input"
    rds = next(r for r in cfg.rules if "RDS" in r.name)
    assert rds.src_zones == ["out"] and rds.dst_set.contains_ip("10.1.1.10") and rds.svc_set.has_port(3389)
    assert not next(r for r in cfg.rules if "ancienne" in r.name).enabled
    assert cfg.rules[-1].action == "deny" and cfg.rules[-1].src_set.is_any
    assert {(n.int_ip, n.ext_ports) for n in cfg.nat} == {("10.1.1.10", "3389"), ("10.1.2.25", "25")}
    assert cfg.services["snmp_communities"] == ["public"]


def test_watchguard_reader():
    cfg, meta = load.from_file(CFG / "watchguard.xml")
    assert meta["vendor"] == "watchguard" and cfg.version == "12.8.3" and cfg.model == "T40"
    assert {i.name: i.role for i in cfg.interfaces} == {"External": "wan", "Trusted": "lan", "Optional-1": "dmz"}
    nas = next(r for r in cfg.rules if r.name == "NAS-in")
    assert nas.nat and nas.dst_set.contains_ip("10.0.1.50") and nas.svc_set.has_port(5001)
    tel = next(r for r in cfg.rules if r.name == "Telnet-admin")
    assert tel.layer == "input" and tel.svc_set.has_port(23)
    assert cfg.vpn[0].enc == ["DES"] and cfg.nat and cfg.nat[0].int_ip == "10.0.1.50"


def test_unifi_reader():
    cfg, meta = load.from_file(CFG / "unifi_api.json", "unifi")
    assert cfg.model == "UDMPRO" and "Network 9.4.19" in cfg.version
    roles = {i.name: i.role for i in cfg.interfaces}
    assert roles["IoT"] == "iot" and roles["Invites"] == "guest" and roles["Internet 1"] == "wan"
    p1 = cfg.rules[0]
    assert p1.src_set.contains_ip("10.20.20.10") and p1.dst_set.contains_ip("10.20.10.50")   # zone « Internal » = ses réseaux
    p3 = next(r for r in cfg.rules if "Admin" in r.name)
    assert p3.layer == "input" and p3.src_zones == ["External"] and p3.svc_set.has_port(443) and not p3.svc_set.has_port(443, 17)
    assert {(n.ext_ports, n.int_ip) for n in cfg.nat} == {("32400", "10.20.10.12"), ("3389", "10.20.10.50")}
    assert cfg.services["upnp"] and cfg.services["ips_mode"] == "ids" and cfg.services["snmp_communities"] == ["public"]


def test_detection_rejects_unknown(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("bonjour", encoding="utf-8")
    try:
        load.from_file(p)
    except ValueError as exc:
        assert "non reconnu" in str(exc)
    else:
        raise AssertionError("fichier inconnu accepté")
