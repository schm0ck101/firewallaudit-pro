"""Lecteur Sophos Firewall (SFOS v18 à v21) : fichier « Entities.xml » obtenu par
Sauvegarde et firmware › Import/Export › Exporter la configuration complète
(archive .tar contenant Entities.xml, acceptée telle quelle).

L'ordre des règles est celui du fichier (ordre d'évaluation de SFOS).
"""
from __future__ import annotations

import io
import tarfile
import xml.etree.ElementTree as ET
import zipfile

from .model import ALLOW, DENY, WAN, Admin, FwConfig, Interface, Nat, Rule, VpnTunnel, guess_role
from .sets import AddrSet, SvcSet, parse_addr

ZONE_TYPE = {"LAN": "lan", "WAN": WAN, "DMZ": "dmz", "VPN": "vpn", "WiFi": "guest", "Local": "local"}
DH = {"1(DH768)": 1, "2(DH1024)": 2, "5(DH1536)": 5, "14(DH2048)": 14, "15(DH3072)": 15, "16(DH4096)": 16,
      "19(ecp256)": 19, "20(ecp384)": 20, "21(ecp521)": 21, "31(curve25519)": 31}


def extract_xml(raw: bytes) -> bytes:
    """Entities.xml depuis un .tar / .tar.gz / .zip / ou le XML lui-même."""
    if raw.lstrip()[:5] == b"<?xml" or raw.lstrip()[:1] == b"<":
        return raw
    bio = io.BytesIO(raw)
    try:
        with tarfile.open(fileobj=bio) as t:
            for m in t.getmembers():
                if m.name.lower().endswith("entities.xml"):
                    return t.extractfile(m).read()
    except tarfile.TarError:
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for n in z.namelist():
                if n.lower().endswith("entities.xml"):
                    return z.read(n)
    except zipfile.BadZipFile:
        pass
    raise ValueError("Entities.xml introuvable dans le fichier (export Sophos attendu)")


def _t(el, path: str, default: str = "") -> str:
    x = el.find(path) if el is not None else None
    return (x.text or "").strip() if x is not None and x.text else default


def _ts(el, path: str) -> list[str]:
    return [(x.text or "").strip() for x in el.findall(path)] if el is not None else []


def to_model(raw: bytes, source: str = "") -> FwConfig:
    root = ET.fromstring(extract_xml(raw))
    apiv = root.get("APIVersion", "")
    ver = ""
    if apiv[:4].isdigit():                       # « 1905.1 » = SFOS 19.5, « 2100.1 » = SFOS 21.0
        ver = f"SFOS {int(apiv[:2])}.{int(apiv[2:4])}"
    cfg = FwConfig(vendor="Sophos Firewall", version=ver, source=source)
    cfg.hostname = _t(root, ".//HostName") or _t(root, ".//ApplianceName")

    # zones et services d'administration par zone
    zone_admin = {}
    for z in root.iter("Zone"):
        name = _t(z, "Name")
        role = ZONE_TYPE.get(_t(z, "Type"), guess_role(name))
        cfg.zones[name] = role
        adm = []
        for grp in ("AdminServices", "AuthenticationServices", "NetworkServices", "OtherServices"):
            g = z.find(f"ApplianceAccess/{grp}")
            if g is not None:
                adm += [c.tag.lower() for c in g if (c.text or "").strip().lower() == "enable"]
        zone_admin[name] = adm
    for i in root.iter("Interface"):
        name = _t(i, "Name")
        zone = _t(i, "NetworkZone")
        ip, mask = _t(i, "IPAddress"), _t(i, "Netmask")
        cidr = []
        if ip and mask:
            import ipaddress
            try:
                cidr.append(str(ipaddress.IPv4Interface(f"{ip}/{mask}")))
            except ValueError:
                pass
        cfg.interfaces.append(Interface(name=name, role=cfg.zones.get(zone, guess_role(zone)), zone=zone, ips=cidr,
                                        admin=zone_admin.get(zone, []), description=_t(i, "Hardware")))
    for v in root.iter("VLAN"):
        zone = _t(v, "Zone")
        cfg.interfaces.append(Interface(name=_t(v, "Name") or f"{_t(v, 'Hardware')}.{_t(v, 'VLANID')}",
                                        role=cfg.zones.get(zone, guess_role(zone)), zone=zone,
                                        vlan=int(_t(v, "VLANID")) if _t(v, "VLANID").isdigit() else None,
                                        admin=zone_admin.get(zone, [])))

    # objets
    hosts: dict[str, AddrSet] = {}
    for h in root.iter("IPHost"):
        typ = _t(h, "HostType")
        name = _t(h, "Name")
        if typ == "IP":
            r = parse_addr(_t(h, "IPAddress"))
        elif typ == "Network":
            r = parse_addr(f"{_t(h, 'IPAddress')} {_t(h, 'Subnet')}")
        elif typ == "IPRange":
            r = parse_addr(f"{_t(h, 'StartIPAddress')}-{_t(h, 'EndIPAddress')}")
        elif typ == "IPList":
            hosts[name] = AddrSet.parse(_t(h, "ListOfIPAddresses").split(","))
            continue
        else:
            r = None
        hosts[name] = AddrSet([r]) if r else AddrSet(opaque=frozenset([name]))
    for f in root.iter("FQDNHost"):
        hosts[_t(f, "Name")] = AddrSet(opaque=frozenset([f"{_t(f, 'Name')} ({_t(f, 'FQDN')})"]))
    hgroups = {_t(g, "Name"): _ts(g, "HostList/Host") for g in root.iter("IPHostGroup")}
    svcs: dict[str, SvcSet] = {}
    for s in root.iter("Services"):
        name = _t(s, "Name")
        if not name:
            continue
        ss = SvcSet()
        for d in s.iter("ServiceDetail"):
            proto = _t(d, "Protocol").lower() or _t(d, "ProtocolName").lower()
            dp = _t(d, "DestinationPort")
            if proto in ("tcp", "udp") and dp:
                lo, _, hi = dp.replace(":", "-").partition("-")
                if lo.isdigit():
                    ss.add(proto, int(lo), int(hi) if hi.isdigit() else int(lo))
            elif proto:
                ss.add(proto if proto != "icmp" else "icmp")
        svcs[name] = ss if (ss.m or ss.opaque) else SvcSet(opaque=frozenset([name]))
    sgroups = {_t(g, "Name"): _ts(g, "ServiceList/Service") for g in root.iter("ServiceGroup")}

    def addr(names: list[str], depth=0) -> AddrSet:
        if not names:
            return AddrSet.any()
        s = AddrSet()
        for n in names:
            if n.lower() in ("any", ""):
                return AddrSet.any()
            if n in hgroups and depth < 8:
                s = s.union(addr(hgroups[n], depth + 1))
            elif n in hosts:
                s = s.union(hosts[n])
            else:
                s = s.union(AddrSet(opaque=frozenset([n])))
        return s

    def svc(names: list[str], depth=0) -> SvcSet:
        if not names:
            return SvcSet.any()
        s = SvcSet()
        for n in names:
            if n.lower() in ("any", "all"):
                return SvcSet.any()
            if n in sgroups and depth < 8:
                s = s.union(svc(sgroups[n], depth + 1))
            else:
                s = s.union(svcs.get(n, SvcSet(opaque=frozenset([n]))))
        return s

    pos = 0
    for fr in root.iter("FirewallRule"):
        pol = fr.find("NetworkPolicy")
        if pol is None:
            pol = fr.find("UserPolicy")
        if pol is None:
            pol = fr.find("HTTPBasedPolicy")
        if pol is None:
            continue
        r = Rule(id=str(pos + 1), position=pos, name=_t(fr, "Name"), enabled=_t(fr, "Status", "Enable") == "Enable")
        pos += 1
        act = _t(pol, "Action", "Drop")
        r.action = ALLOW if act == "Accept" else DENY
        r.src_zones, r.dst_zones = _ts(pol, "SourceZones/Zone"), _ts(pol, "DestinationZones/Zone")
        r.src_names = _ts(pol, "SourceNetworks/Network") or ["Any"]
        r.dst_names = _ts(pol, "DestinationNetworks/Network") or ["Any"]
        r.svc_names = _ts(pol, "Services/Service") or ["Any"]
        r.set_src(addr([n for n in r.src_names if n != "Any"]))
        r.set_dst(addr([n for n in r.dst_names if n != "Any"]))
        r.set_svc(svc([n for n in r.svc_names if n != "Any"]))
        r.users = _ts(pol, "Identity/Member")
        sch = _t(pol, "Schedule", "All The Time")
        r.schedule = "" if sch in ("All The Time", "") else sch
        r.log = _t(pol, "LogTraffic", "Disable") == "Enable"
        prof = []
        for tag, label in (("WebFilter", "filtrage web"), ("ApplicationControl", "contrôle applicatif"),
                           ("IntrusionPrevention", "IPS"), ("ScanVirus", "antivirus"), ("ScanFTP", "antivirus FTP"),
                           ("DecryptHTTPS", "inspection HTTPS"), ("ProxyMode", "proxy")):
            v = _t(pol, tag)
            if v and v not in ("None", "Disable", "Allow All", "0"):
                prof.append(f"{label}:{v}")
        r.profiles = prof
        r.comment = _t(fr, "Description")
        r.raw = ET.tostring(fr, encoding="unicode")[:1200]
        cfg.rules.append(r)

    for i, nr in enumerate(root.iter("NATRule")):
        td = _t(nr, "TranslatedDestination")
        if not td or td.lower() in ("original", ""):
            continue
        od = _ts(nr, "OriginalDestinationNetworks/Network")
        osv = _ts(nr, "OriginalServices/Service")
        ports = []
        for n in osv:
            s = svcs.get(n)
            if s:
                for lo, hi in s.ports(6) + s.ports(17):
                    ports.append(str(lo) if lo == hi else f"{lo}-{hi}")
        src = _ts(nr, "OriginalSourceNetworks/Network")
        cfg.nat.append(Nat(id=str(i), name=_t(nr, "Name"), enabled=_t(nr, "Status", "Enable") == "Enable",
                           ext_ip=",".join(od), ext_ports=",".join(sorted(set(ports))) or ("" if not osv else ",".join(osv)),
                           int_ip=", ".join(addr([td]).describe(2).split(", ")) if td in hosts else td,
                           src_restrict=[s for s in src if s.lower() != "any"], raw=ET.tostring(nr, encoding="unicode")[:1000]))

    # administrateurs
    for u in root.iter("User"):
        if _t(u, "UserType") == "Administrator":
            name = _t(u, "Username")
            cfg.admins.append(Admin(name=name, profile=_t(u, "Profile"), enabled=_t(u, "Status", "Active") == "Active",
                                    mfa=_t(u, "OTP") == "Enable" or None, default_name=name.lower() == "admin"))
    # VPN IPsec
    policies = {}
    for p in root.iter("IPSecPolicy"):
        ph1 = p.find("Phase1")
        enc = [_t(ph1, f"EncryptionAlgorithm{i}") for i in (1, 2, 3) if _t(ph1, f"EncryptionAlgorithm{i}")]
        auth = [_t(ph1, f"AuthenticationAlgorithm{i}") for i in (1, 2, 3) if _t(ph1, f"AuthenticationAlgorithm{i}")]
        dh = [DH.get(x.text.strip(), 0) for x in ph1.iter("DHGroup")] if ph1 is not None else []
        policies[_t(p, "Name")] = {"ike": 2 if "2" in _t(p, "KeyExchange") else 1, "enc": enc, "auth": auth, "dh": dh,
                                   "mode": _t(p, "AuthenticationMode", "Main Mode").lower()}
    for c in list(root.iter("SiteToSiteVPN")) + list(root.iter("IPSecConnection")):
        pol = policies.get(_t(c, "Policy"), {})
        cfg.vpn.append(VpnTunnel(name=_t(c, "Name"), kind="ipsec", ike=pol.get("ike"), enc=pol.get("enc", []),
                                 auth=pol.get("auth", []), dh=pol.get("dh", []), psk=_t(c, "AuthenticationType") == "PresharedKey",
                                 peer=_t(c, "RemoteHost") or _t(c, "RemoteGateway"), mode=pol.get("mode", ""),
                                 enabled=_t(c, "Status", "Active") in ("Active", "Enable", "")))
    if any(True for _ in root.iter("SSLTunnelAccessSettings")) or any(True for _ in root.iter("SSLVPNPolicy")):
        cfg.vpn.append(VpnTunnel(name="SSL VPN (accès distant)", kind="ssl"))
    if any(_t(x, "Status") == "Enable" for x in root.iter("PPTPConfiguration")):
        cfg.vpn.append(VpnTunnel(name="PPTP", kind="pptp"))
    snmp = [_t(c, "Name") for c in root.iter("SNMPCommunity")]
    cfg.services = {"snmp_communities": [s for s in snmp if s],
                    "log_remote": any(True for _ in root.iter("SyslogServers")) or bool(list(root.iter("Syslog"))),
                    "ntp": bool(list(root.iter("NTPServer")) or list(root.iter("Time"))),
                    "admin_https_port": _t(root, ".//WebAdminSettings/HTTPSport") or _t(root, ".//HTTPSport", "4444"),
                    "user_portal_wan": "userportal" in (zone_admin.get("WAN") or []),
                    "zone_admin": zone_admin}
    return cfg


def detect(raw: bytes) -> bool:
    head = raw[:4000]
    return b"<Configuration" in head and (b"APIVersion" in head or b"FirewallRule" in raw[:2_000_000]) or b"Entities.xml" in head


_ = Admin
