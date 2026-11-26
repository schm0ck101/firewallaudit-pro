"""Pare-feu Windows (Windows Defender Firewall) du poste ou serveur courant,
lu en PowerShell 5.1 sans modification : profils, action par défaut,
journalisation, règles (objet COM HNetCfg.FwPolicy2 : rapide même avec des
centaines de règles) et règles imposées par stratégie de groupe.

Pour un autre serveur : y lancer l'application (portable) ou la commande
« FirewallAuditPro.exe --windows-export fichier.json », puis importer le
fichier.
"""
from __future__ import annotations

import json
import time

from ..net import ps
from .model import ALLOW, DENY, LAN, WAN, Admin, FwConfig, Interface, Rule
from .sets import AddrSet, SvcSet, parse_addr

SCRIPT = r"""
T 'profiles' {
  @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    [ordered]@{ name = "$($_.Name)"; enabled = "$($_.Enabled)"; inbound = "$($_.DefaultInboundAction)"; outbound = "$($_.DefaultOutboundAction)";
      log_blocked = "$($_.LogBlocked)"; log_allowed = "$($_.LogAllowed)"; log_file = "$($_.LogFileName)"; log_size = [int]$_.LogMaxSizeKilobytes;
      local_rules = "$($_.AllowLocalFirewallRules)"; notify = "$($_.NotifyOnListen)"; unicast_multicast = "$($_.AllowUnicastResponseToMulticast)" } })
}
T 'rules' {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  $out = New-Object System.Collections.ArrayList
  foreach ($r in $fw.Rules) {
    [void]$out.Add([ordered]@{ n = $r.Name; g = $r.Grouping; e = [bool]$r.Enabled; d = [int]$r.Direction; a = [int]$r.Action;
      p = [int]$r.Protocol; lp = $r.LocalPorts; rp = $r.RemotePorts; la = $r.LocalAddresses; ra = $r.RemoteAddresses;
      pr = [int]$r.Profiles; app = $r.ApplicationName; svc = $r.ServiceName; et = [bool]$r.EdgeTraversal; it = $r.InterfaceTypes;
      desc = $r.Description; pk = $r.LocalAppPackageId; owner = $r.LocalUserOwner })
  }
  ,$out
}
T 'gpo_rules' {
  try { @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction Stop | Select-Object -First 2000 | ForEach-Object { "$($_.DisplayName)" }) } catch { @() }
}
T 'host' {
  $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
  [ordered]@{ name = $env:COMPUTERNAME; domain = $cs.Domain; part_of_domain = [bool]$cs.PartOfDomain; os = $os.Caption; build = $os.BuildNumber;
    server = ($os.ProductType -ne 1) }
}
T 'connections' {
  @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ alias = $_.InterfaceAlias; category = "$($_.NetworkCategory)"; index = [int]$_.InterfaceIndex } })
}
T 'listening' {
  @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '::1' } |
    Select-Object -Property LocalAddress, LocalPort, OwningProcess -Unique | ForEach-Object {
      $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      [ordered]@{ addr = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; proc = "$($p.ProcessName)" } })
}
T 'third_party' {
  try { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | ForEach-Object { "$($_.displayName)" }) } catch { @() }
}
"""

PROFILE_BITS = {1: "Domaine", 2: "Privé", 4: "Public"}
PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp", 256: None}


def collect(cancel=None) -> dict:
    data, err = ps.run(SCRIPT, timeout=120, cancel=cancel)
    data["_t"] = time.time()
    if err:
        data.setdefault("_errors", []).append(err)
    return data


def _addr(spec: str | None, local_nets: list[str]) -> tuple[AddrSet, list[str]]:
    if not spec or spec.strip() in ("*", ""):
        return AddrSet.any(), ["toutes"]
    s, names = AddrSet(), []
    for part in spec.split(","):
        part = part.strip()
        if part.lower() == "localsubnet":
            s = s.union(AddrSet.parse(local_nets) if local_nets else AddrSet(opaque=frozenset(["sous-réseau local"])))
            names.append("sous-réseau local")
            continue
        r = parse_addr(part)
        if r:
            s = s.union(AddrSet([r]))
        elif ":" not in part:
            s = s.union(AddrSet(opaque=frozenset([part])))
        names.append(part)
    return s, names


def _ports(spec: str | None, proto: int) -> SvcSet:
    pn = PROTO.get(proto, proto)
    if pn is None:
        return SvcSet.any()
    s = SvcSet()
    if not spec or spec.strip() == "*" or pn in ("icmp", "ipv6-icmp"):
        return s.add(pn)
    for part in spec.split(","):
        part = part.strip()
        lo, _, hi = part.partition("-")
        if lo.isdigit():
            s.add(pn, int(lo), int(hi) if hi.isdigit() else int(lo))
        else:
            s.opaque = s.opaque | {f"{pn}:{part}"}       # RPC, RPC-EPMap, IPHTTPS, PlayToDiscovery…
    return s


def _lst(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def to_model(data: dict, source: str = "") -> FwConfig:
    for k in ("profiles", "connections", "listening", "rules", "third_party", "gpo_rules"):
        data[k] = _lst(data.get(k))
    host = data.get("host") or {}
    cfg = FwConfig(vendor="Pare-feu Windows", hostname=host.get("name", ""), version=f"{host.get('os', '')} (build {host.get('build', '')})",
                   source=source or f"poste {host.get('name', '')}")
    cfg.services["windows_profiles"] = data.get("profiles") or []
    cfg.services["windows_connections"] = data.get("connections") or []
    cfg.services["windows_listening"] = data.get("listening") or []
    cfg.services["windows_third_party"] = data.get("third_party") or []
    cfg.services["windows_gpo_rules"] = len(data.get("gpo_rules") or [])
    cfg.services["windows_server"] = bool(host.get("server"))
    cfg.services["windows_domain"] = host.get("domain") if host.get("part_of_domain") else ""
    for p in data.get("profiles") or []:
        cfg.zones[p["name"]] = WAN if p["name"] == "Public" else LAN
    for c in data.get("connections") or []:
        cfg.interfaces.append(Interface(name=c.get("alias", ""), role=WAN if c.get("category") == "Public" else LAN,
                                        zone=c.get("category", "")))
    rules = data.get("rules") or []
    for i, r in enumerate(rules):
        proto = int(r.get("p") or 256)
        inbound = int(r.get("d") or 1) == 1
        rr = Rule(id=str(i + 1), position=i, name=r.get("n") or "", enabled=bool(r.get("e")),
                  action=ALLOW if int(r.get("a") or 0) == 1 else DENY, layer="windows-in" if inbound else "windows-out")
        prof = int(r.get("pr") or 0)
        rr.src_zones = [] if prof in (0, 7, 2147483647) else [n for b, n in PROFILE_BITS.items() if prof & b]
        remote, rnames = _addr(r.get("ra"), [])
        local, lnames = _addr(r.get("la"), [])
        if inbound:
            rr.set_src(remote)
            rr.set_dst(local)
            rr.src_names, rr.dst_names = rnames, lnames
            rr.set_svc(_ports(r.get("lp"), proto))
        else:
            rr.set_src(local)
            rr.set_dst(remote)
            rr.src_names, rr.dst_names = lnames, rnames
            rr.set_svc(_ports(r.get("rp"), proto))
        rr.svc_names = [f"{PROTO.get(proto) or 'tout'} {r.get('lp') if inbound else r.get('rp') or ''}".strip()]
        app = r.get("app") or ""
        svc = r.get("svc") or ""
        pk = r.get("pk") or ""
        if not pk and r.get("owner"):         # règle d'application moderne (Store) : limitée aux applications de cet utilisateur
            pk = f"propriétaire …{r['owner'][-10:]}"
        rr.apps =[x for x in (app, f"service {svc}" if svc and svc != "*" else "", f"application du Store ({pk[:30]}…)" if pk else "") if x]
        rr.comment = r.get("g") or ""
        rr.profiles = ["traversée NAT (Edge)"] if r.get("et") else []
        rr.raw = json.dumps(r, ensure_ascii=False)[:600]
        cfg.rules.append(rr)
    cfg.default_action = DENY
    cfg.admins = [Admin(name="(comptes Windows)", profile="voir SysAudit Pro")]
    return cfg


_ = LAN
