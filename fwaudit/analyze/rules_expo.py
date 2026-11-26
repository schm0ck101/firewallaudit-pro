"""Règles « Exposition Internet » : services publiés (redirections / VIP /
NAT), administration du pare-feu joignable depuis Internet, VPN d'accès
distant exposés, UPnP, résolveur DNS ouvert. Calcule aussi la liste des
ports qu'on DEVRAIT trouver ouverts de l'extérieur (comparée au scan externe)."""
from __future__ import annotations

from ..fw.model import ALLOW, WAN
from .context import SENSITIVE, Ctx
from .model import CRIT, EXPO, INFO, MAJOR, MINOR

R = []
ADMIN_LABELS = {"http": ("administration web non chiffrée (HTTP)", CRIT), "telnet": ("Telnet", CRIT),
                "https": ("administration web (HTTPS)", MAJOR), "ssh": ("SSH", MAJOR), "winbox": ("Winbox", CRIT),
                "www": ("administration web non chiffrée (HTTP)", CRIT), "www-ssl": ("administration web (HTTPS)", MAJOR),
                "api": ("API RouterOS non chiffrée", CRIT), "api-ssl": ("API RouterOS", MAJOR), "ftp": ("FTP", CRIT),
                "snmp": ("SNMP", MAJOR), "fgfm": ("gestion FortiManager", MINOR), "radius-acct": ("RADIUS", MINOR),
                "userportal": ("portail utilisateur", MINOR), "webadminsettings": ("administration web", MAJOR)}


def rule(fn):
    R.append(fn)
    return fn


def _ports(spec: str) -> list[tuple[int, int]]:
    out = []
    for part in str(spec or "").replace(" ", "").split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit():
            out.append((int(lo), int(hi) if hi.isdigit() else int(lo)))
    return out


def expected_exposure(c: Ctx) -> list[dict]:
    """Ports publics attendus d'après la configuration : [{port, proto, why, sensitive}]."""
    exp = []
    for n in c.cfg.nat:
        if not n.enabled:
            continue
        for lo, hi in _ports(n.ext_ports) or [(0, 0)]:
            for p in range(lo, min(hi, lo + 50) + 1) if lo else [0]:
                exp.append({"port": p, "proto": n.proto, "why": f"publication « {n.name or n.id} » → {n.int_ip}:{n.int_port or p}",
                            "restricted": bool(n.src_restrict)})
    wan_ifs = [i for i in c.cfg.interfaces if i.role == WAN]
    for i in wan_ifs:
        for a in i.admin:
            port = {"https": int(c.cfg.services.get("admin_https_port") or 443), "http": 80, "ssh": int(c.cfg.services.get("admin_ssh_port") or 22),
                    "telnet": 23, "www": 80, "www-ssl": 443, "winbox": 8291, "api": 8728, "api-ssl": 8729, "ftp": 21}.get(a)
            if port:
                exp.append({"port": port, "proto": "tcp", "why": f"administration {a} sur {i.name}", "restricted": False})
    for v in c.cfg.vpn:
        if v.kind == "ssl" and v.enabled:
            p = int(str(v.peer).split()[-1]) if str(v.peer).split() and str(v.peer).split()[-1].isdigit() else 443
            exp.append({"port": p, "proto": "tcp", "why": "VPN SSL", "restricted": False})
        if v.kind == "pptp":
            exp.append({"port": 1723, "proto": "tcp", "why": "VPN PPTP", "restricted": False})
    return exp


@rule
def published_services(c: Ctx):
    if c.is_windows:
        return
    allowed_targets = [r for r in c.active if r.action == ALLOW and c.from_wan(r)]
    crit, info = [], []
    for n in c.cfg.nat:
        if not n.enabled:
            continue
        # FortiGate : une VIP n'est exposée que si une règle l'autorise
        if "Fortinet" in c.cfg.vendor and not any(r.dst_set.contains_ip(n.int_ip) for r in allowed_targets):
            continue
        ports = _ports(n.int_port or n.ext_ports) or _ports(n.ext_ports)
        sens = sorted({(p, SENSITIVE[p]) for lo, hi in ports for p in SENSITIVE if lo <= p <= hi and SENSITIVE[p][1] >= 3})
        line = (f"« {n.name or n.id} » : port public {n.ext_ports or 'tous'} ({n.proto}) → {n.int_ip}:{n.int_port or n.ext_ports}"
                + (f", limité à {', '.join(n.src_restrict)}" if n.src_restrict else ", depuis tout Internet"))
        if sens and not n.src_restrict:
            crit.append((line, sens))
        else:
            info.append(line)
        if not ports and not n.src_restrict:
            crit.append((line + " (TOUS les ports)", [(0, ("tous les ports", 4))]))
    for line, sens in crit:
        sev = CRIT if any(s[1] >= 4 for _p, s in sens) else MAJOR
        names = ", ".join(sorted({s[0] for _p, s in sens}))
        c.add(f"expo.nat.{abs(hash(line)) % 10**8}", EXPO, sev, f"{names} publié sur Internet sans restriction",
              line, "Service directement attaquable depuis Internet : force brute, failles connues, rançongiciels.",
              "Supprimer la redirection et passer par un VPN avec MFA ; à défaut, restreindre aux adresses sources connues "
              "et activer IPS + journalisation.")
    if info:
        c.add("expo.nat.list", EXPO, INFO, f"{len(info)} autre(s) service(s) publié(s) sur Internet", "", "",
              "Vérifier que chaque publication est encore nécessaire et maintenue à jour.", info)
    if not c.cfg.nat:
        c.ok("expo.nat", EXPO, "Aucune redirection de port vers l'intérieur")


@rule
def admin_from_wan(c: Ctx):
    cfg = c.cfg
    hits = []
    if "MikroTik" in cfg.vendor:
        # sans blocage final sur « input », tous les services actifs sont joignables depuis Internet
        exposed = not c.has_final_drop("input")
        state = cfg.services.get("mikrotik_services_state") or {}
        addr = cfg.services.get("mikrotik_services_addr") or {}
        explicit = [r for r in c.active if r.layer == "input" and r.action == ALLOW and r.src_set.is_any and not r.extra_conditions]
        for name, on in state.items():
            if not on or name in addr:
                continue
            port = {"telnet": 23, "ftp": 21, "www": 80, "ssh": 22, "www-ssl": 443, "api": 8728, "winbox": 8291, "api-ssl": 8729}[name]
            if exposed or any(r.svc_set.has_port(port) and (not r.src_zones or any(cfg.zone_role(z) == WAN for z in r.src_zones))
                              for r in explicit):
                lab, sev = ADMIN_LABELS.get(name, (name, MAJOR))
                hits.append((sev, f"{lab} (port {port}) joignable depuis Internet"))
    else:
        for i in cfg.interfaces:
            if i.role != WAN or not i.enabled:
                continue
            for a in i.admin:
                if a in ("ping", "fgfm", "probe-response", "dns", "ping6", "capwap"):
                    continue
                lab, sev = ADMIN_LABELS.get(a, (a, MINOR))
                hits.append((sev, f"{lab} activé(e) sur l'interface Internet « {i.name} »"))
        for r in c.active:
            if (r.action == ALLOW and c.to_firewall(r) and c.from_wan(r) and not c.is_default(r)
                    and not (r.users or r.schedule or [a for a in r.apps if not a.startswith("géolocalisation")])):
                for p in (443, 80, 22, 23, 8443, 4444, 10443, 8291, 1300, 4433, 8080, 4117, 4105, 4118):
                    if r.svc_set.has_port(p):
                        sev = MAJOR if r.src_set.is_any else MINOR
                        hits.append((sev, f"règle {r.label()} : accès au pare-feu (port {p}) depuis {r.src_set.public_part().describe(3)}"))
                        break
    admins_trusted = all(a.trusted for a in cfg.admins if a.enabled and a.name != "(comptes Windows)") and cfg.admins
    for sev, line in sorted(set(hits), key=lambda x: -x[0]):
        if admins_trusted and sev == MAJOR:
            sev = MINOR
        c.add(f"expo.admin.{abs(hash(line)) % 10**8}", EXPO, sev, f"Administration du pare-feu exposée : {line}",
              "L'interface d'administration du pare-feu est joignable depuis Internet.",
              "Les interfaces d'administration de pare-feu (Fortinet, Sophos, MikroTik…) font l'objet de failles critiques "
              "régulières, exploitées en masse dans les heures qui suivent leur publication.",
              "Désactiver l'administration sur l'interface WAN ; administrer depuis le LAN ou le VPN, ou via la console cloud "
              "du constructeur avec MFA. À défaut, restreindre aux adresses de confiance.")
    if not hits and not c.is_windows:
        c.ok("expo.admin", EXPO, "Administration du pare-feu non exposée sur Internet (d'après la configuration)")


@rule
def remote_access(c: Ctx):
    for v in c.cfg.vpn:
        if not v.enabled:
            continue
        if v.kind == "ssl" and "Fortinet" in c.cfg.vendor:
            c.add("expo.sslvpn", EXPO, MAJOR, "VPN SSL FortiGate activé sur Internet",
                  f"Portail VPN SSL ({v.peer}).",
                  "Le VPN SSL de FortiOS a connu plusieurs failles critiques exploitées massivement (2018-2025) ; Fortinet le "
                  "retire au profit d'IPsec / ZTNA à partir de FortiOS 7.6.3.",
                  "Migrer vers le VPN IPsec (IKEv2) avec MFA ; en attendant : firmware à jour, MFA obligatoire, restriction "
                  "géographique, surveillance des journaux.")
        elif v.kind == "ssl":
            c.add(f"expo.ssl.{v.name}", EXPO, INFO, f"Portail VPN / utilisateur exposé : {v.name}", "",
                  "Point d'entrée exposé : il doit être à jour et protégé par MFA.", "Vérifier MFA et mises à jour.")


@rule
def upnp_and_dns(c: Ctx):
    s = c.cfg.services
    if s.get("upnp"):
        c.add("expo.upnp", EXPO, MAJOR, "UPnP activé sur le pare-feu",
              "Les appareils du réseau peuvent ouvrir eux-mêmes des ports vers Internet, sans validation.",
              "Un appareil compromis (caméra, objet connecté, poste) s'expose lui-même sur Internet.",
              "Désactiver UPnP et créer à la main les redirections nécessaires.")
    if s.get("dns_open_resolver") and not c.has_final_drop("input"):
        c.add("expo.dns", EXPO, MAJOR, "Résolveur DNS du routeur ouvert sur Internet",
              "Le routeur répond aux requêtes DNS et sa chaîne input ne bloque pas le WAN.",
              "Le routeur sert à des attaques par amplification DNS (et peut être placé sur liste noire).",
              "Bloquer le port 53 depuis le WAN (règle drop finale sur input).")


@rule
def exposure_summary(c: Ctx):
    exp = expected_exposure(c)
    c.snap["_expected_exposure"] = exp
    if exp:
        groups: dict[tuple, list[int]] = {}
        for e in exp:
            groups.setdefault((e["why"].split(" → ")[0], e["proto"], e["restricted"]), []).append(e["port"])

        def ranges(ps):
            ps, out = sorted(set(ps)), []
            for x in ps:
                if out and x == out[-1][1] + 1:
                    out[-1][1] = x
                else:
                    out.append([x, x])
            return ",".join("tous" if a == 0 else str(a) if a == b else f"{a}-{b}" for a, b in out)
        c.add("expo.expected", EXPO, INFO, f"{len(groups)} accès attendu(s) depuis Internet d'après la configuration",
              "Liste comparée au scan externe s'il a été réalisé.", "", "",
              [f"{proto}/{ranges(ps)} : {why}" + (" (sources restreintes)" if rst else "")
               for (why, proto, rst), ps in list(groups.items())[:40]])

RULES = R


_ = MINOR
