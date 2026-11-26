"""Règles « Vérifications sur le terrain » : ce que le pare-feu laisse
réellement passer (sortie, cloisonnement, exposition vue d'Internet), et les
écarts avec ce que dit la configuration."""
from __future__ import annotations

from ..fw.model import DENY, GUEST, IOT, WAN
from .context import SENSITIVE, Ctx
from .model import CRIT, INFO, MAJOR, MINOR, TEST

R = []


def rule(fn):
    R.append(fn)
    return fn


def _config_blocks_out(c: Ctx, port: int) -> list:
    """Règles de la configuration censées bloquer ce port vers Internet."""
    return [r for r in c.active if r.action == DENY and r.svc_set.has_port(port) and not r.svc_set.is_any
            and (WAN in c.roles(r.dst_zones) or not r.dst_zones)]


@rule
def egress(c: Ctx):
    e = c.tests.get("egress")
    if not e:
        c.nc("test.egress", TEST, "Filtrage sortant réel", "Test non réalisé (à lancer depuis le réseau du client).")
        return
    if e.get("error"):
        c.nc("test.egress", TEST, "Filtrage sortant réel", e["error"])
        return
    tcp = e.get("tcp") or {}
    is_open = {int(p): (v.get("open") if isinstance(v, dict) else bool(v)) for p, v in tcp.items()}
    opened = [p for p, o in is_open.items() if o]
    from ..scan.probes import EGRESS_PORTS
    if len(opened) >= len(is_open) - 1 and is_open:
        c.add("test.egress.all", TEST, MINOR, f"Aucun filtrage sortant : {len(opened)}/{len(is_open)} ports testés joignables sur Internet",
              "Depuis ce réseau, toutes les destinations et tous les ports testés sont accessibles.",
              "Un logiciel malveillant communique librement avec l'extérieur (commande à distance, exfiltration, spam, minage).",
              "Mettre en place une politique de sortie : web (80/443), DNS uniquement vers les résolveurs internes, messagerie "
              "vers le serveur prévu ; bloquer le reste et journaliser.")
    for port, sev, why in ((25, MAJOR, "Un poste infecté peut envoyer du spam directement : l'IP publique finit sur liste noire et "
                                       "la messagerie légitime du client est bloquée."),
                           (445, MAJOR, "SMB vers Internet expose les empreintes de mots de passe Windows (attaques par relais) "
                                        "et sert à la propagation de vers."),
                           (139, MINOR, "NetBIOS vers Internet : fuite d'informations."),
                           (23, MINOR, "Telnet sortant : protocole non chiffré."),
                           (6667, MINOR, "IRC : canal de commande historique des botnets."),
                           (9001, MINOR, "Port du réseau Tor : contournement de toutes les protections."),
                           (3389, MINOR, "Bureau à distance vers l'extérieur : prise de main sortante non contrôlée."),
                           (1723, INFO, "PPTP sortant possible.")):
        if is_open.get(port):
            blk = _config_blocks_out(c, port)
            if blk:
                c.add(f"test.egress.mismatch.{port}", TEST, MAJOR,
                      f"Le port {port} ({EGRESS_PORTS[port]}) sort malgré la règle {blk[0].label()} censée le bloquer",
                      "La configuration prévoit un blocage, mais la connexion de test vers Internet a abouti.",
                      "La protection attendue n'existe pas : règle mal placée, mauvaise interface, ou autre chemin de sortie.",
                      "Vérifier l'ordre des règles, les interfaces / zones de la règle, et les autres sorties (box, 4G de secours).",
                      [c.describe(b) for b in blk[:3]])
            else:
                c.add(f"test.egress.{port}", TEST, sev, f"Sortie autorisée vers Internet sur le port {port} ({EGRESS_PORTS[port]})",
                      "Connexion de test vers un serveur public réussie depuis ce réseau.", why,
                      "Bloquer ce port en sortie (sauf depuis les serveurs qui en ont besoin, ex. le serveur de messagerie pour le 25).")
    dd = e.get("dns_direct") or {}
    direct = [f"{v.get('provider')} ({k})" for k, v in dd.items() if v.get("ok")]
    if direct:
        c.add("test.dns.direct", TEST, MINOR, f"Les postes peuvent utiliser des DNS publics directement ({len(direct)})",
              ", ".join(direct),
              "Le filtrage DNS (sécurité, contrôle des catégories) et la journalisation DNS sont contournables.",
              "Bloquer le DNS sortant (53 TCP/UDP) sauf depuis les résolveurs internes / le pare-feu.")
    if e.get("dot") or e.get("doh"):
        c.add("test.dns.encrypted", TEST, INFO, "DNS chiffré (DoT / DoH) utilisable vers l'extérieur",
              ("DoT (853) " if e.get("dot") else "") + ("DoH (Cloudflare)" if e.get("doh") else ""),
              "Les navigateurs et logiciels peuvent résoudre les noms sans passer par le DNS de l'entreprise.",
              "Si un filtrage DNS est en place : bloquer le port 853 et les catégories / domaines DoH connus (option des pare-feu UTM).")
    if not opened:
        c.ok("test.egress", TEST, "Filtrage sortant efficace sur tous les ports testés")


@rule
def segmentation(c: Ctx):
    seg = c.tests.get("segmentation")
    here = c.tests.get("audit_network") or {}
    if seg is None:
        c.nc("test.seg", TEST, "Cloisonnement réel entre réseaux", "Test non réalisé.")
        return
    if not seg:
        c.add("test.seg.none", TEST, INFO, "Aucun autre réseau à tester depuis ce point de branchement", "")
        return
    here_role = here.get("role", "")
    for net, r in seg.items():
        role = r.get("role", "")
        reach = r.get("reachable", 0)
        sens = sorted({f"{h} : {', '.join(str(p) for p in d.get('ports', []) if p in SENSITIVE)}"
                       for h, d in (r.get("hosts") or {}).items() if any(p in SENSITIVE for p in d.get("ports", []))})
        line = f"{net} ({r.get('name') or role}) : {reach} appareil(s) joignable(s) sur {r.get('scanned')} adresses"
        if here_role in (GUEST, IOT) and reach:
            c.add(f"test.seg.{net}", TEST, CRIT if sens else MAJOR,
                  f"Depuis le réseau {'invités' if here_role == GUEST else 'objets connectés'}, le réseau {net} est joignable",
                  line, "Un invité ou un objet connecté compromis peut attaquer les postes et serveurs.",
                  "Bloquer tout trafic de ce réseau vers les réseaux internes (seule la sortie Internet est utile).", sens[:20])
        elif role in (GUEST, IOT, "mgmt") and reach and sens:
            c.add(f"test.seg.{net}", TEST, MINOR, f"Réseau {net} ({r.get('name') or role}) joignable depuis le réseau d'audit",
                  line, "Les services de ce réseau sont atteignables depuis les postes.",
                  "Vérifier que ces accès sont voulus (administration) ; sinon les bloquer.", sens[:20])
        else:
            c.add(f"test.seg.{net}", TEST, INFO, f"Réseau {net} : {reach} appareil(s) joignable(s) depuis le réseau d'audit", line,
                  "", "", sens[:20])
        gp = r.get("gateway_ports") or []
        if gp:
            c.add(f"test.seg.gw.{net}", TEST, INFO, f"Interface du pare-feu {r.get('gateway')} : ports {', '.join(map(str, gp))} ouverts", "")


@rule
def external(c: Ctx):
    ext = c.tests.get("external")
    if not ext:
        c.nc("test.ext", TEST, "Exposition vue d'Internet (scan externe)",
             "Non réalisé : connecter le PC d'audit à Internet par une autre connexion (partage 4G) puis lancer « Test externe ».")
        return
    from ..scan.probes import tls_cert_brand
    expected = {e["port"] for e in c.snap.get("_expected_exposure") or []}
    for ip, t in (ext.get("targets") or {}).items():
        op = t.get("open") or []
        sens = [(p, SENSITIVE[p]) for p in op if p in SENSITIVE and SENSITIVE[p][1] >= 3]
        unexpected = [p for p in op if p not in expected]
        brands = tls_cert_brand(t.get("web") or [])
        ev = [f"port {p} ({SENSITIVE.get(p, ('', 0))[0] or '—'})" + (f" — {t['banners'].get(str(p))}" if (t.get("banners") or {}).get(str(p)) else "")
              for p in op]
        if not op and not any((t.get("udp") or {}).values()):
            c.ok(f"test.ext.{ip}", TEST, f"{ip} : aucun port ouvert vu d'Internet ({ext.get('ports_tested')} ports TCP testés)")
            continue
        if sens:
            c.add(f"test.ext.sens.{ip}", TEST, CRIT if any(s[1] >= 4 for _p, s in sens) else MAJOR,
                  f"Services sensibles ouverts sur Internet ({ip}) : {', '.join(s[0] for _p, s in sens)}",
                  f"Constaté depuis une connexion extérieure ({ext.get('from_ip') or '?'}).",
                  "Ces services sont attaqués en permanence par des robots.",
                  "Fermer ces ports ou les restreindre ; accès distant uniquement par VPN avec MFA.", ev)
        if brands:
            c.add(f"test.ext.admin.{ip}", TEST, MAJOR, f"Page d'administration ou portail VPN visible depuis Internet ({ip})",
                  "; ".join(brands), "Point d'entrée exposé aux failles critiques régulières des pare-feu et VPN.",
                  "Restreindre (adresses de confiance, géo-blocage), MFA, firmware à jour ; idéalement ne pas l'exposer.", brands)
        if unexpected and c.cfg.rules:
            c.add(f"test.ext.unexp.{ip}", TEST, MAJOR, f"{len(unexpected)} port(s) ouvert(s) sur {ip} non prévus par la configuration lue",
                  f"Ports : {', '.join(map(str, unexpected))}.",
                  "Un autre équipement publie des services (box en amont, ancien pare-feu, NAS en UPnP…), ou la configuration analysée "
                  "n'est pas celle en service.", "Identifier quel équipement répond sur ces ports et le corriger.", ev)
        udp = t.get("udp") or {}
        if udp.get("dns_53"):
            c.add(f"test.ext.dns.{ip}", TEST, MAJOR, f"Résolveur DNS ouvert sur Internet ({ip})", "",
                  "Utilisé pour des attaques par amplification ; l'IP du client finit sur liste noire.", "Bloquer le port 53 entrant.")
        if udp.get("snmp_public"):
            c.add(f"test.ext.snmp.{ip}", TEST, CRIT, f"SNMP « public » joignable depuis Internet ({ip})", "",
                  "La configuration réseau est lisible depuis Internet.", "Bloquer SNMP sur l'interface WAN.")
        if op and not sens and not brands and not unexpected:
            c.add(f"test.ext.ok.{ip}", TEST, INFO, f"{ip} : ports ouverts conformes à la configuration ({', '.join(map(str, op))})", "", "", "", ev)
    missing = []
    for e in c.snap.get("_expected_exposure") or []:
        if e["port"] and not e.get("restricted") and all(e["port"] not in (t.get("open") or []) for t in (ext.get("targets") or {}).values()):
            missing.append(f"{e['proto']}/{e['port']} : {e['why']}")
    if missing:
        c.add("test.ext.closed", TEST, INFO, f"{len(missing)} publication(s) de la configuration non joignable(s) de l'extérieur",
              "Prévues dans la configuration mais fermées vues d'Internet (règle inactive, serveur arrêté, filtrage amont).",
              "", "Supprimer les publications obsolètes.", missing[:20])


RULES = R
