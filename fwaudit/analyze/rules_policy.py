"""Règles « Règles de filtrage » : règles trop larges, flux entrants dangereux,
cloisonnement entre zones, règles masquées / redondantes / inutilisées,
journalisation, inspections de sécurité, politique par défaut, hygiène."""
from __future__ import annotations

from ..fw.model import ALLOW, ANY, DENY, GUEST, IOT, LAN, VPN, WAN
from .context import SENSITIVE, Ctx, covers
from .model import CRIT, INFO, MAJOR, MINOR, POL

R = []


def rule(fn):
    R.append(fn)
    return fn


@rule
def any_any(c: Ctx):
    for r in c.active:
        if r.action != ALLOW or r.extra_conditions or not (r.src_set.is_any and r.dst_set.is_any and r.svc_set.is_any):
            continue
        if c.is_windows or c.to_firewall(r) or c.is_default(r):      # politiques par défaut : voir default_matrix
            continue
        sr, dr = c.roles(r.src_zones), c.roles(r.dst_zones)
        if WAN in sr or (ANY in sr and ANY in dr):
            c.add(f"pol.anyany.{r.id}", POL, CRIT, f"Règle « tout autoriser » depuis toutes les zones : {r.label()}",
                  c.describe(r),
                  "Tout le trafic est permis, y compris depuis Internet vers le réseau interne : le pare-feu ne protège plus rien.",
                  "Supprimer cette règle et la remplacer par des règles précises (zones, adresses et services nécessaires).",
                  [r.raw[:300]] if r.raw else None, refs={"rule": r.id})
        elif WAN in dr and (sr & {LAN}):
            c.add(f"pol.egress.{r.id}", POL, MINOR, f"Sortie vers Internet sans restriction : {r.label()}",
                  c.describe(r),
                  "Un poste infecté peut joindre n'importe quel serveur sur n'importe quel port (exfiltration, botnet, spam).",
                  "Limiter la sortie aux services nécessaires (web, DNS vers les résolveurs internes, messagerie…), "
                  "ou au minimum appliquer filtrage web, IPS et contrôle applicatif sur cette règle.", refs={"rule": r.id})
        elif dr and dr <= {GUEST, IOT} and not (sr & {GUEST, IOT, WAN, ANY}):
            c.add(f"pol.wide.{r.id}", POL, MINOR, f"Tout autorisé vers un réseau moins sensible : {r.label()}",
                  c.describe(r),
                  "Les postes internes peuvent tout ouvrir vers ce réseau ; le risque principal (de ce réseau vers les postes) "
                  "dépend des règles inverses.",
                  "Limiter aux flux nécessaires (DHCP, DNS, administration des équipements).", refs={"rule": r.id})
        elif VPN in (sr | dr):
            c.add(f"pol.wide.{r.id}", POL, MINOR, f"Tout autorisé à travers un VPN : {r.label()}",
                  c.describe(r),
                  "Le site ou les utilisateurs distants accèdent à tous les services : une machine compromise de l'autre côté "
                  "du tunnel atteint directement ce réseau.",
                  "Limiter le tunnel aux réseaux et services réellement utilisés (ex. serveurs de fichiers, ERP, téléphonie).", refs={"rule": r.id})
        else:
            c.add(f"pol.wide.{r.id}", POL, MAJOR, f"Règle « tout autoriser » entre zones internes : {r.label()}",
                  c.describe(r), "Le cloisonnement entre ces réseaux est annulé : une machine compromise atteint toutes les autres.",
                  "Restreindre aux flux réellement nécessaires.", refs={"rule": r.id})


@rule
def egress_from_lan(c: Ctx):
    """Réseau interne précis -> tout, tous services (la règle « any/any » classique avec une source LAN)."""
    if c.is_windows:
        return
    for r in c.active:
        if (r.action != ALLOW or r.extra_conditions or r.src_set.is_any or not (r.dst_set.is_any or r.dst_set.is_internet)
                or not r.svc_set.is_any
                or r.src_set.is_public() or c.to_firewall(r) or c.is_default(r) or f"pol.egress.{r.id}" in {f.id for f in c.findings}):
            continue
        if GUEST in c.roles(r.src_zones) or all(role == GUEST for _n, role, a in c.nets_by_role((GUEST, LAN, IOT))
                                                if a.surely_intersects(r.src_set)) and c.nets_by_role((GUEST,)) and \
                any(a.surely_intersects(r.src_set) for _n, _r, a in c.nets_by_role((GUEST,))):
            continue                     # réseau invités : sortir librement sur Internet est son rôle
        if c.roles(r.dst_zones) & {WAN, ANY}:
            c.add(f"pol.egress.{r.id}", POL, MINOR, f"Sortie sans restriction depuis {r.src_set.describe(2)} : {r.label()}",
                  c.describe(r),
                  "Tous les ports et toutes les destinations sont permis (Internet ET les autres réseaux internes s'il n'y a pas "
                  "de zone de destination) : exfiltration, botnet, propagation latérale.",
                  "Limiter aux services nécessaires et appliquer les inspections (IPS, filtrage web) ; bloquer explicitement "
                  "les flux vers les autres réseaux internes.", refs={"rule": r.id})


@rule
def inbound_sensitive(c: Ctx):
    """Flux depuis Internet vers l'intérieur portant sur des services sensibles."""
    if c.is_windows:
        return
    for r in c.active:
        if r.action != ALLOW or not c.from_wan(r) or c.to_firewall(r) or c.is_return(r):
            continue
        hits =[(p, lab, sev) for p, (lab, sev) in SENSITIVE.items() if sev >= 3 and r.svc_set.has_port(p)]
        if not hits or r.svc_set.is_any and r.src_set.is_any and r.dst_set.is_any:
            continue
        geo = r.src_set.geo
        open_src = r.src_set.is_any or r.src_set.size > 2**16 or bool(geo)
        sev = CRIT if open_src and any(s >= 4 for _p, _l, s in hits) else MAJOR if open_src else MINOR
        if open_src and (geo or any(a.startswith("géolocalisation") for a in r.apps)):
            sev = MAJOR if sev == CRIT else sev        # ouvert, mais limité à certains pays
        names = "tous les services" if r.svc_set.is_any else ", ".join(sorted({lab for _p, lab, _s in hits}))
        c.add(f"pol.inbound.{r.id}", POL, sev, f"Accès depuis Internet à {names} : {r.label()}",
              c.describe(r) + ("" if open_src else " (sources restreintes)")
              + (f" — limité au(x) pays {', '.join(geo)} : n'importe quelle adresse de ce pays (et tout VPN ou serveur "
                 "loué qui s'y trouve) passe." if geo else ""),
              "Ces services sont la première cible des attaques automatisées (force brute, failles connues) et la porte "
              "d'entrée habituelle des rançongiciels." if open_src else
              "Même restreint, ce service reste sensible si l'adresse autorisée est compromise ou partagée.",
              "Fermer l'accès direct ; passer par un VPN avec authentification forte (MFA). À défaut : restreindre aux "
              "adresses sources connues, activer l'IPS et journaliser.", refs={"rule": r.id})


@rule
def segmentation(c: Ctx):
    """Réseaux à risque (invités, objets connectés, caméras) autorisés vers les réseaux internes. Le rôle se lit sur la
    zone ET sur les réseaux réellement contenus dans les adresses source (UniFi : tous les VLAN de la zone « Internal »).
    Un réseau n'est signalé que si aucune règle de blocage placée AVANT ne le protège déjà."""
    if c.is_windows:
        return
    risky_nets = c.nets_by_role((GUEST, IOT))
    lan_nets = c.nets_by_role((LAN, "mgmt", "dmz"))
    seen = set()
    for idx, r in enumerate(c.active):
        if r.action != ALLOW or r.extra_conditions or c.is_return(r) or not r.svc_set.is_any:
            continue
        sr, dr = c.roles(r.src_zones), c.roles(r.dst_zones)
        if not (dr & {LAN, ANY, "mgmt", "dmz", GUEST, IOT}) or (r.dst_set.is_public() and not r.dst_set.is_any and WAN in dr):
            continue
        cand = []
        if sr & {GUEST, IOT} and not risky_nets:
            cand.append(("ce réseau", GUEST if GUEST in sr else IOT, r.src_set))
        for name, role, net in risky_nets:
            if r.src_set.surely_intersects(net) and (not r.src_zones or sr & {GUEST, IOT, LAN, ANY}) \
                    and c.itf_in_zones(name, r.src_zones):
                cand.append((name, role, net))
        for name, role, net in cand:
            targets = [(n2, a2) for n2, _r2, a2 in lan_nets if r.dst_set.surely_intersects(a2) and not a2.covers(net) and n2 != name
                       and c.itf_in_zones(n2, r.dst_zones)]
            if not targets:
                continue
            earlier = c.active[:idx]
            open_to = [n2 for n2, a2 in targets if not any(
                d.action == "deny" and not d.extra_conditions and d.svc_set.is_any and d.src_set.covers(net) and d.dst_set.covers(a2)
                and d.layer == r.layer for d in earlier)]
            if not open_to or (name, r.id) in seen:
                continue
            seen.add((name, r.id))
            lab = "invités" if role == GUEST else "objets connectés / caméras"
            dflt = " (règle par défaut du pare-feu)" if c.is_default(r) else ""
            c.add(f"pol.seg.{r.id}.{name}", POL, MAJOR, f"Réseau « {name} » ({lab}) autorisé vers {', '.join(open_to)}{dflt}",
                  c.describe(r) + f". Aucune règle placée avant ne bloque « {name} » vers {', '.join(open_to)}.",
                  "Un appareil invité ou un objet connecté (rarement mis à jour) peut atteindre les postes et serveurs.",
                  f"Ajouter, avant cette règle, un blocage de « {name} » vers {', '.join(open_to)} (puis n'autoriser que les "
                  "flux indispensables, ex. une caméra vers l'enregistreur sur un port précis).",
                  refs={"rule": r.id, "net": name, "net_cidr": net.describe(2), "to": open_to,
                        "to_cidr": [a2.describe(2) for n2, a2 in targets if n2 in open_to]})


@rule
def shadowed(c: Ctx):
    if c.is_windows:          # pare-feu Windows : le blocage l'emporte toujours, l'ordre des règles ne compte pas
        return
    # règles prédéfinies (politiques par défaut, portail invités dépendant de l'authentification) et règles de retour :
    # leur ordre est imposé par le constructeur, les déclarer « masquées » n'aurait pas de sens
    rules = [r for r in c.active if not c.is_default(r) and not c.is_return(r)]
    masked, redundant = [], []
    for j, b in enumerate(rules):
        for a in rules[:j]:
            if covers(a, b):
                (redundant if a.action == b.action else masked).append((a, b))
                break
    for a, b in masked:
        c.add(f"pol.shadow.{b.id}", POL, MAJOR, f"Règle {b.label()} jamais appliquée (masquée par {a.label()})",
              f"La règle {a.label()}, placée avant, englobe entièrement {b.label()} avec l'action inverse "
              f"({'autoriser' if a.action == ALLOW else 'bloquer'}).",
              "L'intention de la règle masquée n'est pas respectée : un blocage voulu ne bloque rien, ou une ouverture "
              "voulue ne fonctionne pas.",
              "Déplacer la règle masquée au-dessus de la règle qui l'englobe, ou corriger l'une des deux.",
              [c.describe(a), c.describe(b)], refs={"rule": b.id, "before": a.id})
    if redundant:
        c.add("pol.redundant", POL, MINOR, f"{len(redundant)} règle(s) redondante(s)",
              "Ces règles sont entièrement couvertes par une règle précédente de même action : elles ne servent à rien.",
              "Une politique encombrée est difficile à relire et favorise les erreurs.",
              "Supprimer les règles redondantes après vérification.",
              [f"{b.label()} couverte par {a.label()}" for a, b in redundant],
              refs={"pairs": [[b.id, a.id] for a, b in redundant]})


@rule
def default_policy(c: Ctx):
    cfg = c.cfg
    if cfg.default_action != ALLOW:
        return
    # RouterOS : sans « drop » final, la chaîne accepte tout
    for layer, label, sev in (("input", "le routeur lui-même (chaîne input)", CRIT), ("filter", "le trafic routé (chaîne forward)", MAJOR)):
        final_drop = c.has_final_drop(layer)
        if not final_drop:
            c.add(f"pol.default.{layer}", POL, sev, f"Aucune règle de blocage pour {label}",
                  "Sur ce système, une chaîne sans règle « drop » finale ACCEPTE tout ce qui n'a pas été explicitement traité.",
                  "Depuis Internet, " + ("toutes les interfaces d'administration du routeur (Winbox, SSH, web, API, DNS) sont joignables."
                                         if layer == "input" else "tout le trafic non prévu traverse le routeur."),
                  "Ajouter en fin de chaîne une règle « drop » pour tout ce qui vient du WAN (ou tout ce qui n'est pas du LAN), "
                  "après les règles « established/related ».", refs={"layer": layer})
        else:
            c.ok(f"pol.default.{layer}", POL, f"Blocage par défaut présent pour {label}")


@rule
def unused_and_disabled(c: Ctx):
    rules = c.cfg.rules
    dis = [r for r in rules if not r.enabled]
    if dis and not c.is_windows:          # Windows livre des centaines de règles désactivées par défaut
        sev = MINOR if len(dis) >= 5 and len(dis) / max(1, len(rules)) > 0.2 else INFO
        c.add("pol.disabled", POL, sev, f"{len(dis)} règle(s) désactivée(s) conservée(s)",
              "", "Des règles désactivées s'accumulent et peuvent être réactivées par erreur.",
              "Supprimer celles qui n'ont plus d'usage (après sauvegarde).", [c.describe(r) for r in dis[:25]],
              refs={"rules": [r.id for r in dis]})
    known = [r for r in c.active if r.hits is not None and r.action == ALLOW]
    zero = [r for r in known if r.hits == 0]
    if known and zero:
        c.add("pol.unused", POL, MINOR, f"{len(zero)} règle(s) d'autorisation jamais utilisée(s)",
              "Compteurs d'utilisation à zéro depuis leur création ou la dernière remise à zéro / le dernier redémarrage.",
              "Une ouverture inutile élargit la surface d'attaque sans contrepartie.",
              "Vérifier avec le client puis supprimer les règles sans usage.", [c.describe(r) for r in zero[:25]], True,
              refs={"rules": [r.id for r in zero]})
    elif not known and not c.is_windows:
        c.nc("pol.hits", POL, "Règles inutilisées", "Les compteurs d'utilisation des règles ne figurent pas dans un fichier de "
             "sauvegarde : lire la configuration en direct (API / SSH) pour les obtenir.")
    if c.cfg.objects_unused:
        c.add("pol.objects", POL, INFO, f"{len(c.cfg.objects_unused)} objet(s) d'adresse non utilisé(s)", "", "", "Faire le ménage.",
              c.cfg.objects_unused[:40], refs={"objects": list(c.cfg.objects_unused)})


@rule
def logging_and_profiles(c: Ctx):
    if c.is_windows:
        return
    nolog = [r for r in c.active if r.action == ALLOW and c.from_wan(r) and r.log is False and not c.is_return(r)
             and not c.is_default(r) and not c.roles(r.dst_zones) <= {VPN}]
    if nolog:
        c.add("pol.nolog", POL, MINOR, f"{len(nolog)} flux entrant(s) autorisé(s) sans journalisation",
              "", "En cas d'incident, impossible de savoir qui s'est connecté et quand.",
              "Activer la journalisation sur toutes les règles ouvertes depuis Internet.", [c.describe(r) for r in nolog[:20]],
              refs={"rules": [r.id for r in nolog]})
    if c.is_utm:
        bare = [r for r in c.active if r.action == ALLOW and not r.profiles and not c.to_firewall(r) and
                (c.from_wan(r) or WAN in c.roles(r.dst_zones))]
        if bare:
            c.add("pol.noprofile", POL, MINOR, f"{len(bare)} règle(s) Internet sans inspection de sécurité",
                  "Ni antivirus, ni IPS, ni filtrage web / applicatif sur ces règles qui touchent Internet.",
                  "Le pare-feu laisse passer les attaques et les logiciels malveillants sans les analyser, alors que la licence le permet souvent.",
                  "Appliquer les profils de sécurité (IPS, antivirus, filtrage web, contrôle applicatif) aux règles Internet.",
                  [c.describe(r) for r in bare[:20]], refs={"rules": [r.id for r in bare]})
    noname = [r for r in c.active if not (r.name or r.comment) and not c.is_windows]
    if len(noname) >= 3:
        c.add("pol.doc", POL, INFO, f"{len(noname)} règle(s) sans nom ni commentaire",
              "", "Sans documentation, personne ne sait pourquoi une règle existe ni si on peut la supprimer.",
              "Nommer chaque règle (objet, demandeur, date).")
    n = len(c.cfg.rules)
    if n > 250:
        c.add("pol.size", POL, INFO, f"Politique volumineuse ({n} règles)", "", "Plus la politique est longue, plus les erreurs passent inaperçues.",
              "Regrouper par objets et supprimer l'inutile ; revue annuelle des règles.")
    if c.active and not any(f.id.startswith("pol.anyany") or f.id.startswith("pol.inbound") or f.id.startswith("pol.shadow")
                            for f in c.findings):
        c.ok("pol.base", POL, f"{len(c.active)} règle(s) active(s) analysée(s) sans règle « tout autoriser » ni flux entrant dangereux")


RULES = R
