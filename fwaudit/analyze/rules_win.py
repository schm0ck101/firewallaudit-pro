"""Règles propres au pare-feu Windows (poste ou serveur) : règles entrantes
trop larges, services sensibles ouverts à tous, autorisations créées par les
fenêtres « Autoriser l'accès » (tous ports, profil Public), traversée NAT,
ports à l'écoute non couverts."""
from __future__ import annotations

from ..fw.model import ALLOW
from .context import SENSITIVE, Ctx
from .model import INFO, MAJOR, MINOR, POL

R = []


def rule(fn):
    R.append(fn)
    return fn


def _inbound(c: Ctx):
    return [r for r in c.active if r.layer == "windows-in" and r.action == ALLOW]


@rule
def inbound_any(c: Ctx):
    if not c.is_windows:
        return
    allports = [r for r in _inbound(c) if r.svc_set.is_any or any(ivs == [(0, 65535)] for ivs in r.svc_set.m.values())]
    pub = [r for r in allports if r.src_set.is_any and (not r.src_zones or "Public" in r.src_zones)]
    prog = [r for r in pub if r.apps and not any(a.startswith("application du Store") for a in r.apps)]
    noprog = [r for r in pub if not r.apps]
    if noprog:
        c.add("pol.win.anyport", POL, MAJOR, f"{len(noprog)} règle(s) entrante(s) : tous ports, toutes adresses, tout programme",
              "Ces règles ouvrent le poste entièrement sur le réseau (profil Public compris).",
              "Le pare-feu ne filtre plus rien pour ce trafic.", "Supprimer ou restreindre (programme, port, adresses distantes).",
              [c.describe(r) for r in noprog[:15]], refs={"rules": [r.id for r in noprog]})
    if prog:
        c.add("pol.win.prog", POL, MINOR, f"{len(prog)} programme(s) autorisé(s) en entrée sur tous les ports, réseau Public compris",
              "Règles créées en général par la fenêtre « Autoriser l'accès » de Windows (clic sur Autoriser).",
              "Ces programmes acceptent des connexions depuis n'importe quel réseau, y compris un Wi-Fi public.",
              "Restreindre ces règles aux profils Domaine/Privé, ou les supprimer si le programme n'a pas besoin d'écouter.",
              [f"{r.name} : {r.apps[0]}" for r in prog[:25]], refs={"rules": [r.id for r in prog]})


@rule
def sensitive_open(c: Ctx):
    if not c.is_windows:
        return
    srv = bool(c.cfg.services.get("windows_server"))
    for port in (3389, 445, 5985, 5986, 1433, 22, 21, 23, 5900, 135):
        rs = [r for r in _inbound(c) if r.svc_set.has_port(port) and not r.svc_set.is_any and r.src_set.is_any
              and not any(ivs == [(0, 65535)] for ivs in r.svc_set.m.values())]
        if not rs:
            continue
        public = [r for r in rs if not r.src_zones or "Public" in r.src_zones]
        lab = SENSITIVE.get(port, (str(port), 3))[0]
        if public:
            c.add(f"pol.win.{port}", POL, MAJOR, f"{lab} ouvert à toutes les adresses, profil Public compris",
                  f"{len(public)} règle(s) entrante(s) active(s).",
                  "Sur un réseau public (hôtel, Wi-Fi d'invités), n'importe qui peut atteindre ce service.",
                  "Restreindre la règle aux profils Domaine/Privé et aux adresses d'administration.", [c.describe(r) for r in public[:10]],
                  refs={"rules": [r.id for r in public], "port": port})
        elif not srv and port in (3389, 5985, 5986):
            c.add(f"pol.win.{port}", POL, MINOR, f"{lab} ouvert à toutes les adresses du réseau",
                  "", "Sur un poste de travail, l'accès distant devrait être limité aux postes d'administration.",
                  "Limiter les adresses distantes (bastion, sous-réseau d'administration).", [c.describe(r) for r in rs[:10]],
                  refs={"rules": [r.id for r in rs], "port": port})


@rule
def edge_and_listening(c: Ctx):
    if not c.is_windows:
        return
    edge = [r for r in _inbound(c) if "traversée NAT (Edge)" in r.profiles and not any(a.startswith("application du Store") for a in r.apps)]
    if edge:
        c.add("pol.win.edge", POL, INFO, f"{len(edge)} règle(s) avec traversée NAT (Edge traversal)",
              "Ces règles acceptent des connexions arrivant à travers un NAT (Teredo / IPv6).",
              "Peut rendre le programme joignable depuis Internet en contournant le routeur.",
              "Désactiver la traversée de périphérie sauf besoin avéré.", [r.name for r in edge[:15]], refs={"rules": [r.id for r in edge]})
    listen = c.cfg.services.get("windows_listening") or []
    if listen:
        ports = sorted({x.get("port") for x in listen if x.get("port") and x["port"] < 49152})
        c.add("pol.win.listen", POL, INFO, f"{len(ports)} port(s) TCP à l'écoute sur le réseau (hors ports dynamiques)",
              "", "", "Vérifier que chaque service à l'écoute est nécessaire.",
              sorted({f"{x['port']} — {x.get('proc')}" for x in listen if x.get("port", 99999) < 49152}, key=lambda t: int(t.split(" ")[0]))[:30])
    gpo = c.cfg.services.get("windows_gpo_rules") or 0
    if gpo:
        c.add("pol.win.gpo", POL, INFO, f"{gpo} règle(s) imposée(s) par stratégie de groupe", "", "", "")


RULES = R
