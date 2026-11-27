"""Points d'attention de chaque correction proposée : impact, à faire AVANT,
retour arrière (avec les valeurs d'origine relevées dans la configuration
quand elles sont connues). Affichés sous la correction et dans l'annexe PDF.
"""
from __future__ import annotations

from .model import Finding

IMPACT, BEFORE, ROLLBACK = "Impact", "Avant", "Retour arrière"


def _orig_rule(gen, rid) -> str:
    r = gen.rule(rid) if rid else None
    if not r:
        return ""
    parts = []
    if r.src_names:
        parts.append("source " + ", ".join(r.src_names[:6]))
    if r.dst_names:
        parts.append("destination " + ", ".join(r.dst_names[:6]))
    if r.svc_names:
        parts.append("services " + ", ".join(r.svc_names[:8]))
    return f"valeurs d'origine de la règle {r.label()} : " + " ; ".join(parts) if parts else ""


def _safe_mode(gen) -> str:
    return " Sur MikroTik : passer en Safe Mode (Ctrl+X dans le terminal) avant de modifier : tout est annulé si la session " \
           "est coupée." if gen.kind == "routeros" else ""


def notes_for(f: Finding, gen) -> list[tuple[str, str]]:
    fid, refs = f.id, f.refs or {}
    out: list[tuple[str, str]] = []

    def add(label, text):
        if text:
            out.append((label, text))

    if fid.startswith("expo.admin."):
        add(IMPACT, "Plus d'administration du pare-feu depuis Internet, prestataire compris (ou seulement depuis les adresses "
                    "conservées).")
        add(BEFORE, "Mettre en place et TESTER l'accès de remplacement (VPN avec MFA, console cloud, ou accès depuis le LAN) ; "
                    "ne pas faire la modification depuis une session qui passe par l'interface concernée (risque de se couper)."
                    + _safe_mode(gen))
        itf = next((i for i in gen.cfg.interfaces if i.name == refs.get("iface")), None)
        add(ROLLBACK, (f"accès d'origine sur « {itf.name} » : {' '.join(itf.admin)}" if itf and itf.admin else
                       _orig_rule(gen, refs.get("rule")) or "restaurer la sauvegarde de configuration."))
    elif fid.startswith("expo.nat.") or fid.startswith("pol.inbound."):
        add(IMPACT, "Les utilisateurs ou prestataires dont l'adresse n'est pas listée perdent l'accès au service publié.")
        add(BEFORE, "Relever dans les journaux les adresses sources réellement utilisées ; prévenir les utilisateurs ; "
                    "idéalement, mettre en place le VPN avant de fermer la publication.")
        rid = refs.get("rule") or (refs.get("rules") or [None])[0]
        add(ROLLBACK, _orig_rule(gen, rid) or "restaurer la sauvegarde de configuration.")
    elif fid.startswith(("pol.anyany.", "pol.wide.", "pol.egress.")):
        add(IMPACT, "Tout flux non listé dans la règle restreinte sera bloqué : risque de coupure d'applications métier.")
        add(BEFORE, "Relever les flux réellement utilisés (journaux / vue du trafic sur 2 à 4 semaines, fins de mois comprises) ; "
                    "les autoriser explicitement, puis restreindre.")
        add(ROLLBACK, _orig_rule(gen, refs.get("rule")))
    elif fid.startswith("pol.seg."):
        add(IMPACT, f"Les échanges entre « {refs.get('net')} » et {', '.join(refs.get('to') or []) or 'les réseaux internes'} "
                    "seront bloqués (impression, enregistreur vidéo, partages…).")
        add(BEFORE, "Lister les flux nécessaires (ex. caméras → enregistreur sur un port précis) et les autoriser AU-DESSUS du "
                    "blocage.")
        add(ROLLBACK, "désactiver la nouvelle règle de blocage.")
    elif fid.startswith("pol.shadow."):
        add(IMPACT, f"La règle {gen.rlabel(refs.get('rule'))} devient effective : son action (blocage ou ouverture) "
                    "s'applique désormais réellement.")
        add(BEFORE, "Vérifier avec le client que cette règle correspond toujours à un besoin ; sinon la supprimer plutôt que la "
                    "déplacer.")
        add(ROLLBACK, f"replacer la règle {gen.rlabel(refs.get('rule'))} sous {gen.rlabel(refs.get('before'))}.")
    elif fid in ("pol.redundant", "pol.disabled", "pol.objects"):
        add(IMPACT, "Aucun effet sur le trafic en principe (éléments couverts, désactivés ou non référencés).")
        add(BEFORE, "Vérifier que la configuration en production est identique à celle auditée (modifications faites depuis).")
        add(ROLLBACK, "restaurer la sauvegarde de configuration.")
    elif fid == "pol.unused":
        add(IMPACT, "Les flux rares (clôtures, sauvegardes mensuelles, maintenance annuelle) peuvent avoir été absents de la "
                    "période observée.")
        add(BEFORE, "S'assurer que les compteurs couvrent au moins un mois complet ; désactiver d'abord, supprimer plus tard.")
        add(ROLLBACK, "réactiver la règle.")
    elif fid == "pol.noprofile":
        add(IMPACT, "Charge processeur et débit : l'inspection peut réduire le débit ; l'IPS peut bloquer des flux légitimes "
                    "(faux positifs) ; l'inspection SSL complète casse certaines applications.")
        add(BEFORE, "Vérifier que les abonnements de sécurité sont actifs et le dimensionnement de l'équipement ; commencer par "
                    "l'IPS en mode surveillance / inspection SSL « certificat » seulement.")
        add(ROLLBACK, "retirer les profils des règles concernées.")
    elif fid == "pol.nolog":
        add(IMPACT, "Volume de journaux en hausse.")
        add(BEFORE, "Vérifier l'espace disque ou le collecteur de journaux.")
    elif fid.startswith("pol.default."):
        add(IMPACT, "Tout ce qui n'est pas explicitement autorisé avant ces règles est bloqué ; une erreur coupe l'accès au routeur.")
        add(BEFORE, "Vérifier la liste d'interfaces « LAN » (et « WAN ») et les règles d'autorisation nécessaires (VPN, "
                    "administration)." + _safe_mode(gen))
        add(ROLLBACK, "supprimer les règles ajoutées (Safe Mode : annulation automatique si la session est perdue).")
    elif fid.startswith("sys.vpn.pptp.") or fid.startswith("sys.vpn.l2tp."):
        add(IMPACT, "Les utilisateurs de ce VPN perdent l'accès distant.")
        add(BEFORE, "Déployer et tester la solution de remplacement (IPsec IKEv2, WireGuard, SSL avec MFA) sur les postes.")
    elif fid.startswith("sys.vpn."):
        v = gen.vpn.get(gen.vpn_of(f))
        add(IMPACT, "Coupure du tunnel pendant la modification, et tant que l'équipement d'en face n'a pas les mêmes paramètres.")
        add(BEFORE, "Planifier avec l'administrateur du site distant (créneau commun, paramètres identiques des deux côtés).")
        if v:
            add(ROLLBACK, f"paramètres d'origine : IKEv{v.ike or '?'} · chiffrement {', '.join(v.enc) or '?'} · intégrité "
                          f"{', '.join(v.auth) or '?'} · DH {', '.join(map(str, v.dh)) or '?'}.")
    elif fid == "expo.sslvpn" or fid.startswith("expo.ssl."):
        add(IMPACT, "Désactivation : plus d'accès distant par VPN SSL. TLS 1.2 minimum : les clients VPN très anciens sont refusés.")
        add(BEFORE, "Déployer le client VPN de remplacement (IPsec IKEv2 / ZTNA) avec MFA ; mettre à jour les clients VPN.")
        add(ROLLBACK, "réactiver le VPN SSL / remettre la version TLS précédente.")
    elif fid == "sys.admin.mfa":
        add(IMPACT, "La connexion exige le second facteur : un jeton mal configuré bloque l'accès du compte.")
        add(BEFORE, "Garder une session d'administration ouverte pendant le test ; conserver un compte de secours (coffre-fort).")
    elif fid == "sys.admin.trust":
        add(IMPACT, "Connexion refusée depuis toute adresse non listée.")
        add(BEFORE, "Inclure l'adresse depuis laquelle on administre ; garder une session ouverte pendant le test.")
    elif fid == "sys.admin.default":
        add(BEFORE, "Créer le compte nominatif, s'y connecter et vérifier ses droits AVANT de supprimer ou restreindre l'ancien.")
    elif fid in ("sys.admin.clear", "sys.admin.telnet"):
        add(IMPACT, "Les outils ou scripts qui utilisent HTTP / Telnet ne pourront plus se connecter.")
        add(BEFORE, "Vérifier les outils de supervision et de sauvegarde automatique de configuration.")
    elif fid == "sys.crypto":
        add(IMPACT, "Les anciens clients (navigateurs, outils SSH, homologues VPN) incompatibles sont refusés.")
        add(BEFORE, "Vérifier les homologues VPN et les outils d'administration.")
    elif fid == "sys.log":
        add(BEFORE, "Vérifier que le collecteur est joignable depuis le pare-feu (règle, route) et son espace de stockage.")
    elif fid.startswith("sys.snmp."):
        add(IMPACT, "La supervision qui utilise l'ancienne communauté ne reçoit plus rien (fausses alertes).")
        add(BEFORE, "Mettre à jour l'outil de supervision en même temps (SNMPv3, identifiants).")
    elif fid == "sys.fw":
        add(IMPACT, "Redémarrage de l'équipement : coupure de quelques minutes (plus longue en cas de conversion de configuration).")
        add(BEFORE, "Sauvegarder la configuration, vérifier le chemin de mise à jour et la compatibilité du modèle, prévoir un accès "
                    "console en cas de problème.")
        add(ROLLBACK, "démarrer sur l'image précédente (partition de secours) et restaurer la sauvegarde.")
    elif fid.startswith("test.egress.mismatch."):
        add(IMPACT, "Aucun : commandes de diagnostic en lecture.")
    elif fid.startswith("test.egress.") or fid == "test.dns.direct":
        port = refs.get("port")
        extra = {25: " (serveur de messagerie, copieurs qui envoient des mails)", 53: " (postes ou serveurs configurés en DNS public)",
                 445: " (rares partages SMB hébergés sur Internet)"}.get(port, "")
        add(IMPACT, f"Les logiciels qui utilisent le port {port} vers Internet seront bloqués{extra}.")
        add(BEFORE, "Rechercher dans les journaux les sources légitimes de ce trafic et les exclure du blocage.")
        add(ROLLBACK, "désactiver la règle de blocage ajoutée.")
    elif fid == "expo.upnp":
        add(IMPACT, "Visioconférence, consoles de jeu ou logiciels pair-à-pair peuvent perdre la connexion directe.")
    elif fid == "expo.dns":
        add(BEFORE, "Vérifier que les postes n'utilisent pas le routeur comme DNS (sinon bloquer seulement depuis le WAN).")
    elif fid.startswith("pol.win."):
        add(IMPACT, "Les connexions entrantes vers ces programmes / ports sont refusées hors des profils et adresses conservés.")
        add(BEFORE, "Vérifier avec l'utilisateur les usages (partage, prise en main à distance) ; règles imposées par GPO : "
                    "modifier la GPO, pas le poste.")
        add(ROLLBACK, "Enable-NetFirewallRule / Set-NetFirewallRule avec les valeurs précédentes (Get-NetFirewallRule -Name …).")
    elif fid.startswith("sys.win.in.") or fid.startswith("sys.win.off."):
        add(IMPACT, "Les services à l'écoute sans règle d'autorisation deviennent injoignables sur ce profil.")
        add(BEFORE, "Lister les ports à l'écoute (Get-NetTCPConnection -State Listen) et créer les règles nécessaires.")
    elif fid.startswith("sys.mt."):
        add(IMPACT, "Mauvaise adresse ou liste d'interfaces = perte de l'accès d'administration.")
        add(BEFORE, "Inclure l'adresse actuelle d'administration." + _safe_mode(gen))
    elif fid == "sys.ips":
        add(IMPACT, "Débit maximal réduit selon le modèle ; quelques faux positifs possibles.")
        add(BEFORE, "Vérifier le débit supporté par la console avec l'IPS ; surveiller les alertes la première semaine.")
    elif fid.startswith("sys.wifi."):
        add(IMPACT, "Les appareils anciens incompatibles (WPA3, PMF) ne se connectent plus : préférer le mode « transition ».")
    elif fid.startswith("sys.unifi.ssh"):
        add(BEFORE, "Prévoir la clé SSH avant de désactiver le mot de passe.")
    return out


def format_notes(notes: list[tuple[str, str]]) -> list[str]:
    return [f"{label} : {text}" for label, text in notes]
