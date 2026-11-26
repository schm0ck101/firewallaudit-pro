"""Règles « Administration et durcissement » : version du système (fin de
support), comptes d'administration, chiffrement des VPN, protocoles obsolètes,
SNMP, journalisation, heure, IPS, Wi-Fi (UniFi) et pare-feu Windows."""
from __future__ import annotations

import re

from ..fw.model import ALLOW
from .context import Ctx
from .model import CRIT, INFO, MAJOR, MINOR, SYS

R = []


def rule(fn):
    R.append(fn)
    return fn


def _ver(s: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    return tuple(int(x or 0) for x in m.groups()) if m else ()


# (constructeur, version minimale encore maintenue, gravité si plus ancienne, explication) — à tenir à jour
SUPPORT = [
    ("Fortinet", (7, 2, 0), MAJOR, "FortiOS antérieur à 7.2 : fin de support (plus de correctifs de sécurité)."),
    ("Fortinet", (7, 4, 0), MINOR, "FortiOS 7.2 : fin du support technique annoncée ; prévoir la 7.4 / 7.6."),
    ("MikroTik", (7, 0, 0), MAJOR, "RouterOS v6 : branche ancienne, plus de nouveautés de sécurité ; passer en v7."),
    ("Sophos", (20, 0, 0), MAJOR, "SFOS antérieur à 20.0 : fin de vie (plus de correctifs)."),
    ("Sophos", (21, 0, 0), MINOR, "SFOS 20 : planifier la migration vers la 21."),
    ("Stormshield", (4, 3, 0), MAJOR, "SNS antérieur à 4.3 : hors support."),
    ("WatchGuard", (12, 10, 0), MINOR, "Fireware antérieur à 12.10 : planifier la mise à jour."),
]


@rule
def firmware(c: Ctx):
    v = _ver(c.cfg.version)
    if c.is_windows:
        return
    if not v:
        c.nc("sys.fw", SYS, "Version du système du pare-feu", "Version absente du fichier lu : la vérifier sur l'équipement.")
        return
    for vendor, minv, sev, why in SUPPORT:
        if vendor in c.cfg.vendor and v < minv:
            c.add("sys.fw", SYS, sev, f"Système du pare-feu ancien : {c.cfg.version}", why,
                  "Les failles publiées depuis ne sont pas corrigées sur cet équipement ; les pare-feu sont des cibles prioritaires.",
                  "Mettre à jour vers la dernière version maintenue (vérifier la compatibilité du modèle) dans une fenêtre de maintenance.",
                  predictive=True)
            return
    c.ok("sys.fw", SYS, f"Version du système : {c.cfg.version}", "Vérifier tout de même qu'il s'agit du dernier correctif de la branche.")


@rule
def admins(c: Ctx):
    real = [a for a in c.cfg.admins if a.enabled and a.name != "(comptes Windows)"]
    if not real:
        if not c.is_windows:
            c.nc("sys.admins", SYS, "Comptes d'administration", "Liste des administrateurs absente de la source lue.")
        return
    default = [a.name for a in real if a.default_name]
    if default:
        c.add("sys.admin.default", SYS, MINOR, f"Compte d'administration au nom prévisible : {', '.join(default)}",
              "", "Les attaques par force brute visent d'abord « admin » / « root ».",
              "Créer des comptes nominatifs et désactiver ou renommer le compte par défaut.")
    untrusted = [a.name for a in real if not a.trusted]
    if "Fortinet" in c.cfg.vendor and untrusted:
        c.add("sys.admin.trust", SYS, MAJOR, f"Administrateurs sans « hôtes de confiance » : {', '.join(untrusted)}",
              "Ces comptes peuvent se connecter depuis n'importe quelle adresse.",
              "Combiné à une interface d'administration exposée, cela ouvre la porte à la force brute et aux failles.",
              "Définir des hôtes de confiance (trusthost) sur chaque compte d'administration.")
    nomfa = [a.name for a in real if a.mfa is False]
    if nomfa:
        c.add("sys.admin.mfa", SYS, MINOR, f"Administrateurs sans double authentification : {', '.join(nomfa)}",
              "", "Un mot de passe volé suffit à prendre le contrôle du pare-feu.", "Activer la MFA (FortiToken, TOTP…).")
    if len(real) > 5:
        c.add("sys.admin.many", SYS, INFO, f"{len(real)} comptes d'administration", "", "", "Revoir la liste (départs, prestataires).",
              [f"{a.name} ({a.profile})" for a in real])
    s = c.cfg.services
    if s.get("admin_telnet"):
        c.add("sys.admin.telnet", SYS, MAJOR, "Administration en Telnet autorisée", "", "Mot de passe en clair sur le réseau.",
              "Désactiver Telnet (SSH uniquement).")
    if "MikroTik" in c.cfg.vendor:
        st = s.get("mikrotik_services_state") or {}
        bad = [n for n in ("telnet", "ftp", "www", "api") if st.get(n)]
        if bad:
            c.add("sys.mt.services", SYS, MINOR, f"Services d'administration non chiffrés actifs : {', '.join(bad)}", "",
                  "Mots de passe en clair ; surface d'attaque inutile.", "/ip service disable telnet,ftp,www,api ; restreindre "
                  "winbox/ssh/www-ssl aux adresses d'administration (address=…).")
        if s.get("mac_server"):
            c.add("sys.mt.mac", SYS, MINOR, "Accès MAC-Telnet / MAC-Winbox ouvert sur toutes les interfaces", "",
                  "Administration possible sans IP depuis n'importe quel port, y compris côté opérateur.",
                  "/tool mac-server set allowed-interface-list=LAN (et mac-winbox).")
    to = s.get("admin_timeout_min")
    if isinstance(to, int) and to > 30:
        c.add("sys.admin.timeout", SYS, MINOR, f"Session d'administration très longue ({to} min)", "",
              "Une console laissée ouverte reste utilisable longtemps.", "Ramener le délai d'inactivité à 10-15 min.")
    if s.get("strong_crypto") is False:
        c.add("sys.crypto", SYS, MINOR, "Chiffrement fort non imposé (strong-crypto désactivé)", "",
              "Protocoles et algorithmes faibles acceptés pour l'administration et les VPN.", "config system global › set strong-crypto enable")


@rule
def clear_admin(c: Ctx):
    """Administration en HTTP / Telnet (interfaces ou règles vers le pare-feu), même sans liste d'administrateurs."""
    clear = [i.name for i in c.cfg.interfaces if any(a in ("http", "telnet", "www") for a in i.admin) and i.role != "wan"]
    clear += [f"règle {r.label()}" for r in c.active if r.action == ALLOW and c.to_firewall(r) and not r.svc_set.is_any
              and (r.svc_set.has_port(23) or r.svc_set.has_port(80)) and not c.is_windows]
    if clear and "MikroTik" not in c.cfg.vendor:
        c.add("sys.admin.clear", SYS, MINOR, f"Administration non chiffrée (HTTP / Telnet) sur : {', '.join(clear)}", "",
              "Le mot de passe administrateur circule en clair sur le réseau interne.", "N'autoriser que HTTPS et SSH.")


WEAK_ENC = {"des", "3des", "null", "rc4", "des-cbc", "3des-cbc"}
WEAK_AUTH = {"md5", "sha1", "sha", "hmac-md5"}


@rule
def vpn(c: Ctx):
    for v in c.cfg.vpn:
        if not v.enabled:
            continue
        if v.kind == "pptp":
            c.add(f"sys.vpn.pptp.{v.name}", SYS, CRIT, f"VPN PPTP actif ({v.name})", "Protocole PPTP / MS-CHAPv2.",
                  "PPTP est cassé depuis 2012 : le trafic et les mots de passe peuvent être déchiffrés.",
                  "Désactiver PPTP ; utiliser IPsec IKEv2, WireGuard ou OpenVPN avec MFA.")
            continue
        if v.kind == "l2tp" and v.psk is False:
            c.add(f"sys.vpn.l2tp.{v.name}", SYS, MAJOR, f"L2TP sans IPsec ({v.name})", "", "Tunnel non chiffré.",
                  "Activer IPsec sur L2TP ou changer de protocole.")
        if v.kind != "ipsec":
            continue
        enc = {e.lower() for e in v.enc}
        auth = {a.lower() for a in v.auth}
        weak = sorted((enc & WEAK_ENC) | (auth & WEAK_AUTH)) + [f"DH {d}" for d in v.dh if 0 < d < 14 and d not in (19, 20, 21)]
        issues = []
        if weak:
            issues.append("algorithmes faibles : " + ", ".join(weak))
        if v.ike == 1 and v.mode.lower().startswith("aggr") and v.psk is not False:
            issues.append("IKEv1 en mode agressif avec clé partagée (empreinte récupérable puis cassable hors ligne)")
        elif v.ike == 1:
            issues.append("IKEv1 (préférer IKEv2)")
        if issues:
            sev = MAJOR if (enc & {"des", "null"}) or (v.mode.lower().startswith("aggr") and v.ike == 1) or any(d in (1, 2) for d in v.dh) else MINOR
            c.add(f"sys.vpn.{v.name}", SYS, sev, f"VPN « {v.name} » : chiffrement insuffisant",
                  " ; ".join(issues) + (f" (homologue {v.peer})" if v.peer else ""),
                  "Un attaquant qui intercepte le tunnel peut déchiffrer ou usurper la connexion.",
                  "IKEv2, AES-256 (GCM), SHA-256 ou plus, groupe DH 14 minimum (19/20/21 conseillés), sur les deux extrémités.",
                  [f"chiffrement : {', '.join(v.enc) or '—'} · intégrité : {', '.join(v.auth) or '—'} · DH : {', '.join(map(str, v.dh)) or '—'}"])
        else:
            c.ok(f"sys.vpn.{v.name}", SYS, f"VPN « {v.name} » : chiffrement correct")


@rule
def snmp_logs_time(c: Ctx):
    s = c.cfg.services
    comms = s.get("snmp_communities") or []
    if any(x.lower() in ("public", "private") for x in comms):
        c.add("sys.snmp.public", SYS, MAJOR, "Communauté SNMP par défaut sur le pare-feu",
              f"Communauté(s) : {', '.join(comms)}.", "Toute la configuration réseau est lisible par n'importe qui (et modifiable si l'écriture est permise).",
              "Changer la communauté ou passer en SNMPv3, et limiter SNMP aux IP de supervision.")
    elif comms:
        c.add("sys.snmp.v2", SYS, MINOR, "SNMP v1/v2c actif sur le pare-feu", "", "Communauté transmise en clair.", "Passer en SNMPv3.")
    if not c.is_windows:
        if s.get("log_remote") is False:
            c.add("sys.log", SYS, MINOR, "Pas de journalisation vers un serveur externe",
                  "Aucun serveur syslog / FortiAnalyzer / collecteur configuré.",
                  "Les journaux locaux sont limités et perdus en cas de redémarrage ou de compromission du pare-feu.",
                  "Envoyer les journaux vers un collecteur (syslog, SIEM, FortiAnalyzer, Sophos Central…).")
        elif s.get("log_remote"):
            c.ok("sys.log", SYS, "Journaux envoyés vers un serveur externe")
        if s.get("ntp") is False:
            c.add("sys.ntp", SYS, MINOR, "Synchronisation de l'heure non configurée", "",
                  "Journaux horodatés faux, VPN par certificats et MFA perturbés.", "Configurer NTP.")


@rule
def unifi_specific(c: Ctx):
    if not c.cfg.vendor.startswith("UniFi"):
        return
    s = c.cfg.services
    mode = (s.get("ips_mode") or "").lower()
    if mode in ("", "disabled"):
        c.add("sys.ips", SYS, MINOR, "Détection / prévention d'intrusion (IPS) désactivée", "", "Les attaques connues ne sont ni bloquées ni signalées.",
              "Activer l'IPS (Paramètres › Sécurité) en mode prévention si le matériel le supporte.")
    elif mode == "ids":
        c.add("sys.ips", SYS, INFO, "IPS en mode détection seulement", "", "Les attaques sont signalées mais pas bloquées.",
              "Passer en mode prévention (IPS) si les performances le permettent.")
    if s.get("ssh") and s.get("ssh_password_auth"):
        c.add("sys.unifi.ssh", SYS, MINOR, "SSH des équipements UniFi activé avec mot de passe", "",
              "Accès root aux équipements si le mot de passe est faible ou réutilisé.", "Utiliser des clés SSH ou désactiver SSH.")
    if s.get("auto_upgrade") is False:
        c.add("sys.unifi.upgrade", SYS, INFO, "Mises à jour automatiques désactivées", "", "", "Planifier les mises à jour manuellement.")
    for w in s.get("wlans") or []:
        if not w.get("enabled"):
            continue
        if w.get("security") == "open" and not w.get("guest"):
            c.add(f"sys.wifi.open.{w['name']}", SYS, MAJOR, f"Wi-Fi « {w['name']} » ouvert (sans mot de passe)", "",
                  "N'importe qui à portée entre sur le réseau.", "Activer WPA2/WPA3.")
        elif w.get("guest") and w.get("security") == "open" and not w.get("l2_isolation"):
            c.add(f"sys.wifi.guest.{w['name']}", SYS, MINOR, f"Wi-Fi invités « {w['name']} » sans isolation des clients", "",
                  "Les invités se voient entre eux.", "Activer l'isolation des clients.")
        elif w.get("security") == "wpapsk" and not w.get("wpa3") and w.get("pmf") == "disabled":
            c.add(f"sys.wifi.wpa2.{w['name']}", SYS, INFO, f"Wi-Fi « {w['name']} » en WPA2 seul, PMF désactivé", "",
                  "Pas de protection contre les déconnexions forcées.", "Activer WPA3 (transition) et PMF facultatif.")


@rule
def windows_profiles(c: Ctx):
    if not c.is_windows:
        return
    s = c.cfg.services
    third = s.get("windows_third_party") or []
    profs = s.get("windows_profiles") or []
    for p in profs:
        if p.get("enabled") != "True":
            sev = INFO if third else CRIT
            c.add(f"sys.win.off.{p['name']}", SYS, sev, f"Pare-feu Windows désactivé (profil {p['name']})",
                  "Un pare-feu tiers est déclaré : " + ", ".join(third) if third else "Aucun pare-feu tiers déclaré.",
                  "Le poste accepte toutes les connexions entrantes sur ce profil.", "Réactiver le pare-feu Windows (ou vérifier le pare-feu tiers).")
        elif p.get("inbound") in ("Allow",):
            c.add(f"sys.win.in.{p['name']}", SYS, CRIT, f"Entrées autorisées par défaut (profil {p['name']})", "",
                  "Toute connexion entrante non prévue est acceptée.", "Action par défaut entrante = Bloquer.")
        if p.get("log_blocked") != "True":
            c.add(f"sys.win.log.{p['name']}", SYS, MINOR if p.get("name") == "Public" else INFO,
                  f"Paquets bloqués non journalisés (profil {p['name']})", "",
                  "Impossible de retrouver une tentative de connexion après coup.",
                  "Activer « Journaliser les paquets ignorés » (journal pfirewall.log, 16 Mo minimum).")
    if profs and all(p.get("enabled") == "True" and p.get("inbound") != "Allow" for p in profs):
        c.ok("sys.win.profiles", SYS, "Pare-feu Windows actif sur les trois profils, entrées bloquées par défaut")
    for conn in s.get("windows_connections") or []:
        if conn.get("category") == "Public" and s.get("windows_domain"):
            c.add("sys.win.public", SYS, MINOR, f"Carte « {conn.get('alias')} » en profil Public sur un poste du domaine", "",
                  "Le profil Public bloque souvent les outils d'administration ; signe d'un problème de détection du domaine (NLA, DNS).",
                  "Vérifier la résolution DNS du domaine et le service « Connaissance des emplacements réseau ».")


RULES = R

_ = ALLOW
