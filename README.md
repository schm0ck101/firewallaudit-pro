# FirewallAudit Pro

**Audit de pare-feu** — application Windows créée par [SCHMOCK](https://schmock.fr).

L'outil lit la configuration du pare-feu (fichier de sauvegarde, API ou SSH en **lecture seule**), la normalise, puis
vérifie sur le terrain ce que le pare-feu laisse réellement passer. Résultat : un **rapport PDF** dont le plan d'action
est un tableau à cocher.

## Pare-feu pris en charge

| Constructeur | Source | État |
|---|---|---|
| Fortinet FortiGate | sauvegarde `.conf` (multi-VDOM) ou API REST (jeton lecture seule, compteurs d'utilisation des règles) | à valider sur exports réels |
| Stormshield SNS | sauvegarde `.na` sans mot de passe, ou dossier `ConfigFiles` zippé | à valider |
| Sophos Firewall (SFOS) | export de configuration (`.tar` / `Entities.xml`) | à valider |
| WatchGuard Firebox | configuration XML de Policy Manager | à valider |
| UniFi (UDM, UCG, UXG…) | API de la console, compte local en lecture seule (pare-feu par zones et anciennes règles) | à valider |
| MikroTik RouterOS | `/export` (`.rsc`) ou SSH en lecture (compteurs inclus) | à valider |
| Pare-feu Windows | ce poste, ou fichier produit par `--windows-export` sur un serveur | **validé** |

## Ce qui est contrôlé

| Domaine | Contrôles |
|---|---|
| **Règles de filtrage** | « tout autoriser », sortie sans restriction, flux entrants vers des services sensibles (RDP, SMB, SQL, Telnet…), réseaux invités / objets connectés ouverts vers l'interne, règles **masquées** (jamais appliquées) et **redondantes** (calcul exact sur les ensembles d'adresses et de ports), règles inutilisées (compteurs), désactivées, sans journalisation, sans inspection (UTM), politique par défaut (RouterOS : accepte tout sans « drop » final) |
| **Exposition Internet** | publications / VIP / redirections (sensibles et sans restriction de source), administration du pare-feu sur le WAN, VPN SSL, UPnP, résolveur DNS ouvert ; liste des ports attendus ouverts |
| **Administration et durcissement** | version du système (fin de support), comptes (nom prévisible, hôtes de confiance, MFA), administration non chiffrée, délai de session, VPN (PPTP, IKEv1 agressif, DES/3DES/MD5/SHA1, DH < 14), SNMP, journalisation externe, NTP, IPS, Wi-Fi (UniFi), profils du pare-feu Windows |
| **Vérifications sur le terrain** | filtrage **sortant** réel (≈ 40 ports vers un serveur public de test, DNS direct, DoT, DoH) — avec détection d'une règle de blocage **qui ne fonctionne pas** ; **cloisonnement** réel vers les autres réseaux ; **exposition vue d'Internet** depuis une connexion extérieure (4G), comparée à la configuration (ports inattendus, pages d'administration, SNMP, DNS) |

## Utilisation

1. **Audit** : client, site, source de la configuration, tests réels → lancer.
2. **Résultats** : notes par domaine, constats avec preuves (extrait de la configuration d'origine), suivi par ligne.
   Bouton **Test externe** : débrancher le PC du réseau du client, le connecter en 4G, scanner les IP publiques ; les
   résultats complètent le même audit.
3. **Configuration** : règles normalisées (avec les constats qui les concernent), publications, interfaces,
   administrateurs, VPN, résultats des tests.
4. **Historique** : audits conservés avec leurs données brutes (ré-analyse possible avec une version plus récente).

Ligne de commande :
`FirewallAuditPro.exe --pdf rapport.pdf --config sauvegarde.conf [--vendor forti] [--no-tests] [--client X --site Y]`,
`--local-windows` (pare-feu de ce poste), `--windows-export fichier.json` (à lancer sur un serveur).

## Limites

- Les règles fondées sur des utilisateurs, applications, pays ou objets dynamiques ne sont pas toujours résolubles :
  elles ne sont jamais déclarées « masquées » sans certitude.
- Les tests réels ne valent que depuis le réseau où le PC est branché.
- Ne remplace pas un test d'intrusion.

## Technique

Python 3.13 + PySide6 6.9 (Windows 10/11 et Server 2016+). Lecteurs, ensembles d'adresses/services et tests écrits sans
dépendance ; SSH (MikroTik) via paramiko. Compilation : `build.ps1` (tests, exécutable, portable, installateur, release).
