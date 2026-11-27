# FirewallAudit Pro

**Audit de pare-feu** — application Windows créée par [SCHMOCK](https://schmock.fr).

L'outil lit la configuration du pare-feu (fichier de sauvegarde, API ou SSH en **lecture seule**), la normalise, puis
vérifie sur le terrain ce que le pare-feu laisse réellement passer. Résultat : un **rapport PDF** dont le plan d'action
est un tableau à cocher.

## Pare-feu pris en charge

| Constructeur | Source |
|---|---|
| Fortinet FortiGate | sauvegarde `.conf` (multi-VDOM, SD-WAN) ou API REST (jeton lecture seule, compteurs d'utilisation des règles) |
| Stormshield SNS | sauvegarde `.na` faite sans mot de passe, ou dossier `ConfigFiles` zippé |
| Sophos Firewall (SFOS) | export de configuration (`.tar` / `Entities.xml`) |
| WatchGuard Firebox | configuration XML de Policy Manager |
| UniFi (UDM, UCG, UXG…) | API de la console, compte local en lecture seule (pare-feu par zones et anciennes règles) |
| MikroTik RouterOS | `/export` (`.rsc`) ou SSH en lecture (compteurs inclus) |
| Pare-feu Windows | ce poste, ou fichier produit par `--windows-export` sur un serveur |

## Ce qui est contrôlé

| Domaine | Contrôles |
|---|---|
| **Règles de filtrage** | « tout autoriser », sortie sans restriction, flux entrants vers des services sensibles (RDP, SMB, SQL, Telnet…), réseaux invités / objets connectés ouverts vers l'interne, règles **masquées** (jamais appliquées) et **redondantes** (calcul exact sur les ensembles d'adresses et de ports), règles inutilisées (compteurs), désactivées, sans journalisation, sans inspection (UTM), politique par défaut (RouterOS : accepte tout sans « drop » final) |
| **Exposition Internet** | publications / VIP / redirections (sensibles et sans restriction de source), administration du pare-feu sur le WAN, VPN SSL, UPnP, résolveur DNS ouvert ; liste des ports attendus ouverts |
| **Administration et durcissement** | version du système (fin de support), comptes (nom prévisible, hôtes de confiance, MFA), administration non chiffrée, délai de session, VPN (PPTP, IKEv1 agressif, DES/3DES/MD5/SHA1, DH < 14), SNMP, journalisation externe, NTP, IPS, Wi-Fi (UniFi), profils du pare-feu Windows |
| **Vérifications sur le terrain** | filtrage **sortant** réel (≈ 40 ports vers un serveur public de test, DNS direct, DoT, DoH) — avec détection d'une règle de blocage **qui ne fonctionne pas** ; **cloisonnement** réel vers les autres réseaux ; **exposition vue d'Internet** depuis une connexion extérieure (4G), comparée à la configuration (ports inattendus, pages d'administration, SNMP, DNS) |

## Corrections proposées

Pour chaque constat, l'application calcule la **modification exacte** à partir de la configuration lue (numéro de règle,
interface, objets) : commandes **CLI FortiOS** (contexte VDOM / global respecté), **RouterOS** et **PowerShell**, ou
**chemin précis dans l'interface** pour Stormshield, WatchGuard, UniFi et Sophos. Elles s'affichent sous chaque constat
(bouton « Copier ») et en annexe du rapport PDF (option dans les paramètres), avec leurs **points d'attention** :
impact, à faire avant, retour arrière (valeurs d'origine). **L'application ne les applique jamais** :
à vérifier, après sauvegarde, dans une fenêtre de maintenance.

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

## Mises à jour

Au démarrage (désactivable dans Paramètres), l'application consulte la dernière release de ce dépôt GitHub et propose
la mise à jour : téléchargement, contrôle de l'empreinte SHA-256 publiée par GitHub, puis installation (version
installée) ou remplacement de l'exécutable à la fermeture (version portable). Rien n'est installé sans accord.

## Licence

[MIT](LICENSE) — © 2026 SCHMOCK.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

- **Committers and reviewers:** [SCHMOCK](https://github.com/schm0ck101)
- **Approvers:** [SCHMOCK](https://github.com/schm0ck101)

Release binaries (portable executable and installer) are built from this repository by GitHub Actions
(`.github/workflows/build.yml`) and signed through SignPath; every release is approved manually.

### Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user
or the person installing or operating it. It contains no telemetry and no analytics. Network connections:

- **Update check** (can be disabled in Settings): `api.github.com` and `github.com` (latest release of this repository).
- **Firewall configuration**: only the device whose address the user enters (read-only API / SSH), or a local file.
- **Real tests, only when the user starts an audit with tests enabled**: outbound filtering test servers
  (`letmeoutofyour.net`, `portquiz.net`), public DNS resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `208.67.222.222`,
  DNS-over-HTTPS `cloudflare-dns.com`), `pool.ntp.org`, public IP lookup (`myip.opendns.com`), connectivity check
  (`www.msftconnecttest.com`), scans of the networks and public addresses selected by the user.

Audit results stay on the computer (local database next to the portable executable or in `%APPDATA%`).
