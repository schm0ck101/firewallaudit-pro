# Journal des versions

Notes publiques : uniquement les fonctions de l'application, jamais d'information
sur les audits, les équipements ou les configurations analysés.

## 1.0.15
- Une source limitée à un pays (géolocalisation) n'est plus considérée comme restreinte.
- Ports des caméras et enregistreurs vidéo ajoutés aux services sensibles.
- Le pays autorisé est toujours affiché dans les sources des règles.

## 1.0.14
- FortiGate : prise en charge des sauvegardes d'un seul VDOM (points globaux signalés « non vérifiés »).
- FortiGate : liens privés d'opérateur (MPLS) et tunnels IPsec reconnus comme réseaux internes.
- Administration du pare-feu : port réel, restrictions par pays et services mal définis mieux détectés.
- VPN SSL : sources autorisées affichées, version TLS obsolète signalée.

## 1.0.13
- Tests sortants évalués selon le réseau du poste d'audit ; cas du poste raccordé en VPN.

## 1.0.12
- Relance de l'application après mise à jour réparée.
- Préparation de la signature de code (licence MIT, compilation automatisée).

## 1.0.11
- Rapport PDF : marges réduites, plan d'action plus lisible.

## 1.0.10
- Plus de fenêtres de console pendant la mise à jour de la version portable.

## 1.0.9
- Tests sortants rattachés à la bonne règle, suivi des constats plus stable.

## 1.0.8
- Mise à jour de la version portable réparée.

## 1.0.7
- Lecteur FortiGate amélioré (zones SD-WAN, règles local-in, redirections).

## 1.0.6
- Mise à jour automatique proposée au démarrage.

## 1.0.5
- Tests réels derrière un proxy ou un déchiffrement SSL ; conditions des règles affichées.

## 1.0.4
- Lecteur Stormshield : sauvegardes chiffrées SNS 4.x prises en charge.

## 1.0.3
- Tests sortants confrontés à la configuration.

## 1.0.2
- Chemin de sortie vers Internet vérifié ; affichage des expositions amélioré.

## 1.0.1
- Lecteurs UniFi et WatchGuard améliorés.

## 1.0.0
- Audit de pare-feu (FortiGate, Stormshield, Sophos, WatchGuard, UniFi, MikroTik, Windows), tests réels de sortie, cloisonnement et exposition externe, rapport PDF à cocher.
