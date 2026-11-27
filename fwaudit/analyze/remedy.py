"""Corrections proposées : pour chaque constat, la modification exacte à faire,
dans la syntaxe du constructeur, à partir des références relevées par l'analyse
(numéro de règle, interface, objets…).

- FortiGate : commandes CLI FortiOS (contexte VDOM / global respecté)
- MikroTik : commandes RouterOS
- Pare-feu Windows : PowerShell (console administrateur)
- Stormshield, WatchGuard, UniFi, Sophos : chemin exact dans l'interface d'administration

L'application ne les applique JAMAIS : elles sont affichées et copiées par
l'intervenant, à vérifier puis appliquer dans une fenêtre de maintenance après
une sauvegarde. Les valeurs à renseigner sont entre chevrons : <…>.
"""
from __future__ import annotations

import ipaddress
import re

from .context import Ctx
from .model import INFO, Finding

KIND_LABEL = {"cli-fortios": "CLI FortiOS", "routeros": "Terminal RouterOS", "powershell": "PowerShell (administrateur)",
              "gui": "Interface d'administration"}
CAUTION = ("Faire une sauvegarde de la configuration avant toute modification ; appliquer dans une fenêtre de maintenance "
           "et vérifier les flux métier ensuite. Les valeurs entre <…> sont à renseigner.")
MAX_ITEMS = 40


def _q(s) -> str:
    return '"' + str(s).replace('"', "'") + '"'


def _objname(s: str, n: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(s)).strip("-")[:n]


def _rid(rid: str) -> str:
    return str(rid).rsplit(":", 1)[-1]


def _ind(text: str, n: int = 4) -> str:
    return "\n".join((" " * n + ln) if ln else ln for ln in text.splitlines())


def _net_parts(desc: str) -> list[str]:
    """« 192.168.30.0/24, 10.0.0.1-10.0.0.9 (+2) » -> plages exploitables."""
    out = []
    for part in re.split(r",\s*", re.sub(r"\(\+\d+\)", "", desc or "")):
        part = part.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", part) or re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", part):
            out.append(part)
    return out


class Base:
    kind = "gui"

    def __init__(self, c: Ctx):
        self.c = c
        self.cfg = c.cfg
        self.rules = {r.id: r for r in c.cfg.rules}
        self.vpn = {v.name: v for v in c.cfg.vpn}

    def rule(self, rid):
        return self.rules.get(str(rid))

    def rlabel(self, rid) -> str:
        r = self.rule(rid)
        return r.label() if r else f"#{rid}"

    # ---------------------------------------------------------------- aiguillage
    def remedy(self, f: Finding) -> str:
        fid, refs = f.id, f.refs or {}
        table = [
            ("pol.anyany.", self.narrow), ("pol.wide.", self.narrow), ("pol.egress.", self.narrow_egress),
            ("pol.inbound.", self.restrict_src), ("pol.seg.", self.seg_block), ("pol.shadow.", self.move_before),
            ("pol.redundant", self.delete_pairs), ("pol.disabled", self.delete_rules), ("pol.unused", self.disable_rules),
            ("pol.objects", self.delete_objects), ("pol.nolog", self.log_rules), ("pol.noprofile", self.profile_rules),
            ("pol.default.", self.default_drop), ("expo.admin.", self.admin), ("expo.nat.", self.nat),
            ("expo.sslvpn", self.sslvpn), ("expo.ssl.tls.", self.ssl_tls), ("expo.upnp", self.upnp), ("expo.dns", self.dns),
            ("sys.vpn.pptp.", self.pptp), ("sys.vpn.l2tp.", self.l2tp), ("sys.vpn.", self.vpn_harden),
            ("sys.admin.mfa", self.mfa), ("sys.admin.trust", self.trusthost), ("sys.admin.default", self.admin_default),
            ("sys.admin.telnet", self.telnet), ("sys.admin.timeout", self.timeout), ("sys.admin.clear", self.clear_admin),
            ("sys.crypto", self.strong_crypto), ("sys.log", self.log_remote), ("sys.snmp.", self.snmp), ("sys.ntp", self.ntp),
            ("sys.fw", self.firmware),
            ("test.egress.mismatch.", self.egress_mismatch), ("test.egress.", self.egress_port), ("test.dns.direct", self.egress_port),
        ]
        if fid.startswith("pol.win.") or fid.startswith("sys.win.") or fid.startswith("sys.mt.") or fid.startswith("sys.unifi.") \
                or fid.startswith("sys.wifi.") or fid == "sys.ips":
            fn = getattr(self, "specific", None)
            return fn(f) if fn else ""
        for pref, fn in table:
            if fid.startswith(pref):
                try:
                    return fn(f, refs) or ""
                except Exception:          # une correction impossible à calculer ne doit jamais casser l'analyse
                    return ""
        return ""

    # implémentations par défaut : rien (le « Que faire » textuel reste valable)
    def narrow(self, f, refs): return ""
    def narrow_egress(self, f, refs): return self.narrow(f, refs)
    def restrict_src(self, f, refs): return ""
    def seg_block(self, f, refs): return ""
    def move_before(self, f, refs): return ""
    def delete_pairs(self, f, refs): return self.delete_rules(f, {"rules": [p[0] for p in refs.get("pairs", [])]})
    def delete_rules(self, f, refs): return ""
    def disable_rules(self, f, refs): return ""
    def delete_objects(self, f, refs): return ""
    def log_rules(self, f, refs): return ""
    def profile_rules(self, f, refs): return ""
    def default_drop(self, f, refs): return ""
    def admin(self, f, refs): return ""
    def nat(self, f, refs): return ""
    def sslvpn(self, f, refs): return ""
    def ssl_tls(self, f, refs): return ""
    def upnp(self, f, refs): return ""
    def dns(self, f, refs): return ""
    def pptp(self, f, refs): return ""
    def l2tp(self, f, refs): return ""
    def vpn_harden(self, f, refs): return ""
    def mfa(self, f, refs): return ""
    def trusthost(self, f, refs): return ""
    def admin_default(self, f, refs): return ""
    def telnet(self, f, refs): return ""
    def timeout(self, f, refs): return ""
    def clear_admin(self, f, refs): return ""
    def strong_crypto(self, f, refs): return ""
    def log_remote(self, f, refs): return ""
    def snmp(self, f, refs): return ""
    def ntp(self, f, refs): return ""
    def firmware(self, f, refs): return ""
    def egress_port(self, f, refs): return ""
    def egress_mismatch(self, f, refs): return ""

    def vpn_of(self, f) -> str:
        m = re.match(r"sys\.vpn\.(?:pptp\.|l2tp\.)?(.+)$", f.id)
        return m.group(1) if m else ""


# =========================================================================== FortiGate
class Forti(Base):
    kind = "cli-fortios"

    def __init__(self, c):
        super().__init__(c)
        s = c.cfg.services
        self.vmode = bool(s.get("forti_vdom_mode"))
        self.vdoms = s.get("forti_vdoms") or []
        self.groups = set(s.get("forti_unused_groups") or [])

    def _vdom_of(self, rid=None) -> str:
        if rid and ":" in str(rid):
            return str(rid).split(":", 1)[0]
        return self.vdoms[0] if self.vdoms else "root"

    def vd(self, body: str, rid=None) -> str:
        if not self.vmode:
            return body
        return f"config vdom\n    edit {_q(self._vdom_of(rid))}\n{_ind(body, 8)}\n    next\nend"

    def gl(self, body: str) -> str:
        return f"config global\n{_ind(body)}\nend" if self.vmode else body

    @staticmethod
    def pol_body(rid, lines: list[str]) -> str:
        return "config firewall policy\n    edit " + _rid(rid) + "\n" + _ind("\n".join(lines), 8) + "\n    next\nend"

    def pol(self, rid, lines: list[str]) -> str:
        return self.vd(self.pol_body(rid, lines), rid)

    def pols(self, ids, lines_of) -> str:
        """Plusieurs règles : un seul bloc « config firewall policy » par VDOM."""
        by_vd: dict[str, list] = {}
        for rid in ids[:MAX_ITEMS]:
            by_vd.setdefault(self._vdom_of(rid), []).append(rid)
        out = []
        for _vdn, lst in by_vd.items():
            edits = "\n".join("    edit " + _rid(rid) + "\n" + _ind("\n".join(lines_of(rid)), 8) + "\n    next" for rid in lst)
            out.append(self.vd("config firewall policy\n" + edits + "\nend", lst[0]))
        return "\n".join(out)

    # ---------------------------------------------------------------- règles
    def narrow(self, f, refs):
        rid = refs.get("rule")
        if not rid:
            return ""
        return ("# Restreindre la règle aux destinations et services réellement utilisés\n"
                + self.pol(rid, ['set dstaddr "<destinations nécessaires>"',
                                 'set service "<services nécessaires>"    # ex. "HTTP" "HTTPS" "DNS"',
                                 "set logtraffic all"]))

    def narrow_egress(self, f, refs):
        rid = refs.get("rule")
        if not rid:
            return ""
        return ("# Sortie Internet : services utiles uniquement + inspections\n"
                + self.pol(rid, ['set service "HTTP" "HTTPS" "DNS" "NTP"    # compléter selon les besoins',
                                 "set utm-status enable", 'set ssl-ssh-profile "certificate-inspection"',
                                 'set ips-sensor "default"', 'set av-profile "default"', 'set webfilter-profile "default"',
                                 'set application-list "default"', "set logtraffic all"]))

    def restrict_src(self, f, refs):
        rid = refs.get("rule")
        r = self.rule(rid)
        if not r:
            return ""
        src = r.src_set
        if not (src.is_any or src.negate or src.geo or src.size > 2 ** 16):
            # sources déjà limitées (prestataire…) : on garde les sources, on limite les services
            return ("# Sources déjà limitées : n'autoriser que les services nécessaires, avec IPS et journalisation\n"
                    + self.pol(rid, ['set service "<services nécessaires>"    # ex. "RDP" "HTTPS"', "set utm-status enable",
                                     'set ips-sensor "default"', "set logtraffic all"]))
        name = f"SRC-AUTORISEES-{_rid(rid)}"
        return ("# Adresses autorisées (un « edit » par adresse ou réseau), puis règle limitée à ces adresses avec IPS et journal\n"
                + self.vd("config firewall address\n" + self.addr_obj(name, "<IP autorisée>") + "\nend\n"
                          + self.pol_body(rid, [f"set srcaddr {_q(name)}", "set utm-status enable", 'set ips-sensor "default"',
                                                "set logtraffic all"]), rid))

    def addr_obj(self, name: str, net: str) -> str:
        """Objet adresse FortiOS : réseau, plage, ou valeur à renseigner (<…>)."""
        if net.startswith("<"):
            return f"    edit {_q(name)}\n        set subnet {net} 255.255.255.255\n    next"
        if "-" in net:
            a, b = net.split("-", 1)
            return f"    edit {_q(name)}\n        set type iprange\n        set start-ip {a}\n        set end-ip {b}\n    next"
        n = ipaddress.ip_network(net if "/" in net else net + "/32", strict=False)
        return f"    edit {_q(name)}\n        set subnet {n.network_address} {n.netmask}\n    next"

    def seg_block(self, f, refs):
        rid, r = refs.get("rule"), self.rule(refs.get("rule"))
        if not r:
            return ""
        src = _net_parts(refs.get("net_cidr", ""))
        dst = [p for d in refs.get("to_cidr", []) for p in _net_parts(d)]
        if not src or not dst:
            return ""
        base = _objname(f"NET-{refs.get('net')}", 30)
        snames = [base + (f"-{i}" if i else "") for i in range(len(src))]
        dnames = [f"NET-INTERNE-{i + 1}" for i in range(len(dst))]
        objs = [self.addr_obj(n, s) for n, s in zip(snames, src)] + [self.addr_obj(n, d) for n, d in zip(dnames, dst)]
        body = ("config firewall address\n" + "\n".join(objs) + "\nend\n"
                "config firewall policy\n    edit 0\n"
                + _ind("\n".join([f"set name {_q('BLOQUER-' + _objname(refs.get('net'), 20) + '-INTERNE')}",
                                  "set srcintf " + (" ".join(_q(z) for z in r.src_zones) or '"any"'),
                                  "set dstintf " + (" ".join(_q(z) for z in r.dst_zones) or '"any"'),
                                  "set srcaddr " + " ".join(_q(n) for n in snames),
                                  "set dstaddr " + " ".join(_q(n) for n in dnames),
                                  "set action deny", 'set schedule "always"', 'set service "ALL"', "set logtraffic all"]), 8)
                + "\n    next\nend")
        return (f"# Bloquer « {refs.get('net')} » vers les réseaux internes, AVANT la règle {_rid(rid)}\n" + self.vd(body, rid)
                + f"\n# Puis placer la nouvelle règle avant la {_rid(rid)} (relever son numéro avec « show firewall policy ») :\n"
                + self.vd(f"config firewall policy\n    move <n° de la nouvelle règle> before {_rid(rid)}\nend", rid))

    def move_before(self, f, refs):
        b, a = refs.get("rule"), refs.get("before")
        if not (a and b):
            return ""
        return (f"# Placer la règle {_rid(b)} avant la règle {_rid(a)} qui la masque\n"
                + self.vd(f"config firewall policy\n    move {_rid(b)} before {_rid(a)}\nend", b))

    def delete_rules(self, f, refs):
        ids = refs.get("rules") or []
        if not ids:
            return ""
        by_vd: dict[str, list] = {}
        for rid in ids[:MAX_ITEMS]:
            by_vd.setdefault(self._vdom_of(rid), []).append(_rid(rid))
        out = []
        for vdn, lst in by_vd.items():
            body = "config firewall policy\n" + "\n".join(f"    delete {x}" for x in lst) + "\nend"
            out.append(self.vd(body, f"{vdn}:x") if ":" in str(ids[0]) else self.vd(body))
        return "# Supprimer les règles (après vérification)\n" + "\n".join(out)

    def disable_rules(self, f, refs):
        ids = refs.get("rules") or []
        if not ids:
            return ""
        return "# Désactiver d'abord (suppression après une période d'observation)\n" + self.pols(ids, lambda rid: ["set status disable"])

    def delete_objects(self, f, refs):
        objs = refs.get("objects") or []
        if not objs:
            return ""
        grp = [o for o in objs if o in self.groups][:MAX_ITEMS]
        adr = [o for o in objs if o not in self.groups][:MAX_ITEMS]
        body = ""
        if grp:
            body += "config firewall addrgrp\n" + "\n".join(f"    delete {_q(o)}" for o in grp) + "\nend\n"
        if adr:
            body += "config firewall address\n" + "\n".join(f"    delete {_q(o)}" for o in adr) + "\nend"
        more = len(objs) - len(grp) - len(adr)
        return ("# Objets inutilisés (FortiOS refuse la suppression d'un objet encore référencé)\n" + self.vd(body.strip())
                + (f"\n# … et {more} autre(s) objet(s) : voir la liste complète dans l'application" if more > 0 else ""))

    def log_rules(self, f, refs):
        return self.pols(refs.get("rules") or [], lambda rid: ["set logtraffic all"])

    def profile_rules(self, f, refs):
        ids = (refs.get("rules") or [])[:MAX_ITEMS]
        if not ids:
            return ""
        def lines(rid):
            r = self.rule(rid)
            out = ["set utm-status enable", 'set ssl-ssh-profile "certificate-inspection"', 'set ips-sensor "default"',
                   'set av-profile "default"']
            if not (r is not None and self.c.from_wan(r)):      # sortie : filtrage web et contrôle applicatif en plus
                out += ['set webfilter-profile "default"', 'set application-list "default"']
            return out
        return ("# Profils de sécurité (adapter les noms aux profils existants : « show ips sensor », « show antivirus profile »)\n"
                + self.pols(ids, lines))

    # ---------------------------------------------------------------- administration
    def _allowaccess(self, iface: str, remove: set) -> str:
        i = next((x for x in self.cfg.interfaces if x.name == iface), None)
        if not i:
            return ""
        keep = [a for a in i.admin if a not in remove]
        line = "set allowaccess " + " ".join(keep) if keep else "unset allowaccess"
        return self.gl(f"config system interface\n    edit {_q(iface)}\n        {line}\n    next\nend")

    def admin(self, f, refs):
        iface, svc = refs.get("iface"), refs.get("svc")
        if refs.get("rule"):
            return self.restrict_src(f, {"rule": refs["rule"]})
        if not (iface and svc):
            return ""
        admin_svcs = {"http", "https", "ssh", "telnet", "snmp", "radius-acct", "ftm", "speed-test"}
        out = [f"# Solution conseillée : plus aucune administration par l'interface Internet « {iface} » (même commande pour "
               "tous les constats de cette interface)", self._allowaccess(iface, admin_svcs)]
        geo = refs.get("geo") or []
        if geo and refs.get("limit"):
            objs = [g.split(" (")[0] for g in geo]
            srcs = refs.get("limit_src") or []
            lim = _rid(str(refs["limit"]).replace("local-in ", ""))
            out.append("# À défaut : retirer le pays de la liste des sources autorisées (local-in " + lim + ")")
            direct = [o for o in objs if o in srcs]
            if direct:
                out.append(self.vd(f"config firewall local-in-policy\n    edit {lim}\n"
                                   + "".join(f"        unselect srcaddr {_q(o)}\n" for o in direct) + "    next\nend"))
            for g in [s for s in srcs if s not in objs]:
                out.append(self.vd(f"config firewall addrgrp\n    edit {_q(g)}\n"
                                   + "".join(f"        unselect member {_q(o)}\n" for o in objs if o not in direct)
                                   + "    next\nend"))
                break
            out.append("# Attention : vérifier les autres règles qui utilisent ce groupe avant de le modifier.")
        elif refs.get("near") and refs.get("near_svc"):
            name = next((n for n in refs["near_svc"] if svc.lower() in n.lower()), refs["near_svc"][0])
            port = refs.get("port") or 161
            proto = "udp" if port == 161 else "tcp"
            out.append(f"# À défaut : corriger le service « {name} » utilisé par la règle {refs['near']} "
                       f"(le service réel est en {proto.upper()})")
            out.append(self.vd(f"config firewall service custom\n    edit {_q(name)}\n        set {proto}-portrange "
                               f"{'161-162' if port == 161 else port}\n    next\nend"))
        elif not refs.get("limit"):
            port = refs.get("port") or 443
            out.append("# À défaut : limiter l'accès aux adresses d'administration (règle local-in de refus « sauf »)")
            out.append(self.vd("config firewall address\n" + self.addr_obj("ADMIN-AUTORISES", "<IP d'administration>") + "\nend\n"
                               f"config firewall service custom\n    edit \"ADMIN-{svc.upper()}-{port}\"\n"
                               f"        set {'udp' if port == 161 else 'tcp'}-portrange {port}\n    next\nend\n"
                               "config firewall local-in-policy\n    edit 0\n"
                               f"        set intf {_q(iface)}\n        set srcaddr \"ADMIN-AUTORISES\"\n        set srcaddr-negate enable\n"
                               f"        set dstaddr \"all\"\n        set service \"ADMIN-{svc.upper()}-{port}\"\n"
                               "        set schedule \"always\"\n        set action deny\n    next\nend"))
        return "\n".join(x for x in out if x)

    def nat(self, f, refs):
        rules = refs.get("rules") or []
        if not rules:
            return ""
        label = str(refs.get("nat_name") or refs.get("nat"))
        name = "SRC-" + _objname(label, 36)
        edits = "\n".join("    edit " + _rid(rid) + "\n" + _ind("\n".join(
            [f"set srcaddr {_q(name)}", "set utm-status enable", 'set ips-sensor "default"', "set logtraffic all"]), 8) + "\n    next"
            for rid in rules[:10])
        body = ("config firewall address\n" + self.addr_obj(name, "<IP autorisée>") + "\nend\n"
                "config firewall policy\n" + edits + "\nend")
        return ("# Solution conseillée : supprimer la publication et passer par le VPN\n"
                f"# À défaut : limiter les sources des règles qui laissent passer vers « {label} »\n" + self.vd(body, rules[0]))

    def sslvpn(self, f, refs):
        return ("# Si le VPN SSL n'est plus utilisé (migration vers IPsec IKEv2 + MFA faite) :\n"
                + self.vd("config vpn ssl settings\n    set status disable\nend")
                + "\n# Sinon, au minimum : MFA sur le groupe VPN, TLS 1.2 minimum, sources limitées\n"
                + self.vd("config vpn ssl settings\n    set ssl-min-proto-ver tls1-2\n    set source-address \"<pays ou adresses autorisés>\"\n"
                          "    set login-attempt-limit 3\n    set login-block-time 3600\nend"))

    def ssl_tls(self, f, refs):
        return self.vd("config vpn ssl settings\n    set ssl-min-proto-ver tls1-2\nend")

    def pptp(self, f, refs):
        return self.gl("config vpn pptp\n    set status disable\nend") if not self.vmode else self.vd("config vpn pptp\n    set status disable\nend")

    def l2tp(self, f, refs):
        return self.vd("config vpn l2tp\n    set status disable\nend")

    def vpn_harden(self, f, refs):
        name = self.vpn_of(f)
        if name not in self.vpn or self.vpn[name].kind != "ipsec":
            return ""
        return (f"# Tunnel « {name} » : à modifier À L'IDENTIQUE sur l'équipement d'en face (sinon le tunnel tombe)\n"
                + self.vd(f"config vpn ipsec phase1-interface\n    edit {_q(name)}\n        set ike-version 2\n"
                          "        set proposal aes256gcm-prfsha384 aes256-sha256\n        set dhgrp 21 20 19 14\n    next\nend\n"
                          "config vpn ipsec phase2-interface\n    edit \"<phase 2 de " + name + ">\"\n"
                          "        set proposal aes256gcm aes256-sha256\n        set pfs enable\n        set dhgrp 21 20 19 14\n    next\nend"))

    def mfa(self, f, refs):
        names = [a.name for a in self.cfg.admins if a.mfa is False][:MAX_ITEMS]
        return self.gl("config system admin\n" + "\n".join(
            f"    edit {_q(n)}\n        set two-factor email    # ou fortitoken / fortitoken-cloud\n"
            f"        set email-to \"<adresse de {n}>\"\n    next" for n in names) + "\nend") if names else ""

    def trusthost(self, f, refs):
        names = [a.name for a in self.cfg.admins if a.enabled and not a.trusted][:MAX_ITEMS]
        return self.gl("config system admin\n" + "\n".join(
            f"    edit {_q(n)}\n        set trusthost1 <réseau d'administration> <masque>\n        set trusthost2 <IP du prestataire> 255.255.255.255\n    next"
            for n in names) + "\nend") if names else ""

    def admin_default(self, f, refs):
        names = [a.name for a in self.cfg.admins if a.default_name]
        return ("# 1. Créer un compte nominatif super_admin (avec MFA et hôtes de confiance), s'y connecter, puis :\n"
                + self.gl("config system admin\n" + "".join(f"    delete {_q(n)}\n" for n in names) + "end")) if names else ""

    def telnet(self, f, refs):
        return self.gl("config system global\n    set admin-telnet disable\nend")

    def timeout(self, f, refs):
        return self.gl("config system global\n    set admintimeout 15\nend")

    def clear_admin(self, f, refs):
        out = []
        for i in self.cfg.interfaces:
            if i.role != "wan" and any(a in ("http", "telnet") for a in i.admin):
                out.append(self._allowaccess(i.name, {"http", "telnet"}))
        return "\n".join(out)

    def strong_crypto(self, f, refs):
        return self.gl("config system global\n    set strong-crypto enable\nend")

    def log_remote(self, f, refs):
        return self.gl("config log syslogd setting\n    set status enable\n    set server \"<IP du serveur syslog>\"\n"
                       "    set mode reliable\nend")

    def snmp(self, f, refs):
        return ("# SNMPv3 chiffré pour la supervision, puis suppression de la communauté v1/v2c\n"
                + self.gl("config system snmp user\n    edit \"supervision\"\n        set notify-hosts <IP de supervision>\n"
                          "        set security-level auth-priv\n        set auth-proto sha256\n        set auth-pwd <mot de passe>\n"
                          "        set priv-proto aes256\n        set priv-pwd <mot de passe>\n    next\nend\n"
                          "config system snmp community\n    delete <n° de la communauté, voir « show system snmp community »>\nend"))

    def ntp(self, f, refs):
        return self.gl("config system ntp\n    set ntpsync enable\n    set type fortiguard\nend")

    def egress_port(self, f, refs):
        port = refs.get("port")
        if not port:
            return ""
        protos = refs.get("protos") or ["tcp"]
        r = self.rule(refs.get("rule")) if refs.get("rule") else None
        svc = f"BLOQUER-{'-'.join(p.upper() for p in protos)}-{port}"
        src_names = (r.src_names if r and r.src_names else ["all"])
        lines = [f"set name {_q(f'BLOQUER-SORTIE-{port}')}",
                 "set srcintf " + (" ".join(_q(z) for z in r.src_zones) if r and r.src_zones else '"<interface LAN>"'),
                 "set dstintf " + (" ".join(_q(z) for z in r.dst_zones) if r and r.dst_zones else '"<interface Internet>"'),
                 "set srcaddr " + (_q(refs["except"]) if refs.get("except") else " ".join(_q(n) for n in src_names))]
        if refs.get("except"):
            lines.append("set srcaddr-negate enable    # tout le monde SAUF les résolveurs internes")
        elif port == 25:
            lines.append('# exception : exclure le serveur de messagerie (set srcaddr-negate enable + son adresse)')
        lines += ['set dstaddr "all"', "set action deny", f"set service {_q(svc)}", 'set schedule "always"', "set logtraffic all"]
        body = (f"config firewall service custom\n    edit {_q(svc)}\n"
                + "".join(f"        set {p}-portrange {port}\n" for p in protos) + "    next\nend\n"
                "config firewall policy\n    edit 0\n" + _ind("\n".join(lines), 8) + "\n    next\nend")
        rid = r.id if r else None
        out = f"# Bloquer le port {port} en sortie\n" + self.vd(body, rid)
        target = _rid(r.id) if r else "<n° de la première règle de sortie vers Internet>"
        out += (f"\n# Puis placer la nouvelle règle avant la {target} (relever son numéro avec « show firewall policy ») :\n"
                + self.vd(f"config firewall policy\n    move <n° de la nouvelle règle> before {target}\nend", rid))
        return out

    def egress_mismatch(self, f, refs):
        port = refs.get("port")
        if not port:
            return ""
        return ("# Diagnostic : quelle règle laisse réellement passer ce flux ? (lancer une connexion de test pendant la trace)\n"
                + (f"diagnose sys vd list    # puis : config vdom / edit <vdom> (mode VDOM)\n" if self.vmode else "")
                + "diagnose debug reset\n"
                f"diagnose debug flow filter dport {port}\n"
                "diagnose debug flow show function-name enable\n"
                "diagnose debug flow trace start 20\n"
                "diagnose debug enable\n"
                "# … lire « Allowed by Policy-<n°> » (règle réellement appliquée), puis :\n"
                "diagnose debug disable\ndiagnose debug reset")

    def firmware(self, f, refs):
        return ("# Vérifier le chemin de mise à jour recommandé (docs.fortinet.com › Upgrade Path) puis :\n"
                "# Système › Microgiciel et mise à jour (System › Firmware & Registration) › Mettre à jour\n"
                "execute backup config ftp <fichier> <serveur>    # ou sauvegarde depuis l'interface")


# =========================================================================== MikroTik
class MikroTik(Base):
    kind = "routeros"

    def sel(self, rid) -> str:
        r = self.rule(rid)
        if r and r.name:
            return f'[find comment={_q(r.name)}]'
        return f"numbers={rid}"

    def numbers_note(self, ids) -> str:
        """Règles sans commentaire : désignées par leur numéro d'export, à vérifier (règles dynamiques comprises dans « print »)."""
        bare = [str(r) for r in ids if not (self.rule(r) and self.rule(r).name)]
        return ("# Vérifier d'abord les numéros avec « /ip firewall filter print » (règles sans commentaire : "
                + ", ".join(bare) + ")\n") if bare else ""

    def _path(self, rid) -> str:
        r = self.rule(rid)
        return "/ip firewall filter" if not r or r.layer in ("input", "filter", "forward") else "/ip firewall filter"

    def narrow(self, f, refs):
        rid = refs.get("rule")
        return (self.numbers_note([rid]) + f"{self._path(rid)} set {self.sel(rid)} dst-address-list=<destinations> protocol=tcp "
                "dst-port=<ports>") if rid else ""

    def restrict_src(self, f, refs):
        rid = refs.get("rule")
        if not rid:
            return ""
        return (self.numbers_note([rid]) + "/ip firewall address-list add list=SOURCES-AUTORISEES address=<IP autorisée>\n"
                f"{self._path(rid)} set {self.sel(rid)} src-address-list=SOURCES-AUTORISEES")

    def seg_block(self, f, refs):
        src = _net_parts(refs.get("net_cidr", ""))
        dst = [p for d in refs.get("to_cidr", []) for p in _net_parts(d)]
        rid = refs.get("rule")
        if not (src and dst and rid):
            return ""
        r = self.rule(rid)
        place = f" place-before=[find comment={_q(r.name)}]" if r and r.name else f" place-before={rid}"
        return "\n".join(f"/ip firewall filter add chain=forward action=drop src-address={s} dst-address={d} "
                         f"comment=\"bloquer {refs.get('net')} vers interne\"{place}" for s in src for d in dst)

    def move_before(self, f, refs):
        b, a = refs.get("rule"), refs.get("before")
        return ("# Vérifier d'abord les numéros avec « /ip firewall filter print »\n"
                f"/ip firewall filter move numbers={b} destination={a}") if a and b else ""

    def delete_rules(self, f, refs):
        ids = (refs.get("rules") or [])[:MAX_ITEMS]
        return self.numbers_note(ids) + "\n".join(f"/ip firewall filter remove {self.sel(rid)}" for rid in ids)

    def disable_rules(self, f, refs):
        ids = (refs.get("rules") or [])[:MAX_ITEMS]
        return self.numbers_note(ids) + "\n".join(f"/ip firewall filter disable {self.sel(rid)}" for rid in ids)

    def delete_objects(self, f, refs):
        return "\n".join(f"/ip firewall address-list remove [find list={_q(o)}]" for o in (refs.get("objects") or [])[:MAX_ITEMS])

    def log_rules(self, f, refs):
        ids = (refs.get("rules") or [])[:MAX_ITEMS]
        return self.numbers_note(ids) + "\n".join(f"/ip firewall filter set {self.sel(rid)} log=yes log-prefix=\"entrant\"" for rid in ids)

    def default_drop(self, f, refs):
        if refs.get("layer") == "input":
            return ("# Protection du routeur (chaîne input) — la liste d'interfaces « LAN » doit exister (/interface list member)\n"
                    "/ip firewall filter\n"
                    "add chain=input action=accept connection-state=established,related,untracked comment=\"input : établies\"\n"
                    "add chain=input action=drop connection-state=invalid comment=\"input : invalides\"\n"
                    "add chain=input action=accept protocol=icmp comment=\"input : ICMP\"\n"
                    "add chain=input action=drop in-interface-list=!LAN comment=\"input : bloquer tout sauf LAN\"")
        return ("/ip firewall filter\n"
                "add chain=forward action=accept connection-state=established,related,untracked comment=\"forward : établies\"\n"
                "add chain=forward action=drop connection-state=invalid comment=\"forward : invalides\"\n"
                "add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN "
                "comment=\"forward : bloquer WAN non publié\"")

    def admin(self, f, refs):
        svc = refs.get("svc")
        if refs.get("rule"):
            return self.restrict_src(f, {"rule": refs["rule"]})
        if not svc:
            return ""
        if svc in ("telnet", "ftp", "www", "api"):
            return f"/ip service disable {svc}"
        return f"/ip service set {svc} address=<réseau d'administration>"

    def nat(self, f, refs):
        nid = refs.get("nat")
        n = next((x for x in self.cfg.nat if x.id == nid), None)
        sel = f'[find comment={_q(n.name)}]' if n and n.name else f"numbers={nid}"
        return ("/ip firewall address-list add list=SOURCES-AUTORISEES address=<IP autorisée>\n"
                f"/ip firewall nat set {sel} src-address-list=SOURCES-AUTORISEES\n"
                f"# ou supprimer la redirection : /ip firewall nat disable {sel}")

    def dns(self, f, refs):
        return "/ip dns set allow-remote-requests=no    # si le routeur ne sert pas de DNS au LAN ; sinon : drop input final"

    def upnp(self, f, refs):
        return "/ip upnp set enabled=no"

    def pptp(self, f, refs):
        return "/interface pptp-server server set enabled=no"

    def l2tp(self, f, refs):
        return "/interface l2tp-server server set use-ipsec=required"

    def vpn_harden(self, f, refs):
        name = self.vpn_of(f)
        return (f"# Pair « {name} » : à modifier aussi sur l'équipement d'en face\n"
                f"/ip ipsec peer set [find name={_q(name)}] exchange-mode=ike2\n"
                "/ip ipsec profile set [find name=<profil du pair>] hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=ecp256,modp2048\n"
                "/ip ipsec proposal set [find name=<proposition>] auth-algorithms=sha256 enc-algorithms=aes-256-gcm pfs-group=ecp256")

    def snmp(self, f, refs):
        return ("/snmp community set [find default=yes] name=<nouvelle communauté> addresses=<IP de supervision>\n"
                "# mieux : SNMPv3 — /snmp community add name=supervision security=private authentication-protocol=SHA1 "
                "encryption-protocol=AES authentication-password=<…> encryption-password=<…> addresses=<IP de supervision>")

    def log_remote(self, f, refs):
        return ("/system logging action add name=syslog target=remote remote=<IP du serveur syslog>\n"
                "/system logging add topics=info action=syslog\n/system logging add topics=warning action=syslog\n"
                "/system logging add topics=critical action=syslog")

    def ntp(self, f, refs):
        return "/system ntp client set enabled=yes servers=fr.pool.ntp.org"

    def firmware(self, f, refs):
        return "/system package update set channel=stable\n/system package update check-for-updates\n/system package update install"

    def egress_port(self, f, refs):
        port = refs.get("port")
        if not port:
            return ""
        r = self.rule(refs.get("rule")) if refs.get("rule") else None
        place = (f" place-before=[find comment={_q(r.name)}]" if r and r.name else f" place-before={r.id}" if r else "")
        exc = " src-address-list=!RESOLVEURS-INTERNES" if refs.get("except") else ""
        out = ("/ip firewall address-list add list=RESOLVEURS-INTERNES address=<IP du résolveur interne>\n" if exc else "")
        for p in refs.get("protos") or ["tcp"]:
            out += (f"/ip firewall filter add chain=forward action=drop protocol={p} dst-port={port} out-interface-list=WAN{exc} "
                    f"log=yes comment=\"bloquer sortie {port}/{p}\"{place}\n")
        return (self.numbers_note([r.id]) if r and not r.name else "") + out.strip()

    def specific(self, f):
        if f.id == "sys.mt.services":
            return ("/ip service disable telnet,ftp,www,api\n"
                    "/ip service set winbox,ssh,www-ssl address=<réseau d'administration>")
        if f.id == "sys.mt.mac":
            return ("/tool mac-server set allowed-interface-list=LAN\n/tool mac-server mac-winbox set allowed-interface-list=LAN\n"
                    "/ip neighbor discovery-settings set discover-interface-list=LAN")
        return ""


# =========================================================================== Windows
def _ps(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


class Windows(Base):
    kind = "powershell"

    def egress_port(self, f, refs):
        port = refs.get("port")
        if not port:
            return ""
        return "\n".join(f"New-NetFirewallRule -DisplayName 'Bloquer sortie {p.upper()} {port}' -Direction Outbound -Protocol {p.upper()} "
                          f"-RemotePort {port} -Action Block -Profile Any" for p in refs.get("protos") or ["tcp"])

    def _names(self, refs) -> list[str]:
        return [self.rule(r).name for r in (refs.get("rules") or [])[:MAX_ITEMS] if self.rule(r) and self.rule(r).name]

    def specific(self, f):
        refs = f.refs or {}
        names = self._names(refs)
        prof = f.id.rsplit(".", 1)[-1]
        if f.id == "pol.win.anyport":
            return "# Désactiver (supprimer ensuite avec Remove-NetFirewallRule si aucun usage)\n" + "\n".join(
                f"Disable-NetFirewallRule -Name {_ps(n)}" for n in names)
        if f.id == "pol.win.prog":
            return "# Limiter aux profils Domaine / Privé\n" + "\n".join(
                f"Set-NetFirewallRule -Name {_ps(n)} -Profile Domain,Private" for n in names)
        if f.id == "pol.win.edge":
            return "\n".join(f"Set-NetFirewallRule -Name {_ps(n)} -EdgeTraversalPolicy Block" for n in names)
        if re.match(r"pol\.win\.\d+$", f.id):
            return ("# Limiter au réseau d'administration (et aux profils Domaine / Privé)\n" + "\n".join(
                f"Set-NetFirewallRule -Name {_ps(n)} -Profile Domain,Private -RemoteAddress <réseau d'administration>" for n in names))
        if f.id.startswith("sys.win.off."):
            return f"Set-NetFirewallProfile -Profile {prof} -Enabled True"
        if f.id.startswith("sys.win.in."):
            return f"Set-NetFirewallProfile -Profile {prof} -DefaultInboundAction Block"
        if f.id.startswith("sys.win.log."):
            return (f"Set-NetFirewallProfile -Profile {prof} -LogBlocked True -LogMaxSizeKilobytes 16384 "
                    "-LogFileName '%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log'")
        if f.id == "sys.win.public":
            return ("# Diagnostic de la détection du domaine\nGet-NetConnectionProfile\nResolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN\n"
                    "Restart-Service NlaSvc -Force    # relance la détection (coupure réseau brève)")
        return ""


# =========================================================================== interfaces graphiques
class Gui(Base):
    """Constructeurs administrés surtout par l'interface web : chemin exact + réglage à faire."""
    kind = "gui"
    P = {}            # chemins propres au constructeur

    def p(self, key, **kw) -> str:
        return self.P[key].format(**kw)

    def rname(self, rid) -> str:
        r = self.rule(rid)
        if not r:
            return f"n° {rid}"
        return f"n° {r.id}" + (f" « {r.name} »" if r.name and r.name != r.id else "")

    def narrow(self, f, refs):
        rid = refs.get("rule")
        return self.p("rule", r=self.rname(rid)) + "\n" + self.P["narrow"] + self.P.get("apply", "") if rid else ""

    def restrict_src(self, f, refs):
        rid = refs.get("rule")
        r = self.rule(rid)
        if not r:
            return ""
        src = r.src_set
        if not (src.is_any or src.negate or src.geo or src.size > 2 ** 16):
            return (self.p("rule", r=self.rname(rid)) + "\n  Sources déjà limitées : n'autoriser que les services (ports) "
                    "nécessaires, activer l'IPS et la journalisation." + self.P.get("apply", ""))
        return self.p("rule", r=self.rname(rid)) + "\n" + self.P["src"] + self.P.get("apply", "")

    def seg_block(self, f, refs):
        rid = refs.get("rule")
        if not rid:
            return ""
        return self.p("seg", r=self.rname(rid), net=refs.get("net"), cidr=refs.get("net_cidr", ""),
                      to=", ".join(refs.get("to") or []), tocidr=", ".join(refs.get("to_cidr") or [])) + self.P.get("apply", "")

    def move_before(self, f, refs):
        b, a = refs.get("rule"), refs.get("before")
        return self.p("move", b=self.rname(b), a=self.rname(a)) + self.P.get("apply", "") if a and b else ""

    def _list(self, refs, key):
        ids = (refs.get("rules") or [])[:MAX_ITEMS]
        if not ids:
            return ""
        return self.P[key] + "\n" + "\n".join(f"  • règle {self.rname(r)}" for r in ids) + self.P.get("apply", "")

    def delete_rules(self, f, refs): return self._list(refs, "delete")
    def disable_rules(self, f, refs): return self._list(refs, "disable")
    def log_rules(self, f, refs): return self._list(refs, "rule_log")
    def profile_rules(self, f, refs): return self._list(refs, "profiles") if "profiles" in self.P else ""

    def delete_objects(self, f, refs):
        objs = (refs.get("objects") or [])[:MAX_ITEMS]
        return (self.P["objects"] + "\n" + "\n".join(f"  • {o}" for o in objs)) if objs and "objects" in self.P else ""

    def admin(self, f, refs):
        if refs.get("rule"):
            return self.p("rule", r=self.rname(refs["rule"])) + "\n" + self.P["admin_rule"] + self.P.get("apply", "")
        return self.P.get("admin", "")

    def nat(self, f, refs):
        rules = refs.get("rules") or []
        txt = self.p("nat", n=refs.get("nat_name") or refs.get("nat"))
        if rules and "rule" in self.P:
            txt += "\nPuis, pour chaque règle qui laisse passer ce flux :\n" + "\n".join(
                "  • " + self.p("rule", r=self.rname(r)) + " — " + self.P["src"].splitlines()[0].strip() for r in rules[:10])
        return txt + self.P.get("apply", "")

    def vpn_harden(self, f, refs):
        name = self.vpn_of(f)
        return self.p("vpn", v=name) if "vpn" in self.P and name in self.vpn else ""

    def egress_port(self, f, refs):
        port = refs.get("port")
        if not port or "egress" not in self.P:
            return ""
        r = self.rule(refs.get("rule")) if refs.get("rule") else None
        protos = "/".join(p.upper() for p in refs.get("protos") or ["tcp"])
        where = f"AU-DESSUS de la règle {self.rname(r.id)}" if r else "avant les règles de sortie vers Internet"
        src = (f"tout SAUF {refs['except']}" if refs.get("except")
               else (r.src_set.describe(3) if r else "réseaux internes"))
        return self.p("egress", where=where, src=src, port=port, protos=protos) + self.P.get("apply", "")

    def _simple(key):        # noqa: N805 (fabrique utilisée dans le corps de la classe)
        def fn(self, f, refs):
            return self.P.get(key, "")
        return fn

    sslvpn = _simple("sslvpn")
    ssl_tls = _simple("ssl_tls")
    pptp = _simple("pptp")
    l2tp = _simple("l2tp")
    mfa = _simple("mfa")
    trusthost = _simple("trusthost")
    admin_default = _simple("admin_default")
    log_remote = _simple("log")
    snmp = _simple("snmp")
    ntp = _simple("ntp")
    firmware = _simple("firmware")
    upnp = _simple("upnp")
    clear_admin = _simple("clear")
    timeout = _simple("timeout")
    del _simple


class Stormshield(Gui):
    P = {
        "rule": "Configuration › Politique de sécurité › Filtrage et NAT › politique active › onglet Filtrage › règle {r}",
        "narrow": "  Destination : remplacer « Any » par les objets nécessaires ; Port / protocole : uniquement les services utiles ;\n"
                  "  Inspection de sécurité : niveau IPS, Antivirus et Filtrage URL activés.",
        "src": "  Source › Objets sources : remplacer « Any » par le groupe des adresses autorisées\n"
               "  (Configuration › Objets › Objets réseau › Ajouter › Groupe) ; Action › Niveau de trace : Standard.",
        "seg": "Configuration › Politique de sécurité › Filtrage et NAT › onglet Filtrage : AJOUTER une règle juste AU-DESSUS de la règle {r}\n"
               "  Action : bloquer · Source : « {net} » ({cidr}) · Destination : {to} ({tocidr}) · Port : Any · Niveau de trace : Standard",
        "move": "Configuration › Politique de sécurité › Filtrage et NAT › onglet Filtrage : sélectionner la règle {b}\n"
                "  et la remonter (bouton « Monter ») au-dessus de la règle {a}.",
        "delete": "Configuration › Politique de sécurité › Filtrage et NAT › onglet Filtrage › sélectionner puis « Supprimer » :",
        "disable": "Configuration › Politique de sécurité › Filtrage et NAT › onglet Filtrage › double-clic sur l'état → « off » :",
        "rule_log": "Filtrage et NAT › onglet Filtrage › règle › Action › onglet Général › Niveau de trace : Standard (connexions) :",
        "profiles": "Filtrage et NAT › onglet Filtrage › colonne « Inspection de sécurité » : niveau IPS + Antivirus (+ Filtrage URL/SSL "
                    "pour la sortie) sur :",
        "objects": "Configuration › Objets › Objets réseau › sélectionner l'objet › « Vérifier l'utilisation » puis « Supprimer » :",
        "nat": "Configuration › Politique de sécurité › Filtrage et NAT › onglet NAT (ou redirection intégrée à la règle « {n} ») :\n"
               "  supprimer la publication (accès par VPN) ou limiter la Source originale aux adresses autorisées.",
        "admin_rule": "  Source : limiter aux adresses d'administration (jamais « Any » / « Internet ») ; Port : uniquement HTTPS / SSH.",
        "admin": "Configuration › Système › Configuration › onglet Administration du firewall :\n"
                 "  Accès aux pages d'administration › Postes d'administration autorisés : réseau d'administration uniquement ;\n"
                 "  Accès distant par SSH : désactivé ou limité aux mêmes postes.",
        "vpn": "Configuration › VPN › VPN IPsec › onglet Correspondants › « {v} » : Version IKE = 2 ;\n"
               "  onglet Profils de chiffrement › profil IKE de « {v} » : AES-256 · SHA-256 · DH19 (ou DH14) ;\n"
               "  profil IPsec : AES-256-GCM · PFS DH19 — à modifier À L'IDENTIQUE sur l'équipement d'en face.",
        "sslvpn": "Configuration › VPN › VPN SSL : désactiver si inutilisé, sinon MFA (TOTP) obligatoire et sources limitées.",
        "ssl_tls": "Configuration › VPN › VPN SSL › Configuration avancée : TLS 1.2 minimum.",
        "pptp": "Configuration › VPN › VPN PPTP : désactiver le service.",
        "mfa": "Configuration › Utilisateurs › Méthodes d'authentification : activer TOTP ;\n"
               "Configuration › Système › Administrateurs › compte › Authentification multifacteur (TOTP), SNS 4.5 ou plus.",
        "trusthost": "Configuration › Système › Configuration › onglet Administration du firewall › Postes d'administration autorisés.",
        "admin_default": "Configuration › Système › Administrateurs : créer des comptes nominatifs, puis restreindre / mot de passe fort "
                         "sur « admin » (non supprimable).",
        "log": "Configuration › Notifications › Traces - Syslog - IPFIX › onglet Syslog : activer un profil,\n"
               "  Serveur syslog : <IP du serveur> · Protocole : TCP (ou TLS) · Format : RFC5424.",
        "snmp": "Configuration › Notifications › Agent SNMP : désactiver v1 / v2c ; onglet SNMPv3 : utilisateur,\n"
                "  authentification SHA, chiffrement AES ; limiter aux IP de supervision.",
        "ntp": "Configuration › Système › Configuration › onglet Paramètres généraux › Paramètres de date/heure : synchronisation NTP.",
        "firmware": "Configuration › Système › Maintenance › onglet Mise à jour du système : version maintenue (sauvegarde avant).",
        "clear": "Configuration › Système › Configuration › onglet Administration du firewall : accès HTTPS uniquement.",
        "egress": "Configuration › Politique de sécurité › Filtrage et NAT › onglet Filtrage : AJOUTER une règle {where}\n"
                  "  Action : bloquer · Source : {src} · Destination : Internet · Port : {protos} {port} · Niveau de trace : Standard",
        "apply": "\nPuis « Appliquer » (la politique est activée immédiatement).",
    }


class WatchGuard(Gui):
    P = {
        "rule": "Pare-feu › Stratégies de pare-feu (Firewall › Firewall Policies) › stratégie {r}",
        "narrow": "  Onglet Paramètres : « Vers » (To) limité aux destinations nécessaires ; type de stratégie limité aux ports utiles\n"
                  "  (remplacer « Any » / « Outgoing » par HTTP-proxy, HTTPS-proxy, DNS…) ; activer IPS et WebBlocker.",
        "src": "  Onglet Paramètres › « De » (From) : retirer Any-External et ajouter les adresses (ou l'alias) autorisées ;\n"
               "  onglet Propriétés › Journalisation : cocher « Envoyer un message de journal ».",
        "seg": "Pare-feu › Stratégies de pare-feu › Ajouter une stratégie « Any » : Connexions = Refusées,\n"
               "  De : « {net} » ({cidr}) · Vers : {to} ({tocidr}) ; en ordre manuel, la placer AU-DESSUS de la stratégie {r}.",
        "move": "Pare-feu › Stratégies de pare-feu : passer en ordre manuel (Policy Manager › Affichage › Mode manuel)\n"
                "  et placer la stratégie {b} au-dessus de {a}.",
        "delete": "Pare-feu › Stratégies de pare-feu › sélectionner › Action › Supprimer :",
        "disable": "Pare-feu › Stratégies de pare-feu › stratégie › décocher « Activer » (Enable) :",
        "rule_log": "Pare-feu › Stratégies de pare-feu › stratégie › onglet Propriétés › Journalisation › « Envoyer un message de journal » :",
        "profiles": "Abonnements › Intrusion Prevention (IPS) : activer pour toutes les stratégies ; stratégies web en proxy "
                    "(HTTP/HTTPS-proxy) avec Gateway AntiVirus, APT Blocker et WebBlocker, notamment :",
        "objects": "Pare-feu › Alias : supprimer les alias inutilisés :",
        "nat": "Pare-feu › SNAT (ou stratégie avec NAT statique) « {n} » : supprimer la publication (accès par VPN),\n"
               "  ou limiter « De » (From) de la stratégie aux adresses autorisées.",
        "admin_rule": "  « De » (From) : retirer Any-External, garder le réseau d'administration (stratégies WatchGuard / WatchGuard Web UI).",
        "admin": "Pare-feu › Stratégies de pare-feu › stratégies « WatchGuard » et « WatchGuard Web UI » :\n"
                 "  « De » (From) : retirer Any-External, garder le réseau d'administration (et WatchGuard Cloud si utilisé).",
        "vpn": "VPN › Branch Office VPN › Passerelles › « {v} » › Paramètres de phase 1 : Version IKEv2,\n"
               "  Transform SHA2-256 + AES (256 bits), groupe DH 14, 19 ou 20 ; Tunnels › Phase 2 : AES-256-GCM, PFS groupe 14+.\n"
               "  À modifier À L'IDENTIQUE sur l'équipement d'en face.",
        "sslvpn": "VPN › Mobile VPN › SSL : désactiver si inutilisé, sinon MFA (AuthPoint) et IKEv2 de préférence.",
        "ssl_tls": "VPN › Mobile VPN › SSL › Paramètres avancés : TLS 1.2 minimum.",
        "pptp": "VPN › Mobile VPN › PPTP : décocher « Activer Mobile VPN avec PPTP ».",
        "l2tp": "VPN › Mobile VPN › L2TP : exiger IPsec.",
        "mfa": "Authentification › Serveurs : AuthPoint (ou RADIUS avec MFA) pour les comptes d'administration.",
        "trusthost": "Pare-feu › Stratégies « WatchGuard » / « WatchGuard Web UI » : « De » limité au réseau d'administration.",
        "admin_default": "Système › Utilisateurs et rôles (Users and Roles) : comptes nominatifs ; mot de passe fort sur « admin ».",
        "log": "Système › Journalisation (Logging) : envoyer vers WatchGuard Cloud / Dimension ou un serveur syslog <IP>.",
        "snmp": "Système › SNMP : SNMPv3 (authentification SHA, chiffrement AES) ; limiter aux IP de supervision.",
        "ntp": "Système › NTP : activer la synchronisation.",
        "firmware": "Système › Mise à niveau (Upgrade OS) : version maintenue (sauvegarde avant).",
        "egress": "Pare-feu › Stratégies de pare-feu › Ajouter une stratégie ({protos} {port}) : Connexions = Refusées,\n"
                  "  De : {src} · Vers : Any-External ; en ordre manuel, la placer {where}.",
        "apply": "\nPuis « Enregistrer » (Save).",
    }


class UniFi(Gui):
    def rname(self, rid) -> str:
        """UniFi : la règle se retrouve par son nom et ses zones (les identifiants internes ne sont pas affichés)."""
        r = self.rule(rid)
        if not r:
            return f"« {rid} »"
        zones = f" ({', '.join(r.src_zones) or 'toutes'} → {', '.join(r.dst_zones) or 'toutes'})" if r.src_zones or r.dst_zones else ""
        return f"« {r.name or r.id} »{zones}"

    P = {
        "rule": "Paramètres › Pare-feu et sécurité (Network 9+ : Policy Table / Zones) › règle {r}",
        "narrow": "  Destination : réseaux ou adresses nécessaires ; Port : uniquement les services utiles.",
        "src": "  Source : remplacer « Tout » / « Externe » par les adresses autorisées (liste d'adresses / groupe).",
        "seg": "Paramètres › Pare-feu et sécurité › Créer une politique (Network 9+ : Policy Table › Créer) :\n"
               "  Action : Bloquer · Source : réseau « {net} » ({cidr}) · Destination : {to} ({tocidr}),\n"
               "  à placer AU-DESSUS de la règle {r} (glisser dans la liste).",
        "move": "Paramètres › Pare-feu et sécurité : glisser la règle {b} au-dessus de la règle {a}.",
        "delete": "Paramètres › Pare-feu et sécurité › règle › Supprimer :",
        "disable": "Paramètres › Pare-feu et sécurité › règle › désactiver :",
        "rule_log": "Paramètres › Pare-feu et sécurité › règle › activer « Journalisation » (Syslog) :",
        "nat": "Paramètres › Routage (ou Pare-feu et sécurité) › Redirection de port « {n} » :\n"
               "  supprimer (accès par le VPN Teleport / WireGuard) ou renseigner « Source autorisée » = adresses limitées.",
        "admin_rule": "  Source : réseau d'administration uniquement.",
        "admin": "UniFi OS › Paramètres › Accès à distance : désactiver l'accès local depuis le WAN ; administrer via unifi.ui.com (MFA).",
        "vpn": "Paramètres › VPN › VPN site à site › « {v} » › Avancé : version IKEv2 ; chiffrement AES-256, hachage SHA-256,\n"
               "  groupe DH 14 ou 19 (phase 1 et 2), PFS activé — à modifier À L'IDENTIQUE en face.",
        "pptp": "Paramètres › VPN › Serveur VPN : supprimer le serveur PPTP / L2TP sans IPsec ; utiliser WireGuard ou OpenVPN.",
        "l2tp": "Paramètres › VPN › Serveur VPN L2TP : clé pré-partagée IPsec obligatoire, ou passer en WireGuard.",
        "mfa": "unifi.ui.com › Mon compte › Sécurité : activer la double authentification pour chaque administrateur.",
        "admin_default": "UniFi OS › Admins et utilisateurs : comptes nominatifs, supprimer les comptes génériques.",
        "log": "Paramètres › Système (CyberSecure) › Journalisation : activer Syslog vers <IP du serveur>.",
        "snmp": "Paramètres › Système › Avancé › SNMP : SNMPv3 uniquement, ou désactiver.",
        "ntp": "Paramètres › Système › Avancé › NTP : serveurs NTP.",
        "firmware": "UniFi OS › Paramètres › Mises à jour : mettre à jour la console et l'application Network.",
        "upnp": "Paramètres › Internet › WAN › UPnP : désactiver.",
        "egress": "Paramètres › Pare-feu et sécurité › Créer une politique : Action Bloquer · Source : {src} ·\n"
                  "  Destination : zone Externe (Internet) · Port : {protos} {port} ; la placer {where}.",
        "apply": "\nPuis « Appliquer les modifications ».",
    }

    def specific(self, f):
        if f.id == "sys.ips":
            return "Paramètres › Sécurité (CyberSecure) › Protection contre les intrusions : mode « Prévention » (IPS), toutes catégories."
        if f.id == "sys.unifi.ssh":
            return "Paramètres › Système › Avancé › Authentification des appareils : désactiver SSH, ou clé SSH à la place du mot de passe."
        if f.id == "sys.unifi.upgrade":
            return "UniFi OS › Paramètres › Mises à jour : planifier les mises à jour automatiques (nuit / week-end)."
        if f.id.startswith("sys.wifi."):
            name = f.id.split(".", 2)[-1].split(".", 1)[-1]
            if f.id.startswith("sys.wifi.open."):
                return f"Paramètres › Wi-Fi › « {name} » › Sécurité : WPA2/WPA3 Personnel, mot de passe fort."
            if f.id.startswith("sys.wifi.guest."):
                return f"Paramètres › Wi-Fi › « {name} » › Avancé : activer « Isolation des clients » (Client Device Isolation)."
            return f"Paramètres › Wi-Fi › « {name} » › Sécurité : WPA2/WPA3 (transition) ; PMF : Facultatif."
        return ""


class Sophos(Gui):
    P = {
        "rule": "Règles et stratégies (Rules and policies) › Règles de pare-feu › règle {r}",
        "narrow": "  Destination et services : uniquement les réseaux et services nécessaires ; activer IPS, filtrage web et contrôle applicatif.",
        "src": "  Source › Réseaux et appareils : remplacer « Any » par les adresses autorisées ; activer la journalisation.",
        "seg": "Règles et stratégies › Ajouter une règle de pare-feu « Bloquer » : Source « {net} » ({cidr}) → Destination {to} ({tocidr}),\n"
               "  placée AU-DESSUS de la règle {r}.",
        "move": "Règles et stratégies › Règles de pare-feu : glisser la règle {b} au-dessus de {a}.",
        "delete": "Règles et stratégies › Règles de pare-feu › Supprimer :",
        "disable": "Règles et stratégies › Règles de pare-feu › désactiver (interrupteur) :",
        "rule_log": "Règles et stratégies › règle › « Consigner le trafic du pare-feu » :",
        "profiles": "Règles et stratégies › règle › Analyse et protections : IPS, filtrage web, antivirus (HTTP/HTTPS), contrôle applicatif :",
        "nat": "Règles et stratégies › Règles NAT › « {n} » : supprimer (accès par VPN) ou limiter les sources d'origine.",
        "admin_rule": "  Source : réseau d'administration uniquement.",
        "admin": "Administration › Accès aux appareils (Device access) : décocher HTTPS / SSH pour la zone WAN ;\n"
                 "  si nécessaire, « Hôtes et réseaux autorisés » = réseau d'administration.",
        "vpn": "VPN de site à site › IPsec › « {v} » › Profil : IKEv2, AES-256, SHA2-256, DH 14/19 — à l'identique en face.",
        "mfa": "Authentification › Mot de passe à usage unique (OTP) : activer pour l'administration (WebAdmin, console).",
        "log": "Paramètres système › Paramètres des journaux : ajouter un serveur syslog <IP>.",
        "snmp": "Administration › SNMP : SNMPv3 uniquement.",
        "ntp": "Administration › Heure : NTP.",
        "firmware": "Sauvegarde et microgiciel › Microgiciel : version maintenue.",
        "admin_default": "Administration › Paramètres de l'appareil › administrateurs : créer des comptes nominatifs (profil "
                         "Administrateur) ; changer le mot de passe du compte « admin » (non supprimable) et activer l'OTP.",
        "egress": "Règles et stratégies › Ajouter une règle de pare-feu « Bloquer » : Source {src} → zone WAN, service {protos} {port},\n"
                  "  placée {where}.",
        "apply": "\nPuis « Enregistrer ».",
    }


def _vendor(c: Ctx) -> Base | None:
    v = c.cfg.vendor
    if "Fortinet" in v:
        return Forti(c)
    if "MikroTik" in v:
        return MikroTik(c)
    if c.is_windows:
        return Windows(c)
    if "Stormshield" in v:
        return Stormshield(c)
    if "WatchGuard" in v:
        return WatchGuard(c)
    if v.startswith("UniFi"):
        return UniFi(c)
    if "Sophos" in v:
        return Sophos(c)
    return None


def attach(c: Ctx) -> None:
    """Calcule la correction proposée de chaque constat (en place)."""
    gen = _vendor(c)
    if gen is None:
        return
    for f in c.findings:
        if f.severity < INFO:            # conformes et non vérifiés : rien à corriger
            continue
        if f.id.startswith("sys.note") or f.id in ("expo.expected", "expo.nat.list"):
            continue
        txt = gen.remedy(f)
        if txt and txt.strip():
            f.remedy = txt.strip()
            f.remedy_kind = gen.kind
