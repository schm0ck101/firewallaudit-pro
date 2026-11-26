"""Chargement d'une configuration : fichier (type détecté automatiquement) ou
lecture en direct (API FortiGate, API UniFi, SSH MikroTik, poste Windows).
Toutes les lectures en direct sont des LECTURES : aucune modification."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request
from pathlib import Path

from . import forti, mikrotik, sophos, stormshield, unifi, watchguard, windows
from .model import FwConfig

VENDORS = {
    "forti": ("Fortinet FortiGate", "Sauvegarde .conf (Système › Paramètres › Sauvegarder) ou API (jeton en lecture seule)", True),
    "stormshield": ("Stormshield SNS", "Sauvegarde .na sans mot de passe, ou dossier ConfigFiles (zip)", False),
    "sophos": ("Sophos Firewall", "Export de configuration complète (.tar contenant Entities.xml)", False),
    "watchguard": ("WatchGuard Firebox", "Configuration XML (Policy Manager › Enregistrer sous)", False),
    "unifi": ("UniFi", "API de la console (compte local en lecture seule)", True),
    "mikrotik": ("MikroTik RouterOS", "Fichier /export (.rsc) ou SSH en lecture", True),
    "windows": ("Pare-feu Windows", "Ce poste, ou fichier .json produit par --windows-export sur un serveur", True),
}
VALIDATED = {"forti": False, "stormshield": False, "sophos": False, "watchguard": False, "unifi": False, "mikrotik": False,
             "windows": True}      # lecteurs validés sur des données réelles (mis à jour au fil des retours terrain)


def detect(raw: bytes) -> str | None:
    head = raw[:4096].decode("utf-8", "replace")
    if head.lstrip().startswith("{") and '"rules"' in raw[:2_000_000].decode("utf-8", "replace") and '"profiles"' in head + raw[:200000].decode("utf-8", "replace"):
        return "windows"
    if forti.detect(head) or forti.detect(raw[:400000].decode("utf-8", "replace")):
        return "forti"
    if mikrotik.detect(raw[:400000].decode("utf-8", "replace")):
        return "mikrotik"
    if watchguard.detect(raw):
        return "watchguard"
    try:
        if sophos.detect(raw) or sophos.extract_xml(raw):
            return "sophos"
    except ValueError:
        pass
    if stormshield.detect(raw):
        return "stormshield"
    return None


def from_file(path: str | Path, vendor: str | None = None) -> tuple[FwConfig, dict]:
    p = Path(path)
    raw = p.read_bytes()
    v = vendor or detect(raw)
    if not v:
        raise ValueError("Type de fichier non reconnu. Formats pris en charge : " + "; ".join(f"{a} ({b})" for a, b, _ in VENDORS.values()))
    src = p.name
    if v == "forti":
        cfg = forti.to_model(raw.decode("utf-8", "replace"), src)
    elif v == "mikrotik":
        cfg = mikrotik.to_model(raw.decode("utf-8", "replace"), src)
    elif v == "sophos":
        cfg = sophos.to_model(raw, src)
    elif v == "stormshield":
        cfg = stormshield.to_model(raw, src)
    elif v == "watchguard":
        cfg = watchguard.to_model(raw, src)
    elif v == "windows":
        cfg = windows.to_model(json.loads(raw.decode("utf-8-sig")), src)
    elif v == "unifi":
        cfg = unifi.to_model(json.loads(raw.decode("utf-8-sig")), src)
    else:
        raise ValueError(v)
    return cfg, {"vendor": v, "source": "file", "file": src, "size": len(raw)}


# ------------------------------------------------------------------ FortiGate
def forti_api(host: str, token: str, vdom: str = "root", timeout: float = 20) -> tuple[FwConfig, dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}"

    def get(path: str, raw: bool = False):
        req = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            b = r.read()
        return b if raw else json.loads(b)
    text = get("/api/v2/monitor/system/config/backup?scope=global", raw=True).decode("utf-8", "replace")
    cfg = forti.to_model(text, f"API {host}")
    hits = {}
    try:
        for e in get(f"/api/v2/monitor/firewall/policy?vdom={vdom}").get("results", []):
            hits[str(e.get("policyid"))] = (e.get("hit_count"), e.get("last_used"))
    except Exception:
        pass
    for r in cfg.rules:
        k = r.id.split(":")[-1]
        if k in hits:
            r.hits = hits[k][0]
            r.last_hit = time.strftime("%d/%m/%Y", time.localtime(hits[k][1])) if hits[k][1] else ""
    try:
        st = get("/api/v2/monitor/system/status")
        cfg.serial = st.get("serial", cfg.serial)
        cfg.version = (st.get("version") or cfg.version).lstrip("v")
    except Exception:
        pass
    return cfg, {"vendor": "forti", "source": "api", "host": host, "hits": bool(hits)}


# ------------------------------------------------------------------- MikroTik
def mikrotik_ssh(host: str, user: str, password: str = "", key_file: str = "", port: int = 22) -> tuple[FwConfig, dict]:
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=port, username=user, password=password or None, key_filename=key_file or None, timeout=10,
                look_for_keys=False, allow_agent=False)
    try:
        def run(cmd):
            _i, o, e = cli.exec_command(cmd, timeout=60)
            return o.read().decode("utf-8", "replace")
        text = run("/export verbose") or run("/export")
        stats = run("/ip firewall filter print stats terse without-paging")
        users = run("/user print terse without-paging")
    finally:
        cli.close()
    cfg = mikrotik.to_model(text, f"SSH {host}")
    # compteurs par règle (dans l'ordre, hors règles dynamiques)
    counts = []
    for line in stats.splitlines():
        m = re.match(r"\s*(\d+)\s+([A-Z ]*)\s", line)
        if not m or "D" in m.group(2):
            continue
        pk = re.search(r"packets=(\d+)", line)
        counts.append(int(pk.group(1)) if pk else None)
    rules_all = [r for r in cfg.rules]
    if counts and len(counts) >= len(rules_all):
        by_idx = {i: c for i, c in enumerate(counts)}
        for r in rules_all:
            r.hits = by_idx.get(int(r.id))
    from .model import Admin
    for line in users.splitlines():
        nm = re.search(r"name=(\S+)", line)
        if nm:
            gr = re.search(r"group=(\S+)", line)
            ad = re.search(r"address=(\S*)", line)
            cfg.admins.append(Admin(name=nm.group(1), profile=gr.group(1) if gr else "", trusted=[ad.group(1)] if ad and ad.group(1) else [],
                                    enabled=" X " not in line[:8], default_name=nm.group(1) == "admin"))
    return cfg, {"vendor": "mikrotik", "source": "ssh", "host": host, "hits": bool(counts)}


# ---------------------------------------------------------------------- UniFi
def unifi_api(host: str, user: str, password: str, site: str = "default") -> tuple[FwConfig, dict]:
    data = unifi.fetch(host, user, password, site)
    cfg = unifi.to_model(data)
    return cfg, {"vendor": "unifi", "source": "api", "host": host, "errors": data.get("_errors", []),
                 "raw_api": unifi.sanitize(data)}


def windows_local() -> tuple[FwConfig, dict]:
    data = windows.collect()
    return windows.to_model(data), {"vendor": "windows", "source": "local", "raw": data}
