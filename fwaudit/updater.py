"""Mise à jour de l'application depuis les releases GitHub du projet.

* vérification : dernière release publiée (API publique GitHub, sans compte ni donnée personnelle envoyée) ;
* téléchargement du bon fichier : installateur pour une version installée, exécutable portable sinon ;
  contrôle de la taille et de l'empreinte SHA-256 publiée par GitHub ;
* application :
  - version installée : l'installateur est lancé en mode silencieux (il ferme l'application, met à jour,
    puis la relance) ;
  - version portable : le nouvel exécutable est déposé à côté de l'actuel, puis un petit script remplace
    l'ancien dès que l'application est fermée et relance la nouvelle version (données conservées, elles sont
    dans le dossier voisin).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import APP_VERSION, is_portable

log = logging.getLogger(__name__)
REPO = "schm0ck101/firewallaudit-pro"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
UA = "FirewallAuditPro-updater"


@dataclass
class Update:
    version: str
    notes: str
    page: str
    asset_name: str
    asset_url: str
    size: int
    sha256: str


def parse_version(v: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


def is_newer(remote: str, local: str = APP_VERSION) -> bool:
    return parse_version(remote) > parse_version(local)


def installed_mode() -> str:
    """« portable », « installed » ou « source » (lancé depuis les sources : pas de mise à jour automatique)."""
    if not getattr(sys, "frozen", False):
        return "source"
    return "portable" if is_portable() else "installed"


def check(timeout: float = 8.0) -> Update | None:
    """Dernière release si elle est plus récente que la version en cours, sinon None. Lève OSError / ValueError
    en cas d'échec réseau (l'appelant décide d'ignorer silencieusement ou d'afficher)."""
    req = urllib.request.Request(API, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read(1_000_000).decode("utf-8"))
    if d.get("draft") or d.get("prerelease"):
        return None
    ver = (d.get("tag_name") or "").lstrip("vV")
    if not ver or not is_newer(ver):
        return None
    want = "portable" if installed_mode() == "portable" else "setup"
    asset = next((a for a in d.get("assets") or [] if want in a.get("name", "").lower() and a.get("name", "").endswith(".exe")),
                 None)
    if not asset:
        return None
    digest = asset.get("digest") or ""
    return Update(version=ver, notes=(d.get("body") or "").strip(), page=d.get("html_url") or "",
                  asset_name=asset["name"], asset_url=asset["browser_download_url"], size=int(asset.get("size") or 0),
                  sha256=digest.split(":", 1)[1].lower() if digest.lower().startswith("sha256:") else "")


def download(u: Update, dest_dir: Path, progress=None, cancel: threading.Event | None = None) -> Path:
    """Télécharge le fichier de la mise à jour, contrôle taille et empreinte. Renvoie son chemin."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for old in dest_dir.glob("FirewallAuditPro*.part"):          # restes d'un essai précédent
        try:
            old.unlink()
        except OSError:
            pass
    final = dest_dir / u.asset_name
    try:
        running = Path(sys.executable).resolve()
    except OSError:
        running = None
    if final.resolve() == running or final.name.lower() == Path(sys.executable).name.lower():
        # jamais le nom de l'exécutable en cours : Windows refuse de l'écraser tant qu'il tourne
        final = dest_dir / f"{Path(u.asset_name).stem}-{u.version}{Path(u.asset_name).suffix}"
    part = final.with_name(final.name + ".part")
    h = hashlib.sha256()
    got = 0
    req = urllib.request.Request(u.asset_url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r, open(part, "wb") as f:
        total = int(r.headers.get("Content-Length") or u.size or 0)
        while True:
            if cancel and cancel.is_set():
                f.close()
                part.unlink(missing_ok=True)
                raise InterruptedError("Téléchargement annulé.")
            chunk = r.read(256 * 1024)
            if not chunk:
                break
            f.write(chunk)
            h.update(chunk)
            got += len(chunk)
            if progress:
                progress(got, total)
    if u.size and got != u.size:
        part.unlink(missing_ok=True)
        raise ValueError(f"Téléchargement incomplet ({got} octets sur {u.size}).")
    if u.sha256 and h.hexdigest() != u.sha256:
        part.unlink(missing_ok=True)
        raise ValueError("Empreinte SHA-256 incorrecte : fichier corrompu ou modifié, mise à jour abandonnée.")
    final.unlink(missing_ok=True)
    part.replace(final)
    return final


def portable_target_dir() -> Path:
    """Dossier où déposer le nouvel exécutable portable : à côté de l'actuel si possible."""
    here = Path(sys.executable).resolve().parent
    try:
        t = here / ".update_test"
        t.write_text("ok", encoding="utf-8")
        t.unlink()
        return here
    except OSError:
        return Path(tempfile.gettempdir()) / "FirewallAuditPro-update"


def apply(path: Path) -> str:
    """Lance l'application de la mise à jour ; l'appelant doit ensuite FERMER l'application.
    Renvoie un message pour l'utilisateur."""
    mode = installed_mode()
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    if mode == "installed":
        subprocess.Popen([str(path), "/SILENT", "/SP-", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"],
                         close_fds=True, creationflags=flags)
        return "L'installateur va mettre à jour l'application puis la relancer."
    if mode == "portable":
        exe = Path(sys.executable).resolve()
        if path.parent.resolve() != exe.parent:
            # dossier de l'exécutable non modifiable : on laisse le fichier téléchargé à disposition
            return f"Nouvelle version téléchargée : {path}\nRemplacez l'exécutable actuel par celui-ci."
        pids = sorted({os.getpid(), os.getppid()})      # exécutable « un seul fichier » : chargeur + application
        script = Path(tempfile.gettempdir()) / f"fwaudit-update-{os.getpid()}.cmd"
        waits = "\n".join(f'tasklist /FI "PID eq {p}" 2>nul | find "{p}" >nul && goto wait' for p in pids)
        script.write_text(
            "@echo off\r\n"
            "set n=0\r\n"
            ":wait\r\n"
            "set /a n+=1\r\n"
            "if %n% gtr 120 goto end\r\n"
            "ping -n 2 127.0.0.1 >nul\r\n"
            + waits.replace("\n", "\r\n") + "\r\n"
            f'move /Y "{path}" "{exe}" >nul 2>&1 || goto wait\r\n'
            f'start "" "{exe}"\r\n'
            ":end\r\n"
            'del "%~f0"\r\n', encoding="oem" if os.name == "nt" else "utf-8", errors="replace")
        # console CACHÉE héritée par les commandes du script (tasklist, find, ping) : avec un processus détaché,
        # chacune ouvrait sa propre fenêtre de console
        si = subprocess.STARTUPINFO() if os.name == "nt" else None
        if si is not None:
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
        subprocess.Popen(["cmd.exe", "/d", "/c", str(script)], close_fds=True, startupinfo=si,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                         | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        return "La nouvelle version remplacera l'actuelle dès la fermeture, puis se relancera."
    return "Lancé depuis les sources : mettre à jour avec git."
