"""Mise à jour : comparaison de versions, choix du fichier selon le mode (installé / portable), contrôle d'empreinte."""
import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("FWAUDIT_DATA_DIR", str(Path(os.environ.get("TEMP", "/tmp")) / "fwaudit-tests"))

from fwaudit import updater  # noqa: E402

PAYLOAD = b"MZ" + b"x" * 5000


class FakeResp(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def release(tag="v9.9.9", digest=True):
    sha = hashlib.sha256(PAYLOAD).hexdigest()
    return {"tag_name": tag, "draft": False, "prerelease": False, "body": "Corrections", "html_url": "https://example/r",
            "assets": [{"name": "FirewallAuditPro-Portable.exe", "size": len(PAYLOAD), "browser_download_url": "https://example/p",
                        "digest": f"sha256:{sha}" if digest else None},
                       {"name": "FirewallAuditPro-Setup-9.9.9.exe", "size": len(PAYLOAD), "browser_download_url": "https://example/s",
                        "digest": f"sha256:{sha}" if digest else None}]}


def test_versions():
    assert updater.is_newer("1.0.10", "1.0.9") and updater.is_newer("v1.1.0", "1.0.5")
    assert not updater.is_newer("1.0.5", "1.0.5") and not updater.is_newer("1.0.4", "1.0.5")


def test_check_picks_asset(monkeypatch):
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda req, timeout=0: FakeResp(json.dumps(release()).encode()))
    monkeypatch.setattr(updater, "installed_mode", lambda: "installed")
    u = updater.check()
    assert u.version == "9.9.9" and u.asset_name.startswith("FirewallAuditPro-Setup") and len(u.sha256) == 64
    monkeypatch.setattr(updater, "installed_mode", lambda: "portable")
    assert updater.check().asset_name == "FirewallAuditPro-Portable.exe"
    monkeypatch.setattr(updater.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp(json.dumps(release("v0.0.1")).encode()))
    assert updater.check() is None                                  # pas plus récente


def test_download_verifies_digest(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "installed_mode", lambda: "portable")
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda req, timeout=0: FakeResp(json.dumps(release()).encode()))
    u = updater.check()
    monkeypatch.setattr(updater.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp(PAYLOAD, {"Content-Length": str(len(PAYLOAD))}))
    p = updater.download(u, tmp_path)
    assert p.read_bytes() == PAYLOAD
    u.sha256 = "0" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        updater.download(u, tmp_path / "x")
    assert not list((tmp_path / "x").glob("*.part"))


def test_download_never_overwrites_running_exe(monkeypatch, tmp_path):
    """Version portable : le fichier publié peut porter le nom de l'exécutable lancé (Windows refuse de l'écraser)."""
    monkeypatch.setattr(updater, "installed_mode", lambda: "portable")
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda req, timeout=0: FakeResp(json.dumps(release()).encode()))
    u = updater.check()
    running = tmp_path / "FirewallAuditPro-Portable.exe"
    running.write_bytes(b"ancien")
    monkeypatch.setattr(updater.sys, "executable", str(running))
    (tmp_path / "FirewallAuditPro-Portable.exe.part").write_bytes(b"reste")
    monkeypatch.setattr(updater.urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResp(PAYLOAD, {"Content-Length": str(len(PAYLOAD))}))
    p = updater.download(u, tmp_path)
    assert p.name == "FirewallAuditPro-Portable-9.9.9.exe" and running.read_bytes() == b"ancien"
    assert not list(tmp_path.glob("*.part"))
