"""Point d'entrée de FirewallAudit Pro."""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import sys
import threading
import traceback

from .config import APP_NAME, APP_VERSION, Settings, data_dir, setup_logging

log = logging.getLogger("fwaudit")


def _compat_old_windows() -> None:
    """Windows 10 < 1809 / Server 2016 : le moteur de polices DirectWrite de Qt 6.8+
    (IDWriteFactory5, 1703+) n'y affiche que des carrés. On force le moteur GDI de
    Windows, avant toute création de QApplication. Sans effet sur les versions récentes."""
    try:
        if sys.platform == "win32" and sys.getwindowsversion().build < 17763:
            os.environ.setdefault("QT_QPA_PLATFORM", "windows:fontengine=gdi")
    except Exception:
        pass


_compat_old_windows()


def _excepthook(t, e, tb):
    log.error("Exception non gérée :\n%s", "".join(traceback.format_exception(t, e, tb)))
    from PySide6.QtWidgets import QApplication, QMessageBox
    if QApplication.instance() and threading.current_thread() is threading.main_thread():
        # emplacement précis (3 derniers appels) : suffit au support à partir d'une capture d'écran
        where = " ← ".join(f"{fr.filename.replace(chr(92), '/').rsplit('/', 1)[-1]}:{fr.lineno} {fr.name}"
                           for fr in reversed(traceback.extract_tb(tb)[-3:]))
        QMessageBox.warning(None, APP_NAME, f"Erreur inattendue (version {APP_VERSION}) :\n{e}\n\nEmplacement : {where}"
                                            f"\n\nDétails : {data_dir() / 'fwaudit.log'}")


def windows_export(path: str) -> int:
    """Exporte le pare-feu Windows de ce poste (à lancer sur un serveur, puis importer le fichier)."""
    from .fw import windows
    data = windows.collect()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, default=str)
    return 0


def cli_collect(out: str | None, pdf: str | None = None, client: str = "", site: str = "", config_file: str = "",
                vendor: str = "", local_windows: bool = False, no_tests: bool = False, networks: str = "") -> int:
    """Mode ligne de commande (sans interface) : audit -> JSON et/ou PDF."""
    from .analyze.engine import analyze
    from .scan import runner
    split = lambda t: [x.strip() for x in (t or "").split(",") if x.strip()]  # noqa: E731
    src = runner.Source("windows_local") if local_windows else runner.Source("file", path=config_file, vendor=vendor)
    opts = runner.Options(source=src, egress=not no_tests, segmentation=not no_tests, extra_networks=split(networks))
    snap = runner.run(opts, progress=lambda k, label, st, d: print(f"[{st}] {label} {d}", flush=True) if st != "info" else None)
    a = analyze(snap)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"analysis": a.to_dict(), "snapshot": snap}, f, ensure_ascii=False, indent=1, default=str)
    if pdf:
        from PySide6.QtGui import QGuiApplication
        app = QGuiApplication.instance() or QGuiApplication(["FirewallAuditPro"])  # noqa: F841
        from . import report
        rec = {"client": client, "site": site, "ts": snap.get("started"), "snapshot_options": snap.get("options", {})}
        report.export_pdf(pdf, rec, a, Settings())
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="FirewallAuditPro")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--collect", metavar="FICHIER.json", help="audit sans interface, résultat en JSON")
    ap.add_argument("--pdf", metavar="FICHIER.pdf", help="audit sans interface, rapport PDF")
    ap.add_argument("--config", default="", help="fichier de configuration du pare-feu à analyser")
    ap.add_argument("--vendor", default="", help="type forcé : forti, stormshield, sophos, watchguard, unifi, mikrotik, windows")
    ap.add_argument("--local-windows", action="store_true", help="analyser le pare-feu Windows de ce poste")
    ap.add_argument("--no-tests", action="store_true", help="pas de tests réels (configuration seule)")
    ap.add_argument("--networks", default="", help="réseaux supplémentaires pour le test de cloisonnement")
    ap.add_argument("--windows-export", metavar="FICHIER.json", help="exporter le pare-feu Windows de ce poste (à importer ensuite)")
    ap.add_argument("--client", default="")
    ap.add_argument("--site", default="")
    args, _rest = ap.parse_known_args(argv)
    setup_logging(args.debug)
    log.info("Démarrage %s %s", APP_NAME, APP_VERSION)
    if args.windows_export:
        try:
            return windows_export(args.windows_export)
        except Exception:
            log.exception("Export Windows")
            return 1
    if args.collect or args.pdf:
        try:
            return cli_collect(args.collect, args.pdf, args.client, args.site, args.config, args.vendor, args.local_windows,
                               args.no_tests, args.networks)
        except Exception:
            log.exception("Mode ligne de commande")
            return 1
    sys.excepthook = _excepthook
    threading.excepthook = lambda a: log.error("Exception dans %s", a.thread.name,
                                               exc_info=(a.exc_type, a.exc_value, a.exc_traceback))
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SCHMOCK.FirewallAuditPro")
    except Exception:
        pass
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import QApplication

    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    from .store import Store
    from .ui import theme
    from .ui.context import AppContext
    from .ui.main_window import MainWindow

    settings = Settings()
    theme.apply_theme(settings.get("ui.theme", "dark"))
    app.setWindowIcon(QIcon(theme.app_icon_pixmap(256)))
    store = Store()
    ctx = AppContext(settings, store)
    win = MainWindow(ctx)
    win.show()
    code = app.exec()
    store.close()
    return code
