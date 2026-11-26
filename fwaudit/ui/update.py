"""Proposition de mise à jour : vérification en tâche de fond, fenêtre de proposition, téléchargement avec
progression, application puis fermeture de l'application."""
from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QProgressDialog

from .. import updater
from ..config import APP_NAME, APP_VERSION

log = logging.getLogger(__name__)


class Updater(QObject):
    found = Signal(object, bool)          # Update | None, vérification manuelle
    failed = Signal(str, bool)
    progressed = Signal(int, int)
    downloaded = Signal(str)
    download_failed = Signal(str)

    def __init__(self, ctx, parent_widget, busy=lambda: False):
        super().__init__(parent_widget)
        self.ctx = ctx
        self.win = parent_widget
        self.busy = busy                  # audit en cours : on ne propose pas au milieu
        self._cancel = threading.Event()
        self._dlg: QProgressDialog | None = None
        self._pending = None
        self.found.connect(self._on_found)
        self.failed.connect(self._on_failed)
        self.progressed.connect(self._on_progress)
        self.downloaded.connect(self._on_downloaded)
        self.download_failed.connect(self._on_download_failed)

    # ------------------------------------------------------------ vérification
    def check(self, manual: bool = False):
        if updater.installed_mode() == "source" and not manual:
            return

        def run():
            try:
                self.found.emit(updater.check(), manual)
            except Exception as exc:                 # hors ligne, proxy, GitHub indisponible…
                log.info("Vérification des mises à jour impossible : %s", exc)
                self.failed.emit(str(exc), manual)
        threading.Thread(target=run, name="update-check", daemon=True).start()

    def check_at_startup(self):
        if self.ctx.settings.get("update.auto_check", True):
            QTimer.singleShot(2500, lambda: self.check(False))

    def _on_failed(self, msg: str, manual: bool):
        if manual:
            QMessageBox.warning(self.win, "Mise à jour", f"Impossible de vérifier les mises à jour :\n{msg}")

    def _on_found(self, u, manual: bool):
        if u is None:
            if manual:
                QMessageBox.information(self.win, "Mise à jour", f"{APP_NAME} {APP_VERSION} est la dernière version.")
            return
        if not manual and self.ctx.settings.get("update.skip", "") == u.version:
            return
        if self.busy():
            self._pending = (u, manual)           # proposé à la fin de l'audit en cours
            QTimer.singleShot(60_000, self._retry_pending)
            return
        self._propose(u, manual)

    def _retry_pending(self):
        if self._pending:
            u, manual = self._pending
            self._pending = None
            self._on_found(u, manual)

    def _propose(self, u, manual: bool):
        if updater.installed_mode() == "source":
            QMessageBox.information(self.win, "Mise à jour", f"Version {u.version} disponible ({u.page}).\n"
                                    "Application lancée depuis les sources : mettre à jour avec git.")
            return
        notes = u.notes[:900] + ("…" if len(u.notes) > 900 else "")
        box = QMessageBox(self.win)
        box.setWindowTitle("Mise à jour disponible")
        box.setIcon(QMessageBox.Information)
        box.setText(f"<b>{APP_NAME} {u.version}</b> est disponible (version actuelle : {APP_VERSION}).")
        box.setInformativeText("Télécharger et installer maintenant ? L'application redémarrera ; "
                               "l'historique des audits et les paramètres sont conservés.")
        if notes:
            box.setDetailedText(notes)
        now = box.addButton("Mettre à jour", QMessageBox.AcceptRole)
        later = box.addButton("Plus tard", QMessageBox.RejectRole)
        skip = box.addButton("Ignorer cette version", QMessageBox.DestructiveRole) if not manual else None
        box.setDefaultButton(now)
        box.exec()
        if box.clickedButton() is now:
            self._download(u)
        elif skip is not None and box.clickedButton() is skip:
            self.ctx.settings.set("update.skip", u.version)
            self.ctx.settings.save()
        _ = later

    # ------------------------------------------------------------ téléchargement
    def _download(self, u):
        self._cancel.clear()
        self._dlg = QProgressDialog(f"Téléchargement de la version {u.version}…", "Annuler", 0, 100, self.win)
        self._dlg.setWindowTitle("Mise à jour")
        self._dlg.setWindowModality(Qt.WindowModal)
        self._dlg.setMinimumDuration(0)
        self._dlg.canceled.connect(self._cancel.set)
        self._dlg.show()
        dest = updater.portable_target_dir() if updater.installed_mode() == "portable" else \
            self.ctx_temp_dir()

        def run():
            try:
                p = updater.download(u, dest, lambda got, tot: self.progressed.emit(got, tot), self._cancel)
                self.downloaded.emit(str(p))
            except InterruptedError:
                self.download_failed.emit("")
            except Exception as exc:
                log.warning("Téléchargement de la mise à jour : %s", exc)
                self.download_failed.emit(str(exc))
        threading.Thread(target=run, name="update-download", daemon=True).start()

    @staticmethod
    def ctx_temp_dir():
        import tempfile
        from pathlib import Path
        return Path(tempfile.gettempdir()) / "FirewallAuditPro-update"

    def _on_progress(self, got: int, total: int):
        if self._dlg and total:
            self._dlg.setValue(min(99, int(got * 100 / total)))
            self._dlg.setLabelText(f"Téléchargement… {got / 1e6:.1f} / {total / 1e6:.1f} Mo")

    def _on_download_failed(self, msg: str):
        if self._dlg:
            self._dlg.close()
        if msg:
            QMessageBox.warning(self.win, "Mise à jour", f"La mise à jour a échoué :\n{msg}")

    def _on_downloaded(self, path: str):
        from pathlib import Path
        if self._dlg:
            self._dlg.setValue(100)
            self._dlg.close()
        try:
            msg = updater.apply(Path(path))
        except Exception as exc:
            QMessageBox.warning(self.win, "Mise à jour", f"Impossible de lancer la mise à jour :\n{exc}")
            return
        restart = not msg.startswith("Nouvelle version téléchargée")
        QMessageBox.information(self.win, "Mise à jour", msg + ("\n\nL'application va se fermer." if restart else ""))
        if restart:
            QApplication.instance().quit()
