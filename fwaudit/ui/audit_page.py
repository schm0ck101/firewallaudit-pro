"""Page « Audit » : client, source de la configuration (fichier, API, SSH,
poste Windows), tests réels, lancement et progression."""
from __future__ import annotations

import logging
import threading
import time

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QProgressBar, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget)

from ..analyze.engine import analyze
from ..fw.load import VALIDATED, VENDORS
from ..scan import runner
from . import theme
from .common import muted, page_title, panel

log = logging.getLogger(__name__)

SOURCES = [("file", "Fichier de configuration (sauvegarde / export)"), ("forti_api", "FortiGate en direct (API, jeton en lecture seule)"),
           ("unifi_api", "UniFi en direct (console, compte local en lecture seule)"),
           ("mikrotik_ssh", "MikroTik en direct (SSH en lecture)"), ("windows_local", "Pare-feu Windows de ce poste")]


class Worker(QObject):
    progress = Signal(str, str, str, str)
    finished = Signal(object, object)
    failed = Signal(str)

    def __init__(self, opts: runner.Options):
        super().__init__()
        self.opts = opts
        self.cancel = threading.Event()

    def run(self):
        try:
            snap = runner.run(self.opts, progress=lambda *a: self.progress.emit(*a), cancel=self.cancel)
            self.finished.emit(snap, analyze(snap))
        except runner.Cancelled:
            self.failed.emit("Audit annulé.")
        except Exception as exc:
            log.exception("Audit")
            self.failed.emit(str(exc))


def _split(t: str) -> list[str]:
    return [x.strip() for x in t.replace(";", ",").replace("\n", ",").split(",") if x.strip()]


def _line(placeholder: str = "", password: bool = False) -> QLineEdit:
    w = QLineEdit()
    w.setPlaceholderText(placeholder)
    if password:
        w.setEchoMode(QLineEdit.Password)
    return w


class AuditPage(QWidget):
    done = Signal(int)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.thread = self.worker = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        self.scroll.setWidget(body)
        outer.addWidget(self.scroll)
        root = QVBoxLayout(body)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(12)
        root.addWidget(page_title("Audit du pare-feu"))
        root.addWidget(muted("Lecture seule : la configuration est lue (fichier, API ou SSH) sans jamais être modifiée. Les tests "
                             "réels se lancent depuis le réseau du client ; le test d'exposition se fait ensuite depuis une "
                             "connexion extérieure (bouton « Test externe » de la page Résultats)."))

        box, bl = panel()
        bl.addWidget(QLabel("<b>Intervention</b>"))
        f = QFormLayout()
        self.client = QComboBox()
        self.client.setEditable(True)
        self.client.setInsertPolicy(QComboBox.NoInsert)
        self.client.lineEdit().setPlaceholderText("Nom du client")
        self.site = _line("Site ou équipement (ex. « Siège — FortiGate 60F »)")
        self.notes = _line("Motif, remarques…")
        f.addRow("Client", self.client)
        f.addRow("Site", self.site)
        f.addRow("Notes", self.notes)
        bl.addLayout(f)
        root.addWidget(box)

        box, bl = panel()
        bl.addWidget(QLabel("<b>Configuration à analyser</b>"))
        self.kind = QComboBox()
        for k, lab in SOURCES:
            self.kind.addItem(lab, k)
        bl.addWidget(self.kind)
        self.stack = QStackedWidget()
        # fichier
        w = QWidget()
        wv = QVBoxLayout(w)
        wv.setContentsMargins(0, 0, 0, 0)
        fl = QFormLayout()
        wv.addLayout(fl)
        row = QHBoxLayout()
        self.path =_line("Sauvegarde FortiGate (.conf), Stormshield (.na), Sophos (.tar / Entities.xml), WatchGuard (.xml), MikroTik (.rsc)…")
        b = QPushButton("Parcourir…")
        b.clicked.connect(self._pick)
        row.addWidget(self.path, 1)
        row.addWidget(b)
        fl.addRow("Fichier", row)
        self.vendor = QComboBox()
        self.vendor.addItem("Détection automatique", "")
        for k, (lab, how, _live) in VENDORS.items():
            self.vendor.addItem(lab, k)
        fl.addRow("Type", self.vendor)
        self.formats = muted("<br>".join(f"<b>{lab}</b> : {how}" + ("" if VALIDATED.get(k) else " — <i>lecteur à valider sur un export réel</i>")
                                         for k, (lab, how, _l) in VENDORS.items()))
        self.formats.setTextFormat(Qt.RichText)
        wv.addWidget(self.formats)
        self.stack.addWidget(w)
        # FortiGate API
        w = QWidget()
        fl = QFormLayout(w)
        self.f_host, self.f_token = _line("adresse:port de l'interface d'administration"), _line("jeton d'un profil en lecture seule", True)
        fl.addRow("FortiGate", self.f_host)
        fl.addRow("Jeton API", self.f_token)
        fl.addRow("", muted("Système › Administrateurs › Créer › Administrateur API REST, profil en lecture seule, hôte de confiance = ce PC. "
                            "Donne aussi les compteurs d'utilisation des règles."))
        self.stack.addWidget(w)
        # UniFi
        w = QWidget()
        fl = QFormLayout(w)
        self.u_host, self.u_user, self.u_pw, self.u_site = _line("adresse de la console"), _line("compte LOCAL"), _line("", True), _line("default")
        fl.addRow("Console", self.u_host)
        fl.addRow("Utilisateur", self.u_user)
        fl.addRow("Mot de passe", self.u_pw)
        fl.addRow("Site", self.u_site)
        fl.addRow("", muted("Compte local avec le rôle « Lecture seule » (Paramètres › Admins). Les comptes UI.com avec MFA ne sont pas acceptés par l'API locale."))
        self.stack.addWidget(w)
        # MikroTik
        w = QWidget()
        fl = QFormLayout(w)
        self.m_host, self.m_user, self.m_pw, self.m_key = _line("adresse"), _line("utilisateur (groupe read suffit)"), _line("", True), _line("(facultatif) clé privée")
        fl.addRow("Routeur", self.m_host)
        fl.addRow("Utilisateur", self.m_user)
        fl.addRow("Mot de passe", self.m_pw)
        fl.addRow("Clé", self.m_key)
        fl.addRow("", muted("Commandes envoyées : /export, /ip firewall filter print stats, /user print (lecture)."))
        self.stack.addWidget(w)
        # Windows
        w = QWidget()
        fl = QVBoxLayout(w)
        fl.addWidget(muted("Analyse le pare-feu Windows de CE poste (profils, règles, stratégies de groupe, ports à l'écoute). "
                           "Pour un serveur : lancer l'application portable dessus, ou « FirewallAuditPro.exe --windows-export fichier.json » "
                           "puis importer le fichier ici (type « Pare-feu Windows »)."))
        self.stack.addWidget(w)
        bl.addWidget(self.stack)
        self.kind.currentIndexChanged.connect(self._switch)
        self._switch(0)
        root.addWidget(box)

        box, bl = panel()
        bl.addWidget(QLabel("<b>Tests réels depuis ce réseau</b>"))
        self.t_egress = QCheckBox("Filtrage sortant (≈ 40 ports vers un serveur de test public, DNS direct, DNS chiffré)")
        self.t_seg = QCheckBox("Cloisonnement : ce qui est joignable dans les autres réseaux du pare-feu depuis ici")
        self.t_egress.setChecked(True)
        self.t_seg.setChecked(True)
        bl.addWidget(self.t_egress)
        bl.addWidget(self.t_seg)
        f3 = QFormLayout()
        self.extra = _line("réseaux supplémentaires à tester, ex. 10.0.50.0/24")
        self.pub = _line("IP publiques du client (en plus de celles détectées), pour le test externe")
        f3.addRow("Réseaux", self.extra)
        f3.addRow("IP publiques", self.pub)
        bl.addLayout(f3)
        bl.addWidget(muted("Pour tester le cloisonnement d'un réseau invités ou objets connectés, brancher le PC dans ce réseau et "
                           "relancer un audit."))
        root.addWidget(box)

        row = QHBoxLayout()
        self.go = QPushButton("  Lancer l'audit")
        self.go.setObjectName("Primary")
        self.go.setMinimumHeight(42)
        self.go.setMinimumWidth(240)
        self.go.clicked.connect(self.start)
        self.stop_btn = QPushButton("Annuler")
        self.stop_btn.clicked.connect(self.stop)
        self.stop_btn.hide()
        row.addWidget(self.go)
        row.addWidget(self.stop_btn)
        self.status = QLabel("")
        self.status.setObjectName("Muted")
        row.addWidget(self.status, 1)
        root.addLayout(row)
        self.bar = QProgressBar()
        self.bar.setRange(0, len(runner.STEPS))
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.hide()
        root.addWidget(self.bar)
        self.steps_box, sl = panel()
        g = QGridLayout()
        self.rows = {}
        for i, (k, lab) in enumerate(runner.STEPS):
            dot, l2, st = QLabel("○"), QLabel(lab), QLabel("en attente")
            st.setObjectName("Muted")
            st.setWordWrap(True)
            g.addWidget(dot, i, 0)
            g.addWidget(l2, i, 1)
            g.addWidget(st, i, 2)
            self.rows[k] = (dot, st)
        g.setColumnStretch(2, 1)
        sl.addLayout(g)
        self.steps_box.hide()
        root.addWidget(self.steps_box)
        root.addStretch(1)
        self.timer = QTimer(self, interval=500, timeout=lambda: self.status.setText(f"Audit en cours… {time.monotonic() - self.t0:.0f} s"))
        self.t0 = 0.0
        self.reload()

    def _switch(self, i: int):
        """Seule la page affichée compte pour la hauteur (sinon : vide sous les formulaires courts)."""
        from PySide6.QtWidgets import QSizePolicy
        for k in range(self.stack.count()):
            pol = QSizePolicy.Preferred if k == i else QSizePolicy.Ignored
            self.stack.widget(k).setSizePolicy(QSizePolicy.Preferred, pol)
        self.stack.setCurrentIndex(i)
        self.stack.adjustSize()

    def _pick(self):
        p, _ = QFileDialog.getOpenFileName(self, "Configuration du pare-feu", "",
                                           "Configurations (*.conf *.na *.tar *.tgz *.gz *.xml *.rsc *.txt *.json *.zip);;Tous les fichiers (*)")
        if p:
            self.path.setText(p)

    def reload(self):
        s = self.ctx.settings
        cur = self.client.currentText()
        self.client.clear()
        self.client.addItems(self.ctx.store.clients())
        self.client.setCurrentText(cur or s.get("last.client", ""))
        if not self.site.text():
            self.site.setText(s.get("last.site", ""))
        self.go.setIcon(theme.glyph_icon(theme.G_PLAY, theme.palette().accent_text))

    def apply_theme(self):
        self.go.setIcon(theme.glyph_icon(theme.G_PLAY, theme.palette().accent_text))

    def _source(self) -> runner.Source | None:
        k = self.kind.currentData()
        if k == "file":
            if not self.path.text().strip():
                QMessageBox.warning(self, "Audit", "Choisir le fichier de configuration.")
                return None
            return runner.Source("file", path=self.path.text().strip(), vendor=self.vendor.currentData() or "")
        if k == "forti_api":
            return runner.Source(k, host=self.f_host.text().strip(), secret=self.f_token.text())
        if k == "unifi_api":
            return runner.Source(k, host=self.u_host.text().strip(), user=self.u_user.text().strip(), secret=self.u_pw.text(),
                                 site=self.u_site.text().strip() or "default")
        if k == "mikrotik_ssh":
            return runner.Source(k, host=self.m_host.text().strip(), user=self.m_user.text().strip(), secret=self.m_pw.text(),
                                 key_file=self.m_key.text().strip())
        return runner.Source("windows_local")

    def start(self):
        if self.thread:
            return
        src = self._source()
        if not src:
            return
        if src.kind in ("forti_api", "unifi_api", "mikrotik_ssh") and not src.host:
            QMessageBox.warning(self, "Audit", "Indiquer l'adresse de l'équipement.")
            return
        s = self.ctx.settings
        s.set("last.client", self.client.currentText().strip())
        s.set("last.site", self.site.text().strip())
        try:
            s.save()
        except OSError:
            pass
        opts = runner.Options(source=src, egress=self.t_egress.isChecked(), segmentation=self.t_seg.isChecked(),
                              extra_networks=_split(self.extra.text()), public_ips=_split(self.pub.text()))
        for dot, st in self.rows.values():
            dot.setText("○")
            dot.setStyleSheet("")
            st.setText("en attente")
        self.n = 0
        self.bar.setValue(0)
        self.bar.show()
        self.steps_box.show()
        QTimer.singleShot(50, lambda: self.scroll.ensureWidgetVisible(self.steps_box))
        self.go.setEnabled(False)
        self.stop_btn.show()
        self.t0 = time.monotonic()
        self.timer.start()
        self.thread = QThread(self)
        self.worker = Worker(opts)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.thread.start()

    def stop(self):
        if self.worker:
            self.worker.cancel.set()
            self.status.setText("Annulation…")

    def _progress(self, key, _label, state, detail):
        p = theme.palette()
        if key not in self.rows:
            return
        dot, st = self.rows[key]
        if state == "start":
            dot.setText("●")
            dot.setStyleSheet(f"color:{p.accent}")
            st.setText("en cours…")
        elif state == "info":
            st.setText(f"en cours… {detail}")
        else:
            self.n += 1
            self.bar.setValue(self.n)
            sym, col = {"error": ("✖", p.crit), "skip": ("–", p.muted)}.get(state, ("✓", p.ok))
            dot.setText(sym)
            dot.setStyleSheet(f"color:{col}")
            st.setText(detail[:260])

    def _cleanup(self):
        self.timer.stop()
        if self.thread:
            self.thread.quit()
            self.thread.wait(5000)
        self.thread = self.worker = None
        self.go.setEnabled(True)
        self.stop_btn.hide()

    def _finished(self, snap, analysis):
        dur = time.monotonic() - self.t0
        self._cleanup()
        self.f_token.clear()
        self.u_pw.clear()
        self.m_pw.clear()
        aid = self.ctx.store.save(client=self.client.currentText().strip(), site=self.site.text().strip(),
                                  notes=self.notes.text().strip(), auditor=self.ctx.settings.get("report.auditor", ""),
                                  analysis=analysis, snapshot=snap)
        self.status.setText(f"Audit terminé en {dur:.0f} s — note {analysis.scores.get('global')} / 100")
        self.notes.clear()
        self.reload()
        self.ctx.history_changed.emit()
        self.done.emit(aid)

    def _failed(self, msg):
        self._cleanup()
        self.status.setText(msg)
        if msg != "Audit annulé.":
            QMessageBox.warning(self, "Audit", f"L'audit a échoué :\n{msg}")
