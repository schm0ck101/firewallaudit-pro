"""Page « Configuration » : règles normalisées (avec les constats qui les
concernent), publications, interfaces, administrateurs, VPN, et résultats des
tests réels (sortie, cloisonnement, exposition externe)."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from ..analyze.model import SEVERITY
from ..fw.model import ROLE_LABELS, FwConfig
from ..scan.probes import EGRESS_PORTS
from . import theme
from .common import fill_table, make_table, muted, page_title, sev_color


class ConfigPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 14)
        top = QHBoxLayout()
        top.addWidget(page_title("Configuration et tests"), 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtrer le tableau affiché…")
        self.search.setFixedWidth(320)
        self.search.textChanged.connect(self._filter)
        top.addWidget(self.search)
        root.addLayout(top)
        self.sub = muted("")
        root.addWidget(self.sub)
        self.tabs = QTabWidget()
        self.tables = {}
        spec = {"Règles": ["#", "Nom", "Action", "Zones", "Source", "Destination", "Services", "Conditions", "Journal", "Inspections",
                           "Utilisée", "Constats"],
                "Publications": ["Nom", "Actif", "IP publique", "Ports", "Protocole", "Vers", "Port interne", "Sources autorisées"],
                "Interfaces": ["Interface", "Rôle", "Zone", "Adresses", "VLAN", "Administration ouverte", "Description"],
                "Administrateurs et VPN": ["Type", "Nom", "Détail", "Restriction / chiffrement", "MFA / état"],
                "Sortie vers Internet": ["Port", "Usage", "Résultat"],
                "Cloisonnement": ["Réseau", "Nom / rôle", "Adresses testées", "Joignables", "Appareils et ports", "Interface du pare-feu"],
                "Exposition externe": ["IP publique", "Ports ouverts", "Pages / bannières", "UDP", "Ping"]}
        for name, headers in spec.items():
            t = make_table(headers)
            self.tables[name] = t
            if name == "Règles":
                split = QSplitter(Qt.Horizontal)
                split.addWidget(t)
                self.detail = QTextBrowser()
                split.addWidget(self.detail)
                split.setSizes([1050, 380])
                t.itemSelectionChanged.connect(self._rule_detail)
                self.tabs.addTab(split, name)
            else:
                self.tabs.addTab(t, name)
        root.addWidget(self.tabs, 1)
        self.tabs.currentChanged.connect(lambda _i: self._filter(self.search.text()))
        ctx.current_changed.connect(self.load)
        self._view = []
        self.load()

    def apply_theme(self):
        self.load()

    def load(self):
        for t in self.tables.values():
            t.setRowCount(0)
        self.detail.clear()
        a, rec = self.ctx.analysis, self.ctx.rec
        if not a or not rec:
            self.sub.setText("Aucun audit ouvert.")
            return
        snap = self.ctx.snap
        cfg = FwConfig.from_dict(snap.get("config") or {"vendor": "?"})
        s = a.site
        self.sub.setText(f"{s.get('vendor')} {s.get('model') or ''} · {s.get('version') or 'version inconnue'} · source : {s.get('source')} · "
                         f"{s.get('rules')} règle(s) dont {s.get('active_rules')} active(s)")
        # règles
        self._view = a.rules_view or []
        rows = []
        for r in self._view:
            zones = f"{', '.join(r['src_zones']) or 'toutes'} → {', '.join(r['dst_zones']) or 'toutes'}"
            flags = r.get("flags") or []
            rows.append([(str(r["pos"] + 1), r["pos"]), r.get("name") or str(r["id"]),
                         ("autorise" if r["action"] == "allow" else "bloque") + ("" if r["enabled"] else " (désactivée)"),
                         zones, r["src"], r["dst"], r["svc"], ", ".join(r.get("conditions") or [])[:80],
                         {True: "oui", False: "non", None: "—"}[r.get("log")], ", ".join(r.get("profiles") or [])[:80],
                         "—" if r.get("hits") is None else str(r["hits"]), " · ".join(f[1] for f in flags)[:160]])
        t = self.tables["Règles"]
        fill_table(t, rows, numeric={0}, sortable=False)
        p = theme.palette()
        for i, r in enumerate(self._view):
            flags = r.get("flags") or []
            if flags:
                col = QColor(sev_color(max(f[0] for f in flags)))
                for c in (1, 11):
                    if t.item(i, c):
                        t.item(i, c).setForeground(col)
            if not r["enabled"]:
                for c in range(t.columnCount()):
                    if t.item(i, c):
                        t.item(i, c).setForeground(QColor(p.muted))
            act = t.item(i, 2)
            if act and r["enabled"]:
                act.setForeground(QColor(p.ok if r["action"] == "allow" else p.crit))
        # publications
        fill_table(self.tables["Publications"], [[n.name or n.id, "oui" if n.enabled else "non", n.ext_ip or "IP WAN", n.ext_ports or "tous",
                                                  n.proto, n.int_ip, n.int_port, ", ".join(n.src_restrict) or "tout Internet"] for n in cfg.nat])
        fill_table(self.tables["Interfaces"], [[i.name, ROLE_LABELS.get(i.role, i.role), i.zone, ", ".join(i.ips), i.vlan or "",
                                                ", ".join(i.admin), i.description] for i in cfg.interfaces])
        av = [["Administrateur", x.name, x.profile, ", ".join(x.trusted) or "partout", {True: "MFA", False: "sans MFA", None: "—"}[x.mfa]]
              for x in cfg.admins]
        av += [["VPN " + v.kind.upper(), v.name, f"IKEv{v.ike} {v.mode}".strip() if v.kind == "ipsec" and v.ike else v.peer,
                " / ".join(x for x in (", ".join(v.enc), ", ".join(v.auth), "DH " + ", ".join(map(str, v.dh)) if v.dh else "") if x),
                "actif" if v.enabled else "désactivé"] for v in cfg.vpn]
        fill_table(self.tables["Administrateurs et VPN"], av)
        # tests
        tests = snap.get("tests") or {}
        e = tests.get("egress") or {}
        er = []
        for port, v in sorted((e.get("tcp") or {}).items(), key=lambda kv: int(kv[0])):
            ok = v.get("open") if isinstance(v, dict) else v
            er.append([(port, int(port)), EGRESS_PORTS.get(int(port), ""), "OUVERT vers Internet" if ok else "bloqué"])
        for srv, v in (e.get("dns_direct") or {}).items():
            er.append([("53", 53), f"DNS direct vers {v.get('provider')} ({srv})", "possible" if v.get("ok") else "bloqué / redirigé"])
        if e:
            er.append([("853", 853), "DNS chiffré DoT", "possible" if e.get("dot") else "bloqué"])
            er.append([("443", 443), "DNS chiffré DoH (Cloudflare)", "possible" if e.get("doh") else "bloqué"])
        fill_table(self.tables["Sortie vers Internet"], er, numeric={0})
        sr = []
        for net, r in (tests.get("segmentation") or {}).items():
            hosts = "; ".join(f"{h} ({', '.join(map(str, d.get('ports') or [])) or 'ping'})" for h, d in list((r.get("hosts") or {}).items())[:12])
            sr.append([net, f"{r.get('name')} ({ROLE_LABELS.get(r.get('role'), r.get('role') or '?')})", r.get("scanned"),
                       r.get("reachable"), hosts, f"{r.get('gateway')} : {', '.join(map(str, r.get('gateway_ports') or [])) or '—'}"])
        fill_table(self.tables["Cloisonnement"], sr)
        xr = []
        ext = tests.get("external") or {}
        for ip, r in (ext.get("targets") or {}).items():
            pages = "; ".join(f"{w.get('port')}: {w.get('title') or w.get('server') or ''}" for w in r.get("web") or [] if w and not w.get("error"))
            banners = "; ".join(f"{k}: {v[:50]}" for k, v in (r.get("banners") or {}).items())
            xr.append([ip, ", ".join(map(str, r.get("open") or [])) or "aucun", "; ".join(x for x in (pages, banners) if x),
                       ", ".join(k for k, v in (r.get("udp") or {}).items() if v) or "—", "répond" if r.get("icmp") else "non"])
        fill_table(self.tables["Exposition externe"], xr)
        if not ext:
            self.tables["Exposition externe"].setRowCount(1)
            from PySide6.QtWidgets import QTableWidgetItem
            self.tables["Exposition externe"].setItem(0, 0, QTableWidgetItem("Test externe non réalisé (page Résultats › Test externe)"))
        self._filter(self.search.text())

    def _rule_detail(self):
        rows = self.tables["Règles"].selectionModel().selectedRows()
        if not rows or rows[0].row() >= len(self._view):
            return
        r = self._view[rows[0].row()]
        e = html.escape
        h = [f"<h3>Règle {e(str(r['id']))} {('« ' + e(r['name']) + ' »') if r.get('name') else ''}</h3>"]
        for f in r.get("flags") or []:
            h.append(f"<p style='color:{sev_color(f[0])}; font-weight:600'>{SEVERITY[f[0]]} : {e(f[1])}</p>")
        for lab, val in (("Source (objets)", ", ".join(r.get("src_names") or [])), ("Source (adresses)", r["src"]),
                         ("Destination (objets)", ", ".join(r.get("dst_names") or [])), ("Destination (adresses)", r["dst"]),
                         ("Services", f"{', '.join(r.get('svc_names') or [])} → {r['svc']}"), ("Couche", r.get("layer")),
                         ("Commentaire", r.get("comment"))):
            if val:
                h.append(f"<p><b>{lab}</b><br>{e(str(val))}</p>")
        if r.get("raw"):
            h.append(f"<p><b>Configuration d'origine</b></p><pre style='font-size:8.5pt'>{e(r['raw'])}</pre>")
        self.detail.setHtml("".join(h))

    def _filter(self, txt: str):
        txt = (txt or "").lower().strip()
        w = self.tabs.currentWidget()
        if isinstance(w, QSplitter):
            w = w.widget(0)
        if w is None or not hasattr(w, "rowCount"):
            return
        for r in range(w.rowCount()):
            show = not txt or any(txt in (w.item(r, c).text().lower() if w.item(r, c) else "") for c in range(w.columnCount()))
            w.setRowHidden(r, not show)
