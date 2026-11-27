"""Moteur d'analyse du pare-feu : applique les règles à l'instantané
(configuration normalisée + tests réels), calcule les notes."""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field

from . import rules_expo, rules_policy, rules_sys, rules_tests, rules_win
from .context import Ctx
from .model import CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, SYS, Finding

log = logging.getLogger(__name__)
# l'ordre compte : l'exposition attendue (rules_expo) est utilisée par rules_tests
ALL_RULES = rules_policy.RULES + rules_win.RULES + rules_expo.RULES + rules_sys.RULES + rules_tests.RULES


@dataclass
class Analysis:
    findings: list[Finding]
    scores: dict[str, int]
    site: dict
    rules_view: list = field(default_factory=list)      # règles normalisées + constats par règle (onglet « Règles »)
    rule_errors: list[str] = field(default_factory=list)

    @property
    def machine(self) -> dict:
        return self.site

    @property
    def hosts(self) -> dict:
        return {}

    @property
    def problems(self) -> list[Finding]:
        return sorted((f for f in self.findings if f.severity >= MINOR), key=lambda f: (-f.severity, f.domain, f.title))

    @property
    def risks(self) -> list[Finding]:
        return [f for f in self.problems if f.predictive]

    def counts(self) -> dict[int, int]:
        out = {CRIT: 0, MAJOR: 0, MINOR: 0, INFO: 0, OK: 0, NOT_CHECKED: 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings], "scores": self.scores, "site": self.site,
                "rules_view": self.rules_view, "rule_errors": self.rule_errors}

    @staticmethod
    def from_dict(d: dict) -> "Analysis":
        return Analysis([Finding.from_dict(x) for x in d.get("findings", [])], d.get("scores", {}), d.get("site", {}),
                        d.get("rules_view", []), d.get("rule_errors", []))


def score(findings: list[Finding]) -> int:
    n = {s: sum(1 for f in findings if f.severity == s) for s in (CRIT, MAJOR, MINOR)}
    pen = min(60, 25 * n[CRIT]) + min(30, 8 * n[MAJOR]) + min(12, 2 * n[MINOR])
    return max(0, 100 - pen)


def global_score(findings: list[Finding], scores: dict[str, int]) -> int:
    used = [scores[d] for d in DOMAINS if any(f.domain == d and f.severity != NOT_CHECKED for f in findings)]
    sc = round(sum(used) / len(used)) if used else 100
    if any(f.severity == CRIT for f in findings):
        sc = min(sc, 49)
    elif any(f.severity == MAJOR for f in findings):
        sc = min(sc, 84)
    return sc


def analyze(snapshot: dict, prev_snapshot: dict | None = None) -> Analysis:
    c = Ctx(snapshot, prev_snapshot)
    errors = []
    for rule in ALL_RULES:
        try:
            rule(c)
        except Exception as exc:
            log.error("Règle %s : %s\n%s", rule.__name__, exc, traceback.format_exc())
            errors.append(f"{rule.__module__.rsplit('.', 1)[-1]}.{rule.__name__} : {exc}")
    try:
        from . import remedy
        remedy.attach(c)
    except Exception as exc:              # les corrections proposées ne doivent jamais empêcher l'analyse
        log.error("Corrections proposées : %s\n%s", exc, traceback.format_exc())
        errors.append(f"remedy : {exc}")
    for note in c.cfg.notes:
        c.add(f"sys.note.{abs(hash(note)) % 10**8}", SYS, INFO, "Remarque de lecture de la configuration", note)
    for e in snapshot.get("errors") or []:
        c.nc(f"nc.step.{abs(hash(e)) % 10**8}", SYS, "Étape du diagnostic incomplète", e)
    best: dict[str, Finding] = {}
    for f in c.findings:
        if f.id not in best or f.severity > best[f.id].severity:
            best[f.id] = f
    findings = list(best.values())
    scores = {d: score([f for f in findings if f.domain == d]) for d in DOMAINS}
    scores["global"] = global_score(findings, scores)
    # vue des règles : chaque règle avec les constats qui la citent
    by_rule: dict[str, list] = {}
    for f in findings:
        for prefix in ("pol.anyany.", "pol.egress.", "pol.wide.", "pol.inbound.", "pol.seg.", "pol.shadow."):
            if f.id.startswith(prefix):
                rest = f.id[len(prefix):]
                rid = max((r.id for r in c.cfg.rules if rest == r.id or rest.startswith(r.id + ".")), key=len, default=rest)
                by_rule.setdefault(rid, []).append([f.severity, f.title])
    for f in findings:
        if f.id == "pol.redundant":
            for ev in f.evidence:
                rid = ev.split(" ", 1)[0].lstrip("#")
                by_rule.setdefault(rid, []).append([f.severity, "Règle redondante"])
    view = []
    for r in c.cfg.rules:
        view.append({"id": r.id, "pos": r.position, "name": r.name, "enabled": r.enabled, "action": r.action, "layer": r.layer,
                     "src_zones": r.src_zones, "dst_zones": r.dst_zones, "src": r.src_set.describe(3), "dst": r.dst_set.describe(3),
                     "svc": r.svc_set.describe(4), "conds": list(r.apps) + list(r.users), "src_names": r.src_names, "dst_names": r.dst_names, "svc_names": r.svc_names,
                     "conditions": r.users + r.apps + ([r.schedule] if r.schedule else []), "log": r.log, "profiles": r.profiles,
                     "hits": r.hits, "comment": r.comment, "flags": by_rule.get(str(r.id), []), "raw": (r.raw or "")[:1500]})
    cfg = c.cfg
    site = {"name": cfg.hostname or cfg.source or cfg.vendor, "vendor": cfg.vendor, "model": cfg.model, "version": cfg.version,
            "serial": cfg.serial, "source": cfg.source, "rules": len(cfg.rules), "active_rules": len(c.active), "nat": len(cfg.nat),
            "vpn": len(cfg.vpn), "admins": len(cfg.admins), "interfaces": [(i.name, i.role, ", ".join(i.ips)) for i in cfg.interfaces],
            "tests": sorted(k for k in c.tests if c.tests.get(k) and k in ("egress", "segmentation", "external")),
            "key": f"{cfg.vendor}|{cfg.hostname or cfg.serial or cfg.source}",
            "public_ips": c.tests.get("public_ips") or [], "meta": {k: v for k, v in c.meta.items() if k != "raw"}}
    return Analysis(findings, scores, site, view, errors)
