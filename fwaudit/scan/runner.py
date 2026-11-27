"""Orchestration d'un audit de pare-feu.

Phase 1 (sur le réseau du client) : lecture de la configuration (fichier,
API ou SSH en lecture, ou pare-feu Windows local), repérage du réseau
d'audit et des IP publiques, tests de sortie et de cloisonnement.
Phase 2 (facultative, depuis une connexion extérieure, ex. partage 4G) :
scan des IP publiques du client — ajoutée ensuite au même audit.

Aucun identifiant n'est écrit dans l'instantané.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field

from .. import config
from ..fw import load
from ..net import local, tests
from . import probes

log = logging.getLogger(__name__)

STEPS = [("load", "Lecture de la configuration du pare-feu"), ("local", "Réseau du poste d'audit et IP publique"),
         ("egress", "Test du filtrage sortant"), ("segmentation", "Test du cloisonnement entre réseaux")]
STEP_LABELS = dict(STEPS)


@dataclass
class Source:
    kind: str = "file"          # file | forti_api | unifi_api | mikrotik_ssh | windows_local
    path: str = ""
    vendor: str = ""            # forcé (sinon détecté)
    host: str = ""
    user: str = ""
    secret: str = ""            # mot de passe ou jeton API (jamais conservé)
    key_file: str = ""
    site: str = "default"

    def public(self) -> dict:
        return {"kind": self.kind, "path": self.path.split("\\")[-1].split("/")[-1], "vendor": self.vendor, "host": self.host,
                "user": self.user}


@dataclass
class Options:
    source: Source = field(default_factory=Source)
    egress: bool = True
    segmentation: bool = True
    extra_networks: list[str] = field(default_factory=list)     # réseaux supplémentaires à tester (cloisonnement)
    public_ips: list[str] = field(default_factory=list)         # IP publiques du client (en plus de celles détectées)


class Cancelled(Exception):
    pass


def load_config(src: Source):
    if src.kind == "file":
        return load.from_file(src.path, src.vendor or None)
    if src.kind == "forti_api":
        return load.forti_api(src.host, src.secret)
    if src.kind == "unifi_api":
        return load.unifi_api(src.host, src.user, src.secret, src.site or "default")
    if src.kind == "mikrotik_ssh":
        return load.mikrotik_ssh(src.host, src.user, src.secret, src.key_file)
    if src.kind == "windows_local":
        cfg, meta = load.windows_local()
        meta.pop("raw", None)
        return cfg, meta
    raise ValueError(f"source inconnue : {src.kind}")


def _public_candidates(cfg, measured: str) -> list[str]:
    out = []
    for ip in [measured] + [x.split("/")[0] for i in cfg.interfaces if i.role == "wan" for x in i.ips] + [n.ext_ip for n in cfg.nat]:
        try:
            a = ipaddress.IPv4Address(str(ip).split(",")[0].strip())
        except ValueError:
            continue
        if a.is_global and str(a) not in out:
            out.append(str(a))
    return out


def run(opts: Options, progress=None, cancel: threading.Event | None = None) -> dict:
    cancel = cancel or threading.Event()
    snap: dict = {"app": f"{config.APP_NAME} {config.APP_VERSION}", "started": time.time(), "errors": [],
                  "options": {"source": opts.source.public(), "egress": opts.egress, "segmentation": opts.segmentation,
                              "extra_networks": opts.extra_networks}, "tests": {}, "steps": {}}

    def step(key, fn):
        if cancel.is_set():
            raise Cancelled()
        if progress:
            progress(key, STEP_LABELS[key], "start", "")
        t0 = time.monotonic()
        try:
            detail = fn() or ""
            state = "skip" if detail == "non demandé" else "done"
        except Cancelled:
            raise
        except Exception as exc:
            log.exception("étape %s", key)
            detail, state = f"erreur : {exc}", "error"
            snap["errors"].append(f"{STEP_LABELS[key]} : {exc}")
            if key == "load":
                raise
        snap["steps"][key] = {"seconds": round(time.monotonic() - t0, 1), "detail": detail, "state": state}
        if progress:
            progress(key, STEP_LABELS[key], state, detail)

    holder = {}

    def s_load():
        cfg, meta = load_config(opts.source)
        holder["cfg"] = cfg
        snap["config"] = cfg.to_dict()
        snap["meta"] = {k: v for k, v in meta.items() if k not in ("raw",)}
        return (f"{cfg.vendor} {cfg.model} {cfg.version} — {len(cfg.rules)} règle(s), {len(cfg.nat)} publication(s), "
                f"{len(cfg.interfaces)} interface(s)").replace("  ", " ")

    def s_local():
        loc = local.collect(cancel)
        nets = local.networks(loc)
        snap["local_networks"] = nets
        pub = tests.public_ip()
        measured = pub.get("ip", "") if pub.get("ok") else ""
        cfg = holder["cfg"]
        here = {}
        for n in nets:
            ip = ipaddress.IPv4Address(n["local_ip"])
            for i in cfg.interfaces:
                for cidr in i.ips:
                    try:
                        if ip in ipaddress.IPv4Interface(cidr).network:
                            here = {"network": n["network"], "interface": i.name, "role": i.role, "ip": n["local_ip"]}
                    except ValueError:
                        continue
        if not here and nets:
            here = {"network": nets[0]["network"], "interface": "", "role": "", "ip": nets[0].get("local_ip", "")}
        snap["tests"]["audit_network"] = here
        snap["tests"]["public_ips"] = sorted(set(_public_candidates(cfg, measured) + opts.public_ips))
        snap["tests"]["public_measured"] = measured
        return (f"réseau {here.get('network', '?')}" + (f" (interface « {here['interface']} »)" if here.get("interface") else "")
                + f" · IP publique {measured or 'inconnue'}")

    def s_egress():
        if not opts.egress:
            return "non demandé"
        e = probes.egress(cancel)
        snap["tests"]["egress"] = e
        if e.get("error"):
            return e["error"]
        n = sum(1 for v in e["tcp"].values() if v.get("open"))
        return f"{n} / {len(e['tcp'])} ports sortants ouverts vers Internet"

    def s_seg():
        if not opts.segmentation:
            return "non demandé"
        cfg = holder["cfg"]
        here = snap["tests"].get("audit_network") or {}
        targets = []
        seen = set()
        for i in cfg.interfaces:
            if i.role == "wan":
                continue
            for cidr in i.ips:
                try:
                    itf = ipaddress.IPv4Interface(cidr)
                except ValueError:
                    continue
                if itf.network.is_global or itf.network.is_link_local or str(itf.network) in seen or itf.network.prefixlen >= 31:
                    continue
                seen.add(str(itf.network))
                targets.append({"name": i.name, "network": str(itf.network), "role": i.role, "gateway": str(itf.ip)})
        for n in opts.extra_networks:
            try:
                net = ipaddress.IPv4Network(n, strict=False)
                if str(net) not in seen:
                    targets.append({"name": "ajouté", "network": str(net), "role": "", "gateway": ""})
            except ValueError:
                snap["errors"].append(f"Réseau ignoré (format) : {n}")
        local_nets = [x["network"] for x in snap.get("local_networks") or []]
        res = probes.segmentation(targets, local_nets, cancel,
                                  progress=lambda t: progress("segmentation", STEP_LABELS["segmentation"], "info", t) if progress else None)
        snap["tests"]["segmentation"] = res
        reach = sum(1 for r in res.values() if r.get("reachable"))
        return f"{len(res)} réseau(x) testé(s) depuis {here.get('network', '?')}, {reach} joignable(s)"

    try:
        step("load", s_load)
        step("local", s_local)
        step("egress", s_egress)
        step("segmentation", s_seg)
    finally:
        snap["finished"] = time.time()
    return snap


def run_external(snap: dict, progress=None, cancel: threading.Event | None = None, extra_ips: list[str] | None = None) -> dict:
    """Scan externe des IP publiques de l'audit ; vérifie d'abord que le PC n'est plus sur le réseau du client."""
    targets = sorted(set((snap.get("tests") or {}).get("public_ips") or []) | set(extra_ips or []))
    if not targets:
        raise ValueError("Aucune IP publique connue pour ce client : la saisir dans « IP publiques ».")
    now = probes.current_public_ip()
    if now and now in targets:
        raise ValueError(f"Ce PC sort encore sur Internet par {now}, une IP du client : le scan ne serait pas représentatif. "
                         "Connectez-le à une autre connexion (partage 4G du téléphone) puis relancez.")
    exp_ports = []
    try:
        from ..analyze.engine import analyze
        analyze(snap)        # calcule l'exposition attendue (_expected_exposure)
        exp_ports = [e["port"] for e in snap.get("_expected_exposure") or [] if e.get("port")]
    except Exception:
        log.exception("exposition attendue")
    res = probes.external_scan(targets, exp_ports, cancel, progress)
    res["from_ip"] = now or res.get("from_ip")
    snap.setdefault("tests", {})["external"] = res
    snap.pop("_expected_exposure", None)
    return snap
