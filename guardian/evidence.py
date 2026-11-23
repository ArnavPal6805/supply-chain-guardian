"""Step 5: one evidence-backed list of findings with an initial risk level.

Combines Step 3 (vulnerabilities + root cause) and Step 4 (anomalies), adds
context, and scores each finding. The score is transparent: every adjustment is
listed as a factor, so a reviewer (or the AI agent later) can see *why*.

Context used:
- runtime vs dev/test-only dependency (from the lockfile scope)
- whether application code imports the package or the direct dependency that
  brings it in (a cheap reachability signal: "imported" is not proof of
  "vulnerable code is called")
- EPSS (probability of exploitation) and CISA KEV (known exploited), when the
  machine is online; reported as "not checked" otherwise
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from collections import defaultdict
from pathlib import Path

from .anomalies import TEST_HINT

LEVELS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]
SEV_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5, "unknown": 5.0}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", "vendor", ".venv", "venv", "__pycache__",
             "target", ".next", ".angular", "out"}
SRC_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".java", ".kt"}
PY_MODULE = {"pillow": "PIL", "pyyaml": "yaml", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
             "python-dateutil": "dateutil", "protobuf": "google.protobuf", "opencv-python": "cv2",
             "pyjwt": "jwt", "python-dotenv": "dotenv", "pyopenssl": "OpenSSL", "pycryptodome": "Crypto",
             "grpcio": "grpc", "google-api-core": "google.api_core", "google-auth": "google.auth",
             "python-json-logger": "pythonjsonlogger", "msgpack-python": "msgpack"}


def level_of(score: float) -> str:
    for t, name in LEVELS:
        if score >= t:
            return name
    return "info"


# --------------------------------------------------------------- import index (reachability-lite)

class ImportIndex:
    def __init__(self, repo: Path, max_files: int = 20000):
        self.npm: dict[str, list] = defaultdict(list)
        self.py: dict[str, list] = defaultdict(list)
        self.go: list[tuple[str, str, int]] = []
        self.java: list[tuple[str, str, int]] = []
        n = 0
        for dirpath, dirnames, files in os.walk(repo):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for f in files:
                p = Path(dirpath) / f
                if p.suffix not in SRC_EXT:
                    continue
                n += 1
                if n > max_files:
                    return
                try:
                    if p.stat().st_size > 1_000_000:
                        continue
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rel = str(p.relative_to(repo))
                for i, line in enumerate(text.splitlines(), 1):
                    if p.suffix in (".py",):
                        m = re.match(r"\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", line)
                        if m:
                            self.py[(m.group(1) or m.group(2))].append((rel, i))
                    elif p.suffix == ".go":
                        for m in re.finditer(r'"([\w.\-]+\.[\w.\-/]+)"', line):
                            if "import" in line or line.startswith("\t\"") or line.strip().startswith('"'):
                                self.go.append((m.group(1), rel, i))
                    elif p.suffix in (".java", ".kt"):
                        m = re.match(r"\s*import\s+(?:static\s+)?([\w.]+)", line)
                        if m:
                            self.java.append((m.group(1), rel, i))
                    else:
                        for m in re.finditer(r"""(?:require\(\s*|from\s+|import\s+|import\(\s*)['"]([^'"\s]+)['"]""", line):
                            spec = m.group(1)
                            if spec.startswith((".", "/", "node:")):
                                continue
                            parts = spec.split("/")
                            name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
                            self.npm[name].append((rel, i))

    def lookup(self, eco: str, name: str) -> list[tuple[str, int]]:
        if eco == "npm":
            return self.npm.get(name, [])
        if eco == "pypi":
            key = name.lower()
            mod = PY_MODULE.get(key, re.sub(r"[-.]", "_", key))
            return [x for m, refs in self.py.items() if m == mod or m.startswith(mod + ".") for x in refs]
        if eco == "golang":
            return [(f, i) for path, f, i in self.go if path == name or path.startswith(name + "/")]
        if eco == "maven":
            group = name.split(":")[0]
            return [(f, i) for imp, f, i in self.java if imp.startswith(group)]
        return []


def usage(index: ImportIndex, eco: str, names: list[str]) -> dict:
    """Is any of `names` imported by application (non-test) code?"""
    app, tests = [], []
    for n in names:
        for f, i in index.lookup(eco, n):
            (tests if TEST_HINT.search(f) else app).append({"package": n, "file": f, "line": i})
    if eco not in ("npm", "pypi", "golang", "maven"):
        state = "unknown"
    elif app:
        state = "imported"
    elif tests:
        state = "tests-only"
    else:
        # for Python/Maven, module names don't always match package names: absence is weak evidence
        state = "not-imported" if eco in ("npm", "golang") else "unknown"
    return {"state": state, "app": app[:5], "tests": tests[:3]}


# --------------------------------------------------------------- EPSS / KEV (optional, online)

def _get_json(url: str, timeout: int = 12):
    req = urllib.request.Request(url, headers={"User-Agent": "supply-chain-guardian"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def exploit_intel(cves: list[str], log=print) -> dict:
    out = {"epss": {}, "kev": set(), "epss_checked": False, "kev_checked": False}
    if os.environ.get("GUARDIAN_OFFLINE", "").lower() in ("1", "true", "yes") or not cves:
        return out
    try:
        cves = sorted(set(cves))
        for i in range(0, len(cves), 80):
            d = _get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80]))
            for row in d.get("data", []):
                out["epss"][row["cve"]] = float(row.get("epss", 0))
        out["epss_checked"] = True
    except Exception as e:  # noqa: BLE001
        log(f"EPSS lookup unavailable ({type(e).__name__}); exploit probability not checked")
    try:
        d = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        out["kev"] = {v["cveID"] for v in d.get("vulnerabilities", [])}
        out["kev_checked"] = True
    except Exception as e:  # noqa: BLE001
        log(f"CISA KEV lookup unavailable ({type(e).__name__}); known-exploited status not checked")
    return out


# --------------------------------------------------------------- build the findings list

def build(model: dict, vuln_result: dict | None, anomalies: list[dict], repo: Path, log=print) -> dict:
    comps, projects = model["components"], model["projects"]
    index = ImportIndex(repo)
    vf = (vuln_result or {}).get("findings", [])
    intel = exploit_intel([f["cve"] for f in vf if f.get("cve")], log=log)
    issues = []

    for f in vf:
        c = comps.get(f["component_id"]) if f.get("component_id") else None
        malicious = f["advisory"].startswith("MAL-")
        base = 10.0 if malicious else (f["score"] if f.get("score") else SEV_BASE[f["severity"]])
        factors = [{"factor": "malicious package (OSV MAL advisory)" if malicious else
                    (f"CVSS {f['score']}" if f.get("score") else f"severity {f['severity']}"), "delta": base}]
        score = base
        epss = intel["epss"].get(f.get("cve") or "")
        kev = (f.get("cve") in intel["kev"]) if f.get("cve") else False
        if kev:
            score += 1.5; factors.append({"factor": "in CISA Known Exploited Vulnerabilities", "delta": 1.5})
        if epss is not None:
            if epss >= 0.5:
                score += 1.0; factors.append({"factor": f"EPSS {epss:.2f} (likely to be exploited)", "delta": 1.0})
            elif epss >= 0.1:
                score += 0.5; factors.append({"factor": f"EPSS {epss:.2f}", "delta": 0.5})
            else:
                factors.append({"factor": f"EPSS {epss:.3f} (low exploitation probability)", "delta": 0})
        # usage: the package itself or the direct dependencies that bring it in, per project
        names = {f["package"]}
        for o in f.get("occurrences", []):
            for d in o.get("introduced_by") or []:
                if d in comps:
                    names.add(comps[d]["name"])
        use = usage(index, f["ecosystem_key"], sorted(names))
        if not malicious:
            if f.get("dev_only"):
                score -= 3.0; factors.append({"factor": "dev / test dependency only (not shipped)", "delta": -3.0})
            if use["state"] == "imported" and not f.get("dev_only"):
                score += 0.5; factors.append({"factor": f"app code imports {use['app'][0]['package']}", "delta": 0.5})
            elif use["state"] == "tests-only":
                score -= 1.5; factors.append({"factor": "only imported from test code", "delta": -1.5})
            elif use["state"] == "not-imported" and not f.get("dev_only"):
                score -= 1.0; factors.append({"factor": "not imported by app code (likely tooling or indirect)", "delta": -1.0})
            if not f.get("fixed_in"):
                factors.append({"factor": "no fixed version published", "delta": 0})
        score = round(max(0.0, min(10.0, score)), 1)
        occ = f.get("occurrences") or []
        ev = [{"label": "advisory", "value": f["advisory"] + (f" / {', '.join(a for a in f['aliases'] if a.startswith('CVE-'))}"
                                                              if any(a.startswith('CVE-') for a in f.get("aliases", [])) else "")},
              {"label": "severity", "value": f"{f['severity']}" + (f" (CVSS {f['score']})" if f.get("score") else "")},
              {"label": "installed", "value": f"{f['package']}@{f['version']}"},
              {"label": "fixed in", "value": f.get("fixed_in") or "no fix published"},
              {"label": "scope", "value": "dev / test only" if f.get("dev_only") else "runtime"},
              {"label": "EPSS", "value": f"{epss:.3f}" if epss is not None else ("not found" if intel["epss_checked"] else "not checked (offline)")},
              {"label": "CISA KEV", "value": ("yes" if kev else "no") if intel["kev_checked"] else "not checked (offline)"},
              {"label": "app usage", "value": {"imported": "imported by application code", "tests-only": "imported by tests only",
                                               "not-imported": "not imported by application code",
                                               "unknown": "not determined for this ecosystem"}[use["state"]]}]
        for u in use["app"][:3]:
            ev.append({"label": "import", "value": f"{u['file']}:{u['line']} ({u['package']})"})
        issues.append({
            "type": "vulnerability", "kind": "malicious-package" if malicious else "known-vulnerability",
            "id": f["id"], "title": f"{f['package']}@{f['version']}: {f['summary']}",
            "subject": f"{f['package']}@{f['version']}", "component_id": f.get("component_id"),
            "advisory": f["advisory"], "cve": f.get("cve"), "references": f.get("references", []),
            "details": f.get("details"), "occurrences": occ,
            "file": occ[0]["project_file"] if occ else None, "line": None,
            "explanation": occ[0]["root_cause"]["explanation"] if occ else "",
            "recommendation": occ[0]["fix"]["action"] if occ else "",
            "evidence": ev, "usage": use,
            "risk": {"score": score, "level": level_of(score), "factors": factors},
            "confidence": "high"})

    for i, a in enumerate(anomalies, 1):
        c = comps.get(a["component_id"]) if a.get("component_id") else None
        base = SEV_BASE[a["severity"]]
        factors = [{"factor": f"{a['kind']} ({a['severity']})", "delta": base}]
        score = base
        if c and c.get("dev_only") and a["kind"] not in ("integrity-changed", "unexpected-registry", "origin-changed"):
            score -= 2.0; factors.append({"factor": "dev / test dependency only", "delta": -2.0})
        if a.get("file") and TEST_HINT.search(a["file"]) and a["kind"] in ("unpinned-image", "image-not-digest-pinned"):
            factors.append({"factor": "used for tests", "delta": 0})
        if a.get("confidence") == "medium":
            factors.append({"factor": "heuristic: needs human review", "delta": 0})
        score = round(max(0.0, min(10.0, score)), 1)
        issues.append({**a, "id": f"A-{i:03d}", "occurrences": [],
                       "risk": {"score": score, "level": level_of(score), "factors": factors}})

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    issues.sort(key=lambda x: (order[x["risk"]["level"]], -x["risk"]["score"], x["type"] != "vulnerability", x["id"]))

    by_comp: dict[str, dict] = {}
    by_file: dict[str, dict] = {}
    for x in issues:
        tgt = by_comp.setdefault(x["component_id"], {"n": 0, "level": None, "ids": []}) if x.get("component_id") \
            else by_file.setdefault(x.get("file") or "?", {"n": 0, "level": None, "ids": []})
        tgt["n"] += 1
        tgt["ids"].append(x["id"])
        if tgt["level"] is None or order[x["risk"]["level"]] < order[tgt["level"]]:
            tgt["level"] = x["risk"]["level"]
    by_comp.pop(None, None)

    counts = defaultdict(int)
    kinds = defaultdict(int)
    for x in issues:
        counts[x["risk"]["level"]] += 1
        kinds[x["kind"]] += 1
    summary = {"total": len(issues),
               "vulnerabilities": sum(1 for x in issues if x["type"] == "vulnerability"),
               "anomalies": sum(1 for x in issues if x["type"] == "anomaly"),
               "by_level": {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
               "by_kind": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
               "epss_checked": intel["epss_checked"], "kev_checked": intel["kev_checked"]}
    return {"issues": issues, "by_component": by_comp, "by_file": by_file, "summary": summary}
