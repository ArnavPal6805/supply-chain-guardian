"""Step 3 (detection part): known vulnerabilities + root cause, joined to the graph.

1. Run OSV-Scanner on the generated CycloneDX SBOM (same inventory as the graph).
2. Join each advisory to its graph node (purl / ecosystem+name+version).
3. Work out the fixed version for the installed version.
4. Root cause, per project: is the package declared directly? If transitive, does every
   parent's *declared range* already allow the fix (stale lockfile) or does a parent block
   it (needs a parent / direct-dependency upgrade or an override)?
5. Group findings by the fix that resolves them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import defaultdict
from functools import cmp_to_key
from pathlib import Path

from .versions import cmp, satisfies

OSV_ECO = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven", "crates.io": "cargo",
           "NuGet": "nuget", "RubyGems": "gem", "Packagist": "composer", "GitHub Actions": "githubactions",
           "Pub": "pub", "Hex": "hex"}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
OVERRIDE_HINT = {
    "npm": 'add an "overrides" entry in package.json',
    "pypi": "add a constraint (e.g. in requirements.in / constraints.txt)",
    "maven": "pin it in <dependencyManagement>",
    "golang": "require the fixed version in go.mod (go get <module>@<version>)",
}


def _norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name.lower()


def find_scanner() -> str | None:
    return os.environ.get("GUARDIAN_OSV_SCANNER") or shutil.which("osv-scanner")


def run_osv(bom_path: Path, log=print, timeout: int = 900) -> dict | None:
    exe = find_scanner()
    if not exe:
        log("osv-scanner not found on PATH (set GUARDIAN_OSV_SCANNER); skipping vulnerability scan")
        return None
    cmd = [exe, "scan", "source", "-L", str(bom_path), "--format", "json"]
    if os.environ.get("GUARDIAN_OSV_OFFLINE", "").lower() in ("1", "true", "yes"):
        cmd += ["--offline", "--offline-vulnerabilities"]
    log("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log("osv-scanner timed out")
        return None
    # exit 0 = clean, 1 = vulnerabilities found, 128 = no packages found
    if r.returncode not in (0, 1, 128):
        err = [l for l in r.stderr.splitlines() if l.strip()][-3:]
        log(f"osv-scanner failed (exit {r.returncode}): " + " | ".join(err))
        if not r.stdout.strip().startswith("{"):
            return None
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        log("osv-scanner output was not JSON")
        return None


def _severity(score: str | None, db_sev: str | None) -> tuple[str, float | None]:
    try:
        s = float(score) if score not in (None, "") else None
    except ValueError:
        s = None
    if s is not None:
        lvl = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "unknown"
        return lvl, s
    m = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
    return m.get((db_sev or "").upper(), "unknown"), None


def _fixed_version(vuln: dict, eco: str, name: str, version: str) -> tuple[str | None, str | None]:
    """(fixed version for the range containing `version`, introduced)"""
    cands = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if OSV_ECO.get(pkg.get("ecosystem"), "") != eco or _norm(eco, pkg.get("name", "")) != _norm(eco, name):
            continue
        for rng in aff.get("ranges", []):
            introduced = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    lo_ok = introduced in (None, "0") or cmp(version, introduced) >= 0
                    if lo_ok and cmp(version, ev["fixed"]) < 0:
                        return ev["fixed"], introduced
                    cands.append(ev["fixed"])
    later = sorted((f for f in cands if cmp(f, version) > 0), key=cmp_to_key(cmp))
    return (later[0] if later else None), None


def _pid_spec_key(project: dict) -> str | None:
    return f"root::{project['source_file']}" if project.get("source_file") else None


def analyze(osv: dict, model: dict, edge_specs: dict, log=print) -> dict:
    comps, projects = model["components"], model["projects"]
    index = defaultdict(list)
    for c in comps.values():
        if c.get("version"):
            index[(c["ecosystem_key"], _norm(c["ecosystem_key"], c["name"]), c["version"].lstrip("v")
                   if c["ecosystem_key"] != "golang" else c["version"])].append(c)
    # specs for direct deps, by child purl (any manifest)
    root_specs = defaultdict(dict)
    for (parent, child), spec in edge_specs.items():
        if parent.startswith("root::"):
            root_specs[child][parent[6:]] = spec

    findings, unmatched = [], 0
    for res in osv.get("results", []):
        for p in res.get("packages", []):
            pkg = p.get("package", {})
            eco = OSV_ECO.get(pkg.get("ecosystem"), (pkg.get("ecosystem") or "").lower())
            name, version = pkg.get("name", ""), pkg.get("version", "")
            key_v = version if eco == "golang" else version.lstrip("v")
            matches = index.get((eco, _norm(eco, name), key_v)) or []
            if not matches:
                unmatched += 1
            vmap = {v["id"]: v for v in p.get("vulnerabilities", [])}
            for grp in p.get("groups", []) or [{"ids": [v]} for v in vmap]:
                ids = grp.get("ids", [])
                v = next((vmap[i] for i in ids if i in vmap), None)
                if not v:
                    continue
                aliases = sorted(set(grp.get("aliases", []) + v.get("aliases", [])) - {v["id"]})
                level, score = _severity(grp.get("max_severity"),
                                         (v.get("database_specific") or {}).get("severity"))
                fixed, introduced = _fixed_version(v, eco, name, version)
                for c in matches or [None]:
                    findings.append({
                        "advisory": v["id"], "aliases": aliases,
                        "cve": next((a for a in [v["id"]] + aliases if a.startswith("CVE-")), None),
                        "summary": v.get("summary") or (v.get("details") or "")[:160],
                        "details": (v.get("details") or "")[:2500],
                        "severity": level, "score": score,
                        "cvss": [s.get("score") for s in v.get("severity", []) if s.get("score")],
                        "cwes": (v.get("database_specific") or {}).get("cwe_ids", []),
                        "published": v.get("published"), "modified": v.get("modified"),
                        "references": [r.get("url") for r in v.get("references", [])][:8],
                        "package": name, "version": version, "ecosystem": pkg.get("ecosystem"),
                        "ecosystem_key": eco, "fixed_in": fixed, "affected_since": introduced,
                        "component_id": c["id"] if c else None,
                        "purl": c["purl"] if c else None,
                        "dev_only": c["dev_only"] if c else None,
                        "direct": c["direct"] if c else None,
                    })
    if unmatched:
        log(f"{unmatched} OSV packages could not be matched to graph nodes")

    # ------------------------------------------------------------- root cause per project
    for i, f in enumerate(sorted(findings, key=lambda f: (-SEV_ORDER[f["severity"]], -(f["score"] or 0),
                                                          f["package"])), 1):
        f["id"] = f"V-{i:03d}"
    findings.sort(key=lambda f: f["id"])
    for f in findings:
        c = comps.get(f["component_id"]) if f["component_id"] else None
        f["occurrences"] = []
        if not c:
            continue
        for pid, info in (c.get("by_project") or {}).items():
            proj = projects.get(pid, {})
            f["occurrences"].append(_root_cause(f, c, pid, proj, info, comps, edge_specs, root_specs))
        if not f["occurrences"] and c.get("path_project"):   # e.g. Go indirect: parent unknown
            proj = projects.get(c["path_project"], {})
            f["occurrences"].append({
                "project": c["path_project"], "project_file": proj.get("source_file"),
                "path": [c["id"]], "direct": False, "introduced_by": [],
                "root_cause": {"kind": "parent-unknown",
                               "explanation": "Transitive dependency, but the manifest does not record which "
                                              "dependency pulls it in."},
                "fix": _fix("pin", f, f["package"], proj)})

    for c in comps.values():
        c["vulns"] = []
    for f in findings:
        if f["component_id"] in comps:
            comps[f["component_id"]]["vulns"].append(f["id"])
    for c in comps.values():
        sev = [x["severity"] for x in findings if x["component_id"] == c["id"]]
        c["max_severity"] = max(sev, key=lambda s: SEV_ORDER[s]) if sev else None

    return {"findings": findings, "groups": _group(findings), "summary": _summary(findings)}


def _fix(kind: str, f: dict, target: str, proj: dict, detail: str = "") -> dict:
    eco = f["ecosystem_key"]
    to = f["fixed_in"]
    text = {
        "upgrade-direct": f"Upgrade {target} to {to} or later in {proj.get('source_file') or 'the manifest'}",
        "refresh-lockfile": (f"Refresh the lockfile so {f['package']} resolves to {to}+ "
                             f"(e.g. `npm update {f['package']}`); no manifest change needed"
                             if eco == "npm" else f"Re-resolve dependencies so {f['package']} becomes {to}+"),
        "upgrade-parent": f"Upgrade {target} to a version whose dependency tree allows {f['package']} {to}+, "
                          f"or {OVERRIDE_HINT.get(eco, 'pin it explicitly')} for {f['package']}@{to}",
        "pin": f"Pin {f['package']} to {to}+ ({OVERRIDE_HINT.get(eco, 'pin it explicitly')})" if to
               else f"No fixed version of {f['package']} yet: consider replacing it or mitigating",
        "no-fix": f"No fixed version of {f['package']} is published: replace it, mitigate, or accept with review",
    }[kind]
    return {"kind": kind, "target": target, "to": to, "action": text, "detail": detail}


def _root_cause(f, c, pid, proj, info, comps, edge_specs, root_specs) -> dict:
    eco, fixed, name = f["ecosystem_key"], f["fixed_in"], f["package"]
    path = info["path"]
    occ = {"project": pid, "project_file": proj.get("source_file"), "path": path,
           "direct": info["direct"], "introduced_by": info["introduced_by"]}
    label = lambda cid: f'{comps[cid]["name"]}@{comps[cid]["version"]}' if cid in comps else cid

    if fixed is None:
        occ["root_cause"] = {"kind": "no-fix", "explanation": f"No patched version of {name} is listed in the advisory."}
        occ["fix"] = _fix("no-fix", f, name, proj)
        return occ

    if info["direct"]:
        spec = None
        specs = root_specs.get(c["purl"], {})
        if proj.get("source_file") in specs:
            spec = specs[proj["source_file"]]
        elif specs:
            spec = next(iter(specs.values()))
        allows = satisfies(eco, fixed, spec)
        if allows:
            occ["root_cause"] = {"kind": "direct-stale-lock", "declared_spec": spec,
                                 "explanation": f"{name} is a direct dependency declared as `{spec}`, which already "
                                                f"allows {fixed}, but the lockfile resolved {f['version']}."}
            occ["fix"] = _fix("refresh-lockfile", f, name, proj)
        else:
            why = (f"declared as `{spec}`, which does not allow {fixed}" if allows is False
                   else f"declared directly{f' as `{spec}`' if spec else ''}")
            occ["root_cause"] = {"kind": "direct", "declared_spec": spec,
                                 "explanation": f"{name}@{f['version']} is a direct dependency ({why})."}
            occ["fix"] = _fix("upgrade-direct", f, name, proj)
        return occ

    # transitive: check every parent inside this project
    in_proj = lambda cid: cid in comps and pid in (comps[cid].get("by_project") or {})
    parents = [p for p in c["parents"] if in_proj(p)]
    checks = []
    for p in parents:
        spec = edge_specs.get((comps[p]["purl"], c["purl"]))
        checks.append({"parent": p, "parent_label": label(p), "spec": spec, "allows_fix": satisfies(eco, fixed, spec)})
    blockers = [x for x in checks if x["allows_fix"] is False]
    unknown = [x for x in checks if x["allows_fix"] is None]
    directs = info["introduced_by"]

    if checks and not blockers and not unknown:
        reqs = "; ".join(f"{x['parent_label']} requires `{x['spec']}`" for x in checks[:3])
        occ["root_cause"] = {
            "kind": "stale-lock", "parents": checks,
            "explanation": f"Every parent already allows {name} {fixed}+ ({reqs}). "
                           f"The old version is only pinned by the lockfile."}
        occ["fix"] = _fix("refresh-lockfile", f, name, proj)
    elif blockers:
        b = blockers[0]
        via = sorted({d for x in blockers for d in ([x["parent"]] if comps[x["parent"]].get("by_project", {}).get(pid, {}).get("direct")
                                                       else comps[x["parent"]].get("by_project", {}).get(pid, {}).get("introduced_by", []))})
        target = ", ".join(label(d).rsplit("@", 1)[0] for d in via) or b["parent_label"]
        occ["root_cause"] = {
            "kind": "blocked-by-parent", "parents": checks,
            "blockers": [{"parent": x["parent"], "parent_label": x["parent_label"], "spec": x["spec"]} for x in blockers],
            "explanation": f"{b['parent_label']} requires {name} `{b['spec']}`, which excludes the fixed "
                           f"version {fixed}. The fix has to come from upgrading {b['parent_label'].rsplit('@', 1)[0]}"
                           f"{' (brought in by ' + target + ')' if target != b['parent_label'] else ''} or an override."}
        occ["fix"] = _fix("upgrade-parent", f, target, proj)
    else:
        target = ", ".join(label(d).rsplit("@", 1)[0] for d in directs) or (label(parents[0]) if parents else name)
        par = ", ".join(x["parent_label"] for x in checks[:3])
        occ["root_cause"] = {
            "kind": "transitive", "parents": checks,
            "explanation": f"{name} is pulled in by {par or 'another package'}"
                           f"{' (via direct dependency ' + target + ')' if directs else ''}. "
                           f"The declared range is not recorded for this ecosystem, so check whether a newer "
                           f"{target} brings {fixed}+."}
        occ["fix"] = _fix("upgrade-parent", f, target, proj)
    return occ


def _group(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for f in findings:
        for o in f["occurrences"]:
            fx = o["fix"]
            key = (o["project_file"], fx["kind"], fx["target"])
            g = groups.setdefault(key, {"project_file": o["project_file"], "kind": fx["kind"], "target": fx["target"],
                                        "action": fx["action"], "findings": [], "packages": set(),
                                        "max_severity": "unknown", "max_score": 0.0, "runtime": False})
            if f["id"] not in g["findings"]:
                g["findings"].append(f["id"])
            g["packages"].add(f"{f['package']}@{f['version']}")
            if SEV_ORDER[f["severity"]] > SEV_ORDER[g["max_severity"]]:
                g["max_severity"] = f["severity"]
            g["max_score"] = max(g["max_score"], f["score"] or 0)
            g["runtime"] = g["runtime"] or f["dev_only"] is False
            if fx["to"] and (not g.get("to") or cmp(fx["to"], g["to"]) > 0) and \
                    fx["kind"] in ("upgrade-direct", "refresh-lockfile", "pin"):
                g["to"] = fx["to"]
                g["action"] = fx["action"]     # action text naming the highest fixed version needed
            if fx["kind"] == "upgrade-parent" and len(g["packages"]) > 1:
                g["action"] = (f"Upgrade {fx['target']} (fixes {len(g['packages'])} vulnerable packages), "
                               f"or add overrides for each")
    out = sorted(groups.values(), key=lambda g: (-SEV_ORDER[g["max_severity"]], -g["max_score"], -len(g["findings"])))
    for i, g in enumerate(out, 1):
        g["id"] = f"G-{i:02d}"
        g["packages"] = sorted(g["packages"])
    return out


def _summary(findings: list[dict]) -> dict:
    by = defaultdict(int)
    for f in findings:
        by[f["severity"]] += 1
    return {"total": len(findings),
            "packages": len({(f["ecosystem_key"], f["package"], f["version"]) for f in findings}),
            "by_severity": {k: by.get(k, 0) for k in ("critical", "high", "medium", "low", "unknown")},
            "runtime": sum(1 for f in findings if f["dev_only"] is False),
            "dev_only": sum(1 for f in findings if f["dev_only"]),
            "with_fix": sum(1 for f in findings if f["fixed_in"])}
