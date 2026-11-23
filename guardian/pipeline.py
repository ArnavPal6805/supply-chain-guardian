"""End-to-end Day-1 pipeline: Step 1 (discover components) + Step 2 (supply chain view)."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import anomalies, artifacts, cdxgen_runner, clone, cyclonedx, evidence, vulns
from . import graph as G
from .detect import detect
from .inventory import ROOT, Inventory
from .normalize import normalize
from .parsers import golang, maven, npm, python


@dataclass
class Options:
    engine: str = "auto"              # auto | cdxgen | builtin
    generate_lockfiles: bool = True   # npm install --package-lock-only --ignore-scripts
    run_build_tools: bool = True      # allow `mvn dependency:tree`, `go mod graph`
    scan_vulns: bool = True           # OSV-Scanner on the SBOM + root-cause analysis
    baseline: str | None = None       # previous scan's result.json (or its folder) for "what changed"
    keep_repo: bool = True


@dataclass
class Run:
    out_dir: Path
    log_lines: list[str] = field(default_factory=list)
    stage: str = "queued"
    started: float = field(default_factory=time.time)

    def log(self, msg: str) -> None:
        line = f"[{time.time() - self.started:6.1f}s] {msg}"
        self.log_lines.append(line)
        print(line, flush=True)

    def set_stage(self, stage: str) -> None:
        self.stage = stage
        self.log(f"== {stage}")


def _generate_npm_lockfiles(repo: Path, rel_dirs: list[str], run: Run) -> list[str]:
    """Resolve a lockfile WITHOUT running any package scripts."""
    npm_bin = shutil.which("npm")
    if not npm_bin:
        run.log("npm not found: cannot generate lockfiles; npm projects will be direct-deps only")
        return []
    done = []
    for rel in rel_dirs:
        d = repo / rel
        # Respect a repo-level "package-lock=false" by overriding it explicitly for this command.
        base = [npm_bin, "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                "--no-fund", "--package-lock=true", "--workspaces=false",
                "--fetch-retries=1", "--fetch-retry-maxtimeout=15000", "--fetch-timeout=60000"]
        for extra in ([], ["--legacy-peer-deps"]):
            cmd = base + extra
            run.log(f"$ npm {' '.join(cmd[1:])}   (in {rel})")
            try:
                r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=900)
            except subprocess.TimeoutExpired:
                run.log("  timed out")
                break
            if r.returncode == 0 and (d / "package-lock.json").exists():
                done.append(rel)
                break
            err = (r.stderr or r.stdout)
            lines = [l for l in err.strip().splitlines() if "complete log" not in l]
            run.log("  failed: " + (lines[-1] if lines else "?")[:300])
            if "ERESOLVE" not in err:
                break  # network/registry errors won't be fixed by --legacy-peer-deps
    return done


def _builtin_inventories(repo: Path, det, opts: Options, generated: set[str], run: Run) -> list[Inventory]:
    invs: list[Inventory] = []
    for d in det.npm:
        try:
            inv = npm.parse(d, repo)
            rel = str(d.relative_to(repo)) or "."
            if rel in generated:
                inv.method += " (generated at scan time)"
                inv.notes.append("This project does not commit a lockfile. The lockfile was resolved at "
                                 "scan time with --ignore-scripts, so versions reflect the registry today "
                                 "and may differ from what the project last shipped.")
            invs.append(inv)
        except Exception as e:  # noqa: BLE001 - keep going on one bad file
            run.log(f"npm parse failed for {d}: {e}")
    for d in det.maven:
        try:
            invs += maven.parse(d, repo, run_maven=opts.run_build_tools, log=run.log)
        except Exception as e:  # noqa: BLE001
            run.log(f"maven parse failed for {d}: {e}")
    for f in det.python:
        try:
            if f.name == "poetry.lock":
                invs.append(python.parse_poetry_lock(f, repo))
            elif f.name == "uv.lock":
                invs.append(python.parse_uv_lock(f, repo))
            elif f.name == "Pipfile.lock":
                invs.append(python.parse_pipfile_lock(f, repo))
            else:
                invs.append(python.parse_requirements(f, repo))
        except Exception as e:  # noqa: BLE001
            run.log(f"python parse failed for {f}: {e}")
    for d in det.golang:
        try:
            invs.append(golang.parse(d, repo, run_go=opts.run_build_tools, log=run.log))
        except Exception as e:  # noqa: BLE001
            run.log(f"go parse failed for {d}: {e}")
    return [i for i in invs if i.packages or not i.complete]


def _action_key(purl: str | None):
    """('owner','repo','ref') for pkg:github/... (cdxgen) and pkg:githubactions/... (ours)."""
    if not purl or not purl.startswith(("pkg:github/", "pkg:githubactions/")):
        return None
    from urllib.parse import unquote
    body = purl.split("/", 1)[1].split("?")[0].split("#")[0]
    path, _, ref = body.rpartition("@")
    segs = unquote(path).lower().split("/")
    return (segs[0], segs[1], unquote(ref).lower()) if len(segs) >= 2 and ref else None


def _dedupe_actions(primary: dict, extra: dict) -> None:
    """cdxgen v13 records GitHub Actions as pkg:github/... components. We add our own
    pkg:githubactions/... components (with pinning facts), so drop cdxgen's duplicates,
    keeping their cdx:github:* properties on our component and re-pointing their edges."""
    ours = {}
    for c in extra.get("components", []):
        k = _action_key(c.get("purl"))
        if k and c["purl"].startswith("pkg:githubactions/"):
            ours.setdefault(k, c)
    if not ours:
        return
    replaced = {}
    keep = []
    for c in primary.get("components", []):
        k = _action_key(c.get("purl"))
        if k and c["purl"].startswith("pkg:github/") and k in ours:
            mine = ours[k]
            names = {p["name"] for p in mine.get("properties", [])}
            mine.setdefault("properties", []).extend(
                p for p in c.get("properties", []) if p.get("name") not in names)
            replaced[c.get("bom-ref")] = mine["bom-ref"]
        else:
            keep.append(c)
    primary["components"] = keep
    deps = []
    for d in primary.get("dependencies", []):
        if d["ref"] in replaced:
            continue
        d["dependsOn"] = sorted({replaced.get(x, x) for x in d.get("dependsOn", [])})
        deps.append(d)
    primary["dependencies"] = deps


def _enrich_from_builtin(primary: dict, builtin: dict) -> int:
    """Copy lockfile facts (install scripts, dev flag, integrity) onto cdxgen components."""
    by_purl = {c["purl"]: c for c in builtin.get("components", []) if c.get("purl")}
    n = 0
    for c in primary.get("components", []):
        b = by_purl.get(c.get("purl"))
        if not b:
            continue
        have = {p.get("name") for p in c.get("properties", [])}
        add = [p for p in b.get("properties", []) if p["name"] not in have]
        changed = False
        if add:
            c.setdefault("properties", []).extend(add)
            changed = True
        if not c.get("hashes") and b.get("hashes"):
            c["hashes"] = b["hashes"]
            changed = True
        n += changed
    return n


def _merge_extra(primary: dict, extra: dict) -> dict:
    """Add projects/components/edges from `extra` into `primary` (dedupe by bom-ref)."""
    _dedupe_actions(primary, extra)
    meta = primary.setdefault("metadata", {}).setdefault("component", {"bom-ref": "__root__", "name": "repo"})
    meta.setdefault("components", [])
    have_refs = {c.get("bom-ref") for c in primary.get("components", [])}
    have_purls = {c.get("purl") for c in primary.get("components", []) if c.get("purl")}
    for p in extra["metadata"]["component"].get("components", []):
        meta["components"].append(p)
    for c in extra.get("components", []):
        if c["bom-ref"] not in have_refs and c.get("purl") not in have_purls:
            primary.setdefault("components", []).append(c)
    deps = {d["ref"]: d for d in primary.setdefault("dependencies", [])}
    root_ref = meta["bom-ref"]
    for d in extra.get("dependencies", []):
        ref = root_ref if d["ref"] == extra["metadata"]["component"]["bom-ref"] else d["ref"]
        if ref in deps:
            deps[ref]["dependsOn"] = sorted(set(deps[ref].get("dependsOn", [])) | set(d["dependsOn"]))
        else:
            new = {"ref": ref, "dependsOn": d["dependsOn"]}
            primary["dependencies"].append(new)
            deps[ref] = new
    return primary


def _cross_check(model: dict, builtin_model: dict | None, engine_used: str) -> list[dict]:
    """Compare the SBOM engine's counts with the package managers' own view."""
    checks = []
    if engine_used != "cdxgen" or not builtin_model:
        return checks
    a = {c["purl"] for c in model["components"].values() if c["purl"]}
    b = {c["purl"] for c in builtin_model["components"].values() if c["purl"]}
    for eco in sorted({c["ecosystem_key"] for c in builtin_model["components"].values()}):
        ea = {p for p in a if p.startswith(f"pkg:{eco}/")}
        eb = {p for p in b if p.startswith(f"pkg:{eco}/")}
        if not eb:
            continue
        checks.append({"ecosystem": eco, "cdxgen": len(ea), "lockfile_parser": len(eb),
                       "only_in_cdxgen": sorted(ea - eb)[:20], "only_in_lockfile": sorted(eb - ea)[:20]})
    return checks


def analyze(source: str, out_dir: Path, opts: Options | None = None, run: Run | None = None) -> dict:
    opts = opts or Options()
    run = run or Run(out_dir=out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    run.set_stage("Fetching repository")
    repo_info = clone.fetch(source, out_dir / "repo", log=run.log)
    repo = Path(repo_info["path"])

    run.set_stage("Detecting manifests, lockfiles, containers and CI")
    det = detect(repo)
    detection = det.summary(repo)
    run.log(f"npm={len(det.npm)} maven={len(det.maven)} python={len(det.python)} go={len(det.golang)} "
            f"dockerfiles={len(det.dockerfiles)} compose={len(det.compose)} workflows={len(det.workflows)} "
            f"other={len(det.other)}")

    generated: set[str] = set()
    if det.lockfiles_missing and opts.generate_lockfiles:
        run.set_stage("Resolving missing npm lockfiles (scripts disabled)")
        generated = set(_generate_npm_lockfiles(repo, det.lockfiles_missing, run))

    run.set_stage("Parsing lockfiles with built-in parsers")
    invs = _builtin_inventories(repo, det, opts, generated, run)
    builtin_bom = cyclonedx.build_bom(invs, repo_info)

    engine_used = "builtin"
    bom = builtin_bom
    if opts.engine in ("auto", "cdxgen"):
        run.set_stage("Generating SBOM with cdxgen")
        cdx = cdxgen_runner.run(repo, out_dir / "cdxgen", log=run.log)
        if cdx:
            engine_used = "cdxgen"
            bom = cdx
            n = _enrich_from_builtin(bom, builtin_bom)
            run.log(f"Added lockfile facts (install scripts, dev flags, hashes) to {n} cdxgen components")
            # keep repo identity on the root component
            mc = bom.setdefault("metadata", {}).setdefault("component", {})
            mc.setdefault("bom-ref", f"repo:{repo_info['name']}")
            mc.setdefault("name", repo_info["name"])
            mc.setdefault("type", "application")
        elif opts.engine == "cdxgen":
            raise RuntimeError("cdxgen was requested but did not produce an SBOM (see log)")
        else:
            run.log("Falling back to the built-in engine")

    run.set_stage("Inspecting container images and CI/CD workflows")
    dockerfiles = [artifacts.parse_dockerfile(p, repo) for p in det.dockerfiles]
    composes = [artifacts.parse_compose(p, repo) for p in det.compose]
    workflows = [artifacts.parse_workflow(p, repo) for p in det.workflows]
    art_invs = artifacts.build_inventories(dockerfiles, composes, workflows)
    if art_invs:
        bom = _merge_extra(bom, cyclonedx.build_bom(art_invs, repo_info))

    run.set_stage("Building the dependency graph")
    model = normalize(bom)
    stats = G.analyze(model)
    builtin_model = None
    if engine_used == "cdxgen" and invs:
        builtin_model = normalize(builtin_bom)
        G.analyze(builtin_model)
    checks = _cross_check(model, builtin_model, engine_used)

    (out_dir / "bom.cdx.json").write_text(json.dumps(bom, indent=2), encoding="utf-8")

    # declared ranges per edge (from the lockfile parsers), used by Steps 3 and 4
    edge_specs = {}
    for inv in invs:
        for (parent, child), spec in inv.edge_specs.items():
            key = f"root::{inv.source_file}" if parent == ROOT else parent
            edge_specs.setdefault((key, child), spec)
            # manifests: also index by package.json path (lockfile sits next to it)
            if parent == ROOT and inv.source_file.endswith(("package-lock.json", "npm-shrinkwrap.json")):
                pj = inv.source_file.rsplit("/", 1)[0] + "/package.json" if "/" in inv.source_file else "package.json"
                edge_specs.setdefault((f"root::{pj}", child), spec)

    vuln_result = None
    if opts.scan_vulns:
        run.set_stage("Step 3: scanning for known vulnerabilities (OSV)")
        osv = vulns.run_osv(out_dir / "bom.cdx.json", log=run.log)
        if osv is not None:
            (out_dir / "osv-raw.json").write_text(json.dumps(osv), encoding="utf-8")
            run.set_stage("Step 3: tracing root causes through the graph")
            vuln_result = vulns.analyze(osv, model, edge_specs, log=run.log)
            vs = vuln_result["summary"]
            run.log(f"{vs['total']} vulnerability findings in {vs['packages']} packages "
                    f"({vs['by_severity']['critical']} critical, {vs['by_severity']['high']} high), "
                    f"{len(vuln_result['groups'])} root-cause groups")
            (out_dir / "vulns.json").write_text(json.dumps(vuln_result, indent=2, default=list), encoding="utf-8")

    run.set_stage("Step 4: detecting supply-chain anomalies")
    found = anomalies.detect(model, {"dockerfiles": dockerfiles, "compose": composes}, {"workflows": workflows},
                             detection, sorted(generated), repo, edge_specs)
    change = None
    if opts.baseline:
        bpath = Path(opts.baseline)
        bpath = bpath / "result.json" if bpath.is_dir() else bpath
        try:
            base = json.loads(bpath.read_text(encoding="utf-8"))
            run.log(f"Comparing with baseline {bpath} (commit {((base.get('repository') or {}).get('commit') or '?')[:12]})")
            diffs, change = anomalies.diff(base, model, repo)
            found += diffs
            run.log(f"Changes since baseline: {change['added']} added, {change['updated']} updated, "
                    f"{change['removed']} removed, {change['integrity_changed']} integrity changes")
        except (OSError, ValueError) as e:
            run.log(f"Baseline could not be read: {e}")
    run.log(f"{len(found)} anomalies detected")

    run.set_stage("Step 5: building evidence and risk levels")
    findings = evidence.build(model, vuln_result, found, repo, log=run.log)
    findings["changes"] = change
    fs = findings["summary"]
    run.log(f"{fs['total']} findings: " + ", ".join(f"{v} {k}" for k, v in fs["by_level"].items() if v))
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2, default=list), encoding="utf-8")

    run.set_stage("Writing outputs")
    components = sorted(model["components"].values(), key=lambda c: (not c["direct"], c["ecosystem"], c["name"]))
    result = {
        "repository": {k: v for k, v in repo_info.items() if k != "path"},
        "engine": engine_used,
        "options": opts.__dict__,
        "detection": detection,
        "projects": list(model["projects"].values()),
        "stats": stats,
        "cross_check": checks,
        "containers": {"dockerfiles": dockerfiles, "compose": composes},
        "ci_cd": {"workflows": workflows},
        "components": components,
        "vulnerabilities": vuln_result,
        "findings": findings,
        "generated_lockfiles": sorted(generated),
        "duration_seconds": round(time.time() - run.started, 1),
    }
    (out_dir / "result.json").write_text(json.dumps(result, indent=2, default=list), encoding="utf-8")
    (out_dir / "graph.json").write_text(json.dumps(G.graph_payload(model, findings)), encoding="utf-8")
    (out_dir / "log.txt").write_text("\n".join(run.log_lines), encoding="utf-8")
    if not opts.keep_repo and not repo_info.get("local"):
        shutil.rmtree(repo, ignore_errors=True)
    run.set_stage("Done")
    run.log(f"{stats['packages']} packages ({stats['direct']} direct, {stats['transitive']} transitive), "
            f"{stats['container_images']} images, {stats['ci_components']} CI components, engine={engine_used}")
    return result
