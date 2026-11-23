"""Go: go.mod (+ go.sum hashes), optionally `go mod graph` for exact parent links."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .. import purl as P
from ..inventory import ROOT, Inventory, Pkg


def parse_go_mod(text: str) -> tuple[str, dict[str, tuple[str, bool]], dict[str, str]]:
    module = ""
    reqs: dict[str, tuple[str, bool]] = {}
    replaces: dict[str, str] = {}
    block = None
    for raw in text.splitlines():
        line = raw.split("//")[0].strip() if "// indirect" not in raw else raw.strip()
        if not line:
            continue
        if line.startswith("module "):
            module = line.split()[1].strip('"')
            continue
        if line.endswith("(") and line.split()[0] in ("require", "replace", "exclude", "retract"):
            block = line.split()[0]
            continue
        if line == ")":
            block = None
            continue
        kind = block
        if line.startswith(("require ", "replace ")):
            kind, line = line.split(None, 1)
        if kind == "require":
            indirect = "// indirect" in line
            parts = line.split("//")[0].split()
            if len(parts) >= 2:
                reqs[parts[0]] = (parts[1], indirect)
        elif kind == "replace" and "=>" in line:
            left, right = [s.strip() for s in line.split("=>", 1)]
            replaces[left.split()[0]] = right
    return module, reqs, replaces


def parse(project_dir: Path, repo_root: Path, run_go: bool = True, log=print) -> Inventory:
    gomod = project_dir / "go.mod"
    rel = str(gomod.relative_to(repo_root))
    module, reqs, replaces = parse_go_mod(gomod.read_text(encoding="utf-8"))
    inv = Inventory(ecosystem="golang", source_file=rel, project_name=module or project_dir.name,
                    method="go.mod")
    sums = {}
    gosum = project_dir / "go.sum"
    if gosum.exists():
        for line in gosum.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 3 and not parts[1].endswith("/go.mod"):
                sums[(parts[0], parts[1])] = parts[2]

    purl_of = {}
    for mod, (ver, indirect) in reqs.items():
        purl = P.golang(mod, ver)
        purl_of[mod] = purl
        props = {"go:indirect": "true"} if indirect else {}
        if mod in replaces:
            props["go:replacedBy"] = replaces[mod]
        inv.add(Pkg(purl=purl, name=mod, version=ver, integrity=sums.get((mod, ver)),
                    resolved_url=f"https://proxy.golang.org/{mod.lower()}/@v/{ver}.zip",
                    properties=props))

    graph_ok = False
    go = shutil.which("go")
    if run_go and go:
        env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
        try:
            log(f"$ go mod graph   (in {rel.rsplit('/', 1)[0] if '/' in rel else '.'})")
            r = subprocess.run([go, "mod", "graph"], cwd=project_dir, capture_output=True,
                               text=True, timeout=300, env=env)
            if r.returncode == 0 and r.stdout.strip():
                for line in r.stdout.splitlines():
                    a, _, b = line.partition(" ")
                    am, _, av = a.partition("@")
                    bm, _, bv = b.partition("@")
                    parent = ROOT if am == module else (purl_of.get(am) if reqs.get(am, ("",))[0] == av else None)
                    if parent and bm in purl_of:
                        inv.link(parent, purl_of[bm])
                graph_ok = True
                inv.method = "go.mod + go mod graph"
            else:
                log("go mod graph failed; using go.mod direct/indirect markers. "
                    + r.stderr.strip()[-300:])
        except subprocess.TimeoutExpired:
            log("go mod graph timed out")
    if not graph_ok:
        for mod, (ver, indirect) in reqs.items():
            if not indirect:
                inv.link(ROOT, purl_of[mod])
        n_ind = sum(1 for _, i in reqs.values() if i)
        if n_ind:
            inv.complete = False
            inv.notes.append(f"{n_ind} modules are marked '// indirect' in go.mod: they are transitive, "
                             "but go.mod does not say which dependency pulls them in. "
                             "Install Go to resolve exact paths with `go mod graph`.")
    return inv
