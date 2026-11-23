"""Maven: resolved tree via `mvn dependency:tree`, fallback to pom.xml direct deps.

Maven has no lockfile, so the only accurate transitive tree comes from asking
Maven to resolve it. We deliberately use the *system* `mvn`, never the repo's
`mvnw` wrapper (that is a script shipped by the repo and downloads a Maven
distribution from a URL the repo chooses).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import purl as P
from ..inventory import ROOT, Inventory, Pkg

DEP_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"
SCOPE_MAP = {"compile": "required", "runtime": "required", "system": "required",
             "provided": "optional", "test": "optional", "import": "optional"}


def parse_tree_text(text: str, rel: str) -> list[Inventory]:
    """Parse `dependency:tree` text output (one or more modules)."""
    invs: list[Inventory] = []
    inv: Inventory | None = None
    stack: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("["):
            continue
        m = re.search(r"[A-Za-z0-9_$]", line)
        if not m:
            continue
        depth = m.start() // 3
        body = line[m.start():]
        optional = body.endswith("(optional)")
        body = re.sub(r"\s*\(.*\)\s*$", "", body).strip()
        parts = body.split(":")
        if depth == 0:
            # module root: group:artifact:packaging:version
            g, a = parts[0], parts[1]
            v = parts[3] if len(parts) > 3 else None
            inv = Inventory(ecosystem="maven", source_file=rel, project_name=f"{g}:{a}",
                            project_version=v, method="mvn dependency:tree")
            invs.append(inv)
            stack = []
            continue
        if inv is None or len(parts) < 5:
            continue
        if len(parts) >= 6:
            g, a, typ, classifier, v, scope = parts[:6]
        else:
            g, a, typ, v, scope = parts[:5]
            classifier = None
        purl = P.maven(g, a, v, typ)
        props = {"maven:scope": scope}
        if classifier:
            props["maven:classifier"] = classifier
        if optional:
            props["maven:optional"] = "true"
        inv.add(Pkg(purl=purl, name=f"{g}:{a}", version=v,
                    scope=SCOPE_MAP.get(scope, "required"), properties=props))
        stack = stack[: depth - 1]
        parent = stack[-1] if stack else ROOT
        inv.link(parent, purl)
        stack.append(purl)
    return invs


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def parse_pom_direct(pom_path: Path, rel: str) -> Inventory:
    root = ET.parse(pom_path).getroot()
    _strip_ns(root)
    props = {}
    for el in (root.find("properties") or []):
        props[el.tag] = (el.text or "").strip()
    parent = root.find("parent")
    g = root.findtext("groupId") or (parent.findtext("groupId") if parent is not None else "")
    a = root.findtext("artifactId") or "root"
    v = root.findtext("version") or (parent.findtext("version") if parent is not None else None)
    props.update({"project.version": v or "", "project.groupId": g or "",
                  "version": v or ""})

    def sub(s: str | None) -> str | None:
        if not s:
            return None
        for _ in range(5):
            s2 = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            if s2 == s:
                break
            s = s2
        return None if "${" in s else s

    inv = Inventory(ecosystem="maven", source_file=rel, project_name=f"{g}:{a}", project_version=v,
                    method="pom.xml only (Maven not run)", complete=False)
    inv.notes.append("Maven was not run, so only direct dependencies are known and versions "
                     "managed by a parent/BOM are unresolved. Install Maven (or use cdxgen) "
                     "for the full transitive tree.")
    managed = 0
    for dep in root.findall("./dependencies/dependency"):
        dg, da = sub(dep.findtext("groupId")), sub(dep.findtext("artifactId"))
        if not dg or not da:
            continue
        dv = sub(dep.findtext("version"))
        scope = dep.findtext("scope") or "compile"
        if dv is None:
            managed += 1
        purl = P.maven(dg, da, dv, dep.findtext("type"))
        inv.add(Pkg(purl=purl, name=f"{dg}:{da}", version=dv, scope=SCOPE_MAP.get(scope, "required"),
                    properties={"maven:scope": scope,
                                **({"maven:versionManaged": "true"} if dv is None else {})}))
        inv.link(ROOT, purl)
    if managed:
        inv.notes.append(f"{managed} direct dependencies have versions managed by a parent POM/BOM.")
    return inv


def parse(project_dir: Path, repo_root: Path, run_maven: bool = True, log=print,
          timeout: int = 600) -> list[Inventory]:
    pom = project_dir / "pom.xml"
    rel = str(pom.relative_to(repo_root))
    mvn = shutil.which("mvn")
    if run_maven and mvn:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "tree.txt"
            cmd = [mvn, "-B", "-q", DEP_PLUGIN, f"-DoutputFile={out}", "-DappendOutput=true",
                   "-Dstyle.color=never"]
            log(f"$ {' '.join(cmd)}")
            try:
                r = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True,
                                   timeout=timeout)
                if r.returncode == 0 and out.exists() and out.stat().st_size:
                    invs = parse_tree_text(out.read_text(encoding="utf-8"), rel)
                    if invs:
                        return invs
                errs = [l for l in (r.stdout + r.stderr).splitlines()
                        if l.startswith("[ERROR]") and l.strip() != "[ERROR]"]
                log("mvn dependency:tree failed; falling back to pom.xml. "
                    + (errs[0][:300] if errs else f"exit code {r.returncode}"))
            except subprocess.TimeoutExpired:
                log("mvn dependency:tree timed out; falling back to pom.xml")
    elif run_maven:
        log("`mvn` not found on PATH; falling back to pom.xml (direct deps only)")
    return [parse_pom_direct(pom, rel)]
