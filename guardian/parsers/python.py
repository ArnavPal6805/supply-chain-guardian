"""Python: requirements.txt (incl. pip-compile / uv '# via' graphs), poetry.lock, uv.lock, Pipfile.lock."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .. import purl as P
from ..inventory import ROOT, Inventory, Pkg

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;\s\\]*)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path, repo_root: Path) -> Inventory:
    rel = str(path.relative_to(repo_root))
    inv = Inventory(ecosystem="pypi", source_file=rel, project_name=path.parent.name or "root",
                    method="requirements.txt")
    entries: list[dict] = []
    current: dict | None = None
    in_via_block = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if current is None:
                continue
            body = stripped.lstrip("#").strip()
            if body.startswith("via"):
                rest = body[3:].strip()
                if rest:
                    current["via"].append(rest)
                    in_via_block = False
                else:
                    in_via_block = True
            elif in_via_block and body:
                current["via"].append(body)
            continue
        in_via_block = False
        if stripped.startswith(("-", "--hash")):
            continue  # options (-r, -e, --index-url) and hash continuation lines
        m = REQ_RE.match(stripped)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(3), m.group(4)
        current = {"name": name, "pinned": op in ("==", "===") and bool(ver),
                   "version": ver if op in ("==", "===") else None,
                   "spec": (op or "") + (ver or ""), "via": []}
        entries.append(current)

    has_graph = any(e["via"] for e in entries)
    names = {norm(e["name"]): e for e in entries}
    purl_of = {}
    for e in entries:
        purl = P.pypi(e["name"], e["version"])
        purl_of[norm(e["name"])] = purl
        props = {}
        if not e["pinned"]:
            props["pypi:versionSpec"] = e["spec"] or "(any)"
        inv.add(Pkg(purl=purl, name=e["name"], version=e["version"], properties=props))
    for e in entries:
        child = purl_of[norm(e["name"])]
        if not has_graph:
            inv.link(ROOT, child)
            continue
        parents = [v for v in e["via"] if not v.startswith("-")]
        direct = any(v.startswith("-r") or v.startswith("-c") for v in e["via"]) or not e["via"]
        if direct:
            inv.link(ROOT, child)
        for parent in parents:
            pn = norm(re.split(r"[\s\[(]", parent)[0])
            if pn in names:
                inv.link(purl_of[pn], child)
    if has_graph:
        inv.method = "requirements.txt (pip-compile/uv '# via' graph)"
    else:
        inv.complete = False
        inv.notes.append("Plain requirements file: no dependency graph, every entry treated as direct. "
                         "Transitive packages installed by pip are not listed.")
    unpinned = sum(1 for e in entries if not e["pinned"])
    if unpinned:
        inv.complete = False
        inv.notes.append(f"{unpinned} requirements are not pinned to an exact version.")
    return inv


def _pyproject_direct(project_dir: Path) -> set[str]:
    pp = project_dir / "pyproject.toml"
    if not pp.exists():
        return set()
    data = tomllib.loads(pp.read_text(encoding="utf-8"))
    out = set()
    for spec in data.get("project", {}).get("dependencies", []) or []:
        m = REQ_RE.match(spec)
        if m:
            out.add(norm(m.group(1)))
    for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
        for spec in group:
            m = REQ_RE.match(spec)
            if m:
                out.add(norm(m.group(1)))
    for spec in (data.get("dependency-groups", {}) or {}).values():
        for s in spec:
            if isinstance(s, str) and (m := REQ_RE.match(s)):
                out.add(norm(m.group(1)))
    poetry = data.get("tool", {}).get("poetry", {})
    out |= {norm(k) for k in (poetry.get("dependencies") or {}) if k.lower() != "python"}
    out |= {norm(k) for k in (poetry.get("dev-dependencies") or {})}
    for g in (poetry.get("group") or {}).values():
        out |= {norm(k) for k in (g.get("dependencies") or {})}
    return out


def parse_poetry_lock(path: Path, repo_root: Path) -> Inventory:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    inv = Inventory(ecosystem="pypi", source_file=str(path.relative_to(repo_root)),
                    project_name=path.parent.name or "root", method="poetry.lock")
    purl_of = {}
    for pkg in data.get("package", []):
        purl = P.pypi(pkg["name"], pkg.get("version"))
        purl_of[norm(pkg["name"])] = purl
        dev = pkg.get("category") == "dev"
        inv.add(Pkg(purl=purl, name=pkg["name"], version=pkg.get("version"),
                    scope="optional" if dev else "required",
                    resolved_url=(pkg.get("source") or {}).get("url"),
                    integrity=((pkg.get("files") or [{}])[0] or {}).get("hash")))
    for pkg in data.get("package", []):
        for dep, spec in (pkg.get("dependencies") or {}).items():
            if norm(dep) in purl_of:
                if isinstance(spec, dict):
                    spec = spec.get("version")
                elif isinstance(spec, list):
                    spec = None
                inv.link(purl_of[norm(pkg["name"])], purl_of[norm(dep)], spec)
    direct = _pyproject_direct(path.parent)
    _mark_direct(inv, purl_of, direct)
    return inv


def parse_uv_lock(path: Path, repo_root: Path) -> Inventory:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    inv = Inventory(ecosystem="pypi", source_file=str(path.relative_to(repo_root)),
                    project_name=path.parent.name or "root", method="uv.lock")
    purl_of, roots = {}, set()
    for pkg in data.get("package", []):
        src = pkg.get("source") or {}
        if "editable" in src or "virtual" in src:
            roots.add(norm(pkg["name"]))
            inv.project_name, inv.project_version = pkg["name"], pkg.get("version")
            continue
        purl = P.pypi(pkg["name"], pkg.get("version"))
        purl_of[norm(pkg["name"])] = purl
        sdist = pkg.get("sdist") or {}
        inv.add(Pkg(purl=purl, name=pkg["name"], version=pkg.get("version"),
                    resolved_url=src.get("registry") or src.get("url") or src.get("git"),
                    integrity=sdist.get("hash")))
    for pkg in data.get("package", []):
        parent = ROOT if norm(pkg["name"]) in roots else purl_of.get(norm(pkg["name"]))
        deps = list(pkg.get("dependencies") or [])
        for grp in (pkg.get("dev-dependencies") or pkg.get("optional-dependencies") or {}).values():
            deps += grp
        for d in deps:
            if parent and norm(d["name"]) in purl_of:
                inv.link(parent, purl_of[norm(d["name"])])
    if not roots:
        _mark_direct(inv, purl_of, _pyproject_direct(path.parent))
    return inv


def parse_pipfile_lock(path: Path, repo_root: Path) -> Inventory:
    data = json.loads(path.read_text(encoding="utf-8"))
    inv = Inventory(ecosystem="pypi", source_file=str(path.relative_to(repo_root)),
                    project_name=path.parent.name or "root", method="Pipfile.lock", complete=False)
    inv.notes.append("Pipfile.lock has no parent/child graph; all packages attached to the project.")
    for section, scope in (("default", "required"), ("develop", "optional")):
        for name, e in (data.get(section) or {}).items():
            ver = (e.get("version") or "").lstrip("=") or None
            purl = P.pypi(name, ver)
            inv.add(Pkg(purl=purl, name=name, version=ver, scope=scope,
                        integrity=(e.get("hashes") or [None])[0]))
            inv.link(ROOT, purl)
    return inv


def _mark_direct(inv: Inventory, purl_of: dict, direct: set[str]) -> None:
    if direct:
        for n in direct:
            if n in purl_of:
                inv.link(ROOT, purl_of[n])
        return
    # No manifest info: anything nobody depends on is a top-level dependency.
    children = {c for _, c in inv.edges}
    for purl in inv.packages:
        if purl not in children:
            inv.link(ROOT, purl)
    inv.notes.append("Direct dependencies inferred (no pyproject.toml found): packages nothing else depends on.")
