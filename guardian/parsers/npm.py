"""npm: package-lock.json (v1, v2, v3) and package.json-only fallback."""

from __future__ import annotations

import json
from pathlib import Path

from .. import purl as P
from ..inventory import ROOT, Inventory, Pkg

DEP_KEYS = ("dependencies", "optionalDependencies", "peerDependencies")


def _name_from_key(key: str) -> str:
    idx = key.rfind("node_modules/")
    return key[idx + len("node_modules/"):] if idx >= 0 else key


def _resolve(packages: dict, from_key: str, dep: str) -> str | None:
    """Node's module resolution: look in nested node_modules, then walk up."""
    path = from_key
    while True:
        cand = f"{path}/node_modules/{dep}" if path else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not path:
            return None
        idx = path.rfind("node_modules/")
        path = path[:idx].rstrip("/") if idx > 0 else ""


def parse_lock_v2(lock: dict, rel: str) -> Inventory:
    packages: dict = lock.get("packages", {})
    root = packages.get("", {})
    inv = Inventory(
        ecosystem="npm",
        source_file=rel,
        project_name=lock.get("name") or root.get("name") or Path(rel).parent.name or "root",
        project_version=lock.get("version") or root.get("version"),
        method=f"package-lock.json v{lock.get('lockfileVersion')}",
    )

    # Workspace links: node_modules/foo -> packages/foo
    def target(key: str) -> str:
        e = packages.get(key, {})
        if e.get("link") and e.get("resolved") in packages:
            return e["resolved"]
        return key

    key_to_purl: dict[str, str] = {}
    for key, e in packages.items():
        if key == "" or e.get("link"):
            continue
        if "node_modules/" not in key:          # workspace package source dir
            name = e.get("name") or Path(key).name
        else:
            name = _name_from_key(key)
        # Aliased deps ("foo": "npm:bar@1") carry the real name in "name".
        real = e.get("name") if e.get("name") and "node_modules/" in key else name
        version = e.get("version")
        purl = P.npm(real, version)
        key_to_purl[key] = purl
        props = {}
        if e.get("hasInstallScript"):
            props["npm:hasInstallScript"] = "true"
        if e.get("dev"):
            props["npm:dev"] = "true"
        if e.get("optional"):
            props["npm:optional"] = "true"
        if e.get("inBundle"):
            props["npm:bundled"] = "true"
        if "node_modules/" not in key:
            props["npm:workspace"] = key
        scope = "optional" if (e.get("dev") or e.get("devOptional")) else "required"
        inv.add(Pkg(purl=purl, name=real, version=version, scope=scope,
                    resolved_url=e.get("resolved"), integrity=e.get("integrity"),
                    license=e.get("license") if isinstance(e.get("license"), str) else None,
                    properties=props))

    unresolved = 0
    for key, e in packages.items():
        if e.get("link"):
            continue
        parent = ROOT if key == "" else key_to_purl.get(key)
        if parent is None:
            continue
        keys = DEP_KEYS + (("devDependencies",) if key == "" or "node_modules/" not in key else ())
        for dk in keys:
            for dep, spec in (e.get(dk) or {}).items():
                found = _resolve(packages, key, dep)
                if found is None:
                    if dk == "dependencies":
                        unresolved += 1
                    continue
                child = key_to_purl.get(target(found))
                if child:
                    inv.link(parent, child, spec)
        # workspace packages hang off the root
        if key and "node_modules/" not in key:
            inv.link(ROOT, key_to_purl[key])
    if unresolved:
        inv.notes.append(f"{unresolved} declared dependencies were not present in the lockfile "
                         "(usually optional/platform-specific packages).")
    return inv


def parse_lock_v1(lock: dict, rel: str) -> Inventory:
    inv = Inventory(ecosystem="npm", source_file=rel, project_name=lock.get("name") or "root",
                    project_version=lock.get("version"), method="package-lock.json v1")

    # Flatten nested tree into keys like v2 so the same resolver works.
    flat: dict[str, dict] = {}

    def walk(deps: dict, prefix: str):
        for name, e in (deps or {}).items():
            key = f"{prefix}node_modules/{name}"
            flat[key] = e
            walk(e.get("dependencies"), key + "/")

    walk(lock.get("dependencies"), "")
    key_to_purl = {}
    for key, e in flat.items():
        name = _name_from_key(key)
        purl = P.npm(name, e.get("version"))
        key_to_purl[key] = purl
        inv.add(Pkg(purl=purl, name=name, version=e.get("version"),
                    scope="optional" if e.get("dev") else "required",
                    resolved_url=e.get("resolved"), integrity=e.get("integrity"),
                    properties={"npm:dev": "true"} if e.get("dev") else {}))
    for key, e in flat.items():
        for dep, spec in (e.get("requires") or {}).items():
            found = _resolve(flat, key, dep)
            if found:
                inv.link(key_to_purl[key], key_to_purl[found], spec)
    # v1 has no root dependency list; parse() uses package.json to mark direct deps.
    return inv


def parse_package_json_only(pkg: dict, rel: str) -> Inventory:
    inv = Inventory(ecosystem="npm", source_file=rel, project_name=pkg.get("name") or "root",
                    project_version=pkg.get("version"), method="package.json only (no lockfile)",
                    complete=False)
    inv.notes.append("No lockfile: only direct dependencies with version *ranges* are known. "
                     "Transitive dependencies need a lockfile (enable lockfile generation).")
    for dk in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (pkg.get(dk) or {}).items():
            purl = P.npm(name, None)
            inv.add(Pkg(purl=purl, name=name, version=None,
                        scope="optional" if dk == "devDependencies" else "required",
                        properties={"npm:versionSpec": str(spec), "npm:declaredIn": dk}))
            inv.link(ROOT, purl)
    return inv


def parse(project_dir: Path, repo_root: Path) -> Inventory:
    lock_path = project_dir / "package-lock.json"
    if not lock_path.exists():
        lock_path = project_dir / "npm-shrinkwrap.json"
    pkg_path = project_dir / "package.json"
    pkg = json.loads(pkg_path.read_text(encoding="utf-8")) if pkg_path.exists() else {}
    if lock_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        rel = str(lock_path.relative_to(repo_root))
        if "packages" in lock:
            inv = parse_lock_v2(lock, rel)
        else:
            inv = parse_lock_v1(lock, rel)
            # mark direct deps using package.json
            direct = set()
            declared = {}
            for dk in ("dependencies", "devDependencies", "optionalDependencies"):
                declared.update(pkg.get(dk) or {})
            for p in list(inv.packages.values()):
                if p.name in declared:
                    inv.link(ROOT, p.purl, declared[p.name])
        return inv
    return parse_package_json_only(pkg, str(pkg_path.relative_to(repo_root)))
