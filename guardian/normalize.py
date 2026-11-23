"""Turn ANY CycloneDX SBOM (cdxgen, built-in, Syft, a vendor SBOM...) into the
normalized model every later step uses: components + edges + projects."""

from __future__ import annotations

from urllib.parse import urlparse

from . import purl as P

DEFAULT_ORIGIN = {
    "npm": "registry.npmjs.org", "pypi": "pypi.org", "maven": "repo.maven.apache.org",
    "golang": "proxy.golang.org", "nuget": "api.nuget.org", "cargo": "crates.io",
    "gem": "rubygems.org", "githubactions": "github.com", "docker": "docker.io",
}


def _props(c: dict) -> dict:
    out: dict = {}
    for p in c.get("properties") or []:
        name, val = p.get("name"), p.get("value")
        if name is None:
            continue
        if name in out:
            if not isinstance(out[name], list):
                out[name] = [out[name]]
            out[name].append(val)
        else:
            out[name] = val
    return out


def _walk_components(items, acc):
    for c in items or []:
        acc.append(c)
        _walk_components(c.get("components"), acc)
    return acc


def _origin(ptype: str, purl_parts: dict, resolved: str | None, props: dict) -> dict:
    if resolved:
        if resolved.startswith(("http://", "https://", "git+", "git:", "ssh:")):
            host = urlparse(resolved.replace("git+", "")).hostname or resolved
            return {"host": host, "url": resolved, "source": "lockfile/SBOM"}
        if resolved.startswith(("file:", "./", "../", "/")) or not ("." in resolved.split("/")[0]):
            return {"host": "local path", "url": resolved, "source": "lockfile/SBOM"}
        return {"host": resolved.split("/")[0], "url": resolved, "source": "lockfile/SBOM"}
    if ptype == "docker":
        return {"host": "docker.io", "url": None, "source": "default registry (assumed)"}
    host = DEFAULT_ORIGIN.get(ptype)
    return {"host": host or "unknown", "url": None,
            "source": "default registry (assumed)" if host else "unknown"}


def normalize(bom: dict) -> dict:
    meta_comp = (bom.get("metadata") or {}).get("component") or {}
    root_ref = meta_comp.get("bom-ref") or "__root__"
    projects = {}
    for pc in [meta_comp] + _walk_components(meta_comp.get("components"), []):
        ref = pc.get("bom-ref")
        if not ref:
            continue
        pp = _props(pc)
        notes = pp.get("guardian:note", [])
        projects[ref] = {
            "id": ref, "name": pc.get("name"), "version": pc.get("version"),
            "is_repo_root": ref == root_ref,
            "ecosystem": pp.get("guardian:ecosystem") or P.parse(pc.get("purl", "")).get("type"),
            "source_file": pp.get("guardian:sourceFile") or pp.get("internal:SrcFile") or pp.get("SrcFile"),
            "method": pp.get("guardian:method") or ("repository" if ref == root_ref else "cdxgen"),
            "complete": pp.get("guardian:complete", "true") == "true",
            "notes": notes if isinstance(notes, list) else [notes],
        }

    components = {}
    for c in _walk_components(bom.get("components"), []):
        ref = c.get("bom-ref") or c.get("purl")
        if not ref or ref in projects:
            continue
        purl = c.get("purl") or ""
        pp = P.parse(purl)
        props = _props(c)
        resolved = None
        for er in c.get("externalReferences") or []:
            if er.get("type") == "distribution" and er.get("url"):
                resolved = er["url"]
                break
        resolved = resolved or props.get("internal:ResolvedUrl") or props.get("ResolvedUrl")
        found_in = [o.get("location") for o in ((c.get("evidence") or {}).get("occurrences") or [])
                    if o.get("location")]
        for key in ("internal:SrcFile", "SrcFile"):
            v = props.get(key)
            for f in (v if isinstance(v, list) else [v] if v else []):
                f = f[5:] if f.startswith("/app/") else f      # path inside the cdxgen container
                if f not in found_in:
                    found_in.append(f)
        licenses = []
        for lic in c.get("licenses") or []:
            licenses.append(lic.get("expression") or (lic.get("license") or {}).get("id")
                            or (lic.get("license") or {}).get("name"))
        group = c.get("group")
        name = c.get("name") or pp.get("name") or ref
        components[ref] = {
            "id": ref,
            "purl": purl or None,
            "name": f"{group}:{name}" if group and pp.get("type") == "maven" else
                    (f"{group}/{name}" if group and not name.startswith(group) else name),
            "version": c.get("version") or pp.get("version"),
            "type": c.get("type", "library"),
            "ecosystem_key": pp.get("type") or "unknown",
            "ecosystem": P.ecosystem_of(purl),
            "scope": c.get("scope") or "required",   # CycloneDX default is "required"
            "hashes": [f"{h.get('alg')}:{h.get('content')}" for h in c.get("hashes") or []],
            "licenses": [l for l in licenses if l],
            "origin": _origin(pp.get("type") or "", pp, resolved, props),
            "found_in": found_in,
            "properties": props,
        }

    edges = set()
    for d in bom.get("dependencies") or []:
        src = d.get("ref")
        for dst in d.get("dependsOn") or []:
            if src and dst and src != dst:
                edges.add((src, dst))
    # Drop edges pointing at refs we don't know (keeps the graph consistent).
    known = set(components) | set(projects)
    edges = {(a, b) for a, b in edges if a in known and b in known}

    # cdxgen records the root project's direct deps on the repo root itself. Give them
    # their own project node (e.g. "package.json") so they sit beside frontend/, Dockerfiles...
    root_direct = {b for a, b in edges if a == root_ref and b in components}
    if root_direct:
        rp = _props(meta_comp)
        src = rp.get("internal:SrcFile") or rp.get("SrcFile")
        if isinstance(src, list):
            src = src[0]
        if src and src.startswith("/app/"):
            src = src[5:]
        eco = P.parse(meta_comp.get("purl", "")).get("type") or \
            next(iter(components[c]["ecosystem_key"] for c in root_direct))
        manifest = {"npm": "package.json", "maven": "pom.xml", "pypi": "requirements / pyproject",
                    "golang": "go.mod"}.get(eco, f"{eco} manifest")
        pid = f"{root_ref}#root-manifest"
        projects[pid] = {"id": pid, "name": meta_comp.get("name"), "version": meta_comp.get("version"),
                         "is_repo_root": False, "ecosystem": eco,
                         "source_file": src or f"{manifest} (repository root)",
                         "method": "cdxgen", "complete": True, "notes": []}
        edges = {(pid if a == root_ref and b in root_direct else a, b) for a, b in edges}
        edges.add((root_ref, pid))
    return {"root": root_ref, "projects": projects, "components": components, "edges": edges}
