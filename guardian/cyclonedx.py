"""Write a CycloneDX 1.6 SBOM from built-in inventories."""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

from . import __version__
from .inventory import ROOT, Inventory

TYPE_BY_ECOSYSTEM = {"docker": "container", "githubactions": "application"}


def _hash(integrity: str | None) -> list[dict]:
    """npm/pip integrity strings -> CycloneDX hashes (hex)."""
    if not integrity:
        return []
    out = []
    for item in integrity.split():
        algo, _, val = item.partition("-")
        if not val and ":" in item:                       # sha256:abcd... (pip, docker digests)
            algo, _, val = item.partition(":")
            if all(c in "0123456789abcdef" for c in val.lower()):
                out.append({"alg": algo.upper().replace("SHA", "SHA-"), "content": val.lower()})
            continue
        try:
            hexval = base64.b64decode(val, validate=True).hex()
        except Exception:
            continue
        alg = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}.get(algo)
        if alg:
            out.append({"alg": alg, "content": hexval})
    return out


def build_bom(invs: list[Inventory], repo: dict) -> dict:
    root_ref = f"repo:{repo['name']}"
    projects, components, deps = [], {}, {}

    for inv in invs:
        pref = f"project:{inv.ecosystem}:{inv.source_file}"
        props = [{"name": "guardian:sourceFile", "value": inv.source_file},
                 {"name": "guardian:ecosystem", "value": inv.ecosystem},
                 {"name": "guardian:method", "value": inv.method},
                 {"name": "guardian:complete", "value": str(inv.complete).lower()}]
        props += [{"name": "guardian:note", "value": n} for n in inv.notes]
        projects.append({"type": "application", "bom-ref": pref, "name": inv.project_name,
                         **({"version": inv.project_version} if inv.project_version else {}),
                         "properties": props})
        deps.setdefault(pref, set())
        for pkg in inv.packages.values():
            c = components.get(pkg.purl)
            if c is None:
                c = {"type": TYPE_BY_ECOSYSTEM.get(inv.ecosystem, "library"), "bom-ref": pkg.purl,
                     "name": pkg.name, "purl": pkg.purl, "scope": pkg.scope, "properties": [],
                     "evidence": {"occurrences": []}}
                if pkg.version:
                    c["version"] = pkg.version
                if h := _hash(pkg.integrity):
                    c["hashes"] = h
                elif pkg.integrity:
                    c["properties"].append({"name": "guardian:integrity", "value": pkg.integrity})
                if pkg.resolved_url:
                    c["externalReferences"] = [{"type": "distribution", "url": pkg.resolved_url}]
                if pkg.license:
                    c["licenses"] = [{"expression": pkg.license}]
                components[pkg.purl] = c
            elif pkg.scope == "required":
                c["scope"] = "required"
            existing = {(p["name"], p["value"]) for p in c["properties"]}
            for k, v in pkg.properties.items():
                if (k, v) not in existing:
                    c["properties"].append({"name": k, "value": v})
            loc = {"location": inv.source_file}
            if loc not in c["evidence"]["occurrences"]:
                c["evidence"]["occurrences"].append(loc)
            deps.setdefault(pkg.purl, set())
        for parent, child in inv.edges:
            deps.setdefault(pref if parent == ROOT else parent, set()).add(child)

    dependencies = [{"ref": root_ref, "dependsOn": [p["bom-ref"] for p in projects]}]
    dependencies += [{"ref": ref, "dependsOn": sorted(children)} for ref, children in deps.items()]
    for c in components.values():
        if not c["properties"]:
            del c["properties"]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "supply-chain-guardian",
                                      "version": __version__}]},
            "component": {"type": "application", "bom-ref": root_ref, "name": repo["name"],
                          "version": repo.get("commit") or "unknown",
                          **({"purl": repo["purl"]} if repo.get("purl") else {}),
                          "components": projects},
        },
        "components": list(components.values()),
        "dependencies": dependencies,
    }
