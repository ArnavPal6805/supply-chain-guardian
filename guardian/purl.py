"""Minimal Package URL (purl) helpers.

purl is the universal identifier used by OSV, cdxgen, Syft, Grype, etc.
Keeping every component keyed by purl is what lets later steps
(vulnerability lookup, remediation) stay ecosystem-agnostic.
Spec: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

# purl type -> human ecosystem name
ECOSYSTEMS = {
    "npm": "npm",
    "maven": "Maven",
    "pypi": "PyPI",
    "golang": "Go",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
    "docker": "Container image",
    "oci": "Container image",
    "githubactions": "GitHub Actions",
    "github": "GitHub",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "RPM",
    "generic": "Generic",
}


def _q(s: str) -> str:
    return quote(s, safe="")


def build(ptype: str, name: str, version: str | None = None, namespace: str | None = None,
          qualifiers: dict | None = None) -> str:
    ptype = ptype.lower()
    if ptype == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    parts = [f"pkg:{ptype}/"]
    if namespace:
        parts.append("/".join(_q(seg) for seg in namespace.split("/")) + "/")
    parts.append(_q(name))
    if version:
        parts.append("@" + _q(version))
    if qualifiers:
        parts.append("?" + "&".join(f"{k}={_q(str(v))}" for k, v in sorted(qualifiers.items()) if v))
    return "".join(parts)


def npm(name: str, version: str | None) -> str:
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        return build("npm", pkg, version, namespace=scope)
    return build("npm", name, version)


def maven(group: str, artifact: str, version: str | None, ptype: str | None = None) -> str:
    q = {"type": ptype} if ptype and ptype != "jar" else None
    return build("maven", artifact, version, namespace=group, qualifiers=q)


def pypi(name: str, version: str | None) -> str:
    return build("pypi", name, version)


def golang(module: str, version: str | None) -> str:
    if "/" in module:
        ns, name = module.rsplit("/", 1)
        return build("golang", name, version, namespace=ns)
    return build("golang", module, version)


def parse(purl: str) -> dict:
    """Very small purl parser: returns type, namespace, name, version."""
    out = {"type": None, "namespace": None, "name": None, "version": None}
    if not purl or not purl.startswith("pkg:"):
        return out
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "@" in body:
        # version separator is the LAST '@' after the last '/'
        head, _, tail = body.rpartition("/")
        if "@" in tail:
            tail, ver = tail.split("@", 1)
            out["version"] = unquote(ver)
            body = f"{head}/{tail}" if head else tail
    segs = body.split("/")
    out["type"] = segs[0].lower()
    if len(segs) > 2:
        out["namespace"] = "/".join(unquote(s) for s in segs[1:-1])
    out["name"] = unquote(segs[-1]) if len(segs) > 1 else None
    return out


def ecosystem_of(purl: str | None) -> str:
    t = parse(purl or "").get("type")
    return ECOSYSTEMS.get(t or "", t or "unknown")


def display_name(purl: str) -> str:
    p = parse(purl)
    if p["type"] == "maven" and p["namespace"]:
        return f'{p["namespace"]}:{p["name"]}'
    if p["type"] == "npm" and p["namespace"]:
        return f'{p["namespace"]}/{p["name"]}'
    if p["namespace"]:
        return f'{p["namespace"]}/{p["name"]}'
    return p["name"] or purl
