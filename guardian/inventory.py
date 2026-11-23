"""Intermediate representation produced by the built-in parsers.

Each manifest/lockfile ("project") becomes one Inventory. The pipeline then
turns all inventories into a single CycloneDX SBOM, so the built-in path and
the cdxgen path end up in the *same* format and go through the same
normalizer. That is what keeps everything downstream ecosystem-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ROOT = "__project_root__"  # placeholder parent for direct dependencies


@dataclass
class Pkg:
    purl: str
    name: str
    version: str | None
    scope: str = "required"            # CycloneDX scope: required | optional | excluded
    resolved_url: str | None = None    # where the package manager downloaded it from
    integrity: str | None = None       # e.g. sha512-... from lockfile
    license: str | None = None
    properties: dict = field(default_factory=dict)  # extra facts (dev, install scripts, ...)


@dataclass
class Inventory:
    ecosystem: str                     # npm | maven | pypi | golang | ...
    source_file: str                   # path of manifest/lockfile, relative to repo root
    project_name: str
    project_version: str | None = None
    method: str = ""                   # how it was resolved (lockfile, mvn tree, manifest-only...)
    complete: bool = True              # False when transitive deps could not be resolved
    notes: list[str] = field(default_factory=list)
    packages: dict[str, Pkg] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)  # (parent purl | ROOT, child purl)
    edge_specs: dict[tuple[str, str], str] = field(default_factory=dict)  # declared range per edge
    edge_specs: dict[tuple[str, str], str] = field(default_factory=dict)  # declared range per edge

    def add(self, pkg: Pkg) -> Pkg:
        existing = self.packages.get(pkg.purl)
        if existing is None:
            self.packages[pkg.purl] = pkg
            return pkg
        # Same package reachable as dev and prod -> it's required.
        if pkg.scope == "required":
            existing.scope = "required"
        existing.resolved_url = existing.resolved_url or pkg.resolved_url
        existing.integrity = existing.integrity or pkg.integrity
        for k, v in pkg.properties.items():
            existing.properties.setdefault(k, v)
        return existing

    def link(self, parent: str, child: str, spec: str | None = None) -> None:
        if parent != child:
            self.edges.add((parent, child))
            if spec is not None:
                self.edge_specs.setdefault((parent, child), str(spec))
