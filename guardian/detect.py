"""Walk a repository and find everything that describes its supply chain."""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__", "dist",
             "build", "target", ".gradle", ".idea", ".vscode", "bower_components", ".tox",
             ".mypy_cache", ".next", ".nuxt", "coverage", ".terraform"}

# Files the built-in engine can't parse yet; cdxgen usually can.
OTHER_ECOSYSTEMS = {
    "yarn.lock": "npm (yarn)", "pnpm-lock.yaml": "npm (pnpm)", "bun.lockb": "npm (bun)",
    "build.gradle": "Gradle", "build.gradle.kts": "Gradle", "gradle.lockfile": "Gradle",
    "Cargo.lock": "Rust", "Gemfile.lock": "Ruby", "composer.lock": "PHP",
    "packages.lock.json": ".NET", "*.csproj": ".NET", "Package.resolved": "Swift",
    "pubspec.lock": "Dart", "mix.lock": "Elixir", "conanfile.txt": "C/C++ (Conan)",
    "vcpkg.json": "C/C++ (vcpkg)",
}


@dataclass
class Detection:
    npm: list[Path] = field(default_factory=list)          # dirs containing package.json
    maven: list[Path] = field(default_factory=list)        # dirs with top-level pom.xml
    python: list[Path] = field(default_factory=list)       # lock/requirements files
    golang: list[Path] = field(default_factory=list)       # dirs containing go.mod
    dockerfiles: list[Path] = field(default_factory=list)
    compose: list[Path] = field(default_factory=list)
    workflows: list[Path] = field(default_factory=list)
    other: list[tuple[str, str]] = field(default_factory=list)  # (relpath, ecosystem)
    lockfiles_missing: list[str] = field(default_factory=list)   # npm dirs without lockfile

    def summary(self, root: Path) -> dict:
        rel = lambda p: str(p.relative_to(root)) or "."
        return {
            "npm_projects": [rel(p) for p in self.npm],
            "maven_projects": [rel(p) for p in self.maven],
            "python_files": [rel(p) for p in self.python],
            "go_modules": [rel(p) for p in self.golang],
            "dockerfiles": [rel(p) for p in self.dockerfiles],
            "compose_files": [rel(p) for p in self.compose],
            "workflows": [rel(p) for p in self.workflows],
            "other_ecosystems": [{"file": f, "ecosystem": e} for f, e in self.other],
            "npm_without_lockfile": self.lockfiles_missing,
        }


def detect(root: Path, max_files: int = 200_000) -> Detection:
    d = Detection()
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS and not x.startswith(".")
                             or x == ".github")
        here = Path(dirpath)
        names = set(filenames)
        seen += len(filenames)
        if seen > max_files:
            break
        rel_here = here.relative_to(root)

        if "package.json" in names:
            d.npm.append(here)
            if not ({"package-lock.json", "npm-shrinkwrap.json"} & names):
                if not ({"yarn.lock", "pnpm-lock.yaml"} & names):
                    d.lockfiles_missing.append(str(rel_here) or ".")
        if "pom.xml" in names and not any((p / "pom.xml").exists() for p in here.parents
                                          if root in p.parents or p == root):
            d.maven.append(here)
        if "go.mod" in names:
            d.golang.append(here)

        # Python: prefer a real lockfile over requirements files in the same dir.
        for lock in ("uv.lock", "poetry.lock", "Pipfile.lock"):
            if lock in names:
                d.python.append(here / lock)
                break
        else:
            for f in sorted(filenames):
                if fnmatch.fnmatch(f, "requirements*.txt") or fnmatch.fnmatch(f, "*-requirements.txt"):
                    d.python.append(here / f)

        for f in filenames:
            fl = f.lower()
            if fl == "dockerfile" or fl.startswith("dockerfile.") or fl.endswith(".dockerfile") \
                    or fl == "containerfile":
                d.dockerfiles.append(here / f)
            if fnmatch.fnmatch(fl, "docker-compose*.y*ml") or fnmatch.fnmatch(fl, "compose*.y*ml"):
                d.compose.append(here / f)
            for pat, eco in OTHER_ECOSYSTEMS.items():
                if fnmatch.fnmatch(f, pat):
                    d.other.append((str((here / f).relative_to(root)), eco))

        if rel_here.parts[-2:] == (".github", "workflows"):
            d.workflows += [here / f for f in sorted(filenames) if f.endswith((".yml", ".yaml"))]

    # npm workspaces: member packages are covered by the workspace root's lockfile.
    ws_roots = []
    for p in d.npm:
        try:
            if "workspaces" in json.loads((p / "package.json").read_text(encoding="utf-8")):
                ws_roots.append(p)
        except (OSError, ValueError):
            pass
    if ws_roots:
        members = [p for p in d.npm if any(r in p.parents for r in ws_roots)]
        d.npm = [p for p in d.npm if p not in members]
        member_rels = {str(p.relative_to(root)) for p in members}
        d.lockfiles_missing = [x for x in d.lockfiles_missing if x not in member_rels]
    return d
