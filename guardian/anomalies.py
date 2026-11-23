"""Step 4: supply-chain anomalies (things with no CVE that still deserve a look).

Every detector is deterministic and records *evidence*: the file, the line and
the exact value it saw. Severity here is the detector's base level; Step 5
adjusts it with context (runtime vs dev, test-only files...).

With a baseline (a previous scan's result.json), it also reports what CHANGED:
unexpected new dependencies, version changes, and lockfile entries whose
integrity hash or download URL changed for the same version.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

from .popular import KNOWN_LEGIT, POPULAR
from .versions import cmp

DEFAULT_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
                 "repo.maven.apache.org", "repo1.maven.org", "proxy.golang.org", "github.com",
                 "docker.io", "api.nuget.org", "crates.io", "rubygems.org", "local path"}
TEST_HINT = re.compile(r"(^|/)(test|tests|e2e|spec|cypress|smoke|fixtures?)(/|$)|\.test\.|docker-compose\.test", re.I)


def _osa(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance (insert, delete, substitute, adjacent swap)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _npm_weekly_downloads(name: str) -> int | None:
    """Weekly downloads from the npm API, or None when offline."""
    if os.environ.get("GUARDIAN_OFFLINE", "").lower() in ("1", "true", "yes"):
        return None
    try:
        req = urllib.request.Request(f"https://api.npmjs.org/downloads/point/last-week/{name}",
                                     headers={"User-Agent": "supply-chain-guardian"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return int(json.loads(r.read().decode()).get("downloads", 0))
    except Exception:  # noqa: BLE001
        return None


class Ctx:
    def __init__(self, repo: Path):
        self.repo = repo
        self._cache: dict[str, list[str]] = {}

    def lines(self, rel: str | None) -> list[str]:
        if not rel:
            return []
        if rel not in self._cache:
            try:
                self._cache[rel] = (self.repo / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._cache[rel] = []
        return self._cache[rel]

    def find(self, rel: str | None, needle: str) -> tuple[int | None, str | None]:
        for i, line in enumerate(self.lines(rel), 1):
            if needle in line:
                return i, line.strip()[:240]
        return None, None


def _finding(kind, title, severity, explanation, recommendation, evidence, component=None,
             file=None, line=None, project_file=None, subject=None, confidence="high"):
    return {"type": "anomaly", "kind": kind, "title": title, "severity": severity,
            "explanation": explanation, "recommendation": recommendation, "evidence": evidence,
            "component_id": component["id"] if component else None,
            "subject": subject or (f'{component["name"]}@{component["version"]}' if component else file),
            "file": file, "line": line, "project_file": project_file, "confidence": confidence}


def _lockfile_of(c: dict, projects: dict) -> str | None:
    for f in c.get("found_in") or []:
        if f.endswith(("package-lock.json", "npm-shrinkwrap.json", ".lock", "requirements.txt", "go.mod")):
            return f
    for pid in c.get("projects") or []:
        sf = projects.get(pid, {}).get("source_file")
        if sf:
            return sf
    return (c.get("found_in") or [None])[0]


def detect(model: dict, containers: dict, ci: dict, detection: dict, generated: list[str],
           repo: Path, edge_specs: dict | None = None) -> list[dict]:
    comps, projects = model["components"], model["projects"]
    ctx = Ctx(repo)
    out: list[dict] = []

    typo_seen: set[str] = set()
    for c in comps.values():
        eco = c["ecosystem_key"]
        props = c.get("properties") or {}
        lock = _lockfile_of(c, projects)

        # 1. typosquatting: one edit away from a popular name, not popular itself.
        #    Only DIRECT dependencies: a typo happens where a human typed the name.
        pop = POPULAR.get(eco)
        if pop and c["direct"] and len(c["name"]) >= 5 and c["name"] not in pop \
                and c["name"] not in KNOWN_LEGIT.get(eco, set()) and c["name"] not in typo_seen:
            norm = c["name"].lower()
            near = [p for p in pop if len(p) >= 5 and p != norm and _osa(norm, p, 1) <= 1]
            if eco == "npm":
                near += [p for p in pop if p.replace("-", "") == norm.replace("-", "").replace("_", "")
                         and p != norm and p not in near]
            weekly = _npm_weekly_downloads(c["name"]) if near and eco == "npm" else None
            if near and weekly is not None and weekly >= 50_000:
                near = []          # widely used package: not a typosquat
            if near:
                typo_seen.add(c["name"])
                line, text = ctx.find(lock, f'/{c["name"]}"') if eco == "npm" else ctx.find(lock, c["name"])
                has_script = "true" in (props.get("npm:hasInstallScript"), props.get("cdx:npm:hasInstallScript"))
                out.append(_finding(
                    "typosquat", f'Possible typosquat: {c["name"]} looks like {near[0]}',
                    "high" if has_script else "medium",
                    f'"{c["name"]}" is one edit away from the popular package "{near[0]}" but is not that package.'
                    + (" It also runs an install script." if has_script else ""),
                    f'Confirm {c["name"]} is intended. If it was meant to be {near[0]}, replace it and audit '
                    f'what it ran during install.',
                    [{"label": "package", "value": f'{c["name"]}@{c["version"]}'},
                     {"label": "similar to", "value": ", ".join(near[:3])},
                     {"label": "weekly downloads", "value": f"{weekly:,}" if weekly is not None else "not checked (offline)"},
                     {"label": "dependency path", "value": " → ".join(comps[x]["name"] for x in c["path"] if x in comps)},
                     *([{"label": "install script", "value": "yes"}] if has_script else [])],
                    component=c, file=lock, line=line, confidence="medium"))

        # 2. install scripts (code that runs on `npm install`)
        if "true" in (props.get("npm:hasInstallScript"), props.get("cdx:npm:hasInstallScript")):
            line, text = ctx.find(lock, f'node_modules/{c["name"]}"')
            out.append(_finding(
                "install-script", f'{c["name"]}@{c["version"]} runs an install script', "medium" if not c["dev_only"] else "low",
                f'{c["name"]}@{c["version"]} declares a preinstall/install/postinstall script, so installing it '
                f'executes its code on the developer machine and CI runner.',
                "Check the script is a normal native build (e.g. node-gyp); install with --ignore-scripts where "
                "possible and allow-list packages that need scripts.",
                [{"label": "lockfile flag", "value": "hasInstallScript: true"},
                 {"label": "scope", "value": "dev / test only" if c["dev_only"] else "runtime"},
                 {"label": "dependency path", "value": " → ".join(comps[x]["name"] for x in c["path"] if x in comps)}],
                component=c, file=lock, line=line))

        # 3. unexpected registry / non-registry source
        origin = c.get("origin") or {}
        url = origin.get("url") or ""
        if origin.get("source") == "lockfile/SBOM" and eco in ("npm", "pypi"):
            if url.startswith(("git+", "git:", "github:", "ssh:")) or ".git#" in url:
                out.append(_finding(
                    "git-dependency", f'{c["name"]}@{c["version"]} is installed from a git URL', "medium",
                    "Git dependencies bypass the registry: no immutable published version and no registry malware scanning.",
                    "Depend on a published registry version, or pin the exact commit SHA.",
                    [{"label": "resolved", "value": url}], component=c, file=lock,
                    line=ctx.find(lock, url[:60])[0]))
            elif origin.get("host") not in DEFAULT_HOSTS:
                out.append(_finding(
                    "unexpected-registry", f'{c["name"]}@{c["version"]} comes from {origin.get("host")}', "high",
                    f'Every other {c["ecosystem"]} package comes from the default registry; this one was downloaded '
                    f'from {origin.get("host")}. That is how dependency-confusion and hijacked-mirror attacks look.',
                    "Confirm the host is your organization's registry; otherwise treat as compromised.",
                    [{"label": "resolved", "value": url}], component=c, file=lock,
                    line=ctx.find(lock, url[:60])[0]))

        # 4. missing integrity hash on a locked registry package
        if eco == "npm" and origin.get("source") == "lockfile/SBOM" and origin.get("host") in DEFAULT_HOSTS \
                and origin.get("host") != "local path" and not c.get("hashes") and not props.get("guardian:integrity"):
            out.append(_finding(
                "missing-integrity", f'{c["name"]}@{c["version"]} has no integrity hash in the lockfile', "medium",
                "Without an integrity hash, a tampered tarball cannot be detected at install time.",
                "Regenerate the lockfile so every entry carries an integrity hash.",
                [{"label": "resolved", "value": url}], component=c, file=lock,
                line=ctx.find(lock, f'node_modules/{c["name"]}"')[0]))
        # (known-malicious packages: OSV "MAL-" advisories from Step 3, raised to critical in evidence.py)

    # 6. wildcard / git specs in manifests
    for (parent, child), spec in (edge_specs or {}).items():
        if not parent.startswith("root::") or child not in comps:
            continue
        s = str(spec).strip()
        manifest = parent[6:]
        if s in ("*", "latest", "x", "") or s.startswith((">", ">=")) and "<" not in s:
            c = comps[child]
            pj = manifest if manifest.endswith("package.json") else None
            line, text = ctx.find(pj, f'"{c["name"]}"') if pj else (None, None)
            out.append(_finding(
                "unbounded-version", f'{c["name"]} is declared as "{s}"', "medium",
                f'The manifest accepts any future version of {c["name"]}, so a malicious new release would be '
                f'installed automatically on the next resolve.',
                "Declare a bounded range (e.g. ^x.y.z) and commit a lockfile.",
                [{"label": "declared", "value": f'"{c["name"]}": "{s}"'}], component=c,
                file=pj or manifest, line=line))

    # 7. no committed lockfile
    for rel in generated:
        pj = "package.json" if rel in (".", "") else f"{rel}/package.json"
        npmrc_line, npmrc_text = ctx.find(".npmrc" if rel in (".", "") else f"{rel}/.npmrc", "package-lock")
        if npmrc_line is None:
            npmrc_line, npmrc_text = ctx.find(".npmrc", "package-lock")
            npmrc_file = ".npmrc" if npmrc_line else None
        else:
            npmrc_file = ".npmrc" if rel in (".", "") else f"{rel}/.npmrc"
        ev = [{"label": "project", "value": pj}, {"label": "committed lockfile", "value": "none"}]
        if npmrc_text:
            ev.append({"label": npmrc_file, "value": npmrc_text})
        out.append(_finding(
            "no-lockfile", f"{pj} has no committed lockfile", "medium",
            "Every fresh install resolves version ranges again, so a newly published (possibly compromised) "
            "version can enter silently and builds are not reproducible.",
            "Commit package-lock.json and install with `npm ci`.",
            ev, file=npmrc_file or pj, line=npmrc_line, project_file=pj, subject=pj))

    # 8. container images
    for d in (containers.get("dockerfiles") or []) + (containers.get("compose") or []):
        is_compose = "service" in str(d.get("images", [{}])[0:1])
        finals = [i for i in d.get("images", []) if not i.get("internal_stage")]
        last = finals[-1] if finals and not is_compose else None
        for img in d.get("images", []):
            if img.get("internal_stage") or img.get("unresolved_variable"):
                continue
            needle = img["reference"].split("@")[0]
            line, text = ctx.find(d["file"], needle)
            testy = bool(TEST_HINT.search(d["file"]))
            runtime = img is last
            role = "runtime image" if runtime else ("test" if testy else "service image" if img.get("service") else "build stage")
            ev = [{"label": "reference", "value": img["reference"]},
                  {"label": "registry", "value": img["registry"]}, {"label": "role", "value": role}]
            if img.get("uses_latest"):
                sev = "low" if testy else ("high" if runtime else "medium")
                out.append(_finding(
                    "unpinned-image", f'{img["reference"]} resolves to :latest', sev,
                    ("No tag is given, so Docker pulls :latest. " if img.get("implicit_tag") else "")
                    + "A mutable tag can change underneath the build, including to a compromised image.",
                    "Pin a version tag plus digest (image:tag@sha256:…), and update it deliberately.",
                    ev, file=d["file"], line=line, subject=img["reference"]))
            elif not img.get("pinned_by_digest"):
                out.append(_finding(
                    "image-not-digest-pinned", f'{img["reference"]} is pinned by tag, not digest', "low",
                    "Tags can be moved to different image contents; only a digest is immutable.",
                    "Add @sha256:<digest> to the reference.", ev, file=d["file"], line=line,
                    subject=img["reference"]))
        for o in d.get("observations", []):
            if o["type"] in ("pipe_to_shell", "remote_add"):
                line, _ = ctx.find(d["file"], o["detail"][:40])
                out.append(_finding(
                    "remote-script", "Dockerfile downloads and runs remote code" if o["type"] == "pipe_to_shell"
                    else "Dockerfile adds a file from a URL", "medium",
                    "Content fetched at build time is not pinned or verified.",
                    "Download a pinned version and verify its checksum before use.",
                    [{"label": "instruction", "value": o["detail"]}], file=d["file"], line=line, subject=d["file"]))

    # 9. GitHub Actions pinning (one finding per action reference, listing every use) and risky triggers
    uses_by_ref: dict[str, list] = {}
    for w in ci.get("workflows") or []:
        for u in w.get("uses", []):
            if u.get("kind") in ("action", "reusable-workflow") and u.get("pin") != "commit-sha":
                uses_by_ref.setdefault(u["uses"], []).append((w["file"], u))
    for ref, locs in uses_by_ref.items():
        u = locs[0][1]
        pin, fp = u.get("pin"), u.get("first_party")
        sev = {"branch-or-other": "high", "none": "high"}.get(pin, "low" if fp else "medium")
        out.append(_finding(
            "unpinned-action", f'{ref} is pinned to a {"branch" if pin == "branch-or-other" else pin}'
            + (f" ({len(locs)} uses)" if len(locs) > 1 else ""), sev,
            ("A branch moves with every push: whoever controls that repository controls this workflow."
             if pin in ("branch-or-other", "none") else
             "A tag can be re-pointed to different code (as in the tj-actions/changed-files compromise).")
            + ("" if fp else " This action is published by a third party."),
            "Pin to the full commit SHA and keep the version in a comment (uses: owner/action@<sha> # vX.Y.Z).",
            [{"label": "uses", "value": ref}, {"label": "publisher", "value": "GitHub" if fp else u.get("owner")}]
            + [{"label": "used in", "value": f"{f}:{x.get('line')}"} for f, x in locs[:6]],
            file=locs[0][0], line=u.get("line"), subject=ref))
    for w in ci.get("workflows") or []:
        text = "\n".join(ctx.lines(w["file"]))
        triggers = w.get("triggers") or []
        if "pull_request_target" in triggers or "pull_request_target" in text:
            checks_out_head = re.search(r"github\.event\.pull_request\.head\.(sha|ref)|refs/pull/", text)
            line, ltext = ctx.find(w["file"], "pull_request_target")
            out.append(_finding(
                "risky-trigger", f'{w["file"].rsplit("/", 1)[-1]} runs on pull_request_target'
                + (" and checks out PR code" if checks_out_head else ""),
                "high" if checks_out_head else "medium",
                "pull_request_target runs with the base repository's secrets and write token. "
                + ("Checking out the PR's code and running it lets any outside contributor execute code with those secrets."
                   if checks_out_head else "It must never build or run code from the pull request."),
                "Use pull_request for untrusted code, or never check out / execute the PR head in this workflow.",
                [{"label": "trigger", "value": "pull_request_target"},
                 *([{"label": "checks out", "value": checks_out_head.group(0)}] if checks_out_head else [])],
                file=w["file"], line=line, subject=w["file"]))
        perms = w.get("top_level_permissions")
        if perms == "write-all":
            line, _ = ctx.find(w["file"], "write-all")
            out.append(_finding(
                "broad-permissions", f'{w["file"].rsplit("/", 1)[-1]} grants write-all permissions', "medium",
                "Every job gets a token that can write to the repository.",
                "Set permissions per job, read-only by default.",
                [{"label": "permissions", "value": "write-all"}], file=w["file"], line=line, subject=w["file"]))
    return out


# --------------------------------------------------------------------------- baseline diff

def diff(baseline: dict, model: dict, repo: Path) -> tuple[list[dict], dict]:
    """Compare this scan with a previous scan's result.json."""
    comps, projects = model["components"], model["projects"]
    ctx = Ctx(repo)
    old = {c["purl"]: c for c in baseline.get("components", []) if c.get("purl")}
    old_by_name: dict[tuple, list] = {}
    for c in old.values():
        old_by_name.setdefault((c["ecosystem_key"], c["name"]), []).append(c)
    out: list[dict] = []
    stats = {"added": 0, "removed": 0, "updated": 0, "integrity_changed": 0, "baseline_commit":
             (baseline.get("repository") or {}).get("commit")}

    def h(c):
        return sorted(c.get("hashes") or []) or ([c["properties"]["guardian:integrity"]]
                                                  if (c.get("properties") or {}).get("guardian:integrity") else [])

    for c in comps.values():
        if c["ecosystem_key"] in ("github",):
            continue
        lock = _lockfile_of(c, projects)
        path = " → ".join(comps[x]["name"] for x in c["path"] if x in comps)
        prev = old.get(c.get("purl"))
        if prev:
            ph, ch = h(prev), h(c)
            if ph and ch and ph != ch:
                stats["integrity_changed"] += 1
                out.append(_finding(
                    "integrity-changed", f'{c["name"]}@{c["version"]}: same version, different hash', "critical",
                    "The lockfile now records a different integrity hash for exactly the same package version. "
                    "Published versions are immutable, so this means the lockfile was edited or the artifact was replaced.",
                    "Do not install. Find the commit that changed the lockfile and restore the original hash.",
                    [{"label": "before", "value": ph[0][:90]}, {"label": "after", "value": ch[0][:90]}],
                    component=c, file=lock, line=ctx.find(lock, f'node_modules/{c["name"]}"')[0]))
            po, co = (prev.get("origin") or {}).get("url"), (c.get("origin") or {}).get("url")
            if po and co and po != co and (prev.get("origin") or {}).get("host") != (c.get("origin") or {}).get("host"):
                out.append(_finding(
                    "origin-changed", f'{c["name"]}@{c["version"]} now downloads from {c["origin"]["host"]}', "high",
                    "Same version, different download location.",
                    "Confirm the new host; revert the lockfile change if it is not expected.",
                    [{"label": "before", "value": po}, {"label": "after", "value": co}], component=c, file=lock))
            continue
        same_name = old_by_name.get((c["ecosystem_key"], c["name"]))
        if same_name:
            stats["updated"] += 1
            before = sorted({p["version"] for p in same_name if p.get("version")})
            down = all(cmp(c["version"] or "0", b) < 0 for b in before) if before else False
            new_script = "true" in ((c.get("properties") or {}).get("npm:hasInstallScript"),
                                    (c.get("properties") or {}).get("cdx:npm:hasInstallScript")) and not any(
                "true" in ((p.get("properties") or {}).get("npm:hasInstallScript"),
                           (p.get("properties") or {}).get("cdx:npm:hasInstallScript")) for p in same_name)
            if down or new_script:
                out.append(_finding(
                    "suspicious-update", f'{c["name"]} {", ".join(before)} → {c["version"]}'
                    + (" (downgrade)" if down else "") + (" now runs an install script" if new_script else ""),
                    "high" if new_script else "medium",
                    ("A downgrade can silently reintroduce fixed vulnerabilities. " if down else "")
                    + ("The new version added an install script, which is how many npm compromises execute." if new_script else ""),
                    "Review the change that introduced this version before merging.",
                    [{"label": "before", "value": ", ".join(before)}, {"label": "after", "value": c["version"]},
                     {"label": "dependency path", "value": path}], component=c, file=lock))
            continue
        stats["added"] += 1
        out.append(_finding(
            "new-dependency", f'New {"direct" if c["direct"] else "transitive"} dependency: {c["name"]}@{c["version"]}',
            "medium" if c["direct"] else "low",
            "This package was not in the baseline scan.", "Confirm the change that added it was intended.",
            [{"label": "dependency path", "value": path}, {"label": "origin", "value": (c.get("origin") or {}).get("host")}],
            component=c, file=lock, line=ctx.find(lock, f'/{c["name"]}"')[0], confidence="medium"))
    now = {c.get("purl") for c in comps.values()}
    now_names = {(c["ecosystem_key"], c["name"]) for c in comps.values()}
    stats["removed"] = sum(1 for p, c in old.items() if p not in now and (c["ecosystem_key"], c["name"]) not in now_names)
    return out, stats
