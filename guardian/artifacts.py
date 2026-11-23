"""Container images (Dockerfile, compose) and CI/CD components (GitHub Actions).

These are supply-chain components too: a base image or a third-party Action
runs inside your build. We record *facts* here (where it comes from, how it
is pinned); judging which facts are risky is Step 4's job.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from . import purl as P
from .inventory import ROOT, Inventory, Pkg

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG_RE = re.compile(r"^v?\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]+)?$")
FIRST_PARTY_OWNERS = {"actions", "github"}


# ---------------------------------------------------------------- images

def parse_image_ref(ref: str) -> dict:
    """Split 'registry/ns/name:tag@sha256:..' into parts (Docker reference grammar)."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, path = parts[0], "/".join(parts[1:])
    else:
        registry, path = "docker.io", ref
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    return {"registry": registry, "repository": path, "tag": tag, "digest": digest}


def image_facts(ref: str) -> dict:
    p = parse_image_ref(ref)
    unresolved = "$" in ref
    effective_tag = p["tag"] or (None if p["digest"] else "latest")
    return {
        **p,
        "reference": ref,
        "pinned_by_digest": bool(p["digest"]),
        "uses_latest": (effective_tag == "latest") and not p["digest"],
        "implicit_tag": p["tag"] is None and not p["digest"],
        "unresolved_variable": unresolved,
        "official_docker_library": p["registry"] == "docker.io" and p["repository"].startswith("library/"),
    }


def image_purl(f: dict) -> str:
    ns, _, name = f["repository"].rpartition("/")
    q = {}
    if f["registry"] != "docker.io":
        q["repository_url"] = f["registry"]
    if f["tag"]:
        q["tag"] = f["tag"]
    version = f["digest"] or f["tag"] or "latest"
    return P.build("docker", name, version, namespace=ns or None, qualifiers=q or None)


def _logical_lines(text: str) -> list[str]:
    out, buf = [], ""
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append(buf + s)
        buf = ""
    if buf:
        out.append(buf)
    return out


def parse_dockerfile(path: Path, repo_root: Path) -> dict:
    rel = str(path.relative_to(repo_root))
    args: dict[str, str] = {}
    stages: list[str] = []
    images: list[dict] = []
    observations: list[dict] = []
    for line in _logical_lines(path.read_text(encoding="utf-8", errors="replace")):
        instr, _, rest = line.partition(" ")
        instr = instr.upper()
        if instr == "ARG":
            k, _, v = rest.strip().partition("=")
            if v:
                args[k.strip()] = v.strip().strip('"')
        elif instr == "FROM":
            toks = [t for t in rest.split() if not t.startswith("--")]
            if not toks:
                continue
            raw_ref = toks[0]
            ref = re.sub(r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1), m.group(0)), raw_ref)
            alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
            if ref in stages or ref == "scratch":
                images.append({"reference": ref, "internal_stage": True, "stage_alias": alias})
            else:
                f = image_facts(ref)
                f.update({"stage_alias": alias, "stage_index": len(stages), "internal_stage": False})
                images.append(f)
            stages.append(alias or f"__stage{len(stages)}")
        elif instr == "ADD" and re.search(r"https?://", rest):
            observations.append({"type": "remote_add", "detail": line[:200]})
        elif instr == "RUN" and re.search(r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh", rest):
            observations.append({"type": "pipe_to_shell", "detail": line[:200]})
        elif instr == "USER":
            observations.append({"type": "user", "detail": rest.strip()})
    final_stage = next((i for i in reversed(images) if not i.get("internal_stage")), None)
    return {"file": rel, "images": images, "observations": observations,
            "stages": len(stages), "final_base_image": final_stage["reference"] if final_stage else None}


def parse_compose(path: Path, repo_root: Path) -> dict:
    rel = str(path.relative_to(repo_root))
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        return {"file": rel, "images": [], "error": str(e)}
    images = []
    for svc, cfg in ((data.get("services") or {}) if isinstance(data, dict) else {}).items():
        if isinstance(cfg, dict) and cfg.get("image"):
            f = image_facts(str(cfg["image"]))
            f["service"] = svc
            f["built_locally"] = "build" in cfg
            images.append(f)
    return {"file": rel, "images": images}


# ---------------------------------------------------------------- GitHub Actions

def classify_ref(ref: str) -> str:
    if SHA_RE.match(ref):
        return "commit-sha"
    if SEMVER_TAG_RE.match(ref):
        return "tag"
    return "branch-or-other"


def parse_workflow(path: Path, repo_root: Path) -> dict:
    rel = str(path.relative_to(repo_root))
    text = path.read_text(encoding="utf-8", errors="replace")
    uses, images = [], []
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.search(r"""\buses:\s*['"]?([^'"\s#]+)['"]?\s*(#\s*(\S+))?""", raw)
        if m:
            target, comment = m.group(1), m.group(3)
            entry = {"line": i, "uses": target, "version_comment": comment}
            if target.startswith("./"):
                entry.update(kind="local-action", pin="n/a (in repo)")
            elif target.startswith("docker://"):
                f = image_facts(target[len("docker://"):])
                entry.update(kind="docker-action", image=f,
                             pin="digest" if f["pinned_by_digest"] else "tag")
            else:
                spec, _, ref = target.partition("@")
                segs = spec.split("/")
                owner, repo = segs[0], segs[1] if len(segs) > 1 else ""
                kind = "reusable-workflow" if "/.github/workflows/" in spec else "action"
                entry.update(kind=kind, owner=owner, repo=repo, path="/".join(segs[2:]) or None,
                             ref=ref or None, pin=classify_ref(ref) if ref else "none",
                             first_party=owner.lower() in FIRST_PARTY_OWNERS)
            uses.append(entry)
        m = re.search(r"""^\s*image:\s*['"]?([^'"\s#]+)""", raw)
        if m and "${{" not in m.group(1):
            f = image_facts(m.group(1))
            f["line"] = i
            images.append(f)
    try:
        data = yaml.safe_load(text) or {}
        perms = data.get("permissions") if isinstance(data, dict) else None
        triggers = data.get(True) or data.get("on") if isinstance(data, dict) else None
    except yaml.YAMLError:
        perms, triggers = None, None
    if isinstance(triggers, dict):
        triggers = list(triggers.keys())
    elif isinstance(triggers, str):
        triggers = [triggers]
    return {"file": rel, "uses": uses, "images": images,
            "top_level_permissions": perms, "triggers": triggers}


# ---------------------------------------------------------------- to inventory

def build_inventories(dockerfiles: list[dict], composes: list[dict], workflows: list[dict]) -> list[Inventory]:
    invs = []
    for d in dockerfiles + composes:
        inv = Inventory(ecosystem="docker", source_file=d["file"], project_name=d["file"],
                        method="Dockerfile" if d in dockerfiles else "compose file")
        for f in d.get("images", []):
            if f.get("internal_stage") or f.get("unresolved_variable"):
                continue
            purl = image_purl(f)
            inv.add(Pkg(purl=purl, name=f"{f['registry']}/{f['repository']}", version=f["digest"] or f["tag"] or "latest",
                        resolved_url=f"{f['registry']}/{f['repository']}",
                        integrity=f["digest"],
                        properties={"image:reference": f["reference"],
                                    "image:pinnedByDigest": str(f["pinned_by_digest"]).lower(),
                                    "image:usesLatest": str(f["uses_latest"]).lower()}))
            inv.link(ROOT, purl)
        if inv.packages:
            invs.append(inv)
    for w in workflows:
        inv = Inventory(ecosystem="githubactions", source_file=w["file"], project_name=w["file"],
                        method="GitHub Actions workflow")
        for u in w["uses"]:
            if u["kind"] in ("action", "reusable-workflow") and u.get("ref"):
                ns = u["owner"]
                name = u["repo"]
                purl = P.build("githubactions", name, u["ref"], namespace=ns)
                if u.get("path"):
                    purl += "#" + u["path"]
                inv.add(Pkg(purl=purl, name=f"{u['owner']}/{u['repo']}" + (f"/{u['path']}" if u.get("path") else ""),
                            version=u["ref"],
                            resolved_url=f"https://github.com/{u['owner']}/{u['repo']}",
                            integrity=u["ref"] if u["pin"] == "commit-sha" else None,
                            properties={"actions:pin": u["pin"],
                                        "actions:firstParty": str(u["first_party"]).lower(),
                                        **({"actions:versionComment": u["version_comment"]}
                                           if u.get("version_comment") else {})}))
                inv.link(ROOT, purl)
            elif u["kind"] == "docker-action":
                f = u["image"]
                purl = image_purl(f)
                inv.add(Pkg(purl=purl, name=f"{f['registry']}/{f['repository']}",
                            version=f["digest"] or f["tag"] or "latest", integrity=f["digest"]))
                inv.link(ROOT, purl)
        for f in w["images"]:
            purl = image_purl(f)
            inv.add(Pkg(purl=purl, name=f"{f['registry']}/{f['repository']}",
                        version=f["digest"] or f["tag"] or "latest", integrity=f["digest"],
                        properties={"image:reference": f["reference"]}))
            inv.link(ROOT, purl)
        if inv.packages:
            invs.append(inv)
    return invs
