"""Fetch a public GitHub repository (or use a local path) safely."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)"
    r"(?:\.git)?(?:/(?:tree|commit)/(?P<ref>[^?#]+))?/?(?:[?#].*)?$"
)


class CloneError(Exception):
    pass


def parse_github_url(url: str) -> dict:
    m = GITHUB_RE.match(url.strip())
    if not m:
        raise CloneError("Please enter a GitHub repository URL like https://github.com/owner/repo")
    d = m.groupdict()
    d["url"] = f"https://github.com/{d['owner']}/{d['repo']}.git"
    d["name"] = f"{d['owner']}/{d['repo']}"
    return d


def _git(args: list[str], cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
           "GIT_ASKPASS": "true"}
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=env)


def fetch(source: str, dest: Path, log=print) -> dict:
    """Clone a GitHub URL into dest, or copy-free use of a local directory.

    Returns repo info: name, url, commit, ref, purl, path.
    """
    local = Path(source).expanduser()
    if local.is_dir():
        commit = None
        r = _git(["rev-parse", "HEAD"], cwd=local)
        if r.returncode == 0:
            commit = r.stdout.strip()
        log(f"Using local directory {local}")
        return {"name": local.resolve().name, "url": str(local.resolve()), "commit": commit,
                "ref": None, "purl": None, "path": str(local.resolve()), "local": True}

    info = parse_github_url(source)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--depth", "1", "--no-tags", "--single-branch",
            "-c", "core.symlinks=false", "-c", "protocol.file.allow=never"]
    ref = info.get("ref")
    if ref:
        args += ["--branch", ref]
    args += [info["url"], str(dest)]
    log(f"$ git {' '.join(args)}")
    r = _git(args)
    if r.returncode != 0 and ref:
        # ref may be a commit SHA or a branch name containing '/'; fall back to full fetch of that ref
        log("Branch clone failed, retrying with fetch of the exact ref")
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        for a in (["init", "-q"], ["remote", "add", "origin", info["url"]],
                  ["fetch", "--depth", "1", "origin", ref], ["checkout", "-q", "FETCH_HEAD"]):
            r = _git(a, cwd=dest)
            if r.returncode != 0:
                break
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()[-1:] or ["unknown error"]
        raise CloneError(f"git clone failed: {msg[0]} (is the repository public?)")
    commit = _git(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
    log(f"Cloned {info['name']} at {commit[:12]}")
    return {"name": info["name"], "url": info["url"].removesuffix(".git"), "commit": commit,
            "ref": ref, "purl": f"pkg:github/{info['owner']}/{info['repo']}@{commit}",
            "path": str(dest), "local": False}
