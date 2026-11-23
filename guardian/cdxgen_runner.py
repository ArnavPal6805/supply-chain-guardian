"""Run OWASP cdxgen (local CLI or Docker image) to produce a CycloneDX SBOM.

Safety: we always pass --no-install-deps so cdxgen never runs `npm install`,
`pip install`, etc. on an untrusted repo (installs can execute package
scripts). When using Docker the repo is mounted read-only except for one
output directory.

Speed: --no-babel skips cdxgen's JavaScript/TypeScript usage analysis, which is
slow on large JS repos and not needed for Day 1. Output is streamed to the log
so the UI shows progress, and a timeout falls back to the built-in engine.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

# v13 moved images from ghcr.io/cyclonedx/* to ghcr.io/cdxgen/*. Pin minor version.
DEFAULT_IMAGE = os.environ.get("GUARDIAN_CDXGEN_IMAGE", "ghcr.io/cdxgen/cdxgen:v13.8")
TIMEOUT = int(os.environ.get("GUARDIAN_CDXGEN_TIMEOUT", "600"))   # seconds
BASE_ARGS = ["--no-install-deps", "--no-babel", "--spec-version", "1.6", "--no-validate"]


def docker_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        return subprocess.run([docker, "info"], capture_output=True, timeout=15).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def available() -> str | None:
    """Return 'cli', 'docker', or None."""
    if shutil.which("cdxgen"):
        return "cli"
    if docker_available():
        return "docker"
    return None


def _stream(cmd: list[str], log, timeout: int, prefix: str, env: dict | None = None) -> int | None:
    """Run cmd, forward each output line to log, kill it after `timeout` seconds.
    Returns the exit code, or None on timeout."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            errors="replace", env=env)
    last = {"t": time.time()}

    def pump():
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(f"  {prefix}: {line[:300]}")
                last["t"] = time.time()

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    start = time.time()
    while proc.poll() is None:
        time.sleep(1)
        if time.time() - start > timeout:
            proc.kill()
            log(f"  {prefix}: timed out after {timeout}s (set GUARDIAN_CDXGEN_TIMEOUT to change)")
            return None
        if time.time() - last["t"] > 30:
            log(f"  {prefix}: still running ({int(time.time() - start)}s)…")
            last["t"] = time.time()
    reader.join(timeout=5)
    return proc.returncode


def _ensure_image(log) -> bool:
    r = subprocess.run(["docker", "image", "inspect", DEFAULT_IMAGE], capture_output=True)
    if r.returncode == 0:
        return True
    log(f"Pulling {DEFAULT_IMAGE} (first run only; the image is large, this can take several minutes)")
    code = _stream(["docker", "pull", DEFAULT_IMAGE], log, timeout=1800, prefix="docker pull")
    return code == 0


def run(repo_dir: Path, out_dir: Path, log=print, timeout: int = TIMEOUT, mode: str | None = None) -> dict | None:
    mode = mode or available()
    if mode is None:
        log("cdxgen not available (no `cdxgen` on PATH and no running Docker daemon)")
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "bom.cdxgen.json"
    env = {**os.environ, "FETCH_LICENSE": "false", "CDXGEN_TIMEOUT_MS": str(timeout * 1000)}
    if mode == "cli":
        cmd = ["cdxgen", "-r", str(repo_dir), "-o", str(out_file), *BASE_ARGS]
    else:
        if not _ensure_image(log):
            log("Could not pull the cdxgen image")
            return None
        cmd = ["docker", "run", "--rm",
               "-v", f"{repo_dir.resolve()}:/app:ro",
               "-v", f"{out_dir.resolve()}:/out:rw",
               "-e", "FETCH_LICENSE=false",
               "-e", f"CDXGEN_TIMEOUT_MS={timeout * 1000}",
               DEFAULT_IMAGE, "-r", "/app", "-o", "/out/bom.cdxgen.json", *BASE_ARGS]
    log("$ " + " ".join(cmd))
    code = _stream(cmd, log, timeout=timeout, prefix="cdxgen", env=env)
    if code is None:
        return None
    if not out_file.exists():
        log(f"cdxgen produced no SBOM (exit {code})")
        return None
    try:
        bom = json.loads(out_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        log(f"cdxgen output is not valid JSON: {e}")
        return None
    if not bom.get("components"):
        log("cdxgen SBOM has no components")
        return None
    return bom
