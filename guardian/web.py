"""Web UI: paste a GitHub link, get the supply chain view.

Run:  python -m guardian.web   (then open http://127.0.0.1:5000)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, url_for

from .clone import CloneError, parse_github_url
from .pipeline import Options, Run, analyze

OUTPUT = Path(os.environ.get("GUARDIAN_OUTPUT", "output")).resolve() / "jobs"
MAX_PARALLEL = int(os.environ.get("GUARDIAN_MAX_PARALLEL", "2"))
DOWNLOADS = {"bom.cdx.json", "result.json", "graph.json", "log.txt", "vulns.json", "findings.json"}

app = Flask(__name__)
JOBS: dict[str, dict] = {}
_slots = threading.Semaphore(MAX_PARALLEL)


def _load_existing() -> None:
    if not OUTPUT.exists():
        return
    for d in OUTPUT.iterdir():
        meta = d / "job.json"
        if meta.exists():
            try:
                JOBS[d.name] = json.loads(meta.read_text())
                if JOBS[d.name]["status"] in ("queued", "running"):
                    JOBS[d.name]["status"] = "failed"
                    JOBS[d.name]["error"] = "Server restarted while this job was running"
            except (OSError, ValueError):
                pass


def _save(job_id: str) -> None:
    job = JOBS[job_id]
    (OUTPUT / job_id).mkdir(parents=True, exist_ok=True)
    (OUTPUT / job_id / "job.json").write_text(json.dumps({k: v for k, v in job.items() if k != "run"}))


def _worker(job_id: str, url: str, opts: Options) -> None:
    job = JOBS[job_id]
    run = Run(out_dir=OUTPUT / job_id)
    job["run"] = run
    with _slots:
        job["status"] = "running"
        _save(job_id)
        try:
            res = analyze(url, OUTPUT / job_id, opts, run)
            job.update(status="done", summary={k: res["stats"][k] for k in
                                               ("packages", "direct", "transitive", "container_images",
                                                "ci_components")}, engine=res["engine"])
            if res.get("vulnerabilities"):
                job["summary"]["vulns"] = res["vulnerabilities"]["summary"]["total"]
            fs = (res.get("findings") or {}).get("summary") or {}
            if fs:
                job["summary"]["findings"] = fs["total"]
                job["summary"]["critical"] = fs["by_level"]["critical"]
                job["summary"]["high"] = fs["by_level"]["high"]
                job["summary"]["anomalies"] = fs["anomalies"]
        except CloneError as e:
            job.update(status="failed", error=str(e))
        except Exception as e:  # noqa: BLE001 - surface anything to the UI
            run.log(f"ERROR: {type(e).__name__}: {e}")
            job.update(status="failed", error=f"{type(e).__name__}: {e}")
        finally:
            job["finished"] = time.time()
            job["log"] = run.log_lines[-400:]
            _save(job_id)


@app.get("/")
def index():
    jobs = sorted(JOBS.values(), key=lambda j: -j["created"])[:20]
    done = [j for j in jobs if j["status"] == "done"]
    return render_template("index.html", jobs=jobs, done=done, error=request.args.get("error"))


@app.post("/analyze")
def start():
    url = (request.form.get("url") or "").strip()
    try:
        info = parse_github_url(url)
    except CloneError as e:
        return redirect(url_for("index", error=str(e)))
    opts = Options(engine=request.form.get("engine", "auto"),
                   generate_lockfiles=request.form.get("generate_lockfiles") == "on",
                   run_build_tools=request.form.get("run_build_tools") == "on",
                   scan_vulns=request.form.get("scan_vulns") == "on")
    base = request.form.get("baseline") or ""
    if base:
        if base not in JOBS or JOBS[base].get("status") != "done" or not (OUTPUT / base / "result.json").exists():
            return redirect(url_for("index", error="The selected baseline scan is not available"))
        opts.baseline = str(OUTPUT / base / "result.json")
    if opts.engine not in ("auto", "cdxgen", "builtin"):
        opts.engine = "auto"
    job_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    JOBS[job_id] = {"id": job_id, "url": url, "repo": info["name"], "status": "queued",
                    "created": time.time(), "options": opts.__dict__, "baseline_job": base or None}
    _save(job_id)
    threading.Thread(target=_worker, args=(job_id, url, opts), daemon=True).start()
    return redirect(url_for("job_page", job_id=job_id))


@app.get("/jobs/<job_id>")
def job_page(job_id):
    if job_id not in JOBS:
        abort(404)
    return render_template("job.html", job=JOBS[job_id])


@app.get("/api/jobs/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id) or abort(404)
    run: Run | None = job.get("run")
    return jsonify({**{k: v for k, v in job.items() if k != "run"},
                    "stage": run.stage if run else job.get("status"),
                    "log": (run.log_lines if run else job.get("log", []))[-200:]})


@app.get("/api/jobs/<job_id>/<name>")
def job_file(job_id, name):
    if job_id not in JOBS or name not in DOWNLOADS:
        abort(404)
    d = OUTPUT / job_id
    if not (d / name).exists():
        abort(404)
    return send_from_directory(d, name, as_attachment=request.args.get("download") == "1")


class _QuietPolling(logging.Filter):
    """Hide the once-a-second status polling requests from the console."""
    def filter(self, record):
        return "GET /api/jobs/" not in record.getMessage()


def main() -> None:
    logging.getLogger("werkzeug").addFilter(_QuietPolling())
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _load_existing()
    host = os.environ.get("GUARDIAN_HOST", "127.0.0.1")
    port = int(os.environ.get("GUARDIAN_PORT", "5000"))
    print(f"Supply Chain Guardian UI on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
