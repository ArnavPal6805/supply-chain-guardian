"""Command line: python -m guardian.cli analyze <github-url-or-path> [-o out]"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .pipeline import Options, analyze


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian - Day 1")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="discover components and build the supply chain view")
    a.add_argument("source", help="GitHub URL (https://github.com/owner/repo) or local directory")
    a.add_argument("-o", "--out", help="output directory (default: ./output/<repo>)")
    a.add_argument("--engine", choices=["auto", "cdxgen", "builtin"], default="auto")
    a.add_argument("--no-lockfile-generation", action="store_true",
                   help="don't resolve missing npm lockfiles")
    a.add_argument("--no-build-tools", action="store_true",
                   help="don't run mvn dependency:tree / go mod graph")
    a.add_argument("--no-vulns", action="store_true", help="skip the OSV vulnerability scan")
    a.add_argument("--baseline", help="previous scan's output folder or result.json: report what changed")
    args = ap.parse_args(argv)

    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", args.source.rstrip("/").split("github.com/")[-1])
    out = Path(args.out or Path("output") / slug)
    opts = Options(engine=args.engine, generate_lockfiles=not args.no_lockfile_generation,
                   run_build_tools=not args.no_build_tools, scan_vulns=not args.no_vulns,
                   baseline=args.baseline)
    result = analyze(args.source, out, opts)
    s = result["stats"]
    print(json.dumps({k: s[k] for k in ("packages", "direct", "transitive", "transitive_parent_unknown",
                                        "dev_or_optional", "max_depth", "by_ecosystem",
                                        "container_images", "ci_components")}, indent=2))
    v = result.get("vulnerabilities")
    if v:
        print("vulnerabilities:", json.dumps(v["summary"]))
        for g in v["groups"][:10]:
            print(f"  {g['id']} [{g['max_severity']:8}] {g['project_file']}: {g['action']}  ({len(g['findings'])} findings)")
    f = result.get("findings") or {}
    if f.get("summary"):
        fs = f["summary"]
        print(f"\nfindings: {fs['total']} ({fs['vulnerabilities']} vulnerabilities, {fs['anomalies']} anomalies) - "
              + ", ".join(f"{n} {l}" for l, n in fs["by_level"].items() if n))
        for i in f["issues"][:12]:
            where = f"{i.get('file') or ''}{':' + str(i['line']) if i.get('line') else ''}"
            print(f"  {i['id']} [{i['risk']['level']:8}] {i['title'][:90]}  {where}")
    print(f"\nOutputs in {out}/ : bom.cdx.json, result.json, findings.json, graph.json, log.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
