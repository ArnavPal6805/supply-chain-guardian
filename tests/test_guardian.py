import json
from pathlib import Path

import pytest

from guardian import artifacts, purl
from guardian.clone import CloneError, parse_github_url
from guardian.inventory import ROOT
from guardian.parsers import maven, npm, python
from guardian.pipeline import Options, analyze

FIX = Path(__file__).parent / "fixtures"


def test_purl_roundtrip():
    assert purl.npm("@angular/core", "17.0.0") == "pkg:npm/%40angular/core@17.0.0"
    assert purl.maven("org.yaml", "snakeyaml", "2.4") == "pkg:maven/org.yaml/snakeyaml@2.4"
    assert purl.pypi("Google_Auth", "2.0") == "pkg:pypi/google-auth@2.0"
    p = purl.parse("pkg:npm/%40angular/core@17.0.0")
    assert (p["namespace"], p["name"], p["version"]) == ("@angular", "core", "17.0.0")


@pytest.mark.parametrize("url,name,ref", [
    ("https://github.com/juice-shop/juice-shop", "juice-shop/juice-shop", None),
    ("github.com/spring-projects/spring-petclinic.git", "spring-projects/spring-petclinic", None),
    ("https://github.com/a/b/tree/feature/x", "a/b", "feature/x"),
])
def test_github_url(url, name, ref):
    d = parse_github_url(url)
    assert d["name"] == name and d["ref"] == ref


@pytest.mark.parametrize("bad", ["https://gitlab.com/a/b", "file:///etc", "https://github.com/a",
                                 "https://github.com.evil.com/a/b"])
def test_github_url_rejects(bad):
    with pytest.raises(CloneError):
        parse_github_url(bad)


def test_maven_tree_parser():
    [inv] = maven.parse_tree_text((FIX / "mvn-tree.txt").read_text(), "pom.xml")
    names = {p.name for p in inv.packages.values()}
    assert "org.yaml:snakeyaml" in names and len(inv.packages) == 11
    snake = purl.maven("org.yaml", "snakeyaml", "2.4")
    starter = purl.maven("org.springframework.boot", "spring-boot-starter", "3.5.0")
    assert (starter, snake) in inv.edges
    direct = {c for p, c in inv.edges if p == ROOT}
    assert len(direct) == 5
    boot = inv.packages[purl.maven("org.springframework.boot", "spring-boot", "3.5.0")]
    assert boot.scope == "required"          # compile wins over test
    junit = inv.packages[purl.maven("org.junit.jupiter", "junit-jupiter", "5.12.2")]
    assert junit.scope == "optional"
    netty = next(p for p in inv.packages.values() if "netty" in p.name)
    assert netty.properties["maven:classifier"] == "linux-x86_64"
    assert inv.packages[purl.maven("org.webjars.npm", "bootstrap", "5.3.6")].properties["maven:optional"] == "true"


def _lock():
    return {
        "name": "app", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"a": "^1"}, "devDependencies": {"t": "^1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2"},
                               "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                               "integrity": "sha512-AAAA"},
            "node_modules/a/node_modules/b": {"version": "2.0.0", "hasInstallScript": True},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/t": {"version": "1.0.0", "dev": True, "dependencies": {"b": "^1"}},
        },
    }


def test_npm_nested_resolution(tmp_path):
    inv = npm.parse_lock_v2(_lock(), "package-lock.json")
    a, b2, b1, t = (purl.npm(n, v) for n, v in [("a", "1.0.0"), ("b", "2.0.0"), ("b", "1.0.0"), ("t", "1.0.0")])
    assert (a, b2) in inv.edges          # nested node_modules wins
    assert (t, b1) in inv.edges          # hoisted copy for t
    assert {c for p, c in inv.edges if p == ROOT} == {a, t}
    assert inv.packages[t].scope == "optional"
    assert inv.packages[b2].properties["npm:hasInstallScript"] == "true"


def test_requirements_via_graph(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("certifi==2024.7.4\n    # via requests\nrequests==2.32.3\n    # via -r requirements.in\n")
    inv = python.parse_requirements(f, tmp_path)
    req, cert = purl.pypi("requests", "2.32.3"), purl.pypi("certifi", "2024.7.4")
    assert (ROOT, req) in inv.edges and (req, cert) in inv.edges and (ROOT, cert) not in inv.edges


def test_dockerfile_and_workflow(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "ARG V=20\nFROM node:${V}-alpine AS build\nRUN curl -s https://x.sh | sh\n"
        "FROM build AS test\nFROM gcr.io/distroless/nodejs20\n")
    d = artifacts.parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    refs = [(i["reference"], i.get("internal_stage")) for i in d["images"]]
    assert refs == [("node:20-alpine", False), ("build", True), ("gcr.io/distroless/nodejs20", False)]
    assert d["images"][2]["uses_latest"] and d["images"][2]["registry"] == "gcr.io"
    assert d["observations"][0]["type"] == "pipe_to_shell"
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n"
        "      - uses: someone/tool@main\n      - uses: docker/login-action@v3\n")
    w = artifacts.parse_workflow(wf / "ci.yml", tmp_path)
    assert [u["pin"] for u in w["uses"]] == ["commit-sha", "branch-or-other", "tag"]
    assert w["uses"][0]["version_comment"] == "v7" and w["uses"][0]["first_party"]


def test_pipeline_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"a": "^1"}}))
    (repo / "package-lock.json").write_text(json.dumps(_lock()))
    (repo / "Dockerfile").write_text("FROM node:20\n")
    res = analyze(str(repo), tmp_path / "out", Options(engine="builtin", generate_lockfiles=False))
    comps = {c["id"]: c for c in res["components"]}
    b2 = comps[purl.npm("b", "2.0.0")]
    assert not b2["direct"] and b2["depth"] == 2
    assert [comps[x]["name"] for x in b2["path"]] == ["a", "b"]
    assert b2["introduced_by"] == [purl.npm("a", "1.0.0")]
    assert res["stats"]["packages"] == 4 and res["stats"]["container_images"] == 1
    bom = json.loads((tmp_path / "out" / "bom.cdx.json").read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"


# ------------------------------------------------------------------ Steps 3-5

def _planted_repo(root: Path, left_pad_hash="sha512-AAAA"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "demo", "dependencies": {
        "expresss": "^1.0.0", "left-pad": "*", "evil-lib": "^1.0.0", "gitdep": "github:someone/gitdep",
        "nohash": "^1.0.0"}}))
    lock = {"name": "demo", "lockfileVersion": 3, "packages": {
        "": {"name": "demo", "dependencies": {"expresss": "^1.0.0", "left-pad": "*", "evil-lib": "^1.0.0",
                                              "gitdep": "github:someone/gitdep", "nohash": "^1.0.0"}},
        "node_modules/expresss": {"version": "1.0.0", "hasInstallScript": True,
                                  "resolved": "https://registry.npmjs.org/expresss/-/expresss-1.0.0.tgz",
                                  "integrity": "sha512-BBBB"},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                                  "integrity": left_pad_hash},
        "node_modules/evil-lib": {"version": "1.0.0", "resolved": "https://npm.evil.example.com/evil-lib-1.0.0.tgz",
                                  "integrity": "sha512-CCCC"},
        "node_modules/gitdep": {"version": "0.1.0", "resolved": "git+ssh://git@github.com/someone/gitdep.git#abc"},
        "node_modules/nohash": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/nohash/-/nohash-1.0.0.tgz"}}}
    (root / "package-lock.json").write_text(json.dumps(lock, indent=2))
    (root / "Dockerfile").write_text("FROM node:20 AS build\nFROM gcr.io/distroless/nodejs20\n")
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "pr.yml").write_text(
        "on:\n  pull_request_target:\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: someone/tool@main\n")


def test_anomalies_detected(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    _planted_repo(tmp_path / "repo")
    res = analyze(str(tmp_path / "repo"), tmp_path / "out",
                  Options(engine="builtin", generate_lockfiles=False, scan_vulns=False))
    issues = res["findings"]["issues"]
    kinds = {i["kind"] for i in issues}
    for k in ("typosquat", "install-script", "unexpected-registry", "git-dependency", "missing-integrity",
              "unbounded-version", "unpinned-image", "unpinned-action", "risky-trigger"):
        assert k in kinds, k
    typo = next(i for i in issues if i["kind"] == "typosquat")
    assert "express" in typo["title"] and typo["risk"]["level"] == "high"   # + install script
    trig = next(i for i in issues if i["kind"] == "risky-trigger")
    assert trig["risk"]["level"] == "high" and trig["line"] == 2
    branch = next(i for i in issues if i["kind"] == "unpinned-action" and "someone/tool" in i["title"])
    assert branch["risk"]["level"] == "high"
    img = next(i for i in issues if i["kind"] == "unpinned-image")
    assert img["risk"]["level"] == "high" and img["line"] == 2       # runtime stage, no tag
    reg = next(i for i in issues if i["kind"] == "unexpected-registry")
    assert "npm.evil.example.com" in reg["title"]
    # every finding carries evidence and a risk explanation
    assert all(i["evidence"] and i["risk"]["factors"] for i in issues)


def test_baseline_detects_tampered_lockfile(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    opts = Options(engine="builtin", generate_lockfiles=False, scan_vulns=False)
    _planted_repo(tmp_path / "v1")
    analyze(str(tmp_path / "v1"), tmp_path / "out1", opts)
    _planted_repo(tmp_path / "v2", left_pad_hash="sha512-ZZZZ")          # same version, new hash
    pj = json.loads((tmp_path / "v2" / "package-lock.json").read_text())
    pj["packages"]["node_modules/surprise"] = {"version": "9.9.9", "resolved":
                                               "https://registry.npmjs.org/surprise/-/surprise-9.9.9.tgz",
                                               "integrity": "sha512-DDDD"}
    pj["packages"][""]["dependencies"]["surprise"] = "^9.0.0"
    (tmp_path / "v2" / "package-lock.json").write_text(json.dumps(pj, indent=2))
    res = analyze(str(tmp_path / "v2"), tmp_path / "out2",
                  Options(engine="builtin", generate_lockfiles=False, scan_vulns=False,
                          baseline=str(tmp_path / "out1")))
    issues = res["findings"]["issues"]
    tamper = next(i for i in issues if i["kind"] == "integrity-changed")
    assert tamper["risk"]["level"] == "critical" and "left-pad@1.3.0" in tamper["title"]
    assert any(i["kind"] == "new-dependency" and "surprise" in i["title"] for i in issues)
    assert res["findings"]["changes"]["integrity_changed"] == 1


def test_vuln_root_cause_from_osv(tmp_path, monkeypatch):
    """Feed a recorded OSV result through Step 3 + 5 (no network)."""
    from guardian import vulns, evidence
    from guardian.normalize import normalize
    from guardian import graph as G, cyclonedx
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"dependencies": {"web": "^1.0.0"}},
        "node_modules/web": {"version": "1.0.0", "dependencies": {"qs": "~6.13.0"}},
        "node_modules/qs": {"version": "6.13.0"}}}
    inv = npm.parse_lock_v2(lock, "package-lock.json")
    model = normalize(cyclonedx.build_bom([inv], {"name": "app"}))
    G.analyze(model)
    osv = {"results": [{"packages": [{"package": {"name": "qs", "version": "6.13.0", "ecosystem": "npm"},
            "groups": [{"ids": ["GHSA-test"], "max_severity": "7.5"}],
            "vulnerabilities": [{"id": "GHSA-test", "aliases": ["CVE-2099-0001"], "summary": "proto pollution",
                                 "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.14.0"}]}]}]}]}]}]}
    specs = {(("root::package-lock.json" if p == ROOT else p), c): s for (p, c), s in inv.edge_specs.items()}
    vr = vulns.analyze(osv, model, specs)
    f = vr["findings"][0]
    assert f["fixed_in"] == "6.14.0" and f["cve"] == "CVE-2099-0001"
    rc = f["occurrences"][0]["root_cause"]
    assert rc["kind"] == "blocked-by-parent" and rc["blockers"][0]["spec"] == "~6.13.0"
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    out = evidence.build(model, vr, [], tmp_path)
    assert out["issues"][0]["risk"]["level"] in ("high", "medium")
