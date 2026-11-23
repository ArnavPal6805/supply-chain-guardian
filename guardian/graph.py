"""Dependency graph analysis on the normalized model."""

from __future__ import annotations

from collections import Counter, defaultdict, deque

import networkx as nx


def analyze(model: dict) -> dict:
    root, projects, comps, edges = model["root"], model["projects"], model["components"], model["edges"]
    g = nx.DiGraph()
    g.add_node(root)
    g.add_nodes_from(projects)
    g.add_nodes_from(comps)
    g.add_edges_from(edges)

    # Project nodes = the repo root plus every manifest/lockfile we found.
    project_ids = set(projects) | {root}
    # Root -> projects (so every project hangs off the repo).
    for pid in projects:
        if pid != root and not any(u in project_ids for u in g.predecessors(pid)):
            g.add_edge(root, pid)

    direct: set[str] = set()
    direct_in: dict[str, list[str]] = defaultdict(list)
    for pid in project_ids:
        for child in g.successors(pid):
            if child in comps:
                direct.add(child)
                direct_in[child].append(pid)

    # Orphans (no parent at all). Go '// indirect' modules are transitive with unknown parent;
    # anything else with no parent is treated as a direct dependency (inferred).
    inferred_direct, parent_unknown = set(), set()
    for cid, c in comps.items():
        if g.in_degree(cid) == 0:
            if c["properties"].get("go:indirect") == "true":
                parent_unknown.add(cid)
            else:
                inferred_direct.add(cid)
                direct.add(cid)
    for cid in inferred_direct:
        g.add_edge(root, cid)

    # BFS from the repo root: depth + one shortest path for every component.
    pred: dict[str, str | None] = {root: None}
    depth = {root: 0}
    q = deque([root])
    while q:
        u = q.popleft()
        for v in g.successors(u):
            if v not in pred:
                pred[v] = u
                depth[v] = depth[u] + 1
                q.append(v)

    def path_to(node: str) -> list[str]:
        out = []
        while node is not None:
            out.append(node)
            node = pred.get(node)
        return list(reversed(out))

    # Which direct dependencies pull in each component?
    introduced_by: dict[str, set[str]] = defaultdict(set)
    for d in direct:
        for desc in nx.descendants(g, d):
            if desc in comps and desc not in direct:
                introduced_by[desc].add(d)

    # Projects each component belongs to (reachable from that project).
    in_projects: dict[str, set[str]] = defaultdict(set)
    for pid in projects:
        if pid == root:
            continue
        for desc in nx.descendants(g, pid):
            if desc in comps:
                in_projects[desc].add(pid)

    # Per-project view: shortest path and introducing direct deps *within each project*.
    # A package shared by several services is one node, so global "introduced_by" would mix
    # projects; root-cause analysis needs the per-project answer.
    by_project: dict[str, dict[str, dict]] = defaultdict(dict)
    for pid in list(projects) + ([root] if root not in projects else []):
        dirs = [c for c in g.successors(pid) if c in comps]
        if not dirs:
            continue
        ppred: dict[str, str | None] = {pid: None}
        q = deque([pid])
        while q:
            u = q.popleft()
            for v in g.successors(u):
                if v in comps and v not in ppred:
                    ppred[v] = u
                    q.append(v)
        intro: dict[str, set[str]] = defaultdict(set)
        for d in dirs:
            for x in nx.descendants(g, d):
                if x in comps and x != d:
                    intro[x].add(d)
        dirset = set(dirs)
        for cid in ppred:
            if cid == pid:
                continue
            path, n = [], cid
            while n is not None and n != pid:
                path.append(n)
                n = ppred[n]
            by_project[cid][pid] = {"path": list(reversed(path)), "direct": cid in dirset,
                                    "introduced_by": sorted(intro.get(cid, set()))}

    project_depth_offset = 1 if any(p != root for p in projects) else 0
    for cid, c in comps.items():
        c["direct"] = cid in direct
        c["direct_inferred"] = cid in inferred_direct
        c["direct_in"] = sorted(direct_in.get(cid, []))
        c["parents"] = sorted(p for p in g.predecessors(cid) if p in comps)
        c["children"] = sorted(g.successors(cid))
        c["projects"] = sorted(in_projects.get(cid, set()))
        c["introduced_by"] = sorted(introduced_by.get(cid, set()))
        c["by_project"] = by_project.get(cid, {})
        if cid in pred:
            full = path_to(cid)
            c["path"] = [n for n in full if n in comps]
            c["path_project"] = next((n for n in full if n in projects and n != root), None)
            c["depth"] = len(c["path"])          # 1 = direct dependency
            c["path_known"] = True
        else:
            # e.g. Go '// indirect' module: we know which go.mod lists it, not who pulls it in.
            c["path"], c["depth"] = [cid], None
            c["path_project"] = next((pid for pid, p in projects.items()
                                      if p.get("source_file") and p["source_file"] in c["found_in"]), None)
            if c["path_project"]:
                c["projects"] = [c["path_project"]]
            c["path_known"] = False
        c["dev_only"] = c["scope"] in ("optional", "excluded")

    # --------------------------------------------------------------- stats
    by_eco = Counter(c["ecosystem"] for c in comps.values())
    by_eco_direct = Counter(c["ecosystem"] for c in comps.values() if c["direct"])
    depths = Counter(c["depth"] for c in comps.values() if c["depth"]
                     and c["ecosystem_key"] not in ("docker", "githubactions", "github"))
    fan_in = sorted(((len(c["parents"]), cid) for cid, c in comps.items()), reverse=True)[:15]
    reach = sorted(((len(nx.descendants(g, d)), d) for d in direct), reverse=True)[:15]

    versions_by_name = defaultdict(set)
    for c in comps.values():
        versions_by_name[(c["ecosystem_key"], c["name"])].add(c["version"])
    multi = sorted(((k[1], k[0], sorted(v for v in vs if v)) for k, vs in versions_by_name.items()
                    if len([v for v in vs if v]) > 1), key=lambda x: -len(x[2]))

    lib = [c for c in comps.values() if c["ecosystem_key"] not in ("docker", "githubactions", "github")]
    stats = {
        "total_components": len(comps),
        "packages": len(lib),
        "direct": sum(1 for c in lib if c["direct"]),
        "transitive": sum(1 for c in lib if not c["direct"]),
        "transitive_parent_unknown": len(parent_unknown),
        "dev_or_optional": sum(1 for c in lib if c["dev_only"]),
        "max_depth": max(depths) if depths else 0,
        "depth_histogram": dict(sorted(depths.items())),
        "by_ecosystem": dict(by_eco.most_common()),
        "direct_by_ecosystem": dict(by_eco_direct.most_common()),
        "without_version": sum(1 for c in lib if not c["version"]),
        "without_integrity": sum(1 for c in lib if not c["hashes"]
                                 and not c["properties"].get("guardian:integrity")),
        "with_install_scripts": sum(1 for c in lib if "true" in (c["properties"].get("npm:hasInstallScript"),
                                                                   c["properties"].get("cdx:npm:hasInstallScript"))),
        "non_default_origin": sum(1 for c in lib if c["origin"]["source"] == "lockfile/SBOM"
                                  and c["origin"]["host"] not in _DEFAULT_HOSTS),
        "origins": dict(Counter(c["origin"]["host"] for c in comps.values()).most_common()),
        "container_images": sum(1 for c in comps.values() if c["ecosystem_key"] == "docker"),
        "ci_components": sum(1 for c in comps.values() if c["ecosystem_key"] in ("githubactions", "github")),
        "edges": sum(1 for a, b in g.edges if a in comps and b in comps),
        "most_depended_on": [{"id": cid, "parents": n} for n, cid in fan_in if n > 1],
        "heaviest_direct": [{"id": d, "pulls_in": n} for n, d in reach],
        "multiple_versions": [{"name": n, "ecosystem": e, "versions": v} for n, e, v in multi[:30]],
    }
    return stats


_DEFAULT_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
                  "repo.maven.apache.org", "repo1.maven.org", "proxy.golang.org", "github.com",
                  "docker.io", "api.nuget.org", "crates.io", "rubygems.org"}


def graph_payload(model: dict, findings: dict | None = None, max_nodes: int = 4000) -> dict:
    """Compact node/edge lists for the UI. `risk`/`ni` = worst risk level / number of findings on the node."""
    comps, projects, root = model["components"], model["projects"], model["root"]
    by_comp = (findings or {}).get("by_component", {})
    by_file = (findings or {}).get("by_file", {})
    nodes = [{"id": root, "label": projects.get(root, {}).get("name") or "repository", "kind": "repo"}]
    for pid, p in projects.items():
        if pid != root:
            fi = by_file.get(p.get("source_file") or "", {})
            nodes.append({"id": pid, "label": p.get("source_file") or p["name"], "kind": "project",
                          "ecosystem": p.get("ecosystem"), "risk": fi.get("level"), "ni": fi.get("n", 0)})
    for cid, c in list(comps.items())[:max_nodes]:
        nodes.append({"id": cid, "label": f'{c["name"]}@{c["version"]}' if c["version"] else c["name"],
                      "kind": "component", "eco": c["ecosystem_key"], "direct": c["direct"],
                      "depth": c["depth"], "dev": c["dev_only"],
                      "unknown_parent": not c.get("path_known", True),
                      "sev": c.get("max_severity"), "nv": len(c.get("vulns") or []),
                      "risk": by_comp.get(cid, {}).get("level"), "ni": by_comp.get(cid, {}).get("n", 0)})
    ids = {n["id"] for n in nodes}
    edges = [[a, b] for a, b in model["edges"] if a in ids and b in ids]
    # Transitive deps whose parent is unknown (Go '// indirect'): hang them off their manifest.
    for cid, c in comps.items():
        if cid in ids and not c.get("path_known", True) and c.get("path_project"):
            edges.append([c["path_project"], cid])
    for pid in projects:
        if pid != root and not any(b == pid for _, b in edges):
            edges.append([root, pid])
    return {"nodes": nodes, "edges": edges, "truncated": len(comps) > max_nodes}
