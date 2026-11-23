/* Supply Chain Guardian - results UI (no third-party JS on purpose). */
(function () {
  "use strict";
  const API = `/api/jobs/${window.JOB_ID}`;
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const ECO_COLOR = { npm: "var(--npm)", maven: "var(--maven)", pypi: "var(--pypi)", golang: "var(--golang)", docker: "var(--docker)", githubactions: "var(--githubactions)" };
  const ecoDot = (key, label) => `<span class="eco"><i style="background:${ECO_COLOR[key] || "var(--other)"}"></i>${esc(label)}</span>`;

  let R = null, GRAPH = null, BYID = {}, PROJ = {}, FIND = null, ISS = {}, COMPISS = {};
  const RISK_COLOR = { critical: "#b4232c", high: "#d9480f", medium: "#b7791f", low: "#718096", info: "#8a94a6" };
  const LV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const lvPill = (l) => `<span class="lv lv-${esc(l)}">${esc(l)}</span>`;
  const KIND_LABEL = { "known-vulnerability": "Known vulnerability", "malicious-package": "Malicious package",
    typosquat: "Typosquat", "install-script": "Install script", "unexpected-registry": "Unexpected registry",
    "git-dependency": "Git dependency", "missing-integrity": "Missing integrity hash", "unbounded-version": "Unbounded version",
    "no-lockfile": "No lockfile", "unpinned-image": "Unpinned image", "image-not-digest-pinned": "Image not digest-pinned",
    "remote-script": "Remote script in build", "unpinned-action": "Unpinned action", "risky-trigger": "Risky workflow trigger",
    "broad-permissions": "Broad permissions", "integrity-changed": "Modified lockfile", "origin-changed": "Download source changed",
    "suspicious-update": "Suspicious update", "new-dependency": "Unexpected dependency" };

  // ------------------------------------------------------------ polling
  async function poll() {
    let j;
    try { j = await (await fetch(API)).json(); } catch (e) { setTimeout(poll, 2000); return; }
    $("#stage").textContent = j.status === "failed" ? "Failed" : j.stage || j.status;
    const log = $("#livelog");
    log.textContent = (j.log || []).join("\n");
    log.scrollTop = log.scrollHeight;
    if (j.status === "done") return load(j);
    if (j.status === "failed") {
      $("#headsub").innerHTML = `<span class="status failed">Failed:</span> ${esc(j.error)}`;
      return;
    }
    $("#headsub").innerHTML = `<span class="spinner"></span>${esc(j.stage || j.status)}…`;
    setTimeout(poll, 1200);
  }

  async function load(job) {
    [R, GRAPH] = await Promise.all([fetch(`${API}/result.json`).then((r) => r.json()), fetch(`${API}/graph.json`).then((r) => r.json())]);
    R.components.forEach((c) => (BYID[c.id] = c));
    R.projects.forEach((p) => (PROJ[p.id] = p));
    FIND = R.findings || { issues: [], summary: null, by_component: {}, by_file: {} };
    FIND.issues.forEach((i) => { ISS[i.id] = i; if (i.component_id) (COMPISS[i.component_id] = COMPISS[i.component_id] || []).push(i.id); });
    $("#progress").style.display = "none";
    $("#results").style.display = "block";
    const repo = R.repository;
    $("#headsub").innerHTML = `${repo.url ? `<a href="${esc(repo.url)}" target="_blank" rel="noopener">${esc(repo.url)}</a> · ` : ""}commit <code>${esc((repo.commit || "").slice(0, 12))}</code> · SBOM engine <b>${esc(R.engine)}</b> · ${R.duration_seconds}s`;
    renderCards(); renderOverview(); renderFindings(); setupComponents(); setupGraph(); renderArtifacts(); renderProjects(); renderFiles();
    document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => tab(b.dataset.t)));
  }

  function tab(t) {
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === t));
    document.querySelectorAll(".tab").forEach((s) => s.classList.toggle("on", s.id === `t-${t}`));
  }

  // ------------------------------------------------------------ overview
  function renderCards() {
    const s = R.stats;
    const card = (n, l) => `<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`;
    $("#cards").innerHTML = [card(s.packages, "packages"), card(s.direct, "direct"), card(s.transitive, "transitive"),
      card(s.max_depth, "max dependency depth"), card(s.container_images, "container images"), card(s.ci_components, "CI/CD components"),
      card(R.projects.filter((p) => !p.is_repo_root).length, "manifests / sources")].join("");
    const fs = FIND.summary;
    if (fs) {
      const rc = (n, l) => `<div class="card risk" style="cursor:pointer" onclick="document.querySelector('[data-t=findings]').click()"><div class="n">${n}</div><div class="l">${l}</div></div>`;
      $("#cards").innerHTML = rc(fs.by_level.critical + fs.by_level.high, "critical + high findings") +
        rc(fs.vulnerabilities, "known vulnerabilities") + rc(fs.anomalies, "supply-chain anomalies") + $("#cards").innerHTML;
    }
  }

  function bars(obj, colorFn) {
    const max = Math.max(1, ...Object.values(obj));
    return `<div class="bars">${Object.entries(obj).map(([k, v]) => `<div class="row"><div>${esc(k)}</div><div class="track"><div class="fill" style="width:${(100 * v) / max}%;background:${colorFn(k)}"></div></div><div class="mono">${v}</div></div>`).join("")}</div>`;
  }

  function renderOverview() {
    const s = R.stats;
    const ecoKey = { npm: "npm", Maven: "maven", PyPI: "pypi", Go: "golang", "Container image": "docker", "GitHub Actions": "githubactions" };
    const incomplete = R.projects.filter((p) => !p.complete);
    const notes = R.projects.flatMap((p) => (p.notes || []).map((n) => ({ p, n })));
    const name = (id) => (BYID[id] ? `${BYID[id].name}@${BYID[id].version ?? "?"}` : id);
    let html = findingsGlance() + `<div class="split"><div class="panel"><h2>Components by ecosystem</h2>${bars(s.by_ecosystem, (k) => ECO_COLOR[ecoKey[k]] || "var(--other)")}
      <h3>Dependency depth (1 = direct)</h3>${bars(Object.fromEntries(Object.entries(s.depth_histogram).map(([k, v]) => [`depth ${k}`, v])), () => "var(--accent)")}</div>
      <div class="panel"><h2>Where components come from</h2>${bars(Object.fromEntries(Object.entries(s.origins).slice(0, 10)), () => "#8a94a6")}
      <div class="kv" style="margin-top:14px">
        <div>dev / optional / test</div><div>${s.dev_or_optional}</div>
        <div>without exact version</div><div>${s.without_version}</div>
        <div>without integrity hash</div><div>${s.without_integrity}</div>
        <div>npm install scripts</div><div>${s.with_install_scripts}</div>
        <div>non-default registry</div><div>${s.non_default_origin}</div>
        <div>transitive, parent unknown</div><div>${s.transitive_parent_unknown}</div>
        <div>dependency edges</div><div>${s.edges}</div>
      </div></div></div>`;
    if (incomplete.length || notes.length) {
      html += `<div class="panel"><h2>Completeness</h2><p class="sub">What the Guardian could not fully resolve, so a missing finding isn't mistaken for a clean bill of health.</p>
        ${notes.map(({ p, n }) => `<div class="note"><b class="mono">${esc(p.source_file || p.name)}</b> — ${esc(n)}</div>`).join("")}</div>`;
    }
    if (R.cross_check && R.cross_check.length) {
      html += `<div class="panel"><h2>Cross-check: cdxgen vs lockfile parser</h2><table><tr><th>Ecosystem</th><th>cdxgen</th><th>Lockfile parser</th><th>Only in cdxgen</th><th>Only in lockfile</th></tr>
        ${R.cross_check.map((c) => `<tr><td>${esc(c.ecosystem)}</td><td>${c.cdxgen}</td><td>${c.lockfile_parser}</td><td class="mono">${c.only_in_cdxgen.slice(0, 5).map(esc).join("<br>")}</td><td class="mono">${c.only_in_lockfile.slice(0, 5).map(esc).join("<br>")}</td></tr>`).join("")}</table></div>`;
    }
    html += `<div class="split"><div class="panel"><h2>Heaviest direct dependencies</h2><p class="sub">How many components each direct dependency pulls in.</p><table>
      ${s.heaviest_direct.map((h) => `<tr class="click" data-id="${esc(h.id)}"><td class="mono">${esc(name(h.id))}</td><td>${h.pulls_in}</td></tr>`).join("")}</table></div>
      <div class="panel"><h2>Most depended-on components</h2><p class="sub">Number of packages that directly depend on it.</p><table>
      ${s.most_depended_on.slice(0, 15).map((h) => `<tr class="click" data-id="${esc(h.id)}"><td class="mono">${esc(name(h.id))}</td><td>${h.parents}</td></tr>`).join("")}</table></div></div>`;
    if (s.multiple_versions.length) {
      html += `<div class="panel"><h2>Same package, multiple versions</h2><table><tr><th>Package</th><th>Ecosystem</th><th>Versions</th></tr>
        ${s.multiple_versions.map((m) => `<tr><td class="mono">${esc(m.name)}</td><td>${esc(m.ecosystem)}</td><td class="mono">${m.versions.map(esc).join(", ")}</td></tr>`).join("")}</table></div>`;
    }
    $("#t-overview").innerHTML = html;
    bindRowClicks($("#t-overview"));
    bindFindingClicks($("#t-overview"));
  }

  // ------------------------------------------------------------ Steps 3-5: findings
  function findingsGlance() {
    const fs = FIND.summary;
    if (!fs) return "";
    const total = Math.max(1, fs.total);
    const seg = ["critical", "high", "medium", "low"].map((l) => fs.by_level[l] ? `<div style="width:${(100 * fs.by_level[l]) / total}%;background:${RISK_COLOR[l]}" title="${fs.by_level[l]} ${l}"></div>` : "").join("");
    const top = FIND.issues.slice(0, 5).map((i) => `<div class="fixgroup" data-fid="${esc(i.id)}" style="grid-template-columns:auto 1fr auto">${lvPill(i.risk.level)}<div>${esc(i.title)}<div class="sub">${esc(i.file || "")}${i.line ? ":" + i.line : ""}</div></div><span class="typetag">${esc(KIND_LABEL[i.kind] || i.kind)}</span></div>`).join("");
    return `<div class="panel"><h2>Findings at a glance</h2>
      <p class="sub">${fs.total} findings: ${fs.vulnerabilities} known vulnerabilities and ${fs.anomalies} supply-chain anomalies. ${["critical", "high", "medium", "low"].map((l) => `${fs.by_level[l]} ${l}`).join(" · ")}</p>
      <div class="levelbar">${seg}</div>
      <h3>Highest risk</h3>${top || '<p class="muted">Nothing found.</p>'}
      <p style="margin-top:10px"><button class="ghost" onclick="document.querySelector('[data-t=findings]').click()">All findings →</button></p></div>`;
  }

  function renderFindings() {
    const fs = FIND.summary;
    if (!fs) { $("#t-findings").innerHTML = '<div class="panel"><p class="muted">This scan ran without Steps 3–5.</p></div>'; return; }
    const groups = (R.vulnerabilities?.groups || []).slice(0, 8);
    const ch = FIND.changes;
    const intel = `EPSS ${fs.epss_checked ? "checked" : "not checked (offline)"} · CISA KEV ${fs.kev_checked ? "checked" : "not checked (offline)"}`;
    let html = `<div class="panel"><h2>Findings (${fs.total})</h2>
      <p class="sub">Every finding links a detection to the affected component, its dependency path and the evidence behind it. The risk level is an initial, rule-based assessment; open a finding to see exactly which factors raised or lowered it. ${esc(intel)}.</p>
      ${ch ? `<div class="note">Compared with an earlier scan${ch.baseline_commit ? ` (commit <code>${esc(ch.baseline_commit.slice(0, 12))}</code>)` : ""}: ${ch.added} new packages, ${ch.updated} updated, ${ch.removed} removed, <b>${ch.integrity_changed} lockfile entries with a changed hash</b>.</div>` : ""}
    </div>`;
    if (groups.length) {
      html += `<div class="panel"><h2>Fix first: vulnerabilities grouped by root cause</h2><p class="sub">One change can fix several findings. Groups are ordered by the worst finding they fix.</p>
        ${groups.map((g) => `<div class="fixgroup" data-gid="${esc(g.id)}">${lvPill(g.max_severity === "unknown" ? "info" : g.max_severity)}<div><b>${esc(g.action)}</b><div class="sub mono">${esc(g.project_file || "")} · ${g.packages.slice(0, 4).map(esc).join(", ")}${g.packages.length > 4 ? ` +${g.packages.length - 4}` : ""}</div></div><span class="typetag">${g.findings.length} finding${g.findings.length > 1 ? "s" : ""}</span></div>`).join("")}</div>`;
    }
    const kinds = [...new Set(FIND.issues.map((i) => i.kind))];
    html += `<div class="panel"><div class="toolbar">
        <input id="fq" placeholder="search package, file, advisory…">
        <select id="f-type"><option value="">vulnerabilities + anomalies</option><option value="vulnerability">vulnerabilities</option><option value="anomaly">anomalies</option></select>
        <select id="f-level"><option value="">all risk levels</option>${["critical", "high", "medium", "low"].map((l) => `<option>${l}</option>`).join("")}</select>
        <select id="f-kind"><option value="">all kinds</option>${kinds.map((k) => `<option value="${esc(k)}">${esc(KIND_LABEL[k] || k)}</option>`).join("")}</select>
        <span class="muted" id="fcount"></span></div>
      <div class="scroll"><table id="ftable"><thead><tr><th>Risk</th><th>Kind</th><th>Finding</th><th>Where</th><th>Dependency path</th><th>Recommended fix</th></tr></thead><tbody></tbody></table></div></div>`;
    $("#t-findings").innerHTML = html;
    ["#fq", "#f-type", "#f-level", "#f-kind"].forEach((sel) => $(sel).addEventListener("input", drawFindings));
    $("#t-findings").querySelectorAll("[data-gid]").forEach((el) => el.addEventListener("click", () => {
      const g = R.vulnerabilities.groups.find((x) => x.id === el.dataset.gid);
      $("#fq").value = ""; $("#f-type").value = "vulnerability";
      drawFindings(g.findings);
    }));
    drawFindings();
    bindFindingClicks(document);
  }

  function pathText(ids) {
    return (ids || []).map((x) => BYID[x] ? BYID[x].name : x).join(" → ");
  }

  function drawFindings(onlyIds) {
    const q = $("#fq").value.toLowerCase(), t = $("#f-type").value, l = $("#f-level").value, k = $("#f-kind").value;
    const rows = FIND.issues.filter((i) => (!onlyIds || onlyIds.includes(i.id)) &&
      (!q || `${i.title} ${i.subject} ${i.file} ${i.advisory || ""} ${i.cve || ""}`.toLowerCase().includes(q)) &&
      (!t || i.type === t) && (!l || i.risk.level === l) && (!k || i.kind === k));
    $("#fcount").textContent = `${rows.length} of ${FIND.issues.length}${onlyIds ? " (one fix group, change a filter to reset)" : ""}`;
    $("#ftable tbody").innerHTML = rows.slice(0, 800).map((i) => {
      const occ = (i.occurrences || [])[0];
      const comp = i.component_id && BYID[i.component_id];
      const path = occ ? pathText(occ.path) : comp ? pathText(comp.path) : "";
      return `<tr class="click" data-fid="${esc(i.id)}"><td>${lvPill(i.risk.level)}<div class="sub mono">${i.risk.score}</div></td>
        <td><span class="typetag">${esc(KIND_LABEL[i.kind] || i.kind)}</span></td>
        <td>${esc(i.title)}${i.advisory ? `<div class="sub mono">${esc(i.advisory)}${i.cve ? " · " + esc(i.cve) : ""}</div>` : ""}</td>
        <td class="mono">${esc(i.file || occ?.project_file || "")}${i.line ? ":" + i.line : ""}</td>
        <td class="mono" style="max-width:300px">${esc(path)}</td>
        <td>${esc(i.recommendation || "")}</td></tr>`;
    }).join("");
    bindFindingClicks($("#ftable"));
  }

  function bindFindingClicks(root) {
    root.querySelectorAll("[data-fid]").forEach((el) => { if (!el._b) { el._b = 1; el.addEventListener("click", (e) => { e.stopPropagation(); openFinding(el.dataset.fid); }); } });
  }

  function openFinding(id) {
    const i = ISS[id];
    if (!i) return;
    const comp = i.component_id && BYID[i.component_id];
    const occs = i.occurrences || [];
    const factors = i.risk.factors.map((f, n) => `<div class="factor"><span>${esc(f.factor)}</span><span class="d ${n === 0 ? "" : f.delta < 0 ? "neg" : f.delta > 0 ? "pos" : ""}">${n === 0 ? "base " + f.delta : (f.delta > 0 ? "+" : "") + f.delta}</span></div>`).join("");
    const occHtml = occs.map((o) => {
      const rc = o.root_cause || {};
      const blockers = (rc.blockers || []).map((b) => `<tr><td class="mono">${esc(b.parent_label)}</td><td class="mono">requires ${esc(b.spec)}</td></tr>`).join("");
      return `<div style="margin:10px 0 16px"><div class="sub mono">${esc(o.project_file || "")}${o.direct ? " · direct dependency" : ""}</div>
        <div class="path" style="margin:6px 0">${(o.path || []).map((p, n) => `${n ? '<span class="a">→</span>' : ""}<span class="n ${p === i.component_id ? "me" : ""}">${esc(BYID[p] ? `${BYID[p].name}@${BYID[p].version}` : p)}</span>`).join("")}</div>
        <div class="rc"><b>Root cause (${esc(rc.kind || "")}):</b> ${esc(rc.explanation || "")}</div>
        ${blockers ? `<table style="margin:4px 0 6px">${blockers}</table>` : ""}
        <div><b>Fix:</b> ${esc(o.fix?.action || "")}</div></div>`;
    }).join("");
    const compPath = !occs.length && comp ? `<div class="path">${comp.path.map((p, n) => `${n ? '<span class="a">→</span>' : ""}<span class="n ${p === comp.id ? "me" : ""}">${esc(BYID[p] ? BYID[p].name + "@" + BYID[p].version : p)}</span>`).join("")}</div>` : "";
    $("#drawer").innerHTML = `<button class="ghost close" id="dclose">Close</button>
      <div style="margin:2px 0 8px">${lvPill(i.risk.level)} <span class="typetag" style="margin-left:6px">${esc(i.type)} · ${esc(KIND_LABEL[i.kind] || i.kind)}</span> <span class="muted mono" style="margin-left:6px">${esc(i.id)}</span></div>
      <h2 style="margin-top:4px">${esc(i.title)}</h2>
      <h3>What was detected</h3><p style="margin:0">${esc(i.explanation || "")}</p>
      ${i.file ? `<p class="mono" style="margin:6px 0 0">${esc(i.file)}${i.line ? ":" + i.line : ""}</p>` : ""}
      <h3>Affected component</h3>${comp ? `<div class="chips"><a href="#" data-open="${esc(comp.id)}">${esc(comp.name)}@${esc(comp.version ?? "?")}</a></div><div class="sub mono">${esc(comp.purl || "")}</div>` : `<p class="mono" style="margin:0">${esc(i.subject || i.file || "")}</p>`}
      <h3>Dependency path${occs.length > 1 ? `s (${occs.length} projects)` : ""}</h3>${occHtml || compPath || '<p class="muted">Not a package dependency (file-level finding).</p>'}
      ${!occs.length && i.recommendation ? `<h3>Recommended action</h3><p style="margin:0">${esc(i.recommendation)}</p>` : ""}
      <h3>Evidence</h3><table class="ev">${(i.evidence || []).map((e) => `<tr><td>${esc(e.label)}</td><td class="mono" style="word-break:break-all">${esc(e.value)}</td></tr>`).join("")}</table>
      <h3>Initial risk level: ${lvPill(i.risk.level)} <span class="mono">${i.risk.score}/10</span></h3>${factors}
      ${i.confidence === "medium" ? '<p class="note">Heuristic finding: confirm before acting.</p>' : ""}
      ${i.details ? `<h3>Advisory details</h3><p class="sub" style="white-space:pre-wrap">${esc(i.details.slice(0, 1200))}${i.details.length > 1200 ? "…" : ""}</p>` : ""}
      ${(i.references || []).length ? `<h3>References</h3>${i.references.map((r) => `<div><a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a></div>`).join("")}` : ""}
      ${comp ? '<p style="margin-top:18px"><button class="ghost" id="dgraph">Show in dependency graph</button></p>' : ""}`;
    $("#drawer").classList.add("on");
    $("#dclose").onclick = () => $("#drawer").classList.remove("on");
    if (comp) $("#dgraph").onclick = () => { $("#drawer").classList.remove("on"); tab("graph"); focusNode(comp.id); };
    $("#drawer").querySelectorAll("[data-open]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openDrawer(a.dataset.open); }));
  }

  // ------------------------------------------------------------ components table
  function setupComponents() {
    const ecos = [...new Set(R.components.map((c) => c.ecosystem))].sort();
    $("#f-eco").innerHTML += ecos.map((e) => `<option>${esc(e)}</option>`).join("");
    $("#f-proj").innerHTML += R.projects.filter((p) => !p.is_repo_root).map((p) => `<option value="${esc(p.id)}">${esc(p.source_file || p.name)}</option>`).join("");
    ["#q", "#f-eco", "#f-kind", "#f-scope", "#f-proj"].forEach((s) => $(s).addEventListener("input", drawTable));
    drawTable();
  }

  function drawTable() {
    const q = $("#q").value.toLowerCase(), eco = $("#f-eco").value, kind = $("#f-kind").value, scope = $("#f-scope").value, proj = $("#f-proj").value;
    const rows = R.components.filter((c) =>
      (!q || `${c.name} ${c.purl} ${c.origin.host} ${c.version}`.toLowerCase().includes(q)) &&
      (!eco || c.ecosystem === eco) && (!kind || (kind === "direct") === c.direct) &&
      (!scope || (scope === "dev") === c.dev_only) && (!proj || (c.projects || []).includes(proj)));
    $("#count").textContent = `${rows.length} of ${R.components.length}`;
    const shown = rows.slice(0, 1500);
    $("#ctable tbody").innerHTML = shown.map((c) => {
      const intro = (c.introduced_by || []).slice(0, 2).map((i) => BYID[i]?.name || i).join(", ") + ((c.introduced_by || []).length > 2 ? ` +${c.introduced_by.length - 2}` : "");
      return `<tr class="click" data-id="${esc(c.id)}"><td class="mono">${esc(c.name)}</td><td class="mono">${esc(c.version ?? "—")}</td><td>${ecoDot(c.ecosystem_key, c.ecosystem)}</td>
        <td>${c.direct ? '<span class="pill direct">direct</span>' : c.path_known ? '<span class="pill trans">transitive</span>' : '<span class="pill warn">transitive · path unknown</span>'}</td>
        <td>${c.depth ?? "?"}</td><td>${c.dev_only ? '<span class="pill dev">dev/opt</span>' : "runtime"}</td>
        <td class="mono">${esc(c.origin.host)}</td><td class="mono">${esc(c.direct ? "" : intro)}</td></tr>`;
    }).join("") + (rows.length > shown.length ? `<tr><td colspan="8" class="muted">…${rows.length - shown.length} more, refine the filter</td></tr>` : "");
    bindRowClicks($("#ctable"));
  }

  function bindRowClicks(root) {
    root.querySelectorAll("tr.click[data-id]").forEach((tr) => tr.addEventListener("click", () => openDrawer(tr.dataset.id)));
  }

  // ------------------------------------------------------------ component drawer
  function label(id) {
    if (BYID[id]) return `${BYID[id].name}@${BYID[id].version ?? "?"}`;
    if (PROJ[id]) return PROJ[id].source_file || PROJ[id].name;
    return id;
  }
  function chips(ids, max = 40) {
    if (!ids || !ids.length) return '<span class="muted">none</span>';
    return `<div class="chips">${ids.slice(0, max).map((i) => `<a href="#" data-open="${esc(i)}">${esc(label(i))}</a>`).join("")}${ids.length > max ? ` <span class="muted">+${ids.length - max} more</span>` : ""}</div>`;
  }

  function openDrawer(id) {
    const c = BYID[id];
    if (!c) return;
    const path = c.path_known
      ? `<div class="path"><span class="n">${esc(PROJ[c.path_project]?.source_file || "repo")}</span>${c.path.map((p) => `<span class="a">→</span><span class="n ${p === id ? "me" : ""}">${esc(label(p))}</span>`).join("")}</div>`
      : `<div class="note">Listed in <b class="mono">${esc(c.found_in.join(", "))}</b> as a transitive dependency, but the manifest does not record which dependency pulls it in.</div>`;
    const props = Object.entries(c.properties || {}).filter(([k]) => !k.startsWith("guardian:note"));
    $("#drawer").innerHTML = `<button class="ghost close" id="dclose">Close</button>
      <h2 class="mono" style="margin-top:4px">${esc(c.name)}</h2>
      <div style="margin-bottom:12px">${ecoDot(c.ecosystem_key, c.ecosystem)} &nbsp; ${c.direct ? '<span class="pill direct">direct</span>' : '<span class="pill trans">transitive</span>'} ${c.dev_only ? '<span class="pill dev">dev / optional</span>' : ""}</div>
      <div class="kv">
        <div>version</div><div class="mono">${esc(c.version ?? "unresolved")}</div>
        <div>purl</div><div class="mono" style="word-break:break-all">${esc(c.purl)}</div>
        <div>depth</div><div>${c.depth ?? "unknown"}</div>
        <div>scope</div><div>${esc(c.scope)}</div>
        <div>origin</div><div class="mono" style="word-break:break-all">${esc(c.origin.host)}${c.origin.url ? `<br><span class="muted">${esc(c.origin.url)}</span>` : ""}<br><span class="muted">(${esc(c.origin.source)})</span></div>
        <div>integrity</div><div class="mono" style="word-break:break-all">${c.hashes.length ? c.hashes.map((h) => esc(h.slice(0, 80)) + (h.length > 80 ? "…" : "")).join("<br>") : esc(c.properties["guardian:integrity"] || "none recorded")}</div>
        <div>licenses</div><div>${esc((c.licenses || []).join(", ") || "—")}</div>
        <div>found in</div><div class="mono">${(c.found_in || []).map(esc).join("<br>") || "—"}</div>
        ${c.direct_in && c.direct_in.length ? `<div>direct in</div><div class="mono">${c.direct_in.map((p) => esc(PROJ[p]?.source_file || p)).join("<br>")}</div>` : ""}
      </div>
      ${(COMPISS[id] || []).length ? `<h3 style="color:var(--bad)">Findings (${COMPISS[id].length})</h3>${COMPISS[id].map((fid) => `<div class="fixgroup" data-fid="${esc(fid)}" style="grid-template-columns:auto 1fr">${lvPill(ISS[fid].risk.level)}<div>${esc(ISS[fid].title)}</div></div>`).join("")}` : ""}
      <h3>Dependency path</h3>${path}
      ${c.direct ? "" : `<h3>Introduced by (direct dependencies)</h3>${chips(c.introduced_by)}`}
      <h3>Depended on by (${c.parents.length})</h3>${chips(c.parents)}
      <h3>Depends on (${c.children.length})</h3>${chips(c.children)}
      ${props.length ? `<h3>Properties</h3><div class="kv">${props.map(([k, v]) => `<div class="mono">${esc(k)}</div><div class="mono" style="word-break:break-all">${esc(Array.isArray(v) ? v.join(", ") : v)}</div>`).join("")}</div>` : ""}
      <p style="margin-top:18px"><button class="ghost" id="dgraph">Show in dependency graph</button></p>`;
    $("#drawer").classList.add("on");
    $("#dclose").onclick = () => $("#drawer").classList.remove("on");
    $("#dgraph").onclick = () => { $("#drawer").classList.remove("on"); tab("graph"); focusNode(id); };
    $("#drawer").querySelectorAll("[data-open]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openDrawer(a.dataset.open); }));
    bindFindingClicks($("#drawer"));
  }

  // ------------------------------------------------------------ graph explorer (SVG, no libraries)
  let CH = {}, NODE = {}, RB = {}, expanded = new Set(), highlight = new Set(), limits = {}, riskOnly = false;
  const SERIOUS = (l) => l === "critical" || l === "high";
  const leadsToRisk = (id) => SERIOUS(NODE[id]?.risk) || (RB[id] && RB[id].serious > 0);
  function setupGraph() {
    GRAPH.nodes.forEach((n) => (NODE[n.id] = n));
    GRAPH.edges.forEach(([a, b]) => (CH[a] = CH[a] || []).push(b));
    const order = (id) => { const n = NODE[id]; return n.kind === "project" ? 0 : n.direct ? 1 : 2; };
    Object.values(CH).forEach((arr) => arr.sort((a, b) => order(a) - order(b) || (NODE[a].label || "").localeCompare(NODE[b].label || "")));
    $("#gopts").innerHTML = R.components.slice(0, 3000).map((c) => `<option value="${esc(c.name)}@${esc(c.version ?? "")}">`).join("");
    $("#glegend").innerHTML = Object.entries({ npm: "npm", maven: "Maven", pypi: "PyPI", golang: "Go", docker: "Container image", githubactions: "GitHub Actions" })
      .map(([k, v]) => `<span>${ecoDot(k, v)}</span>`).join("") + `<span>◉ = has dependencies (click to expand)</span><span><b style="color:var(--accent)">D</b> = direct dependency</span><span><b style="color:#8a94a6">T2, T3…</b> = transitive at depth 2, 3…</span><span>dashed = dev / optional</span><span>↺ = cycle</span>`;
    // RB[id] = findings in the subtree below a node (so collapsed nodes can say "▸ 3 below")
    const PAR = {};
    GRAPH.edges.forEach(([a, b]) => (PAR[b] = PAR[b] || []).push(a));
    GRAPH.nodes.filter((n) => n.risk).forEach((n) => {
      const seen = new Set([n.id]), q = [...(PAR[n.id] || [])];
      while (q.length) {
        const a = q.shift();
        if (seen.has(a)) continue;
        seen.add(a);
        const r = (RB[a] = RB[a] || { n: 0, serious: 0, worst: n.risk });
        r.n += 1;
        if (SERIOUS(n.risk)) r.serious += 1;
        if (LV_ORDER[n.risk] < LV_ORDER[r.worst]) r.worst = n.risk;
        (PAR[a] || []).forEach((p) => q.push(p));
      }
    });
    $("#glegend").innerHTML += `<span><b style="color:${RISK_COLOR.critical}">⚠ red / orange</b> = component with findings</span><span>▸ N below = findings deeper in that branch</span>`;
    $("#gfind").onclick = () => {
      riskOnly = !riskOnly;
      $("#gfind").textContent = riskOnly ? "Show the whole graph" : "Only paths to critical & high findings";
      resetGraph();
      if (riskOnly) {
        // open every branch that leads to a critical/high finding; everything else is hidden
        Object.keys(NODE).forEach((id) => { if (RB[id] && RB[id].serious > 0) expanded.add(id); });
        Object.keys(CH).forEach((id) => { limits[id] = 500; });
      }
      drawGraph();
      $("#gbox").scrollTop = 0; $("#gbox").scrollLeft = 0;
    };
    $("#greset").onclick = () => { riskOnly = false; $("#gfind").textContent = "Only paths to critical & high findings"; resetGraph(); drawGraph(); };
    $("#gexpand").onclick = () => { Object.keys(NODE).filter((id) => NODE[id].kind !== "component").forEach((id) => expanded.add(id)); drawGraph(); };
    $("#gfocus").onclick = () => {
      const v = $("#gq").value.trim();
      const c = R.components.find((c) => `${c.name}@${c.version ?? ""}` === v) || R.components.find((c) => c.name === v || c.name.includes(v));
      if (c) focusNode(c.id);
    };
    resetGraph(); drawGraph();
  }
  function resetGraph() {
    expanded = new Set([GRAPH.nodes[0].id]); highlight = new Set(); limits = {};
    const projects = GRAPH.nodes.filter((n) => n.kind === "project");
    if (projects.length <= 3) projects.forEach((p) => expanded.add(p.id));
  }
  function focusNode(id) {
    const c = BYID[id];
    if (!c) return;
    riskOnly = false;
    $("#gfind").textContent = "Only paths to critical & high findings";
    resetGraph();
    highlight = new Set([id]);
    const chain = [GRAPH.nodes[0].id];
    if (c.path_project) chain.push(c.path_project);
    chain.push(...c.path);
    chain.forEach((n) => { expanded.add(n); highlight.add(n); });
    expanded.delete(id);
    // make sure the focused node is within the shown children limit of each parent
    for (let i = 0; i < chain.length - 1; i++) {
      const kids = CH[chain[i]] || [];
      const idx = kids.indexOf(chain[i + 1]);
      if (idx >= 0) limits[chain[i]] = Math.max(limits[chain[i]] || 30, idx + 5);
    }
    $("#gq").value = `${c.name}@${c.version ?? ""}`;
    drawGraph(id);
  }

  function drawGraph(scrollTo) {
    const ROW = 22, COL = 280, rows = [];
    // Build visible tree (DAG unfolded, cycles cut).
    function build(id, depth, onPath, key) {
      const kids = riskOnly ? (CH[id] || []).filter(leadsToRisk) : (CH[id] || []);
      const node = { id, key, depth, kids: [], more: 0, total: kids.length, cycle: onPath.has(id) };
      if (expanded.has(id) && !node.cycle) {
        const lim = limits[id] || 30;
        const p2 = new Set(onPath).add(id);
        kids.slice(0, lim).forEach((k, i) => { const c = build(k, depth + 1, p2, `${key}/${i}`); c.parentId = id; node.kids.push(c); });
        node.more = Math.max(0, kids.length - lim);
      }
      return node;
    }
    const tree = build(GRAPH.nodes[0].id, 0, new Set(), "r");
    let y = 0, maxDepth = 0;
    (function place(n) {
      maxDepth = Math.max(maxDepth, n.depth);
      if (!n.kids.length && !n.more) { n.y = y++; return; }
      n.kids.forEach(place);
      if (n.more) { n.moreY = y++; }
      const ys = n.kids.map((k) => k.y).concat(n.more ? [n.moreY] : []);
      n.y = (Math.min(...ys) + Math.max(...ys)) / 2;
    })(tree);
    const W = (maxDepth + 1) * COL + 80, H = Math.max(y, 1) * ROW + 40;
    const X = (d) => 20 + d * COL, Y = (r) => 20 + r * ROW;
    let edges = "", nodes = "", focusY = null;
    (function draw(n, parentKind) {
      const meta = NODE[n.id] || {};
      const isComp = meta.kind === "component";
      const directHere = isComp && parentKind && parentKind !== "component";
      const depDepth = isComp ? n.depth - 1 : 0;   // repo=0, project=1, direct dependency=2 → depth 1
      const risk = meta.risk;
      const color = risk ? RISK_COLOR[risk] : meta.kind === "repo" ? "#0f1a1f" : meta.kind === "project" ? "var(--accent)" : ECO_COLOR[meta.eco] || "var(--other)";
      const below = RB[n.id];
      const x = X(n.depth), yy = Y(n.y), hasKids = n.total > 0;
      n.kids.forEach((k) => {
        const x2 = X(k.depth), y2 = Y(k.y), dash = NODE[k.id]?.dev ? 'stroke-dasharray="4 3"' : "";
        const hl = highlight.has(n.id) && highlight.has(k.id);
        const directEdge = meta.kind === "project" && NODE[k.id]?.kind === "component";
        const kr = NODE[k.id]?.risk || RB[k.id]?.worst;
        const riskEdge = kr && (kr === "critical" || kr === "high");
        edges += `<path d="M${x + 6},${yy} C${x + COL / 2},${yy} ${x2 - COL / 2},${y2} ${x2 - 6},${y2}" fill="none" stroke="${hl ? "var(--accent)" : riskEdge ? "#e9a3a8" : directEdge ? "#7fbfba" : "#c9ced8"}" stroke-width="${hl ? 2.2 : riskEdge ? 1.6 : directEdge ? 1.5 : 1}" ${dash}/>`;
        draw(k, meta.kind);
      });
      if (n.more) edges += `<text x="${X(n.depth + 1)}" y="${Y(n.moreY) + 4}" fill="var(--accent)" style="cursor:pointer" data-more="${esc(n.id)}">… ${n.more} more</text>`;
      const lab = (meta.label || n.id);
      const short = lab.length > 36 ? lab.slice(0, 35) + "…" : lab;
      const isHl = highlight.has(n.id);
      if (isHl && scrollTo === n.id) focusY = yy;
      nodes += `<g data-node="${esc(n.id)}" style="cursor:${hasKids ? "pointer" : "default"}">
        ${risk ? `<circle cx="${x}" cy="${yy}" r="10" fill="${RISK_COLOR[risk]}" opacity="0.18"/>` : ""}
        <circle cx="${x}" cy="${yy}" r="${risk ? 6 : hasKids ? 6 : 4}" fill="${risk || (hasKids && !expanded.has(n.id)) ? color : "#fff"}" stroke="${color}" stroke-width="2"/>
        ${isHl ? `<rect x="${x + 9}" y="${yy - 9}" width="${short.length * 7 + 8}" height="18" rx="4" fill="var(--accent-soft)"/>` : ""}
        <text x="${x + 12}" y="${yy + 4}" data-label="${esc(n.id)}" fill="${meta.kind === "component" ? "var(--ink)" : color}" font-weight="${!isComp || directHere ? 600 : 400}">${isComp ? (directHere ? '<tspan fill="var(--accent)" font-weight="700">D </tspan>' : `<tspan fill="#8a94a6">T${depDepth} </tspan>`) : ""}${esc(short)}${n.cycle ? " ↺" : ""}${meta.unknown_parent ? ' <tspan fill="var(--warn)">(parent unknown)</tspan>' : ""}${hasKids && !expanded.has(n.id) ? ` <tspan fill="#8a94a6">(+${n.total})</tspan>` : ""}${risk ? ` <tspan fill="${RISK_COLOR[risk]}" font-weight="700">⚠ ${meta.ni} ${risk}</tspan>` : ""}${!expanded.has(n.id) && below ? ` <tspan fill="${RISK_COLOR[below.worst]}">▸ ${below.n} below</tspan>` : ""}</text>
        <title>${esc(lab)}${risk ? `\n${meta.ni} finding(s), worst: ${risk}. Click the label for details.` : ""}${isComp ? (directHere ? `\nDIRECT dependency of ${esc(NODE[n.parentId]?.label || "")}` : `\nTRANSITIVE dependency, depth ${depDepth} (pulled in by ${esc(NODE[n.parentId]?.label || "")})`) : ""}</title></g>`;
    })(tree, null);
    $("#gbox").innerHTML = `<svg width="${W}" height="${H}">${edges}${nodes}</svg>`;
    $("#gbox").querySelectorAll("g[data-node] circle").forEach((c) => c.addEventListener("click", () => toggle(c.parentNode.dataset.node)));
    $("#gbox").querySelectorAll("text[data-label]").forEach((t) => t.addEventListener("click", () => {
      const id = t.dataset.label;
      if (BYID[id]) openDrawer(id); else toggle(id);
    }));
    $("#gbox").querySelectorAll("text[data-more]").forEach((t) => t.addEventListener("click", () => { limits[t.dataset.more] = (limits[t.dataset.more] || 30) + 50; drawGraph(); }));
    if (focusY !== null) $("#gbox").scrollTop = Math.max(0, focusY - 300);
  }
  function toggle(id) {
    if (!(CH[id] || []).length) return;
    expanded.has(id) ? expanded.delete(id) : expanded.add(id);
    drawGraph();
  }

  // ------------------------------------------------------------ containers & CI
  function renderArtifacts() {
    const yesno = (v, good) => v ? `<span class="pill ${good ? "ok" : "bad"}">yes</span>` : `<span class="pill ${good ? "warn" : "ok"}">no</span>`;
    const pinPill = (p) => ({ "commit-sha": '<span class="pill ok">commit SHA</span>', tag: '<span class="pill warn">tag</span>', "branch-or-other": '<span class="pill bad">branch / other</span>', none: '<span class="pill bad">none</span>' }[p] || `<span class="pill trans">${esc(p)}</span>`);
    const imgs = [];
    R.containers.dockerfiles.forEach((d) => d.images.forEach((i) => imgs.push({ src: d.file, ...i })));
    R.containers.compose.forEach((d) => d.images.forEach((i) => imgs.push({ src: `${d.file} (service ${i.service})`, ...i })));
    R.ci_cd.workflows.forEach((w) => w.images.forEach((i) => imgs.push({ src: `${w.file}:${i.line}`, ...i })));
    const external = imgs.filter((i) => !i.internal_stage);
    let html = `<div class="panel"><h2>Container images (${external.length} references, ${new Set(external.map((i) => i.reference)).size} unique)</h2><p class="sub">Base images from Dockerfiles (every build stage), compose files and workflow job containers. Internal multi-stage references are listed for completeness.</p>
      <div class="scroll"><table><tr><th>Source</th><th>Image reference</th><th>Registry</th><th>Tag</th><th>Pinned by digest</th><th>Uses :latest</th></tr>
      ${imgs.map((i) => i.internal_stage ? `<tr><td class="mono">${esc(i.src)}</td><td class="mono muted" colspan="5">FROM ${esc(i.reference)} (earlier build stage)</td></tr>` :
        `<tr><td class="mono">${esc(i.src)}${i.stage_alias ? ` <span class="muted">as ${esc(i.stage_alias)}</span>` : ""}</td><td class="mono" style="word-break:break-all">${esc(i.reference)}</td><td class="mono">${esc(i.registry)}</td><td class="mono">${esc(i.tag ?? (i.implicit_tag ? "(none → latest)" : "—"))}</td><td>${yesno(i.pinned_by_digest, true)}</td><td>${i.uses_latest ? '<span class="pill bad">yes</span>' : '<span class="pill ok">no</span>'}</td></tr>`).join("")}</table></div>`;
    const obs = R.containers.dockerfiles.flatMap((d) => d.observations.filter((o) => o.type !== "user").map((o) => ({ f: d.file, ...o })));
    if (obs.length) html += `<h3>Notable Dockerfile instructions</h3><table>${obs.map((o) => `<tr><td class="mono">${esc(o.f)}</td><td>${esc(o.type)}</td><td class="mono">${esc(o.detail)}</td></tr>`).join("")}</table>`;
    html += `</div>`;
    const uses = R.ci_cd.workflows.flatMap((w) => w.uses.map((u) => ({ file: w.file, ...u })));
    const byPin = uses.reduce((a, u) => ((a[u.pin] = (a[u.pin] || 0) + 1), a), {});
    html += `<div class="panel"><h2>CI/CD components (${uses.length} action references in ${R.ci_cd.workflows.length} workflows)</h2>
      <p class="sub">Pinning: ${Object.entries(byPin).map(([k, v]) => `${pinPill(k)} ${v}`).join(" &nbsp; ")}</p>
      <div class="scroll"><table><tr><th>Workflow</th><th>Line</th><th>Uses</th><th>Pinned to</th><th>Version comment</th><th>Publisher</th></tr>
      ${uses.map((u) => `<tr><td class="mono">${esc(u.file.replace(".github/workflows/", ""))}</td><td>${u.line}</td><td class="mono" style="word-break:break-all">${esc(u.uses)}</td><td>${pinPill(u.pin)}</td><td class="mono">${esc(u.version_comment || "")}</td><td>${u.kind === "local-action" ? "this repo" : u.first_party ? "GitHub" : `third-party (${esc(u.owner || "")})`}</td></tr>`).join("")}</table></div>
      <h3>Workflow triggers and permissions</h3><table><tr><th>Workflow</th><th>Triggers</th><th>Top-level permissions</th></tr>
      ${R.ci_cd.workflows.map((w) => `<tr><td class="mono">${esc(w.file)}</td><td class="mono">${esc((w.triggers || []).join(", "))}</td><td class="mono">${esc(w.top_level_permissions == null ? "not set (repo default)" : JSON.stringify(w.top_level_permissions))}</td></tr>`).join("")}</table></div>`;
    $("#t-artifacts").innerHTML = html;
  }

  // ------------------------------------------------------------ projects / detection
  function renderProjects() {
    const d = R.detection;
    const list = (arr) => arr.length ? arr.map((x) => `<div class="mono">${esc(typeof x === "string" ? x : `${x.file}  (${x.ecosystem})`)}</div>`).join("") : '<span class="muted">none</span>';
    const counts = {};
    R.components.forEach((c) => (c.projects || []).forEach((p) => (counts[p] = (counts[p] || 0) + 1)));
    const directs = {};
    R.components.forEach((c) => (c.direct_in || []).forEach((p) => (directs[p] = (directs[p] || 0) + 1)));
    $("#t-projects").innerHTML = `<div class="panel"><h2>Sources of supply chain data</h2><table><tr><th>File</th><th>Ecosystem</th><th>How it was resolved</th><th>Direct</th><th>Total</th><th>Complete</th></tr>
      ${R.projects.filter((p) => !p.is_repo_root).map((p) => `<tr><td class="mono">${esc(p.source_file || p.name)}</td><td>${esc(p.ecosystem || "")}</td><td>${esc(p.method)}</td><td>${directs[p.id] || 0}</td><td>${counts[p.id] || 0}</td><td>${p.complete ? '<span class="pill ok">yes</span>' : '<span class="pill warn">partial</span>'}</td></tr>`).join("")}</table></div>
      <div class="split"><div class="panel"><h2>Detected</h2>
        <h3>npm projects</h3>${list(d.npm_projects)}<h3>Maven projects</h3>${list(d.maven_projects)}<h3>Python files</h3>${list(d.python_files)}<h3>Go modules</h3>${list(d.go_modules)}</div>
      <div class="panel"><h2>&nbsp;</h2><h3>Dockerfiles</h3>${list(d.dockerfiles)}<h3>Compose files</h3>${list(d.compose_files)}<h3>Workflows</h3>${list(d.workflows)}
        <h3>Other ecosystems (need cdxgen)</h3>${list(d.other_ecosystems)}
        ${R.generated_lockfiles.length ? `<h3>Lockfiles generated at scan time</h3>${list(R.generated_lockfiles)}` : ""}</div></div>`;
  }

  async function renderFiles() {
    const dl = (n, d) => `<tr><td class="mono">${n}</td><td>${d}</td><td><a class="btn ghost" href="${API}/${n}?download=1">download</a> <a class="btn ghost" href="${API}/${n}" target="_blank">open</a></td></tr>`;
    const log = await fetch(`${API}/log.txt`).then((r) => r.text()).catch(() => "");
    $("#t-files").innerHTML = `<div class="panel"><h2>Outputs</h2><table>
      ${dl("bom.cdx.json", "CycloneDX 1.6 SBOM (feed this to Grype, OSV-Scanner, Dependency-Track, dep-scan)")}
      ${dl("result.json", "Normalized components, paths, origins, container & CI facts (input for Day-1 steps 3-5)")}
      ${dl("graph.json", "Dependency graph: nodes and edges")}
      ${dl("findings.json", "Steps 3–5: every finding with evidence, root cause, fix and risk level")}
      ${R.vulnerabilities ? dl("vulns.json", "Step 3: vulnerabilities, root causes and fix groups") : ""}
      ${dl("log.txt", "Every command the Guardian ran")}</table></div>
      <div class="panel"><h2>Run log</h2><pre class="log">${esc(log)}</pre></div>`;
  }

  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#drawer").classList.remove("on"); });
  poll();
})();
