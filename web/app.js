// MedLedger web client
// Single-page app: sign-in -> role-aware sidebar shell.
// Talks to the same gateway endpoints used by cli.py.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const PATIENTS = Array.from({ length: 10 }, (_, i) => `patient_${String(i + 1).padStart(2, "0")}`);

const VIEW_TITLES = {
  overview: { title: "Overview", subtitle: "System status and recent activity." },
  generate: { title: "New Access Event", subtitle: "Record a new EHR access event in the audit log." },
  patient:  { title: "My Audit Trail", subtitle: "Every access event recorded against your record." },
  audit:    { title: "All Records", subtitle: "Decrypted audit events across every patient." },
  verify:   { title: "Integrity Check", subtitle: "Replay each chain locally and compare hashes across nodes." },
  storage:  { title: "Storage Inspector", subtitle: "Raw on-disk view — proves no plaintext PHI is stored." },
};

const ROLE_LABEL = { patient: "Patient", doctor: "Doctor", audit: "Audit Company", admin: "Administrator" };

// ----- session ----------------------------------------------------------
const state = {
  token: localStorage.getItem("medledger.token") || null,
  user:  localStorage.getItem("medledger.user")  || null,
  role:  localStorage.getItem("medledger.role")  || null,
  view:  null,
};

function setSession(user, role, token) {
  state.user = user; state.role = role; state.token = token;
  if (user) {
    localStorage.setItem("medledger.user",  user);
    localStorage.setItem("medledger.role",  role);
    localStorage.setItem("medledger.token", token);
  } else {
    localStorage.removeItem("medledger.user");
    localStorage.removeItem("medledger.role");
    localStorage.removeItem("medledger.token");
  }
  applySession();
}

async function api(method, path, body) {
  const headers = {};
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch (_) { /* ignore */ }
  return { status: resp.status, data };
}

// ----- view switching ---------------------------------------------------
function applySession() {
  document.body.classList.toggle("state-signed-in",  Boolean(state.token));
  document.body.classList.toggle("state-signed-out", !state.token);

  $("#auth-shell").hidden = Boolean(state.token);
  $("#app-shell").hidden  = !state.token;

  if (!state.token) return;

  // user card
  $("#user-name").textContent = state.user;
  $("#user-role").textContent = ROLE_LABEL[state.role] || state.role;
  $("#user-avatar").textContent = (state.user || "?").slice(0, 2).toUpperCase();

  // nav visibility by role
  $$(".nav-item").forEach((el) => {
    const allowed = el.dataset.roles;
    el.hidden = allowed ? !allowed.split(",").includes(state.role) : false;
  });

  // pick a default view if current is hidden / unset
  const visibleNav = $$(".nav-item:not([hidden])");
  const currentEl = state.view ? $(`.nav-item[data-view="${state.view}"]`) : null;
  if (!currentEl || currentEl.hidden) {
    state.view = visibleNav[0]?.dataset.view || "overview";
  }
  showView(state.view);
}

function showView(view) {
  state.view = view;
  $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.view === view));
  $$(".view").forEach((el) => el.hidden = el.dataset.view !== view);
  const meta = VIEW_TITLES[view] || { title: view, subtitle: "" };
  $("#view-title").textContent = meta.title;
  $("#view-subtitle").textContent = meta.subtitle;

  // lazy-load data when switching
  if (view === "overview") refreshOverview();
  if (view === "patient")  loadPatientRecords();
  if (view === "audit")    loadAuditAll();
  if (view === "storage")  loadStorage();
  if (view === "generate") populatePatients();
}

// ----- login -----------------------------------------------------------
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  const user = $("#login-user").value.trim();
  const password = $("#login-pass").value;
  const { status, data } = await api("POST", "/auth/login", { user, password });
  if (status !== 200) {
    $("#login-error").textContent = data?.error || `Sign-in failed (${status}).`;
    return;
  }
  setSession(user, data.role, data.token);
});

$("#logout").addEventListener("click", () => setSession(null, null, null));

$("#nav").addEventListener("click", (e) => {
  const item = e.target.closest(".nav-item");
  if (!item || item.hidden) return;
  showView(item.dataset.view);
});

// ----- generate event --------------------------------------------------
function populatePatients() {
  const sel = $("#access-patient");
  if (sel.options.length) return; // already filled
  for (const p of PATIENTS) {
    const opt = document.createElement("option");
    opt.value = p; opt.textContent = p;
    sel.appendChild(opt);
  }
}

$("#access-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const patient_id = $("#access-patient").value;
  const action = $("#access-action").value;
  const { status, data } = await api("POST", "/ehr/access", { patient_id, action });
  const out = $("#access-result");
  out.hidden = false;
  out.classList.toggle("ok", status === 200);
  out.classList.toggle("bad", status !== 200);
  out.textContent = JSON.stringify(data, null, 2);
});

// ----- overview --------------------------------------------------------
async function refreshOverview() {
  // chain length per node + verify summary
  let report = null;
  try {
    const { status, data } = await api("GET", "/verify");
    if (status === 200) report = data;
  } catch (_) { /* ignore */ }

  const grid = $("#overview-nodes");
  grid.innerHTML = "";
  const nodeIds = ["companyA", "companyB", "companyC"];
  let totalBlocks = 0;

  for (const nid of nodeIds) {
    const card = document.createElement("div");
    card.className = "node-card";
    const nodeReport = report?.nodes?.find((n) => n.node_id === nid);
    const valid = nodeReport ? nodeReport.valid : null;
    const tip = nodeReport?.block_index;
    const reason = nodeReport?.reason;
    const pillCls = valid === true ? "ok" : valid === false ? "bad" : "muted";
    const label   = valid === true ? "Healthy" : valid === false ? "Compromised" : "Unknown";
    card.innerHTML = `
      <div class="node-card-head">
        <span class="node-id">${nid}</span>
        <span class="pill ${pillCls}"><span class="dot"></span>${label}</span>
      </div>
      <div class="node-meta">
        <dt>Replication</dt><dd class="mono">independent</dd>
      </div>
      <div class="node-meta">
        <dt>Last block reviewed</dt><dd class="mono">${tip ?? "—"}</dd>
      </div>
      ${valid === false ? `<div class="node-meta"><dt>Reason</dt><dd class="mono">${escapeHtml(reason || "")}</dd></div>` : ""}
    `;
    grid.appendChild(card);
  }

  // KPI: blocks committed -> use storage on companyA if admin, otherwise rely on verify report length.
  const role = state.role;
  if (role === "admin") {
    try {
      const { status, data } = await api("GET", "/admin/storage/companyA");
      if (status === 200) totalBlocks = Math.max(0, (data?.blocks?.length || 1) - 1);
    } catch (_) { /* ignore */ }
  } else if (report?.nodes?.length) {
    // fallback: estimate from any node's max block index
    const tips = report.nodes.map((n) => n.block_index).filter((x) => typeof x === "number");
    totalBlocks = tips.length ? Math.max(...tips) : 0;
  }

  // System status KPI
  const sysOk = report && report.system_status === "valid";
  const sysBad = report && report.system_status === "compromised";
  $("#kpi-status").innerHTML = sysOk
    ? `<span class="pill ok"><span class="dot"></span>Healthy</span>`
    : sysBad
      ? `<span class="pill bad"><span class="dot"></span>Compromised</span>`
      : `<span class="pill muted"><span class="dot"></span>Unverified</span>`;
  $("#kpi-status-sub").textContent = sysOk
    ? "All chains agree. No tampering detected."
    : sysBad
      ? "Cross-node disagreement detected. See Integrity Check."
      : "Run an integrity check to refresh.";

  $("#kpi-blocks").textContent = totalBlocks > 0 ? totalBlocks : "0";
  $("#kpi-mode").textContent = report?.mode === "quorum" ? "Quorum" : (report?.mode === "strict" ? "Strict" : "—");
  $("#kpi-mode-sub").textContent = report?.mode === "quorum"
    ? "2 of 3 acknowledgements per write."
    : "3 of 3 acknowledgements per write.";
}

$("#overview-refresh").addEventListener("click", refreshOverview);

// ----- patient records -------------------------------------------------
async function loadPatientRecords() {
  $("#patient-self-id").textContent = state.user || "";
  const tbody = $("#patient-table tbody");
  tbody.innerHTML = "";
  const empty = $("#patient-empty");
  empty.hidden = true;

  const { status, data } = await api("GET", `/audit/patient/${state.user}`);
  if (status !== 200) {
    empty.hidden = false;
    empty.textContent = `Could not load records (${status}).`;
    return;
  }
  if (!data.records.length) { empty.hidden = false; return; }
  for (const r of data.records) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${r.index}</td>
      <td class="mono tight">${escapeHtml(r.record.timestamp)}</td>
      <td class="mono">${escapeHtml(r.record.user_id)}</td>
      <td><span class="action-tag" data-action="${r.record.action}">${r.record.action}</span></td>
      <td class="mono tight">${escapeHtml(r.commit_timestamp)}</td>
    `;
    tbody.appendChild(tr);
  }
}

$("#patient-refresh").addEventListener("click", loadPatientRecords);

// ----- audit-all -------------------------------------------------------
let auditAllCache = [];

async function loadAuditAll() {
  const tbody = $("#audit-table tbody");
  tbody.innerHTML = "";
  const empty = $("#audit-empty");
  empty.hidden = true;

  const { status, data } = await api("GET", `/audit/all`);
  if (status !== 200) {
    empty.hidden = false;
    empty.textContent = `Could not load records (${status}).`;
    return;
  }
  auditAllCache = data.records || [];
  renderAuditAll();
}

function renderAuditAll() {
  const tbody = $("#audit-table tbody");
  const empty = $("#audit-empty");
  const filter = ($("#audit-filter").value || "").toLowerCase().trim();
  tbody.innerHTML = "";
  const filtered = auditAllCache.filter((r) => {
    if (!filter) return true;
    return [r.record.patient_id, r.record.user_id, r.record.action]
      .some((s) => s && s.toLowerCase().includes(filter));
  });
  if (!filtered.length) { empty.hidden = false; return; }
  empty.hidden = true;
  for (const r of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${r.index}</td>
      <td class="mono">${escapeHtml(r.record.patient_id)}</td>
      <td class="mono">${escapeHtml(r.record.user_id)}</td>
      <td><span class="action-tag" data-action="${r.record.action}">${r.record.action}</span></td>
      <td class="mono tight">${escapeHtml(r.record.timestamp)}</td>
      <td class="mono tight">${escapeHtml(r.event_id.slice(0, 8))}…</td>
    `;
    tbody.appendChild(tr);
  }
}

$("#audit-refresh").addEventListener("click", loadAuditAll);
$("#audit-filter").addEventListener("input", renderAuditAll);

// ----- verify ----------------------------------------------------------
$("#verify-run").addEventListener("click", async () => {
  const out = $("#verify-result");
  out.innerHTML = `<div class="muted" style="font-size: 12.5px; padding: 8px 0;">Running…</div>`;
  const { status, data } = await api("GET", "/verify");
  if (status !== 200) {
    out.innerHTML = `<div class="commit-result bad">${escapeHtml(JSON.stringify(data, null, 2))}</div>`;
    return;
  }
  renderVerify(out, data);
});

function renderVerify(out, data) {
  out.innerHTML = "";
  const sysOk = data.system_status === "valid";
  const summary = document.createElement("div");
  summary.className = `verify-summary ${sysOk ? "ok" : "bad"}`;
  summary.innerHTML = `
    <span class="pill ${sysOk ? "ok" : "bad"}"><span class="dot"></span>${sysOk ? "Valid" : "Compromised"}</span>
    <div class="summary-text">
      <strong>${sysOk ? "All chains agree" : "Cross-node disagreement detected"}</strong>
      <span>Replication mode: ${data.mode} · ${data.nodes?.length || 0} nodes inspected</span>
    </div>
  `;
  out.appendChild(summary);

  const nodesWrap = document.createElement("div");
  nodesWrap.className = "records-table-wrap";
  for (const n of data.nodes || []) {
    const row = document.createElement("div");
    row.className = `node-row ${n.valid ? "ok" : "bad"}`;
    row.innerHTML = `
      <div class="node-name">${escapeHtml(n.node_id || "?")}</div>
      <div class="node-detail">${n.valid ? "Local replay successful, signatures verified." : escapeHtml(n.reason || "")}${n.block_index != null ? ` <span class="muted">— block #${n.block_index}</span>` : ""}</div>
      <span class="pill ${n.valid ? "ok" : "bad"}"><span class="dot"></span>${n.valid ? "OK" : "Failed"}</span>
    `;
    nodesWrap.appendChild(row);
  }
  out.appendChild(nodesWrap);

  if (data.cross_node_issues?.length) {
    const t = document.createElement("div");
    t.className = "cross-issues-title";
    t.textContent = `Cross-node issues (${data.cross_node_issues.length})`;
    out.appendChild(t);
    for (const issue of data.cross_node_issues) {
      const div = document.createElement("div");
      div.className = "cross-issue";
      div.textContent = JSON.stringify(issue);
      out.appendChild(div);
    }
  }
}

// ----- storage inspector ----------------------------------------------
async function loadStorage() {
  const out = $("#storage-result");
  out.innerHTML = `<div class="muted" style="font-size: 12.5px; padding: 8px 0;">Loading…</div>`;
  const { status, data } = await api("GET", "/admin/storage/companyA");
  if (status !== 200) {
    out.innerHTML = `<div class="commit-result bad">${escapeHtml(JSON.stringify(data, null, 2))}</div>`;
    return;
  }
  renderStorage(out, data.blocks || []);
}

function renderStorage(out, blocks) {
  out.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.className = "storage-wrap";
  const table = document.createElement("table");
  table.className = "storage-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Index</th>
        <th>Event ID</th>
        <th>Committed</th>
        <th>patient_id_hash</th>
        <th>Ciphertext (base64)</th>
        <th>Block hash</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;
  const tbody = table.querySelector("tbody");
  for (const b of blocks) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${b.index}</td>
      <td title="${escapeHtml(b.event_id)}">${escapeHtml(short(b.event_id))}</td>
      <td>${escapeHtml(b.commit_timestamp)}</td>
      <td title="${escapeHtml(b.patient_id_hash)}">${escapeHtml(short(b.patient_id_hash))}</td>
      <td class="cipher-cell" title="${escapeHtml(b.ciphertext)}">${escapeHtml(b.ciphertext || "—")}</td>
      <td title="${escapeHtml(b.hash)}">${escapeHtml(short(b.hash))}</td>
    `;
    tbody.appendChild(tr);
  }
  wrap.appendChild(table);
  out.appendChild(wrap);
}

// ----- helpers ---------------------------------------------------------
function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
function short(s) {
  if (!s) return "—";
  if (s.length <= 14) return s;
  return s.slice(0, 8) + "…" + s.slice(-4);
}

// ----- init ------------------------------------------------------------
applySession();
