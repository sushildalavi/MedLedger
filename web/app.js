const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  token: localStorage.getItem("medledger.token") || null,
  user: localStorage.getItem("medledger.user") || null,
  role: localStorage.getItem("medledger.role") || null,
};

const PATIENTS = Array.from({ length: 10 }, (_, i) => `patient_${String(i + 1).padStart(2, "0")}`);

function setSession(user, role, token) {
  state.user = user;
  state.role = role;
  state.token = token;
  if (user) {
    localStorage.setItem("medledger.user", user);
    localStorage.setItem("medledger.role", role);
    localStorage.setItem("medledger.token", token);
  } else {
    localStorage.removeItem("medledger.user");
    localStorage.removeItem("medledger.role");
    localStorage.removeItem("medledger.token");
  }
  render();
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
  try { data = await resp.json(); } catch (_) { data = null; }
  return { status: resp.status, data };
}

function render() {
  const signedIn = Boolean(state.token);
  $("#login").hidden = signedIn;
  $("#session-label").textContent = signedIn ? `${state.user} (${state.role})` : "not signed in";
  $("#logout").hidden = !signedIn;

  $("#doctor").hidden = !(signedIn && (state.role === "doctor" || state.role === "admin"));
  $("#patient").hidden = !(signedIn && state.role === "patient");
  $("#audit").hidden = !(signedIn && (state.role === "audit" || state.role === "admin"));
  $("#verify").hidden = !signedIn;
  $("#storage").hidden = !(signedIn && state.role === "admin");
}

function fillPatientSelect() {
  const sel = $("#access-patient");
  sel.innerHTML = "";
  for (const p of PATIENTS) {
    const opt = document.createElement("option");
    opt.value = p; opt.textContent = p;
    sel.appendChild(opt);
  }
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  const user = $("#login-user").value.trim();
  const password = $("#login-pass").value;
  const { status, data } = await api("POST", "/auth/login", { user, password });
  if (status !== 200) {
    $("#login-error").textContent = data?.error || `login failed (${status})`;
    return;
  }
  setSession(user, data.role, data.token);
});

$("#logout").addEventListener("click", () => setSession(null, null, null));

$("#access-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const patient_id = $("#access-patient").value;
  const action = $("#access-action").value;
  const { status, data } = await api("POST", "/ehr/access", { patient_id, action });
  $("#access-result").textContent = `[${status}] ${JSON.stringify(data, null, 2)}`;
});

async function loadPatientRecords() {
  const target = state.user;
  const { status, data } = await api("GET", `/audit/patient/${target}`);
  const wrap = $("#patient-records");
  wrap.innerHTML = "";
  if (status !== 200) {
    wrap.innerHTML = `<div class="record">[${status}] ${JSON.stringify(data)}</div>`;
    return;
  }
  if (!data.records.length) {
    wrap.innerHTML = `<div class="record muted">no audit events on record yet.</div>`;
    return;
  }
  for (const r of data.records) renderRecord(wrap, r);
}

async function loadAllRecords() {
  const { status, data } = await api("GET", `/audit/all`);
  const wrap = $("#audit-records");
  wrap.innerHTML = "";
  if (status !== 200) {
    wrap.innerHTML = `<div class="record">[${status}] ${JSON.stringify(data)}</div>`;
    return;
  }
  for (const r of data.records) renderRecord(wrap, r);
}

function renderRecord(wrap, r) {
  const div = document.createElement("div");
  div.className = "record";
  div.innerHTML = `
    <div class="meta">block #${r.index} on ${r.node_id} &middot; committed ${r.commit_timestamp} &middot; event ${r.event_id}</div>
    <div>${r.record.user_id} <strong>${r.record.action}</strong>'d ${r.record.patient_id} at ${r.record.timestamp}</div>
  `;
  wrap.appendChild(div);
}

$("#patient-refresh").addEventListener("click", loadPatientRecords);
$("#audit-refresh").addEventListener("click", loadAllRecords);

$("#verify-run").addEventListener("click", async () => {
  const { status, data } = await api("GET", "/verify");
  const out = $("#verify-result");
  out.innerHTML = "";
  if (status !== 200) {
    out.innerHTML = `<pre class="result">[${status}] ${JSON.stringify(data, null, 2)}</pre>`;
    return;
  }
  const statusEl = document.createElement("div");
  statusEl.className = `verify-status ${data.system_status}`;
  statusEl.textContent = `system status: ${data.system_status} (${data.mode} mode)`;
  out.appendChild(statusEl);

  for (const node of data.nodes) {
    const row = document.createElement("div");
    row.className = `node-row ${node.valid ? "ok" : "bad"}`;
    row.innerHTML = `
      <span><strong>${node.node_id}</strong></span>
      <span>${node.valid ? "valid" : `${node.reason} @ block ${node.block_index ?? "?"}`}</span>
    `;
    out.appendChild(row);
  }
  if (data.cross_node_issues?.length) {
    const wrap = document.createElement("div");
    wrap.className = "cross-issues";
    wrap.innerHTML = `<div class="muted">cross-node issues:</div>`;
    for (const issue of data.cross_node_issues) {
      const div = document.createElement("div");
      div.className = "cross-issue";
      div.textContent = JSON.stringify(issue);
      wrap.appendChild(div);
    }
    out.appendChild(wrap);
  }
});

$("#storage-refresh").addEventListener("click", async () => {
  const { status, data } = await api("GET", "/admin/storage/companyA");
  $("#storage-result").textContent = `[${status}] ${JSON.stringify(data, null, 2)}`;
});

fillPatientSelect();
render();
