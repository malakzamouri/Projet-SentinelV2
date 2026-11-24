// Sentinel — tout le texte venant du réseau est inséré avec textContent : jamais d'innerHTML (protection XSS).
const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
};
const fmtBytes = (n) => {
  const u = ["o", "Ko", "Mo", "Go", "To"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("fr-FR");
const getJSON = async (url) => { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); };

// ---------- onglets ----------
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach((p) => (p.hidden = p.id !== "tab-" + b.dataset.tab));
  if (b.dataset.tab === "connections") loadConnections();
  if (b.dataset.tab === "interfaces") loadInterfaces();
  if (b.dataset.tab === "quarantine") loadQuarantine();
}));

// ---------- état + graphique ----------
function drawChart(history) {
  const c = $("#chart"), dpr = window.devicePixelRatio || 1;
  c.width = c.clientWidth * dpr; c.height = 140 * dpr;
  const g = c.getContext("2d"); g.scale(dpr, dpr);
  const w = c.clientWidth, h = 140, css = getComputedStyle(document.documentElement);
  g.clearRect(0, 0, w, h);
  if (history.length < 2) return;
  const max = Math.max(10, ...history.map((p) => p.pps));
  g.strokeStyle = css.getPropertyValue("--accent"); g.lineWidth = 2; g.beginPath();
  history.forEach((p, i) => {
    const x = (i / (history.length - 1)) * w, y = h - 8 - (p.pps / max) * (h - 20);
    i ? g.lineTo(x, y) : g.moveTo(x, y);
  });
  g.stroke();
  g.fillStyle = css.getPropertyValue("--muted"); g.font = "12px sans-serif";
  g.fillText(`max ${max} paquets/s`, 4, 12);
}

async function refreshStatus() {
  try {
    const s = await getJSON("/api/status");
    $("#state").textContent = s.running ? "Surveillance active" : "Surveillance arrêtée";
    $("#state").className = "state " + (s.running ? "on" : "off");
    const b = $("#banner");
    const msg = s.error || (s.dropped ? `${s.dropped} paquets ignorés : le trafic dépasse la capacité de traitement.` : "");
    b.hidden = !msg; b.textContent = msg;
    $("#k-packets").textContent = s.packets.toLocaleString("fr-FR");
    $("#k-rate").textContent = s.history.length ? s.history[s.history.length - 1].pps : 0;
    $("#k-high").textContent = s.alert_counts.high;
    $("#k-medium").textContent = s.alert_counts.medium;
    const ul = $("#protos"); ul.replaceChildren();
    Object.entries(s.protocols).sort((a, b) => b[1] - a[1]).forEach(([k, v]) => {
      const li = el("li"); li.append(el("span", null, k), el("span", null, v.toLocaleString("fr-FR"))); ul.append(li);
    });
    drawChart(s.history);
  } catch { $("#state").textContent = "Serveur injoignable"; $("#state").className = "state off"; }
}

// ---------- alertes ----------
let lastId = 0;
async function refreshAlerts() {
  try {
    const list = await getJSON("/api/alerts?since=" + lastId);
    const feed = $("#alerts");
    list.forEach((a) => {
      lastId = Math.max(lastId, a.id);
      const li = el("li", a.severity);
      li.append(el("time", null, fmtTime(a.ts)), el("span", "what", a.type));
      const route = [a.src, a.dst].filter(Boolean).join(" → ");
      li.append(el("span", "detail", route ? `${a.message} (${route})` : a.message));
      feed.prepend(li);
    });
    while (feed.children.length > 200) feed.lastChild.remove();
    $("#alerts-empty").hidden = feed.children.length > 0;
  } catch { /* on réessaiera au prochain cycle */ }
}
$("#clear").addEventListener("click", async () => {
  await fetch("/api/alerts/clear", { method: "POST" });
  $("#alerts").replaceChildren(); $("#alerts-empty").hidden = false;
});

// ---------- connexions & interfaces ----------
async function loadConnections() {
  const rows = (await getJSON("/api/connections")).sort((a, b) => !!b.suspicious - !!a.suspicious);
  const body = $("#conn-body"); body.replaceChildren();
  rows.forEach((c) => {
    const tr = el("tr", c.suspicious ? "flag" : "");
    const proc = c.process ? `${c.process} (${c.pid})` : "—";
    [proc, c.local, c.remote || "—", c.suspicious || c.status].forEach((t) => tr.append(el("td", null, t)));
    body.append(tr);
  });
}
async function loadInterfaces() {
  const rows = await getJSON("/api/interfaces");
  const body = $("#if-body"); body.replaceChildren();
  rows.forEach((i) => {
    const tr = el("tr");
    [i.name, i.up ? "actif" : "inactif", i.ips.join(", ") || "—", fmtBytes(i.bytes_recv), fmtBytes(i.bytes_sent)]
      .forEach((t) => tr.append(el("td", null, t)));
    body.append(tr);
  });
}

// ---------- analyse de fichier ----------
$("#scan-file").addEventListener("change", (e) => {
  $("#scan-label").textContent = e.target.files[0] ? e.target.files[0].name : "Choisir un fichier à analyser";
});
$("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = $("#scan-file").files[0]; if (!file) return;
  const fd = new FormData(); fd.append("file", file); fd.append("quarantine", $("#scan-quarantine").checked ? "1" : "0");
  const v = $("#scan-verdict"); $("#scan-result").hidden = false; v.className = ""; v.textContent = "Analyse en cours…";
  $("#scan-meta").replaceChildren(); $("#scan-findings").replaceChildren();
  const r = await fetch("/api/scan", { method: "POST", body: fd });
  const d = await r.json();
  if (!r.ok) { v.textContent = d.error || "Échec de l'analyse."; return; }
  v.className = d.verdict === "malveillant" ? "malveillant" : d.verdict === "suspect" ? "suspect" : "ok";
  v.textContent = `Verdict : ${d.verdict} (score ${d.score}/100)` + (d.quarantined ? " — mis en quarantaine" : "");
  [["Fichier", d.filename], ["Type", d.type], ["Taille", fmtBytes(d.size)], ["Entropie", d.entropy], ["SHA256", d.sha256], ["MD5", d.md5]]
    .forEach(([k, val]) => { $("#scan-meta").append(el("dt", null, k), el("dd", null, val)); });
  if (!d.findings.length) $("#scan-findings").append(el("li", null, "Aucun indice de malveillance détecté."));
  d.findings.forEach((f) => $("#scan-findings").append(el("li", null, `${f.label} (+${f.points})`)));
});

// ---------- quarantaine ----------
async function loadQuarantine() {
  const rows = await getJSON("/api/quarantine");
  const body = $("#q-body"); body.replaceChildren();
  $("#q-empty").hidden = rows.length > 0;
  rows.forEach((m) => {
    const tr = el("tr"), del = el("button", "ghost", "Supprimer");
    del.addEventListener("click", async () => { await fetch("/api/quarantine/" + m.sha256, { method: "DELETE" }); loadQuarantine(); });
    const last = el("td"); last.append(del);
    tr.append(el("td", null, m.name), el("td", null, `${m.verdict} (${m.score}/100)`), el("td", null, m.sha256.slice(0, 16) + "…"), last);
    body.append(tr);
  });
}

refreshStatus(); refreshAlerts();
setInterval(refreshStatus, 2000);
setInterval(refreshAlerts, 2000);
