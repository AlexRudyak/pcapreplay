"use strict";
// pcapreplay GUI. Flow: open a capture -> pick conversations -> say how/where/how fast -> Send.
// All server-supplied text is inserted with textContent, never innerHTML.

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

// ---------- state ----------
const S = {
  info: {}, path: "", analysisPath: "", limits: { filter: "", start: 0, count: 0 },
  data: null,            // analysis summary
  selected: [],          // chosen conversations (+ optional per-conversation changes)
  proto: "all", q: "",   // list view filters
  mode: "",              // "tcp" | "udp" | "": never guessed
  lastState: "idle", lastKind: "", view: "cfg", summaryKey: "", screen: "welcome",
};
let poller = null, toastTimer = null;
const MAX_ROWS = 500;

const SERVICES = { 20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
  137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
  587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1521: "Oracle", 1883: "MQTT", 3306: "MySQL", 3389: "Remote Desktop", 5060: "SIP",
  5353: "mDNS", 5432: "PostgreSQL", 5683: "CoAP", 6379: "Redis", 8080: "HTTP (alt)", 8443: "HTTPS (alt)", 9200: "Elasticsearch", 27017: "MongoDB" };
function serviceName(c) {
  if (c.proto === "icmp" || c.proto === "icmp6") return "Ping (ICMP)";
  return SERVICES[c.serverPort] || (c.proto.toUpperCase() + " port " + c.serverPort);
}

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

// ---------- formatting ----------
const nf = new Intl.NumberFormat();
const fmtInt = (n) => nf.format(Math.round(n));
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
function fmtDur(s) {
  if (s < 1) return Math.round(s * 1000) + " ms";
  if (s < 90) return s.toFixed(1) + " s";
  const m = Math.floor(s / 60); return m + " min " + Math.round(s - m * 60) + " s";
}
const baseName = (p) => p.split(/[\\/]/).filter(Boolean).pop() || p;
const dirName = (p) => p.replace(/[\\/][^\\/]*$/, "");
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const ep = (ip, port, proto) => (proto === "icmp" || proto === "icmp6") ? ip : (ip.includes(":") ? "[" + ip + "]:" + port : ip + ":" + port);
const isSendable = (c) => c.proto === "tcp" || c.proto === "udp";

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 7000);
}
function show(screen) {
  S.screen = screen;
  for (const id of ["welcome", "analyzing", "work", "history"]) $("#" + id).hidden = id !== screen;
}

// ---------- recent files ----------
function recents() { try { return JSON.parse(localStorage.getItem("pcapreplay.recent") || "[]"); } catch (_) { return []; } }
function addRecent(p) { try { localStorage.setItem("pcapreplay.recent", JSON.stringify([p, ...recents().filter((x) => x !== p)].slice(0, 6))); } catch (_) { /* storage unavailable */ } }
function saveSession() { try { localStorage.setItem("pcapreplay.session", JSON.stringify({ path: S.path, limits: S.limits })); } catch (_) { /* ignore */ } }

function fileList(ul, items) {
  ul.replaceChildren();
  for (const it of items) {
    const li = el("li"); li.tabIndex = 0;
    li.append(el("span", "fn", it.name), el("span", "fp", it.path), ...(it.size ? [el("span", "muted", fmtBytes(it.size))] : []));
    const go = () => openCapture(it.path);
    li.onclick = go; li.onkeydown = (e) => { if (e.key === "Enter") go(); };
    ul.append(li);
  }
}
function renderWelcomeLists() {
  const samples = S.info.samples || [];
  $("#samplesBox").hidden = !samples.length; fileList($("#sampleList"), samples);
  const rec = recents().map((p) => ({ name: baseName(p), path: p }));
  $("#recentBox").hidden = !rec.length; fileList($("#recentList"), rec);
}

// ---------- opening and analysing ----------
async function openCapture(path) {
  path = (path || "").trim();
  if (!path) return;
  if (path !== S.analysisPath) {
    S.selected.length = 0; S.data = null; S.proto = "all"; S.q = ""; $("#search").value = "";
    S.limits = { filter: "", start: 0, count: 0 };
  }
  S.path = path; $("#path").value = path;
  await analyze();
}

async function analyze() {
  $("#welcomeError").hidden = true;
  try { await api("/api/stats", { path: S.path, ...S.limits, top: 15 }); }
  catch (e) { analysisFailed(e.message); return; }
  S.summaryKey = "";
  $("#anName").textContent = "Reading " + baseName(S.path) + "…";
  $("#anBar").style.width = "0%"; $("#anText").textContent = "";
  show("analyzing");
  startPolling();
}

function analysisFailed(msg) {
  if (S.data) { show("work"); toast(msg); }
  else { show("welcome"); const e = $("#welcomeError"); e.textContent = msg; e.hidden = false; renderWelcomeLists(); }
}

$("#pathForm").addEventListener("submit", (e) => { e.preventDefault(); openCapture($("#path").value); });
$("#anCancel").onclick = () => api("/api/cancel", {}).catch(() => {});

function handleStats(s) {
  const running = s.state === "running";
  if (running && s.scan) {
    $("#anBar").style.width = s.scan.percent.toFixed(1) + "%";
    $("#anText").textContent = fmtInt(s.scan.packets) + " packets · " + fmtBytes(s.scan.bytes) + (s.scan.total ? " of " + fmtBytes(s.scan.total) : "") + " · " + fmtDur(s.elapsedSec);
    if (S.screen !== "analyzing" && S.screen !== "history") show("analyzing");
    return;
  }
  if (s.state === "failed") { analysisFailed(s.error || "The capture could not be read."); return; }
  const key = s.kind + "|" + s.elapsedSec + "|" + (s.summary ? s.summary.packets : "");
  if (s.summary && key !== S.summaryKey) {
    S.summaryKey = key;
    onAnalyzed(s.summary, s.state === "cancelled");
  } else if (s.state === "cancelled" && !S.data) { show("welcome"); }
  else if (s.state === "cancelled") { show("work"); }
}

function onAnalyzed(sum, partial) {
  S.data = sum; S.analysisPath = S.path;
  addRecent(S.path); saveSession();
  // drop selections whose conversation is no longer part of the (re-)analysis
  const have = new Set(sum.conversations.map((c) => c.selector));
  const before = S.selected.length;
  for (let i = S.selected.length - 1; i >= 0; i--) if (!have.has(S.selected[i].selector)) S.selected.splice(i, 1);
  if (S.screen === "history") H.prevScreen = "work"; else show("work");
  if (S.restore) applyRestore();
  if (before > S.selected.length) toast(plural(before - S.selected.length, "selected conversation") + " no longer match the limits and were unselected.");
  if (partial) toast("Analysis was stopped early: the list is incomplete.");
  renderFileBar(); renderPills(); renderList(); refreshSend();
}

function renderFileBar() {
  const s = S.data;
  $("#fName").textContent = baseName(S.path); $("#fName").title = S.path;
  const bits = [fmtInt(s.packets) + " packets", fmtBytes(s.capBytes)];
  if (s.durationSec) bits.push(fmtDur(s.durationSec));
  bits.push(plural(s.conversationsTotal, "conversation"));
  const lim = [];
  if (S.limits.filter.trim()) lim.push("filtered");
  if (S.limits.start) lim.push("from packet " + fmtInt(S.limits.start));
  if (S.limits.count) lim.push("max " + fmtInt(S.limits.count) + " packets");
  $("#fMeta").textContent = bits.join(" · ") + (lim.length ? "  ·  limited: " + lim.join(", ") : "");
}

// ---------- file dialog ----------
const fileDlg = $("#fileDlg");
let parentDir = "";
async function loadDir(path) {
  try {
    const d = await api("/api/fs?path=" + encodeURIComponent(path || ""));
    parentDir = d.parent;
    $("#curDir").textContent = d.path; $("#up").disabled = !d.parent;
    const ul = $("#entries"); ul.replaceChildren();
    if (!d.entries.length) ul.append(el("li", "muted", "No folders or capture files here"));
    for (const e of d.entries) {
      const li = el("li");
      li.append(el("span", "", (e.dir ? "📁  " : "📄  ") + e.name), el("span", "sz", e.dir ? "" : fmtBytes(e.size)));
      li.onclick = () => {
        const full = d.path.replace(/[\\/]$/, "") + (d.path.includes("\\") ? "\\" : "/") + e.name;
        if (e.dir) loadDir(full); else { fileDlg.close(); openCapture(full); }
      };
      ul.append(li);
    }
  } catch (err) { $("#entries").replaceChildren(el("li", "muted", err.message)); }
}
function openFileDialog() {
  const q = $("#quick"); q.replaceChildren();
  const add = (label, path) => { const b = el("button", "small", label); b.type = "button"; b.onclick = () => loadDir(path); q.append(b); };
  if (S.info.home) add("Home", S.info.home);
  if (S.info.cwd) add("Current folder", S.info.cwd);
  for (const r of (S.info.roots || []).slice(0, 8)) add(r, r);
  for (const s of (S.info.samples || []).slice(0, 1)) add("Examples", dirName(s.path));
  fileDlg.showModal();
  loadDir((S.path ? dirName(S.path) : (S.info.samples && S.info.samples[0] ? dirName(S.info.samples[0].path) : S.info.cwd)) || S.info.home);
}
$("#openBtn").onclick = openFileDialog;
$("#changeBtn").onclick = openFileDialog;
$("#up").onclick = () => parentDir && loadDir(parentDir);

// ---------- details and limits dialogs ----------
function bars(container, rows, nameOf, valOf, fmtVal) {
  container.replaceChildren();
  if (!rows || !rows.length) { container.append(el("div", "muted", "none")); return; }
  const max = Math.max(...rows.map(valOf)) || 1;
  for (const r of rows) {
    const row = el("div", "brow"), track = el("div", "track"), i = el("i");
    i.style.width = (100 * valOf(r) / max).toFixed(1) + "%"; track.append(i);
    row.append(el("span", "name", nameOf(r)), track, el("span", "val", fmtVal(valOf(r))));
    container.append(row);
  }
}
$("#detailsBtn").onclick = () => {
  const s = S.data; if (!s) return;
  const k = $("#kpis"); k.replaceChildren();
  const rate = s.durationSec > 0 ? s.wireBytes * 8 / s.durationSec / 1e6 : 0;
  for (const [v, l] of [[fmtInt(s.packets), "packets (" + s.format + ")"], [fmtBytes(s.capBytes), "captured"], [s.durationSec ? fmtDur(s.durationSec) : "–", "duration"],
    [rate ? rate.toFixed(2) + " Mbit/s" : "–", "average rate"], [fmtInt(s.conversationsTotal), "conversations"], [fmtInt(s.truncated), "cut-off packets"]]) {
    const d = el("div", "kpi"); d.append(el("b", "", v), el("span", "", l)); k.append(d);
  }
  const tot = s.protocols.reduce((a, p) => a + p.packets, 0) || 1;
  bars($("#protoBars"), s.protocols, (p) => p.name, (p) => p.packets, (n) => fmtInt(n) + " · " + (100 * n / tot).toFixed(0) + "%");
  bars($("#talkers"), s.talkers, (t) => t.addr, (t) => t.bytes, fmtBytes);
  bars($("#tcpPorts"), s.tcpPorts, (p) => (SERVICES[p.port] ? SERVICES[p.port] + " (" + p.port + ")" : String(p.port)), (p) => p.packets, (n) => fmtInt(n));
  bars($("#udpPorts"), s.udpPorts, (p) => (SERVICES[p.port] ? SERVICES[p.port] + " (" + p.port + ")" : String(p.port)), (p) => p.packets, (n) => fmtInt(n));
  $("#detailsDlg").showModal();
};

let filterTimer;
$("#filter").addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(async () => {
    const f = $("#filter"), m = $("#filterMsg");
    try {
      const r = await api("/api/filter/check", { filter: f.value });
      f.style.borderColor = r.ok ? "" : "var(--err)";
      m.textContent = r.ok ? (f.value.trim() ? "Filter is valid." : "") : r.error; m.style.color = r.ok ? "" : "var(--err)";
    } catch (_) { /* transient */ }
  }, 250);
});
$("#limitBtn").onclick = () => {
  $("#filter").value = S.limits.filter; $("#start").value = S.limits.start; $("#count").value = S.limits.count;
  $("#limitDlg").showModal();
};
$("#limitReset").onclick = () => { $("#filter").value = ""; $("#start").value = 0; $("#count").value = 0; };
$("#limitApply").onclick = () => {
  S.limits = { filter: $("#filter").value, start: Math.max(0, parseInt($("#start").value, 10) || 0), count: Math.max(0, parseInt($("#count").value, 10) || 0) };
  $("#limitDlg").close(); saveSession(); analyze();
};
$("#moreBtn").onclick = () => { $("#tcpOpts").hidden = S.mode !== "tcp"; $("#moreDlg").showModal(); };
$("#moreDone").onclick = () => { $("#moreDlg").close(); refreshSend(); };

// ---------- conversation list ----------
function renderPills() {
  const box = $("#protoPills"); box.replaceChildren();
  const all = S.data.conversations;
  const cnt = { all: all.length, tcp: all.filter((c) => c.proto === "tcp").length, udp: all.filter((c) => c.proto === "udp").length, other: all.filter((c) => !isSendable(c)).length };
  for (const [k, label] of [["all", "All"], ["tcp", "TCP"], ["udp", "UDP"], ["other", "Other"]]) {
    if (k === "other" && !cnt.other) continue;
    const b = el("button", "", label + " " + cnt[k]); b.type = "button"; b.setAttribute("aria-pressed", String(S.proto === k));
    b.onclick = () => { S.proto = k; renderPills(); renderList(); };
    box.append(b);
  }
}
const selIdx = (sel) => S.selected.findIndex((r) => r.selector === sel);
const matchesView = (c) => {
  if (S.proto === "tcp" && c.proto !== "tcp") return false;
  if (S.proto === "udp" && c.proto !== "udp") return false;
  if (S.proto === "other" && isSendable(c)) return false;
  const q = S.q.trim().toLowerCase();
  return !q || (c.selector + " " + serviceName(c) + " " + c.state).toLowerCase().includes(q);
};

function eff(r) {
  const tIp = $("#tIp").value.trim(), tPort = parseInt($("#tPort").value, 10) || 0;
  return { cIp: r.clientIp || r.c.ip, cPort: Number(r.clientPort) || r.c.port, sIp: r.serverIp || tIp || r.s.ip, sPort: Number(r.serverPort) || tPort || r.s.port };
}
const isChanged = (r) => { const e = eff(r); return e.cIp !== r.c.ip || e.cPort !== r.c.port || e.sIp !== r.s.ip || e.sPort !== r.s.port || r.replace.trim() !== ""; };

function renderList() {
  if (!S.data) return;
  const list = $("#list"), keep = list.scrollTop;
  list.replaceChildren();
  const rows = S.data.conversations.filter(matchesView);
  for (const c of rows.slice(0, MAX_ROWS)) list.append(itemEl(c));
  if (!rows.length) list.append(el("div", "empty", S.data.conversations.length ? "No conversation matches your search." : "This capture contains no conversations."));
  const notes = [];
  if (rows.length > MAX_ROWS) notes.push("Showing the " + MAX_ROWS + " largest matches: search to narrow the list.");
  if (S.data.conversationsTotal > S.data.conversations.length) notes.push("Only the " + fmtInt(S.data.conversations.length) + " largest of " + fmtInt(S.data.conversationsTotal) + " conversations are listed.");
  if (S.data.conversationsUntracked > 0) notes.push(fmtInt(S.data.conversationsUntracked) + " further packets could not be grouped.");
  notes.push("“→” goes from the side that started the conversation to the service it talked to.");
  $("#listNote").textContent = notes.join(" ");
  list.scrollTop = keep;
  syncSelAll();
}

function itemEl(c) {
  const sendable = isSendable(c), idx = selIdx(c.selector), r = idx >= 0 ? S.selected[idx] : null;
  const it = el("div", "item" + (r ? " sel" : "") + (sendable ? "" : " off"));
  it.dataset.sel = c.selector;
  const cb = el("input"); cb.type = "checkbox"; cb.checked = !!r; cb.disabled = !sendable; cb.setAttribute("aria-label", "Select " + c.selector);
  cb.onclick = (e) => e.stopPropagation();
  cb.onchange = () => toggle(c, cb.checked);
  if (sendable) it.onclick = () => cb.click();

  const svc = el("div", "svc"); svc.append(el("b", "", serviceName(c)));
  const tag = el("span", "tag " + c.proto, c.proto.toUpperCase());
  svc.append(tag);

  const ends = el("div", "ends"); ends.append(endsLine(c, r));
  const meta = el("div", "meta");
  meta.append(document.createTextNode(plural(c.packets, "packet") + " · " + fmtBytes(c.bytes)));
  if (c.proto === "tcp" && c.state && c.state !== "-") { meta.append(document.createElement("br")); meta.append(el("span", "state " + c.state.split(" ")[0], c.state)); }
  else if (!sendable) { meta.append(document.createElement("br")); meta.append(el("span", "state", "can’t be replayed")); }

  it.append(cb, svc, ends, meta);
  const edit = el("button", "small edit", r && r.open ? "Done" : "Change…"); edit.type = "button";
  if (r) { edit.onclick = (e) => { e.stopPropagation(); r.open = !r.open; renderList(); }; it.append(edit); } else it.append(el("span"));
  if (r && r.open) it.append(editorEl(c, r));
  return it;
}

function endsLine(c, r) {
  const wrap = el("div"), line = el("div", "line");
  const e = r ? eff(r) : { cIp: c.clientIp, cPort: c.clientPort, sIp: c.serverIp, sPort: c.serverPort };
  const from = el("span", "ep" + (r && (e.cIp !== c.clientIp || e.cPort !== c.clientPort) ? " changed" : ""), ep(e.cIp, e.cPort, c.proto));
  const to = el("span", "ep" + (r && (e.sIp !== c.serverIp || e.sPort !== c.serverPort) ? " changed" : ""), ep(e.sIp, e.sPort, c.proto));
  line.append(from, el("span", "arrow", "→"), to);
  wrap.append(line);
  if (r && isChanged(r)) wrap.append(el("div", "also", "was " + ep(c.clientIp, c.clientPort, c.proto) + " → " + ep(c.serverIp, c.serverPort, c.proto)));
  return wrap;
}

function editorEl(c, r) {
  const box = el("div", "editor"); box.onclick = (e) => e.stopPropagation();
  const g = el("div", "eg");
  const set = (legend, ipKey, portKey, orig) => {
    const fs = el("fieldset"); fs.append(el("legend", "", legend));
    const row = el("div", "row");
    const ip = el("input", "grow"); ip.type = "text"; ip.value = r[ipKey]; ip.placeholder = orig.ip; ip.spellcheck = false; ip.setAttribute("aria-label", legend + " address");
    ip.oninput = () => { r[ipKey] = ip.value.trim(); sync(); };
    row.append(ip);
    if (c.proto === "tcp" || c.proto === "udp") {
      const pt = el("input", "port"); pt.type = "number"; pt.min = 0; pt.max = 65535; pt.value = r[portKey]; pt.placeholder = String(orig.port); pt.setAttribute("aria-label", legend + " port");
      pt.oninput = () => { r[portKey] = pt.value.trim(); sync(); };
      row.append(pt);
    }
    fs.append(row); return fs;
  };
  // Same left-to-right order as the arrow in the row: source on the left, destination on the right.
  g.append(set("Source (who started it)", "clientIp", "clientPort", r.c), set("Destination (the service)", "serverIp", "serverPort", r.s));
  const det = el("details"); det.append(el("summary", "", "Change text inside the payload"));
  const ta = el("textarea"); ta.rows = 2; ta.spellcheck = false; ta.placeholder = "old=>new   (one per line)"; ta.value = r.replace;
  ta.oninput = () => { r.replace = ta.value; sync(); }; det.append(ta); if (r.replace) det.open = true;
  const prev = el("div", "preview");
  function sync() {
    const it = box.parentElement;
    if (it) { const slot = it.querySelector(".ends"); slot.replaceChildren(endsLine(c, r)); }
    const e = eff(r);
    prev.replaceChildren(document.createTextNode("will be sent as  "), el("b", "", ep(e.cIp, e.cPort, c.proto) + "  →  " + ep(e.sIp, e.sPort, c.proto)));
    refreshSend();
  }
  sync();
  box.append(g, det, prev);
  return box;
}

function toggle(c, on) {
  if (on) {
    if (S.mode === "tcp") S.selected.length = 0;     // TCP sends one conversation: the new pick replaces the old
    if (selIdx(c.selector) < 0) S.selected.push({ selector: c.selector, proto: c.proto, c: { ip: c.clientIp, port: c.clientPort }, s: { ip: c.serverIp, port: c.serverPort },
      clientIp: "", clientPort: "", serverIp: "", serverPort: "", replace: "", open: false });
  } else { const i = selIdx(c.selector); if (i >= 0) S.selected.splice(i, 1); }
  renderList(); refreshSend();
}

function syncSelAll() {
  const shown = S.data.conversations.filter((c) => matchesView(c) && isSendable(c)).slice(0, MAX_ROWS);
  const n = shown.filter((c) => selIdx(c.selector) >= 0).length;
  const cb = $("#selAll");
  cb.checked = shown.length > 0 && n === shown.length; cb.indeterminate = n > 0 && n < shown.length;
  cb.disabled = !shown.length || S.mode === "tcp";
  $("#selAllText").textContent = S.mode === "tcp" ? "TCP sends one at a time" : (n ? n + " selected" : "Select all");
}
$("#selAll").onchange = () => {
  const shown = S.data.conversations.filter((c) => matchesView(c) && isSendable(c)).slice(0, MAX_ROWS);
  if ($("#selAll").checked) for (const c of shown) { if (selIdx(c.selector) < 0) toggleQuiet(c); }
  else for (const c of shown) { const i = selIdx(c.selector); if (i >= 0) S.selected.splice(i, 1); }
  renderList(); refreshSend();
};
function toggleQuiet(c) {
  S.selected.push({ selector: c.selector, proto: c.proto, c: { ip: c.clientIp, port: c.clientPort }, s: { ip: c.serverIp, port: c.serverPort },
    clientIp: "", clientPort: "", serverIp: "", serverPort: "", replace: "", open: false });
}
$("#search").addEventListener("input", () => { S.q = $("#search").value; if (S.data) renderList(); });

// ---------- send panel ----------
$$("#modeSeg button").forEach((b) => b.onclick = () => {
  S.mode = b.dataset.mode;
  if (S.mode === "tcp" && S.selected.length > 1) { /* keep, but the panel asks the user to reduce */ }
  renderList(); refreshSend();
});
$("#keepFirst").onclick = () => { S.selected.length = Math.min(1, S.selected.length); renderList(); refreshSend(); };
$("#speed").onchange = () => { $("#customSpeed").hidden = $("#speed").value !== "custom"; refreshSend(); };
$("#recOn").onchange = () => {
  const p = $("#recPath"); p.hidden = !$("#recOn").checked;
  if (!p.hidden && !p.value && S.path) p.value = S.path.replace(/\.(pcapng|pcap|cap)$/i, "") + "-sent.pcapng";
  refreshSend();
};
for (const id of ["#tIp", "#tPort"]) $(id).addEventListener("input", () => { renderListSoft(); refreshSend(); });
function renderListSoft() { if (S.data) { $$("#list .item").forEach((it) => { const r = S.selected[selIdx(it.dataset.sel)]; const c = S.data.conversations.find((x) => x.selector === it.dataset.sel); if (r && c) it.querySelector(".ends").replaceChildren(endsLine(c, r)); }); } }
document.addEventListener("change", (e) => { if (e.target.name === "where") refreshSend(); });
document.addEventListener("input", (e) => { if (e.target.closest("#sendPanel, #moreDlg")) refreshSend(); });

const where = () => (document.querySelector('input[name=where]:checked') || {}).value || "";

function selectionStats() {
  const sel = S.selected;
  const rows = sel.map((r) => S.data && S.data.conversations.find((c) => c.selector === r.selector)).filter(Boolean);
  return { n: sel.length, tcp: sel.filter((r) => r.proto === "tcp").length, udp: sel.filter((r) => r.proto === "udp").length,
    packets: rows.reduce((a, c) => a + c.packets, 0), bytes: rows.reduce((a, c) => a + c.bytes, 0) };
}

function speedBody() {
  const v = $("#speed").value;
  if (v === "orig1") return { paceMode: "original", speed: 1 };
  if (v === "orig2") return { paceMode: "original", speed: 2 };
  if (v === "orig10") return { paceMode: "original", speed: 10 };
  if (v === "burst") return { paceMode: "burst" };
  const t = $("#cType").value, val = $("#cVal").value.trim();
  if (t === "pps") return { paceMode: "pps", pps: parseFloat(val) || 0 };
  if (t === "mbps") return { paceMode: "mbps", mbps: parseFloat(val) || 0 };
  return { paceMode: "fixed", delay: val };
}
function speedText() {
  const v = $("#speed").value;
  if (v === "orig1") return "at the recorded speed";
  if (v === "orig2") return "twice as fast as recorded";
  if (v === "orig10") return "ten times faster than recorded";
  if (v === "burst") return "as fast as possible";
  const t = $("#cType").value, val = $("#cVal").value.trim();
  return t === "pps" ? "at " + val + " packets per second" : t === "mbps" ? "at " + val + " Mbit/s" : "one packet every " + val;
}

function replayBody() {
  const num = (id) => parseInt($(id).value || "0", 10) || 0;
  const tIp = $("#tIp").value.trim(), tPort = parseInt($("#tPort").value, 10) || 0;
  const bulk = $("#bulkReplace").value.split("\n").filter((l) => l.trim());
  const picked = S.selected.filter((r) => r.proto === S.mode);
  return {
    path: S.path, ...S.limits, mode: S.mode, loop: Math.max(1, num("#loop")),
    srcIp: "", dstIp: "", srcPort: 0, dstPort: 0, payload: "", replace: [],
    ...speedBody(), maxGap: "",
    backend: where(), iface: $("#iface").value, srcMac: $("#srcMac").value, dstMac: $("#dstMac").value, ifIndex: num("#ifIndex"), noFirewall: $("#noFirewall").checked,
    seqOffset: num("#seqOffset"), skipBytes: num("#skipBytes"), ackMode: $("#ackMode").value, handshakeTimeout: $("#handshakeTimeout").value,
    record: $("#recOn").checked ? $("#recPath").value.trim() : "", recordRx: $("#recordRx").checked,
    conversations: picked.map((r) => ({
      selector: r.selector, clientIp: r.clientIp, clientPort: Number(r.clientPort) || 0,
      serverIp: r.serverIp || tIp, serverPort: Number(r.serverPort) || tPort,
      replace: [...r.replace.split("\n").filter((l) => l.trim()), ...bulk],
    })),
    onlyConversations: true,
    meta: { speed: $("#speed").value, cType: $("#cType").value, cVal: $("#cVal").value },
  };
}

function refreshSend() {
  if (!S.data) return;
  const st = selectionStats(), elevated = !!S.info.elevated;

  // selection summary
  const sum = $("#selSummary"); sum.replaceChildren();
  if (!st.n) { sum.append(document.createTextNode("Nothing selected yet")); sum.append(el("small", "", "Tick the conversations to send in the list.")); }
  else {
    sum.append(document.createTextNode(plural(st.n, "conversation")));
    const parts = []; if (st.tcp) parts.push(st.tcp + " TCP"); if (st.udp) parts.push(st.udp + " UDP");
    sum.append(el("small", "", parts.join(" · ") + " · " + fmtInt(st.packets) + " packets · " + fmtBytes(st.bytes)));
  }
  $("#keepFirst").hidden = !(S.mode === "tcp" && st.n > 1);
  $("#keepFirst").textContent = "TCP sends one at a time: keep only the first";

  // how
  $$("#modeSeg button").forEach((b) => {
    b.setAttribute("aria-checked", String(b.dataset.mode === S.mode));
    const suggest = !S.mode && st.n && ((b.dataset.mode === "tcp" && st.tcp && !st.udp) || (b.dataset.mode === "udp" && st.udp && !st.tcp));
    b.querySelector(".sug").hidden = !suggest;
  });
  const req = $("#modeReq"); req.textContent = S.mode ? "chosen" : "choose one"; req.className = "req" + (S.mode ? " ok" : "");
  const left = S.mode === "tcp" ? st.udp : S.mode === "udp" ? st.tcp : 0;
  $("#modeHint").textContent = !S.mode ? "The mode is never guessed: pick how the traffic should be sent."
    : S.mode === "tcp" ? "Opens a real connection to the destination and replays what the source sent. One conversation at a time." + (left ? " " + plural(left, "UDP conversation") + " will be left out." : "")
    : "Sends each recorded datagram as it was, for any number of conversations." + (left ? " " + plural(left, "TCP conversation") + " will be left out." : "");

  // where
  const auto = document.querySelector('input[name=where][value=auto]'), nul = document.querySelector('input[name=where][value=null]');
  auto.disabled = !elevated;
  if (!where()) (elevated ? auto : nul).checked = true;
  if (!elevated && auto.checked) nul.checked = true;
  $("#adminNote").hidden = elevated;
  $("#tIp").disabled = $("#tPort").disabled = !st.n;
  $("#targetHint").textContent = st.n ? "Changes the destination of every selected conversation; replies keep matching. You can also set one per conversation (Change…)."
    : "Select conversations first.";

  // can we send?
  const picked = S.selected.filter((r) => r.proto === S.mode).length;
  let why = "";
  if (!st.n) why = "Select at least one conversation.";
  else if (!S.mode) why = "Choose TCP or UDP.";
  else if (!picked) why = "None of the selected conversations is " + S.mode.toUpperCase() + ".";
  else if (S.mode === "tcp" && picked > 1) why = "TCP sends one conversation at a time.";
  else if ($("#recOn").checked && !$("#recPath").value.trim()) why = "Enter where to save the copy, or untick it.";
  else if (S.lastState === "running") why = "Another job is still running.";
  $("#why").textContent = why; $("#why").className = "why" + (why ? " bad" : "");
  $("#sendBtn").disabled = !!why;
  $("#sendBtn").textContent = picked > 1 ? "Send " + picked + " conversations" : "Send";

  // plain-language summary
  const box = $("#sendSummary"); box.replaceChildren();
  if (!why) {
    const b = (t) => { const x = el("b", "", t); box.append(x); }, add = (t) => box.append(document.createTextNode(t));
    add("Will send "); b(plural(picked, S.mode.toUpperCase() + " conversation")); add(" " + speedText() + ", ");
    add(where() === "null" ? "as a test run (nothing leaves this computer)" : "onto the network");
    const tIp = $("#tIp").value.trim(); if (tIp) { add(", to "); b(tIp + ($("#tPort").value ? ":" + $("#tPort").value : "")); }
    if ($("#recOn").checked) add(", saving a copy"); add(".");
  }
}

// ---------- sending and results ----------
$("#sendBtn").onclick = async () => {
  try { await api("/api/replay", replayBody()); S.view = "run"; showRun(); startPolling(); }
  catch (e) { toast(e.message); }
};
$("#stopBtn").onclick = () => api("/api/cancel", {}).catch(() => {});
$("#againBtn").onclick = () => { S.view = "cfg"; showRun(); };
function showRun() { $("#cfgView").hidden = S.view !== "cfg"; $("#runView").hidden = S.view !== "run"; }

async function elevate() {
  try { await api("/api/elevate", {}); toast("A new pcapreplay window is opening with administrator rights. You can close this tab."); }
  catch (e) { toast(e.message); }
}
$("#elevateBtn").onclick = elevate; $("#elevateBtn2").onclick = elevate;

function handleRun(s) {
  if (S.view !== "run") { S.view = "run"; showRun(); }
  if (S.screen !== "work" && S.data) show("work");
  const running = s.state === "running", r = s.replay;
  $("#spin").hidden = !running;
  $("#runTitle").textContent = { running: "Sending…", done: "Finished", failed: "That didn’t work", cancelled: "Stopped" }[s.state] || "Sending…";
  const pill = $("#runPill"); pill.textContent = s.state; pill.className = "pill " + s.state;
  let text = "";
  if (r && s.state === "done") text = "Sent " + fmtInt(r.sent) + " packets (" + fmtBytes(r.bytes) + ") in " + fmtDur(s.elapsedSec) + (where() === "null" ? ". This was a test run: nothing left this computer." : ".");
  else if (r && running) text = "Sent " + fmtInt(r.sent) + " packets so far…";
  else if (s.state === "cancelled") text = "You stopped the replay" + (r ? " after " + fmtInt(r.sent) + " packets." : ".");
  $("#runText").textContent = text;
  const err = $("#runError"); err.hidden = s.state !== "failed"; err.textContent = s.error || "";
  $("#elevateBtn2").hidden = !(s.state === "failed" && /administrator|access denied/i.test(s.error || "") && !S.info.elevated);

  const g = $("#liveGrid"); g.replaceChildren();
  if (r) for (const [v, l] of [[fmtInt(r.sent), "packets sent"], [fmtBytes(r.bytes), "data sent"], [fmtInt(r.pps) + "/s", "packets per second"], [r.mbps.toFixed(1) + " Mbit/s", "speed"]]) {
    const d = el("div"); d.append(el("b", "", v), el("span", "", l)); g.append(d);
  }
  const ti = $("#tcpInfo"); ti.hidden = !s.tcp; ti.replaceChildren();
  if (s.tcp) for (const [k, v] of [["Connection", s.tcp.flow], ["Used source", s.tcp.localIp + ":" + s.tcp.localPort], ["Connect time", s.tcp.handshakeUs ? s.tcp.handshakeUs.toFixed(0) + " µs" : "–"],
    ["Retransmissions", String(s.tcp.retransmits)], ["Server replied with", fmtBytes(s.tcp.rxBytes)], ["Ended", s.tcp.finalState || "–"]]) {
    const d = el("div"); d.append(el("span", "", k), el("span", "", v)); ti.append(d);
  }
  const ri = $("#recInfo"); ri.hidden = !s.recording; ri.replaceChildren();
  if (s.recording) for (const [k, v] of [["Saved to", s.recording.path], ["Packets saved", fmtInt(s.recording.packets)]]) {
    const d = el("div"); d.append(el("span", "", k), el("span", "", v)); ri.append(d);
  }
  $("#log").textContent = s.log.join("\n");
  $("#stopBtn").hidden = !running; $("#againBtn").hidden = running;
  S.lastRunId = s.runId || ""; $("#viewRun").hidden = !s.runId || running;
}
$("#viewRun").onclick = () => { if (S.lastRunId) { openHistory(); openRun(S.lastRunId); } };

// ---------- polling ----------
function startPolling() { clearInterval(poller); poller = setInterval(poll, 400); poll(); }
async function poll() {
  let s;
  try { s = await api("/api/status"); } catch (_) { return; }
  S.lastState = s.state; S.lastKind = s.kind;
  if (s.kind === "stats") handleStats(s); else if (s.kind === "replay") handleRun(s);
  if (s.kind === "replay" && s.state !== "running" && s.runId && S.countedRun !== s.runId) { S.countedRun = s.runId; refreshHistoryCount(); if (S.screen === "history") loadHistory(false); }
  if (S.data) refreshSend();
  if (s.state !== "running") { clearInterval(poller); poller = null; }
}

// ---------- history and pcap library ----------
const H = { enabled: false, tab: "runs", prevScreen: "welcome", runs: [], total: 0, stats: null, settings: null, lib: [], detail: null, pcap: null, pktLoaded: 0, pktTotal: 0 };
const STATE_LABEL = { running: "Running", done: "Finished", failed: "Failed", cancelled: "Stopped", interrupted: "Interrupted" };
const COPY_LABEL = { stored: "Copy stored", reference: "Original only", "too-large": "Too large to copy", removed: "Copy removed", failed: "Copy failed" };

function fmtWhen(iso) {
  const d = new Date(iso), now = new Date(), t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 86400000);
  if (diff === 0) return "Today " + t;
  if (diff === 1) return "Yesterday " + t;
  return d.toLocaleDateString([], { day: "numeric", month: "short", year: d.getFullYear() === now.getFullYear() ? undefined : "numeric" }) + " " + t;
}
const fmtFull = (iso) => new Date(iso).toLocaleString();

async function refreshHistoryCount() {
  try {
    const d = await api("/api/history?limit=1");
    H.enabled = !!d.enabled; H.stats = d.stats || null; H.settings = d.settings || null;
    $("#histBtn").hidden = !H.enabled;
    const n = d.stats ? d.stats.runs : 0;
    $("#histCount").textContent = n; $("#histCount").hidden = !n;
    const p = d.stats ? d.stats.pcaps : 0;
    $("#libCount").textContent = p; $("#libCount").hidden = !p;
  } catch (_) { /* history unavailable */ }
}

function backTarget() { return S.lastState === "running" && S.lastKind === "stats" ? "analyzing" : (S.data ? "work" : "welcome"); }
function openHistory(tab) {
  if (S.screen !== "history") H.prevScreen = S.screen;
  show("history"); setTab(tab || H.tab);
}
function setTab(t) {
  H.tab = t;
  $("#tabRuns").setAttribute("aria-selected", String(t === "runs")); $("#tabLib").setAttribute("aria-selected", String(t === "lib"));
  $("#runsPane").hidden = t !== "runs"; $("#libPane").hidden = t !== "lib";
  if (t === "runs") loadHistory(false); else loadLibrary();
}
$("#histBtn").onclick = () => openHistory();
$("#histBack").onclick = () => show(backTarget());
$("#tabRuns").onclick = () => setTab("runs");
$("#tabLib").onclick = () => setTab("lib");

function statsLine() {
  const s = H.stats; if (!s) return "";
  const mb = (n) => fmtBytes(n);
  return plural(s.runs, "run") + " · " + plural(s.pcaps, "pcap") + " (" + mb(s.pcapBytes) + " of copies)" + (s.packetsBytes ? " · " + mb(s.packetsBytes) + " of packet copies" : "") + " · stored in " + s.dir;
}

// ----- runs -----
const histFilters = () => {
  const p = new URLSearchParams();
  const q = $("#hSearch").value.trim(); if (q) p.set("q", q);
  if ($("#hState").value) p.set("state", $("#hState").value);
  if ($("#hMode").value) p.set("mode", $("#hMode").value);
  if ($("#hPinned").checked) p.set("pinned", "1");
  return p;
};
async function loadHistory(append) {
  const p = histFilters(), filtered = p.toString() !== "";
  p.set("limit", "50"); p.set("offset", append ? String(H.runs.length) : "0");
  let d;
  try { d = await api("/api/history?" + p); } catch (e) { toast(e.message); return; }
  H.enabled = !!d.enabled;
  if (d.enabled) { H.runs = append ? H.runs.concat(d.runs) : d.runs; H.total = d.total; H.stats = d.stats; H.settings = d.settings; }
  renderHistory(filtered);
}
function renderHistory(filtered) {
  const list = $("#hList"); list.replaceChildren();
  for (const r of H.runs) list.append(runRow(r));
  $("#hMore").hidden = H.runs.length >= H.total;
  const empty = $("#hEmpty");
  empty.hidden = H.runs.length > 0;
  empty.textContent = !H.enabled ? "History is turned off." : filtered ? "No run matches your search." : "Nothing has been sent yet. Every run you send is listed here, so you can look at it again or send it again.";
  $("#histSub").textContent = H.enabled ? statsLine() : "";
  const f = histFilters().toString();
  $("#expCsv").href = "/api/history/export?format=csv" + (f ? "&" + f : "");
  $("#expJson").href = "/api/history/export?format=json" + (f ? "&" + f : "");
}
function convSummary(r) {
  const n = r.conversations.length;
  if (n === 1) {
    const c = r.conversations[0], parts = c.selector.split("/");
    let line = parts[1] + " → " + parts[2];
    if (c.newServer) line += "   now → " + c.newServer;
    return line;
  }
  return plural(n, "conversation") + (r.target ? " → " + r.target : "");
}
function runRow(r) {
  const row = el("div", "hrow"); row.tabIndex = 0;
  const main = el("div", "hmain"), title = el("div", "htitle");
  title.append(el("b", "", baseName(r.capture)), el("span", "tag " + r.mode, r.mode.toUpperCase()), el("span", "chip " + (r.dryRun ? "test" : "net"), r.dryRun ? "Test run" : "On the network"));
  main.append(title, el("div", "hsub", convSummary(r)));
  if (r.state === "failed" && r.error) main.append(el("div", "hsub", "⚠ " + r.error));
  if (r.note) main.append(el("div", "hnote", "“" + r.note + "”"));
  const side = el("div", "hside");
  side.append(el("span", "pill " + r.state, STATE_LABEL[r.state] || r.state), el("span", "when", fmtWhen(r.startedAt)));
  side.append(el("span", "res", r.result ? plural(r.result.sent, "packet") + " · " + fmtBytes(r.result.bytes) : "–"));
  const acts = el("div", "acts");
  const star = el("button", "star" + (r.pinned ? " on" : ""), r.pinned ? "★" : "☆"); star.type = "button"; star.title = r.pinned ? "Pinned: never removed automatically" : "Pin"; star.setAttribute("aria-label", "Pin");
  star.onclick = async (e) => { e.stopPropagation(); try { const u = await api("/api/history/" + r.id + "/update", { pinned: !r.pinned }); Object.assign(r, u.run); renderHistory(false); } catch (err) { toast(err.message); } };
  const again = el("button", "small primary", "Send again"); again.type = "button";
  again.onclick = (e) => { e.stopPropagation(); sendAgain(r.id); };
  acts.append(star, again); side.append(acts);
  row.append(el("span", "dot " + r.state), main, side);
  row.onclick = () => openRun(r.id);
  row.onkeydown = (e) => { if (e.key === "Enter") openRun(r.id); };
  return row;
}
let hTimer;
for (const id of ["#hSearch"]) $(id).addEventListener("input", () => { clearTimeout(hTimer); hTimer = setTimeout(() => loadHistory(false), 250); });
for (const id of ["#hState", "#hMode", "#hPinned"]) $(id).addEventListener("change", () => loadHistory(false));
$("#hMore").onclick = () => loadHistory(true);

// ----- run details -----
function armConfirm(btn, label, action) {
  const orig = btn.dataset.label || btn.textContent; btn.dataset.label = orig;
  if (btn.dataset.armed) { clearTimeout(Number(btn.dataset.armed)); delete btn.dataset.armed; btn.textContent = orig; action(); return; }
  btn.textContent = label;
  btn.dataset.armed = String(setTimeout(() => { delete btn.dataset.armed; btn.textContent = orig; }, 4000));
}
function kvRow(box, k, v) { box.append(el("span", "k", k), el("span", "v", v)); }

async function openRun(id) {
  let d;
  try { d = await api("/api/history/" + id); } catch (e) { toast(e.message); return; }
  H.detail = d; const r = d.run;
  $("#rdTitle").textContent = baseName(r.capture);
  const pill = $("#rdPill"); pill.textContent = STATE_LABEL[r.state] || r.state; pill.className = "pill " + r.state;
  $("#rdWhen").textContent = fmtFull(r.startedAt) + (r.result ? " · " + fmtDur(r.result.elapsedMs / 1000) : "");
  const err = $("#rdError"); err.hidden = !(r.error || r.state === "interrupted");
  err.textContent = r.state === "interrupted" ? "The program was closed while this run was still sending." : (r.error || "");

  const f = $("#rdFacts"); f.replaceChildren();
  kvRow(f, "Capture", r.capture);
  const lib = d.pcap;
  kvRow(f, "In the library", lib ? (COPY_LABEL[lib.copyState] || lib.copyState) + (lib.runs > 1 ? " · sent " + lib.runs + " times" : "") : "Not in the library");
  kvRow(f, "Sent as", r.mode.toUpperCase() + (r.loop > 1 ? ", " + r.loop + " passes" : ""));
  kvRow(f, "Where", r.dryRun ? "Test run: nothing left this computer" : "On the network (" + r.backend + ")");
  kvRow(f, "Speed", r.pacing);
  kvRow(f, "Sent to", r.target || "the recorded addresses");

  const cv = $("#rdConvs"); cv.replaceChildren();
  for (const c of r.conversations) {
    const p = c.selector.split("/"), box = el("div", "rdconv");
    box.append(el("span", "ep", p[0].toUpperCase() + "  " + p[1] + " → " + p[2]));
    const ch = []; if (c.newClient) ch.push("source now " + c.newClient); if (c.newServer) ch.push("destination now " + c.newServer); if (c.replace) ch.push(plural(c.replace, "text replacement"));
    box.append(el("small", "", ch.length ? "Changed: " + ch.join(", ") : "Sent exactly as recorded"));
    cv.append(box);
  }
  const g = $("#rdResult"); g.replaceChildren();
  if (r.result) for (const [v, l] of [[fmtInt(r.result.sent), "packets sent"], [fmtBytes(r.result.bytes), "data sent"], [fmtInt(r.result.pps) + "/s", "packets per second"], [r.result.mbps.toFixed(1) + " Mbit/s", "speed"],
    ...(r.result.skipped ? [[fmtInt(r.result.skipped), "skipped"]] : []), ...(r.result.sendErrs ? [[fmtInt(r.result.sendErrs), "send errors"]] : [])]) {
    const x = el("div"); x.append(el("b", "", v), el("span", "", l)); g.append(x);
  }
  const tcp = $("#rdTcp"); tcp.replaceChildren(); tcp.hidden = !r.tcp;
  if (r.tcp) { const t = typeof r.tcp === "string" ? JSON.parse(r.tcp) : r.tcp;
    for (const [k, v] of [["Connection", t.flow], ["Used source", t.localIp + ":" + t.localPort], ["Retransmissions", String(t.retransmits)], ["Server replied with", fmtBytes(t.rxBytes)], ["Ended", t.finalState || "–"]]) {
      const x = el("div"); x.append(el("span", "", k), el("span", "", v)); tcp.append(x);
    } }

  // packets that were transmitted (optional copy)
  $("#rdPkts").replaceChildren(); H.pktLoaded = 0; H.pktTotal = 0;
  const has = d.hasPackets;
  $("#rdPktWrap").hidden = !has; $("#rdMorePkts").hidden = true; $("#rdNoPackets").hidden = has;
  $("#rdPktCount").textContent = has ? "(" + fmtInt(r.packetsCount) + ")" : "";
  if (!has) $("#rdNoPackets").textContent = r.packetsPruned ? "The copy of the transmitted packets was removed to stay within the size limit. The sent pcap itself is kept in the library."
    : (r.result && r.result.sent === 0) ? "No packets were sent."
    : "No copy of the transmitted packets was kept. You can turn this on in History settings; the pcap that was sent is in the library.";
  else loadPackets();
  const dl = $("#rdDownload"); dl.hidden = !has; dl.href = "/api/history/" + r.id + "/packets"; dl.textContent = "Download sent packets";

  $("#rdNote").value = r.note || ""; $("#rdSave").hidden = true;
  $("#rdPin").textContent = r.pinned ? "★ Pinned" : "☆ Pin";
  $("#rdAgain").disabled = !d.openPath; $("#rdAgain").title = d.openPath ? "" : "The capture is no longer available";
  $("#rdDelete").textContent = "Delete"; delete $("#rdDelete").dataset.armed;
  $("#runDlg").showModal();
}
async function loadPackets() {
  const d = H.detail; if (!d) return;
  try {
    const p = await api("/api/history/" + d.run.id + "/preview?offset=" + H.pktLoaded + "&limit=100");
    H.pktTotal = p.total;
    const tb = $("#rdPkts");
    for (const x of p.rows) {
      const tr = el("tr");
      tr.append(el("td", "", String(x.n + 1)), el("td", "", "+" + x.relMs.toFixed(x.relMs < 100 ? 2 : 0) + " ms"), el("td", x.dir, x.dir === "out" ? "→" : x.dir === "in" ? "←" : ""),
        el("td", "mono", x.src && x.dst ? x.src + " → " + x.dst : ""), el("td", "", x.proto), el("td", "num", String(x.len)), el("td", "info", x.info));
      tb.append(tr);
    }
    H.pktLoaded += p.rows.length;
    $("#rdMorePkts").hidden = H.pktLoaded >= H.pktTotal;
    $("#rdMorePkts").textContent = "Show more packets (" + fmtInt(H.pktTotal - H.pktLoaded) + " left)";
  } catch (e) { $("#rdNoPackets").hidden = false; $("#rdNoPackets").textContent = e.message; }
}
$("#rdMorePkts").onclick = loadPackets;
$("#rdNote").addEventListener("input", () => { $("#rdSave").hidden = $("#rdNote").value === (H.detail.run.note || ""); });
$("#rdSave").onclick = async () => {
  try { const u = await api("/api/history/" + H.detail.run.id + "/update", { note: $("#rdNote").value }); H.detail.run = u.run; $("#rdSave").hidden = true; toast("Note saved."); if (S.screen === "history") loadHistory(false); } catch (e) { toast(e.message); }
};
$("#rdPin").onclick = async () => {
  try { const u = await api("/api/history/" + H.detail.run.id + "/update", { pinned: !H.detail.run.pinned }); H.detail.run = u.run; $("#rdPin").textContent = u.run.pinned ? "★ Pinned" : "☆ Pin"; if (S.screen === "history") loadHistory(false); } catch (e) { toast(e.message); }
};
$("#rdDelete").onclick = () => armConfirm($("#rdDelete"), "Click again to delete", async () => {
  try { await api("/api/history/" + H.detail.run.id + "/delete", {}); $("#runDlg").close(); toast("Run deleted."); refreshHistoryCount(); loadHistory(false); } catch (e) { toast(e.message); }
});
$("#rdAgain").onclick = () => sendAgain(H.detail.run.id, H.detail);

// ----- send again -----
async function sendAgain(id, detail) {
  let d = detail;
  if (!d || d.run.id !== id) { try { d = await api("/api/history/" + id); } catch (e) { toast(e.message); return; } }
  if (!d.openPath) { toast("The capture is no longer available: the original was moved or deleted and no copy was kept in the library."); return; }
  let req = {};
  try { req = typeof d.run.request === "string" ? JSON.parse(d.run.request) : (d.run.request || {}); } catch (_) { /* restore what we can */ }
  $("#runDlg").close();
  S.restore = { req, meta: d.run.meta || {}, when: d.run.startedAt, usingCopy: d.openPath !== d.run.capture };
  S.selected.length = 0; S.data = null; S.analysisPath = ""; S.mode = ""; S.proto = "all"; S.q = ""; $("#search").value = "";
  S.path = d.openPath; $("#path").value = d.openPath;
  S.limits = { filter: req.filter || "", start: req.start || 0, count: req.count || 0 };
  S.view = "cfg"; showRun();
  analyze();
}
function speedFromReq(r) {
  if (r.paceMode === "burst") return { speed: "burst" };
  if (r.paceMode === "pps") return { speed: "custom", cType: "pps", cVal: String(r.pps) };
  if (r.paceMode === "mbps") return { speed: "custom", cType: "mbps", cVal: String(r.mbps) };
  if (r.paceMode === "fixed") return { speed: "custom", cType: "fixed", cVal: r.delay };
  return { speed: r.speed === 2 ? "orig2" : r.speed === 10 ? "orig10" : "orig1" };
}
function applyRestore() {
  const { req, meta, when, usingCopy } = S.restore; S.restore = null;
  S.mode = req.mode === "tcp" || req.mode === "udp" ? req.mode : "";
  const have = new Map(S.data.conversations.map((c) => [c.selector, c]));
  let missing = 0;
  for (const cv of req.conversations || []) {
    const c = have.get(cv.selector);
    if (!c) { missing++; continue; }
    S.selected.push({ selector: c.selector, proto: c.proto, c: { ip: c.clientIp, port: c.clientPort }, s: { ip: c.serverIp, port: c.serverPort },
      clientIp: cv.clientIp || "", clientPort: cv.clientPort ? String(cv.clientPort) : "", serverIp: cv.serverIp || "", serverPort: cv.serverPort ? String(cv.serverPort) : "",
      replace: (cv.replace || []).join("\n"), open: false });
  }
  const sp = meta.speed ? { speed: meta.speed, cType: meta.cType, cVal: meta.cVal } : speedFromReq(req);
  $("#speed").value = sp.speed; if (sp.cType) $("#cType").value = sp.cType; if (sp.cVal) $("#cVal").value = sp.cVal;
  $("#customSpeed").hidden = $("#speed").value !== "custom";
  const num = (sel, v, d) => { $(sel).value = v === undefined || v === null || v === "" ? d : v; };
  num("#loop", req.loop, 1); num("#skipBytes", req.skipBytes, 0); num("#seqOffset", req.seqOffset, 0); num("#handshakeTimeout", req.handshakeTimeout, "5s");
  if (req.ackMode) $("#ackMode").value = req.ackMode;
  num("#iface", req.iface, ""); num("#srcMac", req.srcMac, ""); num("#dstMac", req.dstMac, ""); num("#ifIndex", req.ifIndex, 0);
  $("#noFirewall").checked = !!req.noFirewall; $("#recordRx").checked = req.recordRx !== false;
  $("#tIp").value = ""; $("#tPort").value = ""; $("#bulkReplace").value = "";
  let note = "";
  const wantNet = req.backend !== "null";
  if (wantNet && !S.info.elevated) note = " It was sent on the network; that needs administrator rights, so this is set to a test run.";
  const radio = document.querySelector('input[name=where][value=' + (wantNet && S.info.elevated ? "auto" : "null") + ']'); if (radio) radio.checked = true;
  toast("Loaded the settings of the run from " + fmtWhen(when) + (usingCopy ? " (using the pcap stored in the library)" : "") + "." +
    (missing ? " " + plural(missing, "conversation") + " no longer match the capture." : "") + note + " Review them and press Send.");
  renderPills(); renderList(); refreshSend();
}

// ----- pcap library -----
async function loadLibrary() {
  const p = new URLSearchParams(); const q = $("#lSearch").value.trim(); if (q) p.set("q", q); if ($("#lPinned").checked) p.set("pinned", "1");
  let d;
  try { d = await api("/api/library?" + p); } catch (e) { toast(e.message); return; }
  H.enabled = !!d.enabled; H.lib = d.pcaps || []; if (d.stats) H.stats = d.stats; if (d.settings) H.settings = d.settings;
  const list = $("#lList"); list.replaceChildren();
  for (const e of H.lib) list.append(libRow(e));
  const empty = $("#lEmpty"); empty.hidden = H.lib.length > 0;
  empty.textContent = q || $("#lPinned").checked ? "No pcap matches your search." : "The library is empty. Captures you send are added automatically; you can also add the open capture with the button above.";
  $("#histSub").textContent = statsLine();
  $("#libCount").textContent = H.stats ? H.stats.pcaps : ""; $("#libCount").hidden = !(H.stats && H.stats.pcaps);
}
function libRow(e) {
  const row = el("div", "hrow"); row.tabIndex = 0;
  const main = el("div", "hmain"), title = el("div", "htitle");
  title.append(el("b", "", e.name), el("span", "chip " + e.copyState, COPY_LABEL[e.copyState] || e.copyState));
  if (e.pinned) title.append(el("span", "chip", "★ pinned"));
  const src = e.sources && e.sources[0] ? e.sources[0].path : "";
  main.append(title, el("div", "hsub", fmtBytes(e.size) + " · sent " + (e.uses === 1 ? "once" : e.uses + " times") + (e.lastUsed ? " · last " + fmtWhen(e.lastUsed) : "")));
  if (src) main.append(el("div", "hsub", src));
  if (e.note) main.append(el("div", "hnote", "“" + e.note + "”"));
  const side = el("div", "hside"), acts = el("div", "acts");
  const open = el("button", "small primary", "Open"); open.type = "button"; open.disabled = !e.canOpen; open.title = e.canOpen ? "" : "Neither the original nor a copy is available";
  open.onclick = (ev) => { ev.stopPropagation(); openFromLibrary(e); };
  acts.append(open); side.append(acts);
  row.append(el("span", "dot" + (e.copyState === "stored" ? " done" : "")), main, side);
  row.onclick = () => openPcap(e.id);
  row.onkeydown = (ev) => { if (ev.key === "Enter") openPcap(e.id); };
  return row;
}
function openFromLibrary(e) { if (e.canOpen) openCapture(e.openPath); }
let lTimer;
$("#lSearch").addEventListener("input", () => { clearTimeout(lTimer); lTimer = setTimeout(loadLibrary, 250); });
$("#lPinned").addEventListener("change", loadLibrary);
$("#lAdd").onclick = async () => {
  if (!S.path || !S.data) { toast("Open a capture first, then add it here."); return; }
  try { await api("/api/library/add", { path: S.path }); toast(baseName(S.path) + " was added to the library."); refreshHistoryCount(); loadLibrary(); } catch (e) { toast(e.message); }
};

async function openPcap(id) {
  let d;
  try { d = await api("/api/library/" + id); } catch (e) { toast(e.message); return; }
  H.pcap = d; const e = d.pcap;
  $("#pdTitle").textContent = e.name;
  const pill = $("#pdPill"); pill.textContent = COPY_LABEL[e.copyState] || e.copyState; pill.className = "pill " + (e.copyState === "stored" ? "done" : "cancelled");
  $("#pdMeta").textContent = fmtBytes(e.size) + " · added " + fmtFull(e.addedAt);
  const f = $("#pdFacts"); f.replaceChildren();
  kvRow(f, "Where it was", (e.sources || []).map((s) => s.path).join("\n") || "unknown");
  kvRow(f, "Stored copy", e.copyFile ? "Yes, in the library folder" : (e.copyState === "too-large" ? "No: larger than the per-file limit" : e.copyState === "reference" ? "No: copies are turned off" : e.copyState === "removed" ? "No: it was removed" : e.copyError ? "No: " + e.copyError : "No"));
  kvRow(f, "Times sent", String(e.uses)); if (e.lastUsed) kvRow(f, "Last sent", fmtFull(e.lastUsed));
  kvRow(f, "Identity", e.contentHash ? "Recognised by its content (an identical file elsewhere is the same entry)" : "Recognised by its location only");
  const runs = $("#pdRuns"); runs.replaceChildren();
  if (!d.runs.length) runs.append(el("div", "hint", "It has not been sent yet."));
  for (const r of d.runs) {
    const box = el("div", "rdconv"); box.style.cursor = "pointer";
    box.append(el("span", "ep", fmtWhen(r.startedAt) + " · " + r.mode.toUpperCase() + " · " + (STATE_LABEL[r.state] || r.state)), el("small", "", convSummary(r)));
    box.onclick = () => { $("#pcapDlg").close(); openRun(r.id); };
    runs.append(box);
  }
  $("#pdNote").value = e.note || ""; $("#pdSave").hidden = true;
  $("#pdPin").textContent = e.pinned ? "★ Pinned" : "☆ Pin";
  const dl = $("#pdDownload"); dl.hidden = !e.copyFile; dl.href = "/api/library/" + e.id + "/download";
  $("#pdRemoveCopy").hidden = !e.copyFile;
  $("#pdOpen").disabled = !e.canOpen;
  $("#pdDelete").textContent = "Remove from library"; delete $("#pdDelete").dataset.armed;
  $("#pcapDlg").showModal();
}
$("#pdNote").addEventListener("input", () => { $("#pdSave").hidden = $("#pdNote").value === (H.pcap.pcap.note || ""); });
$("#pdSave").onclick = async () => { try { const u = await api("/api/library/" + H.pcap.pcap.id + "/update", { note: $("#pdNote").value }); H.pcap.pcap = u.pcap; $("#pdSave").hidden = true; toast("Note saved."); loadLibrary(); } catch (e) { toast(e.message); } };
$("#pdPin").onclick = async () => { try { const u = await api("/api/library/" + H.pcap.pcap.id + "/update", { pinned: !H.pcap.pcap.pinned }); H.pcap.pcap = u.pcap; $("#pdPin").textContent = u.pcap.pinned ? "★ Pinned" : "☆ Pin"; loadLibrary(); } catch (e) { toast(e.message); } };
$("#pdOpen").onclick = () => { const e = H.pcap.pcap; $("#pcapDlg").close(); openFromLibrary(e); };
$("#pdRemoveCopy").onclick = () => armConfirm($("#pdRemoveCopy"), "Click again to remove", async () => {
  try { await api("/api/library/" + H.pcap.pcap.id + "/remove-copy", {}); $("#pcapDlg").close(); toast("The stored copy was removed."); refreshHistoryCount(); loadLibrary(); } catch (e) { toast(e.message); }
});
$("#pdDelete").onclick = () => armConfirm($("#pdDelete"), "Click again to remove", async () => {
  try { await api("/api/library/" + H.pcap.pcap.id + "/delete", {}); $("#pcapDlg").close(); toast("Removed from the library. The runs that used it stay in the history."); refreshHistoryCount(); loadLibrary(); } catch (e) { toast(e.message); }
});

// ----- settings -----
$("#histSettingsBtn").onclick = async () => {
  let d;
  try { d = await api("/api/history/settings"); } catch (e) { toast(e.message); return; }
  const s = d.settings; H.settings = s; H.stats = d.stats;
  $("#hsSave").checked = s.saveHistory; $("#hsRuns").value = s.maxRuns; $("#hsDays").value = s.maxAgeDays;
  $("#hsKeepPcaps").checked = s.keepPcaps; $("#hsPcapFile").value = s.maxPcapFileMB; $("#hsPcapTotal").value = s.maxPcapsMB;
  $("#hsPackets").checked = s.savePackets; $("#hsMB").value = s.maxPacketsMB;
  const info = $("#hsInfo"); info.replaceChildren();
  for (const [k, v] of [["Stored in", d.stats.dir], ["Runs", fmtInt(d.stats.runs)], ["Pcaps in the library", fmtInt(d.stats.pcaps) + " (" + fmtBytes(d.stats.pcapBytes) + " of copies)"],
    ["Transmitted-packet copies", fmtBytes(d.stats.packetsBytes)], ["Database file", fmtBytes(d.stats.dbBytes)]]) {
    const x = el("div"); x.append(el("span", "", k), el("span", "", v)); info.append(x);
  }
  $("#hsClear").textContent = "Delete all history…"; delete $("#hsClear").dataset.armed;
  $("#histSetDlg").showModal();
};
$("#hsDone").onclick = async () => {
  const n = (id) => Math.max(0, parseInt($(id).value || "0", 10) || 0);
  try {
    const r = await api("/api/history/settings", { saveHistory: $("#hsSave").checked, maxRuns: n("#hsRuns"), maxAgeDays: n("#hsDays"),
      keepPcaps: $("#hsKeepPcaps").checked, maxPcapFileMB: n("#hsPcapFile"), maxPcapsMB: n("#hsPcapTotal"), savePackets: $("#hsPackets").checked, maxPacketsMB: n("#hsMB") });
    $("#histSetDlg").close();
    toast("Settings saved." + (r.removedRuns ? " " + plural(r.removedRuns, "old run") + " removed." : "") + (r.removedPacketCopies ? " " + r.removedPacketCopies + " packet copies removed." : ""));
    refreshHistoryCount(); if (H.tab === "runs") loadHistory(false); else loadLibrary();
  } catch (e) { toast(e.message); }
};
$("#hsClear").onclick = () => armConfirm($("#hsClear"), "Click again: delete all (keeps pinned)", async () => {
  try { const r = await api("/api/history/clear", { keepPinned: true }); $("#histSetDlg").close(); toast(plural(r.removed, "run") + " deleted."); refreshHistoryCount(); loadHistory(false); } catch (e) { toast(e.message); }
});

// ---------- init ----------
(async function init() {
  try {
    S.info = await api("/api/info");
    const b = $("#elev");
    b.textContent = S.info.elevated ? "Administrator" : "Standard user: test runs only";
    b.className = "badge " + (S.info.elevated ? "ok" : "warn");
  } catch (e) { toast(e.message); }
  try { const ses = JSON.parse(localStorage.getItem("pcapreplay.session") || "null"); if (ses && ses.path) { S.path = ses.path; S.analysisPath = ses.path; S.limits = ses.limits || S.limits; } } catch (_) { /* none */ }
  renderWelcomeLists();
  show("welcome");
  refreshHistoryCount();
  poll(); // pick up a job that is already running or finished (page reload)
})();
