"use strict";
// pktreplay GUI. All server-supplied text is inserted with textContent, never innerHTML.

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

let mode = "";          // "tcp" | "udp" | "" (must be chosen explicitly)
let lastState = "idle";
let poller = null;
let info = {};

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
  const u = ["KiB", "MiB", "GiB", "TiB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 2 : 1) + " " + u[i];
}
function fmtDur(s) {
  if (s < 1) return (s * 1000).toFixed(0) + " ms";
  if (s < 90) return s.toFixed(2) + " s";
  const m = Math.floor(s / 60); return m + " min " + Math.round(s - m * 60) + " s";
}

// ---------- tabs ----------
function selectTab(name) {
  for (const t of ["analyze", "replay"]) {
    $("#tab-" + t).setAttribute("aria-selected", String(t === name));
    $("#panel-" + t).hidden = t !== name;
  }
}
$("#tab-analyze").onclick = () => selectTab("analyze");
$("#tab-replay").onclick = () => selectTab("replay");

// ---------- source card ----------
const range = () => ({
  path: $("#path").value.trim(), filter: $("#filter").value,
  start: Math.max(0, parseInt($("#start").value || "0", 10)), count: Math.max(0, parseInt($("#count").value || "0", 10)),
});

let filterTimer;
$("#filter").addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(async () => {
    const f = $("#filter");
    try {
      const r = await api("/api/filter/check", { filter: f.value });
      f.classList.toggle("bad", !r.ok);
      const m = $("#filterMsg");
      m.textContent = r.ok ? "Filter is valid." : r.error;
      m.style.color = r.ok ? "" : "var(--err)";
    } catch (_) { /* ignore transient errors */ }
  }, 250);
});
$("#path").addEventListener("input", refreshButtons);

// ---------- file browser ----------
const dlg = $("#dlg");
let curDir = "", parentDir = "";
async function loadDir(path) {
  try {
    const d = await api("/api/fs?path=" + encodeURIComponent(path || ""));
    curDir = d.path; parentDir = d.parent;
    $("#curDir").textContent = d.path;
    $("#up").disabled = !d.parent;
    const ul = $("#entries"); ul.replaceChildren();
    if (!d.entries.length) ul.append(el("li", "empty", "No folders or capture files here"));
    for (const e of d.entries) {
      const li = el("li");
      li.append(el("span", "", (e.dir ? "📁 " : "📄 ") + e.name), el("span", "sz", e.dir ? "" : fmtBytes(e.size)));
      li.onclick = () => {
        const full = d.path.replace(/[\\/]$/, "") + (d.path.includes("\\") ? "\\" : "/") + e.name;
        if (e.dir) loadDir(full); else { $("#path").value = full; dlg.close(); refreshButtons(); }
      };
      ul.append(li);
    }
  } catch (err) { $("#entries").replaceChildren(el("li", "empty", err.message)); }
}
$("#browse").onclick = () => {
  dlg.showModal();
  const cur = $("#path").value.trim();
  const dir = cur ? cur.replace(/[\\/][^\\/]*$/, "") : info.cwd;
  loadDir(dir || info.home);
};
$("#up").onclick = () => parentDir && loadDir(parentDir);

// ---------- analysis ----------
$("#runStats").onclick = async () => {
  $("#statsError").hidden = true;
  try { await api("/api/stats", { ...range(), top: 15 }); startPolling(); }
  catch (e) { showErr("#statsError", e.message); }
};
$("#stopStats").onclick = () => api("/api/cancel", {}).catch(() => {});

function showErr(sel, msg) { const e = $(sel); e.textContent = msg; e.hidden = !msg; }

function bars(container, rows, nameOf, valOf, fmtVal) {
  container.replaceChildren();
  if (!rows || !rows.length) { container.append(el("div", "empty", "none")); return; }
  const max = Math.max(...rows.map(valOf)) || 1;
  for (const r of rows) {
    const row = el("div", "brow");
    const track = el("div", "track"); const i = el("i"); i.style.width = (100 * valOf(r) / max).toFixed(1) + "%"; track.append(i);
    row.append(el("span", "name", nameOf(r)), track, el("span", "val", fmtVal(valOf(r))));
    container.append(row);
  }
}

function renderSummary(s) {
  $("#statsResult").hidden = false;
  const k = $("#kpis"); k.replaceChildren();
  const rate = s.durationSec > 0 ? s.wireBytes * 8 / s.durationSec / 1e6 : 0;
  for (const [v, l] of [
    [fmtInt(s.packets), "packets (" + s.format + ", link " + s.linkType + ")"], [fmtBytes(s.capBytes), "captured"],
    [fmtBytes(s.wireBytes), "on the wire"], [s.durationSec ? fmtDur(s.durationSec) : "–", "capture duration"],
    [rate ? rate.toFixed(2) + " Mbit/s" : "–", "average rate"], [fmtInt(s.truncated), "truncated packets"],
  ]) { const d = el("div", "kpi"); d.append(el("b", "", v), el("span", "", l)); k.append(d); }
  const total = s.protocols.reduce((a, p) => a + p.packets, 0) || 1;
  bars($("#protoBars"), s.protocols, (p) => p.name, (p) => p.packets, (n) => fmtInt(n) + " · " + (100 * n / total).toFixed(1) + "%");
  bars($("#talkers"), s.talkers, (t) => t.addr, (t) => t.bytes, fmtBytes);
  bars($("#tcpPorts"), s.tcpPorts, (p) => String(p.port), (p) => p.packets, (n) => fmtInt(n) + " pkts");
  bars($("#udpPorts"), s.udpPorts, (p) => String(p.port), (p) => p.packets, (n) => fmtInt(n) + " pkts");
  convData = s;
  renderConversations();
}

// ---------- conversations (analysis) ----------
let convData = null;
const MAX_ROWS = 500;

function renderConversations() {
  const s = convData, tb = $("#convTable tbody");
  tb.replaceChildren();
  if (!s || !s.conversations) { $("#convCard").hidden = true; return; }
  $("#convCard").hidden = false;
  const q = $("#convSearch").value.trim().toLowerCase();
  const rows = s.conversations.filter((c) => !q || (c.selector + " " + c.state).toLowerCase().includes(q));
  $("#convCount").textContent = "(" + fmtInt(s.conversationsTotal) + " tracked" + (q ? ", " + fmtInt(rows.length) + " match" : "") + ")";
  for (const c of rows.slice(0, MAX_ROWS)) {
    const tr = el("tr");
    const proto = el("td"); proto.append(el("span", "tag", c.proto));
    const isPorts = c.proto === "tcp" || c.proto === "udp";
    const ep = (ip, port) => isPorts ? (ip.includes(":") ? "[" + ip + "]:" + port : ip + ":" + port) : ip;
    const btn = el("button", "small", ruleIndex(c.selector) >= 0 ? "Edit in Replay →" : "＋ Replay…");
    btn.type = "button";
    btn.onclick = () => { addRule(c.selector); selectTab("replay"); };
    const act = el("td"); act.append(btn);
    tr.append(proto, el("td", "mono", ep(c.clientIp, c.clientPort)), el("td", "mono", ep(c.serverIp, c.serverPort)),
      el("td", "num", fmtInt(c.packets) + "  (" + fmtInt(c.c2sPackets) + " / " + fmtInt(c.s2cPackets) + ")"),
      el("td", "num", fmtBytes(c.bytes)), el("td", "num", c.durationSec ? fmtDur(c.durationSec) : "–"), el("td", "", c.state), act);
    tb.append(tr);
  }
  const notes = [];
  if (rows.length > MAX_ROWS) notes.push("Showing the " + MAX_ROWS + " largest of " + fmtInt(rows.length) + " matches: refine the filter to see others.");
  if (s.conversationsTotal > s.conversations.length) notes.push("The table lists the " + fmtInt(s.conversations.length) + " largest conversations by bytes (" + fmtInt(s.conversationsTotal) + " tracked).");
  if (s.conversationsUntracked > 0) notes.push(fmtInt(s.conversationsUntracked) + " packets belong to further conversations beyond the tracking limit and are not listed.");
  notes.push("Client = the side that opened the conversation (SYN sender; otherwise first packet, or the well-known port's peer). → / ← are client→server and server→client packets.");
  $("#convNote").textContent = notes.join(" ");
}
$("#convSearch").addEventListener("input", renderConversations);

// ---------- per-conversation rules (replay) ----------
const rules = [];

function splitEndpoint(proto, s) {
  if (proto !== "tcp" && proto !== "udp") return { ip: s, port: 0 };
  const m = s.match(/^\[(.+)\]:(\d+)$/) || s.match(/^([^:]+):(\d+)$/);
  return m ? { ip: m[1], port: Number(m[2]) } : null;
}
function parseSelector(sel) {
  const p = sel.trim().split("/");
  if (p.length !== 3) return null;
  const proto = p[0].toLowerCase(), c = splitEndpoint(proto, p[1]), s = splitEndpoint(proto, p[2]);
  return c && s ? { selector: proto + "/" + p[1] + "/" + p[2], proto, client: c, server: s } : null;
}
const ruleIndex = (sel) => rules.findIndex((r) => r.selector === sel);

function addRule(sel) {
  const p = parseSelector(sel);
  if (!p) return false;
  if (ruleIndex(p.selector) < 0) rules.push({ ...p, clientIp: "", clientPort: "", serverIp: "", serverPort: "", replace: "" });
  renderRules();
  renderConversations();
  return true;
}

function fmtEp(proto, ip, port) {
  if (proto !== "tcp" && proto !== "udp") return ip;
  return (ip.includes(":") ? "[" + ip + "]" : ip) + ":" + port;
}

function renderRules() {
  const box = $("#ruleList");
  box.replaceChildren();
  rules.forEach((r, i) => {
    const hasPorts = r.proto === "tcp" || r.proto === "udp";
    const card = el("div", "rule");
    const head = el("div", "rule-head");
    head.append(el("span", "tag", r.proto), el("span", "sel", r.selector));
    const rm = el("button", "small", "Remove"); rm.type = "button";
    rm.onclick = () => { rules.splice(i, 1); renderRules(); renderConversations(); };
    head.append(rm);
    const grid = el("div", "grid4");
    const preview = el("div", "preview");
    const field = (label, key, placeholder, type) => {
      const l = el("label", "", label); const inp = el("input"); inp.type = type; inp.value = r[key]; inp.placeholder = placeholder;
      if (type === "number") { inp.min = "0"; inp.max = "65535"; } else inp.spellcheck = false;
      inp.oninput = () => { r[key] = inp.value.trim(); updatePreview(); };
      l.append(inp); return l;
    };
    grid.append(field("Client IP", "clientIp", r.client.ip, "text"));
    if (hasPorts) grid.append(field("Client port", "clientPort", String(r.client.port), "number"));
    grid.append(field("Server IP", "serverIp", r.server.ip, "text"));
    if (hasPorts) grid.append(field("Server port", "serverPort", String(r.server.port), "number"));
    const det = el("details"); det.append(el("summary", "", "Payload substitutions for this conversation"));
    const ta = el("textarea"); ta.rows = 2; ta.spellcheck = false; ta.placeholder = "old=>new (one per line)"; ta.value = r.replace;
    ta.oninput = () => { r.replace = ta.value; };
    det.append(ta); if (r.replace) det.open = true;
    function updatePreview() {
      const cIp = r.clientIp || r.client.ip, sIp = r.serverIp || r.server.ip;
      const cPort = r.clientPort || r.client.port, sPort = r.serverPort || r.server.port;
      const changed = r.clientIp || r.clientPort || r.serverIp || r.serverPort;
      preview.replaceChildren(document.createTextNode("replays as  "));
      const b = el(changed ? "b" : "span", "", fmtEp(r.proto, cIp, cPort) + "  ⇄  " + fmtEp(r.proto, sIp, sPort));
      preview.append(b, document.createTextNode(changed ? "   (server replies come FROM the new server address)" : "   (unchanged)"));
    }
    updatePreview();
    card.append(head, grid, preview, det);
    box.append(card);
  });
  $("#convEmpty").hidden = rules.length > 0;
  const badge = $("#ruleBadge"); badge.hidden = rules.length === 0; badge.textContent = String(rules.length);
  updateOnly();
  refreshButtons();
}

$("#addSelector").onclick = () => {
  const v = $("#selectorIn").value.trim();
  if (!v) return;
  if (addRule(v)) { $("#selectorIn").value = ""; $("#selectorErr").textContent = ""; }
  else { $("#selectorErr").textContent = "Expected proto/client/server, e.g. tcp/192.168.1.50:51234/192.168.1.10:80 or icmp/10.0.0.1/10.0.0.2"; $("#selectorErr").style.color = "var(--err)"; }
};
$("#selectorIn").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#addSelector").click(); });

function updateOnly() {
  const cb = $("#onlyListed"), tcp = mode === "tcp";
  cb.disabled = tcp || rules.length === 0;
  if (tcp) cb.checked = rules.length > 0;
  $("#onlyListedText").textContent = tcp
    ? "TCP mode replays a single conversation: the listed one (or the first matching conversation if none is listed)"
    : "Replay only the listed conversations (skip all others)";
}

function ruleBody() {
  return rules.map((r) => ({
    selector: r.selector, clientIp: r.clientIp, serverIp: r.serverIp,
    clientPort: Number(r.clientPort) || 0, serverPort: Number(r.serverPort) || 0,
    replace: r.replace.split("\n").filter((l) => l.trim()),
  }));
}

// ---------- replay form ----------
$$("#modeSeg button").forEach((b) => b.onclick = () => {
  mode = b.dataset.mode;
  $$("#modeSeg button").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
  $("#tcpCard").hidden = mode !== "tcp";
  updateOnly();
  refreshButtons();
});
function paceVisibility() {
  const m = $("#paceMode").value;
  $$("[data-pace]").forEach((l) => l.hidden = l.dataset.pace !== m);
}
$("#paceMode").onchange = paceVisibility;
paceVisibility();

function replayBody() {
  const num = (id) => parseInt($(id).value || "0", 10) || 0;
  const f = (id) => parseFloat($(id).value || "0") || 0;
  return {
    ...range(), mode, loop: Math.max(1, num("#loop")),
    srcIp: $("#srcIp").value, dstIp: $("#dstIp").value, srcPort: num("#srcPort"), dstPort: num("#dstPort"),
    payload: $("#payload").value, replace: $("#replace").value.split("\n").filter((l) => l.trim()),
    paceMode: $("#paceMode").value, speed: f("#speed"), delay: $("#delay").value, pps: f("#pps"), mbps: f("#mbps"), maxGap: $("#maxGap").value,
    backend: $("#backend").value, iface: $("#iface").value, srcMac: $("#srcMac").value, dstMac: $("#dstMac").value,
    ifIndex: num("#ifIndex"), noFirewall: $("#noFirewall").checked,
    seqOffset: num("#seqOffset"), skipBytes: num("#skipBytes"), ackMode: $("#ackMode").value, handshakeTimeout: $("#handshakeTimeout").value,
    record: $("#record").value.trim(), recordRx: $("#recordRx").checked,
    conversations: ruleBody(), onlyConversations: $("#onlyListed").checked && rules.length > 0,
  };
}

$("#runReplay").onclick = async () => {
  showErr("#replayError", "");
  try { await api("/api/replay", replayBody()); startPolling(); }
  catch (e) { showErr("#replayError", e.message); }
};
$("#stopReplay").onclick = () => api("/api/cancel", {}).catch(() => {});

function refreshButtons() {
  const running = lastState === "running";
  const tooMany = mode === "tcp" && rules.length > 1;
  const ready = !!$("#path").value.trim() && !!mode && !tooMany;
  $("#runReplay").disabled = !ready || running;
  $("#runStats").disabled = !$("#path").value.trim() || running;
  const hint = $("#startHint");
  if (!$("#path").value.trim()) hint.textContent = "Choose a capture file first.";
  else if (!mode) hint.textContent = "Select TCP or UDP above: the transmission mode is never guessed.";
  else if (tooMany) hint.textContent = "TCP mode replays a single conversation: remove all but one from the list.";
  else if (mode === "tcp" && rules.length === 0) hint.textContent = "No conversation chosen: TCP will replay the first one that matches the filter. Add one from Analyze to pick.";
  else if (info.elevated === false && $("#backend").value !== "null") hint.textContent = "Raw injection needs elevated privileges; start pktreplay as Administrator/root, or use Dry run.";
  else hint.textContent = "Ready.";
}
$("#backend").onchange = refreshButtons;

// ---------- status polling ----------
function startPolling() {
  clearInterval(poller);
  poller = setInterval(poll, 400);
  poll();
}

async function poll() {
  let s;
  try { s = await api("/api/status"); } catch (_) { return; }
  lastState = s.state;
  const running = s.state === "running";
  const isStats = s.kind === "stats", isReplay = s.kind === "replay";

  // analysis panel
  $("#runStats").hidden = isStats && running; $("#stopStats").hidden = !(isStats && running);
  $("#statsProgress").hidden = !(isStats && s.scan);
  if (isStats && s.scan) {
    $("#statsBar").style.width = s.scan.percent.toFixed(1) + "%";
    $("#statsProgText").textContent = fmtInt(s.scan.packets) + " packets · " + fmtBytes(s.scan.bytes) + (s.scan.total ? " of " + fmtBytes(s.scan.total) : "") + " · " + fmtDur(s.elapsedSec);
  }
  if (isStats) {
    showErr("#statsError", s.state === "failed" ? s.error : "");
    if (s.summary) renderSummary(s.summary);
  }

  // replay panel
  $("#runReplay").hidden = isReplay && running; $("#stopReplay").hidden = !(isReplay && running);
  const pill = $("#pill"); pill.textContent = isReplay ? s.state : "idle"; pill.className = "pill " + (isReplay ? s.state : "");
  if (isReplay) {
    showErr("#replayError", s.state === "failed" ? s.error : "");
    const r = s.replay;
    const g = $("#liveGrid"); g.replaceChildren();
    if (r) for (const [v, l] of [[fmtInt(r.sent), "packets sent"], [fmtBytes(r.bytes), "bytes sent"], [fmtInt(r.pps) + " pps", "rate"], [r.mbps.toFixed(2) + " Mbit/s", "throughput"],
      [fmtInt(r.read), "read from file"], [fmtInt(r.skipped), "skipped"], [fmtInt(r.sendErrs), "send errors"], [fmtDur(s.elapsedSec), "elapsed"]]) {
      const d = el("div"); d.append(el("b", "", v), el("span", "", l)); g.append(d);
    }
    const ti = $("#tcpInfo");
    ti.hidden = !s.tcp; ti.replaceChildren();
    if (s.tcp) for (const [k, v] of [["Flow", s.tcp.flow], ["Live source", s.tcp.localIp + ":" + s.tcp.localPort],
      ["Handshake", s.tcp.handshakeUs ? s.tcp.handshakeUs.toFixed(0) + " µs" : "–"], ["Retransmits", String(s.tcp.retransmits)],
      ["Server sent", fmtBytes(s.tcp.rxBytes) + " / " + s.tcp.rxSegments + " segs"], ["Ended", s.tcp.finalState || "–"]]) {
      const d = el("div"); d.append(el("span", "", k), el("span", "mono", v)); ti.append(d);
    }
    const ri = $("#recInfo");
    ri.hidden = !s.recording; ri.replaceChildren();
    if (s.recording) for (const [k, v] of [["Recording", s.recording.path], ["Packets", fmtInt(s.recording.packets)], ["Bytes", fmtBytes(s.recording.bytes)]]) {
      const d = el("div"); d.append(el("span", "", k), el("span", "mono", v)); ri.append(d);
    }
    const log = $("#log"), atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    log.textContent = s.log.join("\n");
    if (atEnd) log.scrollTop = log.scrollHeight;
  }
  refreshButtons();
  if (!running) { clearInterval(poller); poller = null; }
}

// ---------- init ----------
(async function init() {
  try {
    info = await api("/api/info");
    $("#ver").textContent = (info.version || "dev") + " · " + info.os + "/" + info.arch;
    const b = $("#elev");
    b.textContent = info.elevated ? "Elevated: raw injection available" : "Not elevated: dry run / analysis only";
    b.className = "badge " + (info.elevated ? "ok" : "warn");
  } catch (e) { showErr("#statsError", e.message); }
  refreshButtons();
  poll(); // pick up a job that is already running (page reload)
})();
