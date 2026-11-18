"use strict";
// pktreplay GUI: one page, four steps (Capture -> Choose -> Settings -> Send).
// All server-supplied text is inserted with textContent, never innerHTML.

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

// ---------- state ----------
let mode = "";            // "tcp" | "udp" | "" (never guessed)
let lastState = "idle", lastKind = "";
let poller = null;
let info = {};
let convData = null;      // latest analysis summary
let analysisSource = null; // capture/filter/range convData was built from
let summaryKey = "";
const rules = [];         // ticked conversations (+ optional per-conversation changes)
const MAX_ROWS = 500;

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
const baseName = (p) => p.split(/[\\/]/).filter(Boolean).pop() || p;
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const endpoint = (proto, ip, port) => (proto !== "tcp" && proto !== "udp") ? ip : (ip.includes(":") ? "[" + ip + "]:" + port : ip + ":" + port);

function showErr(sel, msg) { const e = $(sel); e.textContent = msg; e.hidden = !msg; }

// ---------- step 1: capture, filter, analysis ----------
const range = () => ({
  path: $("#path").value.trim(), filter: $("#filter").value,
  start: Math.max(0, parseInt($("#start").value || "0", 10) || 0), count: Math.max(0, parseInt($("#count").value || "0", 10) || 0),
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
      m.textContent = r.ok ? (f.value.trim() ? "Filter is valid." : "Header terms run before payload terms. Use payload contains \"x\" or payload ~ \"regex\".") : r.error;
      m.style.color = r.ok ? "" : "var(--err)";
    } catch (_) { /* transient */ }
  }, 250);
});

async function runAnalysis() {
  showErr("#statsError", "");
  const src = range();
  if (!src.path) { showErr("#statsError", "Choose a capture file first."); return; }
  try {
    await api("/api/stats", { ...src, top: 15 });
    if (analysisSource && analysisSource.path !== src.path) { rules.length = 0; renderSelection(); } // other file: old picks are meaningless
    analysisSource = src; convData = null; summaryKey = "";
    renderConversations();
    startPolling();
  } catch (e) { showErr("#statsError", e.message); }
}
$("#runStats").onclick = runAnalysis;
$("#pickAnalyze").onclick = runAnalysis;
$("#stopStats").onclick = () => api("/api/cancel", {}).catch(() => {});
// Choosing a file (Enter / leaving the field / Browse) analyses it right away.
$("#path").addEventListener("change", () => { if ($("#path").value.trim() && lastState !== "running") runAnalysis(); });

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

function renderSummary(s, partial) {
  $("#overview").hidden = false;
  const chips = $("#chips"); chips.replaceChildren();
  const chip = (b, t) => { const c = el("span", "chip"); c.append(el("b", "", b), document.createTextNode(" " + t)); chips.append(c); };
  chip(fmtInt(s.packets), "packets (" + s.format + ")");
  chip(fmtBytes(s.capBytes), "captured");
  if (s.durationSec) chip(fmtDur(s.durationSec), "long");
  const tot = s.protocols.reduce((a, p) => a + p.packets, 0) || 1;
  chip(s.protocols.map((p) => p.name + " " + (100 * p.packets / tot).toFixed(0) + "%").join(" · ") || "no IP traffic", "");
  chip(fmtInt(s.conversationsTotal), "conversations");
  if (partial) chip("stopped early", "(partial result)");

  const k = $("#kpis"); k.replaceChildren();
  const rate = s.durationSec > 0 ? s.wireBytes * 8 / s.durationSec / 1e6 : 0;
  for (const [v, l] of [[fmtInt(s.packets), "packets (link " + s.linkType + ")"], [fmtBytes(s.capBytes), "captured"], [fmtBytes(s.wireBytes), "on the wire"],
    [s.durationSec ? fmtDur(s.durationSec) : "–", "capture duration"], [rate ? rate.toFixed(2) + " Mbit/s" : "–", "average rate"], [fmtInt(s.truncated), "truncated packets"]]) {
    const d = el("div", "kpi"); d.append(el("b", "", v), el("span", "", l)); k.append(d);
  }
  bars($("#protoBars"), s.protocols, (p) => p.name, (p) => p.packets, (n) => fmtInt(n) + " · " + (100 * n / tot).toFixed(1) + "%");
  bars($("#talkers"), s.talkers, (t) => t.addr, (t) => t.bytes, fmtBytes);
  bars($("#tcpPorts"), s.tcpPorts, (p) => String(p.port), (p) => p.packets, (n) => fmtInt(n) + " pkts");
  bars($("#udpPorts"), s.udpPorts, (p) => String(p.port), (p) => p.packets, (n) => fmtInt(n) + " pkts");
  convData = s;
  renderConversations();
}

// ---------- file browser ----------
const dlg = $("#dlg");
let parentDir = "";
async function loadDir(path) {
  try {
    const d = await api("/api/fs?path=" + encodeURIComponent(path || ""));
    parentDir = d.parent;
    $("#curDir").textContent = d.path;
    $("#up").disabled = !d.parent;
    const ul = $("#entries"); ul.replaceChildren();
    if (!d.entries.length) ul.append(el("li", "empty", "No folders or capture files here"));
    for (const e of d.entries) {
      const li = el("li");
      li.append(el("span", "", (e.dir ? "📁 " : "📄 ") + e.name), el("span", "sz", e.dir ? "" : fmtBytes(e.size)));
      li.onclick = () => {
        const full = d.path.replace(/[\\/]$/, "") + (d.path.includes("\\") ? "\\" : "/") + e.name;
        if (e.dir) loadDir(full);
        else { $("#path").value = full; dlg.close(); $("#path").dispatchEvent(new Event("change")); refreshUI(); }
      };
      ul.append(li);
    }
  } catch (err) { $("#entries").replaceChildren(el("li", "empty", err.message)); }
}
$("#browse").onclick = () => {
  dlg.showModal();
  const cur = $("#path").value.trim();
  loadDir((cur ? cur.replace(/[\\/][^\\/]*$/, "") : info.cwd) || info.home);
};
$("#up").onclick = () => parentDir && loadDir(parentDir);

// ---------- step 2: mode, conversation table, selection ----------
$$("#modeSeg button").forEach((b) => b.onclick = () => {
  mode = b.dataset.mode;
  $$("#modeSeg button").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
  // A ticked conversation of the other protocol cannot be sent in this mode.
  const before = rules.length;
  for (let i = rules.length - 1; i >= 0; i--) if (rules[i].proto !== mode) rules.splice(i, 1);
  if (mode === "tcp" && rules.length > 1) rules.length = 1;
  const dropped = before - rules.length;
  $("#tcpCard").hidden = mode !== "tcp";
  $("#modeHint").textContent = mode === "tcp"
    ? "TCP opens a real connection and replays ONE conversation's client side (the one you tick, or the first match). Replies from the server are handled live."
    : "UDP injects the recorded datagrams as they are. Tick any number of UDP conversations, or none to send all of them.";
  renderConversations(); renderSelection();
  if (dropped) $("#convNote").textContent = "Unticked " + plural(dropped, "conversation") + " that " + mode.toUpperCase() + " mode cannot send.";
  refreshUI();
});

const ruleIndex = (sel) => rules.findIndex((r) => r.selector === sel);

function renderConversations() {
  const s = convData, tb = $("#convTable tbody");
  tb.replaceChildren();
  const analyzing = lastState === "running" && lastKind === "stats";
  $("#noAnalysis").hidden = !!(s && s.conversations);
  $("#convBox").hidden = !(s && s.conversations);
  if (!$("#noAnalysis").hidden) {
    $("#noAnalysis").querySelector("p").textContent = analyzing ? "Analyzing the capture…" : "No conversation list yet.";
    $("#pickAnalyze").disabled = analyzing || lastState === "running" || !$("#path").value.trim();
    return;
  }
  const cur = range(), a = analysisSource;
  const stale = $("#pickStale");
  stale.hidden = !(a && (cur.path !== a.path || cur.filter !== a.filter || cur.start !== a.start || cur.count !== a.count));
  if (!stale.hidden) stale.textContent = "This list comes from an earlier analysis: the capture, filter or packet range has changed since. Click Analyze (step 1) to refresh it.";

  const want = mode === "tcp" ? ["tcp"] : mode === "udp" ? ["udp"] : ["tcp", "udp"];
  const q = $("#convSearch").value.trim().toLowerCase();
  const sendable = s.conversations.filter((c) => c.proto === "tcp" || c.proto === "udp");
  const all = sendable.filter((c) => want.includes(c.proto));
  const rows = all.filter((c) => !q || (c.selector + " " + c.state).toLowerCase().includes(q));
  $("#convCount").textContent = fmtInt(rows.length) + (q ? " of " + fmtInt(all.length) : "") + " " + (mode ? mode.toUpperCase() + " " : "") + "conversations";

  for (const c of rows.slice(0, MAX_ROWS)) {
    const on = ruleIndex(c.selector) >= 0;
    const tr = el("tr", on ? "on" : "");
    const cb = el("input"); cb.type = "checkbox"; cb.checked = on; cb.setAttribute("aria-label", "Replay " + c.selector);
    cb.onclick = (e) => e.stopPropagation();
    cb.onchange = () => toggleConversation(c.selector, cb.checked);
    const ck = el("td", "chk"); ck.append(cb);
    const proto = el("td"); proto.append(el("span", "tag", c.proto));
    tr.onclick = () => cb.click();
    tr.append(ck, proto, el("td", "mono", endpoint(c.proto, c.clientIp, c.clientPort)), el("td", "mono", endpoint(c.proto, c.serverIp, c.serverPort)),
      el("td", "num", fmtInt(c.packets) + "  (" + fmtInt(c.c2sPackets) + " / " + fmtInt(c.s2cPackets) + ")"),
      el("td", "num", fmtBytes(c.bytes)), el("td", "num", c.durationSec ? fmtDur(c.durationSec) : "–"), el("td", "", c.proto === "tcp" ? c.state : "–"));
    tb.append(tr);
  }
  if (!rows.length) { const tr = el("tr"); const td = el("td", "empty", all.length ? "No conversation matches the filter." : "No " + want.join("/").toUpperCase() + " conversations in this capture."); td.colSpan = 8; tr.append(td); tb.append(tr); }

  const notes = [];
  if (rows.length > MAX_ROWS) notes.push("Showing the " + MAX_ROWS + " largest of " + fmtInt(rows.length) + " matches: refine the search to see others.");
  if (s.conversationsTotal > s.conversations.length) notes.push("Listing the " + fmtInt(s.conversations.length) + " largest of " + fmtInt(s.conversationsTotal) + " conversations (by bytes).");
  if (s.conversationsUntracked > 0) notes.push(fmtInt(s.conversationsUntracked) + " packets belong to conversations beyond the tracking limit.");
  const hidden = s.conversations.length - sendable.length;
  if (hidden > 0) notes.push(plural(hidden, "ICMP/other conversation") + " hidden: only TCP and UDP can be replayed.");
  notes.push("Client = the side that opened the conversation. → / ← = client→server / server→client packets.");
  $("#convNote").textContent = notes.join(" ");
  $("#selAll").disabled = mode === "tcp" || !rows.length;
}
$("#convSearch").addEventListener("input", renderConversations);
$("#pickClear").onclick = () => { rules.length = 0; renderConversations(); renderSelection(); refreshUI(); };
$("#selAll").onclick = () => {
  const q = $("#convSearch").value.trim().toLowerCase();
  const rows = (convData ? convData.conversations : []).filter((c) => (!mode || c.proto === mode) && (c.proto === "tcp" || c.proto === "udp") &&
    (!q || (c.selector + " " + c.state).toLowerCase().includes(q))).slice(0, MAX_ROWS);
  for (const c of rows) if (ruleIndex(c.selector) < 0) addRuleObj(c.selector);
  renderConversations(); renderSelection(); refreshUI();
};

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
function addRuleObj(sel) {
  const p = parseSelector(sel);
  if (!p) return false;
  if (ruleIndex(p.selector) < 0) {
    if (mode === "tcp") rules.length = 0; // TCP replays exactly one conversation: ticking another replaces it
    rules.push({ ...p, clientIp: "", clientPort: "", serverIp: "", serverPort: "", replace: "", open: false });
  }
  return true;
}
function toggleConversation(sel, on) {
  if (on) addRuleObj(sel);
  else { const i = ruleIndex(sel); if (i >= 0) rules.splice(i, 1); }
  renderConversations(); renderSelection(); refreshUI();
}

const changed = (r) => !!(r.clientIp || r.clientPort || r.serverIp || r.serverPort || r.replace.trim());

function renderSelection() {
  const box = $("#ruleList");
  box.replaceChildren();
  rules.forEach((r) => {
    const hasPorts = r.proto === "tcp" || r.proto === "udp";
    const card = el("details", "rule"); card.open = r.open;
    card.addEventListener("toggle", () => { r.open = card.open; });
    const head = el("summary");
    const chg = el("span", "chg");
    const rm = el("button", "small", "Untick"); rm.type = "button";
    rm.onclick = (e) => { e.preventDefault(); e.stopPropagation(); toggleConversation(r.selector, false); };
    head.append(el("span", "tag", r.proto), el("span", "sel", r.selector), chg, rm);

    const body = el("div", "body");
    const grid = el("div", "grid4");
    const preview = el("div", "preview");
    const field = (label, key, placeholder, type) => {
      const l = el("label", "", label); const inp = el("input"); inp.type = type; inp.value = r[key]; inp.placeholder = placeholder;
      if (type === "number") { inp.min = "0"; inp.max = "65535"; } else inp.spellcheck = false;
      inp.oninput = () => { r[key] = inp.value.trim(); update(); };
      l.append(inp); return l;
    };
    grid.append(field("Client IP", "clientIp", r.client.ip, "text"));
    if (hasPorts) grid.append(field("Client port", "clientPort", String(r.client.port), "number"));
    grid.append(field("Server IP", "serverIp", r.server.ip, "text"));
    if (hasPorts) grid.append(field("Server port", "serverPort", String(r.server.port), "number"));
    const det = el("details"); det.append(el("summary", "muted", "Change the payload of this conversation"));
    const ta = el("textarea"); ta.rows = 2; ta.spellcheck = false; ta.placeholder = "old=>new (one per line)"; ta.value = r.replace;
    ta.oninput = () => { r.replace = ta.value; update(); };
    det.append(ta); if (r.replace) det.open = true;
    function update() {
      const cIp = r.clientIp || r.client.ip, sIp = r.serverIp || r.server.ip, cPort = r.clientPort || r.client.port, sPort = r.serverPort || r.server.port;
      const ch = changed(r);
      chg.textContent = ch ? "modified" : "unchanged"; chg.className = "chg" + (ch ? " on" : "");
      preview.replaceChildren(document.createTextNode("sent as  "));
      preview.append(el(ch ? "b" : "span", "", endpoint(r.proto, cIp, cPort) + "  ⇄  " + endpoint(r.proto, sIp, sPort)),
        document.createTextNode(ch ? "   (replies come FROM the new server address)" : "   (exactly as recorded)"));
      refreshUI();
    }
    update();
    body.append(grid, preview, det);
    card.append(head, body);
    box.append(card);
  });
  $("#selTitle").textContent = rules.length ? "Selected conversations (" + rules.length + ")" : "Selected conversations";
  $("#convEmpty").hidden = rules.length > 0;
  $("#convEmpty").textContent = mode === "tcp"
    ? "None ticked: TCP will replay the first conversation that matches the filter. Tick one in the list to choose."
    : "None ticked: every conversation of the chosen mode in the capture will be sent exactly as recorded.";
  $("#alsoRow").hidden = !(rules.length > 0 && mode !== "tcp");
}

$("#addSelector").onclick = () => {
  const v = $("#selectorIn").value.trim();
  if (!v) return;
  const e = $("#selectorErr");
  if (addRuleObj(v)) { $("#selectorIn").value = ""; e.textContent = ""; renderConversations(); renderSelection(); refreshUI(); }
  else { e.textContent = "Expected proto/client/server, e.g. tcp/192.168.1.50:51234/192.168.1.10:80"; e.style.color = "var(--err)"; }
};
$("#selectorIn").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#addSelector").click(); });

function ruleBody() {
  return rules.map((r) => ({
    selector: r.selector, clientIp: r.clientIp, serverIp: r.serverIp,
    clientPort: Number(r.clientPort) || 0, serverPort: Number(r.serverPort) || 0,
    replace: r.replace.split("\n").filter((l) => l.trim()),
  }));
}

// ---------- step 3: settings ----------
function paceVisibility() {
  const m = $("#paceMode").value;
  $$("[data-pace]").forEach((l) => l.hidden = l.dataset.pace !== m);
}
$("#paceMode").onchange = paceVisibility;
paceVisibility();

function pacingText() {
  const m = $("#paceMode").value, f = (id) => parseFloat($(id).value) || 0;
  const loop = Math.max(1, parseInt($("#loop").value || "1", 10) || 1);
  let t = "at original timing";
  if (m === "original") { const sp = f("#speed"); if (sp && sp !== 1) t = "at " + sp + "× the original speed"; }
  else if (m === "fixed") t = "one packet every " + ($("#delay").value.trim() || "?");
  else if (m === "pps") t = "at " + fmtInt(f("#pps")) + " packets/s";
  else if (m === "mbps") t = "at " + f("#mbps") + " Mbit/s";
  else if (m === "burst") t = "at line rate";
  return t + (loop > 1 ? ", " + loop + " passes" : "");
}

function globalRewriteActive() {
  return ["#srcIp", "#dstIp", "#payload"].some((id) => $(id).value.trim()) || ["#srcPort", "#dstPort"].some((id) => Number($(id).value) > 0) || $("#replace").value.trim() !== "";
}

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
    conversations: ruleBody(), onlyConversations: rules.length > 0 && (mode === "tcp" || !$("#alsoOthers").checked),
  };
}

// ---------- step 4: summary, button state, status ----------
function buildSummary() {
  const box = $("#sendSummary"); box.replaceChildren();
  const add = (t) => box.append(document.createTextNode(t));
  const bold = (t) => box.append(el("b", "", t));
  const path = $("#path").value.trim();
  if (!path) { add("Open a capture in step 1 to begin."); return; }
  if (!mode) { add("Next: choose "); bold("TCP or UDP"); add(" in step 2."); return; }
  const M = mode.toUpperCase();
  add("Send ");
  if (rules.length) {
    bold(plural(rules.length, M + " conversation"));
    const n = rules.filter(changed).length;
    add(n ? " (" + n + " modified)" : " exactly as recorded");
    if (mode !== "tcp" && $("#alsoOthers").checked) add(", plus all the others unchanged");
  } else if (mode === "tcp") { add("the "); bold("first matching TCP conversation"); }
  else bold("all UDP traffic");
  add(" from "); bold(baseName(path));
  if ($("#filter").value.trim()) add(" (filtered)");
  add(", " + pacingText() + ", ");
  add($("#backend").value === "null" ? "as a dry run: nothing leaves this machine" : "via raw injection onto the network");
  const rec = $("#record").value.trim();
  if (rec) add(", recording to " + baseName(rec));
  add(".");
  if (globalRewriteActive() && (!rules.length || (mode !== "tcp" && $("#alsoOthers").checked))) {
    const w = el("div", "hint warnbox", "Rewrite-every-packet (step 3) is active: it changes every packet that is not individually ticked, including server replies.");
    box.append(w);
  }
}

function refreshUI() {
  const running = lastState === "running";
  const hasPath = !!$("#path").value.trim();
  // range summary
  const r = range(); const parts = [];
  if (r.filter.trim()) parts.push("filtered");
  if (r.start) parts.push("from packet " + fmtInt(r.start));
  if (r.count) parts.push("max " + fmtInt(r.count));
  $("#rangeSummary").textContent = parts.length ? "(" + parts.join(", ") + ")" : "(everything)";
  // settings one-liners
  $("#pacingSum").textContent = pacingText();
  $("#backendSum").textContent = $("#backend").value === "null" ? "dry run" : "raw injection";
  $("#recSum").textContent = $("#record").value.trim() ? baseName($("#record").value.trim()) : "(off)";
  $("#tcpSum").textContent = [$("#skipBytes").value > 0 ? "skip " + $("#skipBytes").value + " B" : "", Number($("#seqOffset").value) ? "seq offset " + $("#seqOffset").value : ""].filter(Boolean).join(", ");
  // buttons
  $("#runStats").disabled = !hasPath || running;
  $("#pickAnalyze").disabled = !hasPath || running;
  const tooMany = mode === "tcp" && rules.length > 1;
  const ready = hasPath && !!mode && !tooMany;
  $("#runReplay").disabled = !ready || running;
  const hint = $("#startHint");
  if (!hasPath) hint.textContent = "";
  else if (!mode) hint.textContent = "Choose TCP or UDP in step 2: the transmission mode is never guessed.";
  else if (tooMany) hint.textContent = "TCP mode replays a single conversation: untick the others.";
  else if (info.elevated === false && $("#backend").value !== "null") hint.textContent = "Raw injection needs Administrator/root. Start pktreplay elevated, or choose Dry run in step 3.";
  else hint.textContent = "";
  buildSummary();
  renderSteps();
}

function renderSteps() {
  const set = (id, cls, text) => { const a = document.querySelector('a[data-step="' + id + '"]'); a.classList.toggle("done", cls === "done"); $("#st-" + id).textContent = text; };
  const analyzing = lastState === "running" && lastKind === "stats";
  set("s1", convData ? "done" : "", analyzing ? "analyzing…" : convData ? fmtInt(convData.conversationsTotal) + " conversations" : "");
  set("s2", mode ? "done" : "", mode ? mode.toUpperCase() + (rules.length ? " · " + rules.length + " ticked" : " · all") : "");
  set("s3", "", "");
  const replayed = lastKind === "replay";
  set("s4", replayed && lastState === "done" ? "done" : "", replayed ? lastState : "");
}

// scroll spy for steps 1-3 (step 4 is always on screen on wide layouts)
if ("IntersectionObserver" in window) {
  const links = Object.fromEntries($$(".steps a").map((a) => [a.dataset.step, a]));
  const visible = new Set();
  const io = new IntersectionObserver((ents) => {
    for (const e of ents) e.isIntersecting ? visible.add(e.target.id) : visible.delete(e.target.id);
    const cur = ["s1", "s2", "s3"].find((id) => visible.has(id));
    Object.entries(links).forEach(([id, a]) => a.classList.toggle("active", id === cur));
  }, { rootMargin: "-20% 0px -55% 0px" });
  ["s1", "s2", "s3"].forEach((id) => io.observe($("#" + id)));
}

$("#runReplay").onclick = async () => {
  showErr("#replayError", "");
  try { await api("/api/replay", replayBody()); startPolling(); }
  catch (e) { showErr("#replayError", e.message); }
};
$("#stopReplay").onclick = () => api("/api/cancel", {}).catch(() => {});

function startPolling() {
  clearInterval(poller);
  poller = setInterval(poll, 400);
  poll();
}

async function poll() {
  let s;
  try { s = await api("/api/status"); } catch (_) { return; }
  lastState = s.state; lastKind = s.kind;
  const running = s.state === "running";
  const isStats = s.kind === "stats", isReplay = s.kind === "replay";

  // step 1: analysis progress
  $("#stopStats").hidden = !(isStats && running);
  $("#runStats").hidden = isStats && running;
  $("#statsProgress").hidden = !(isStats && s.scan && (running || s.state === "cancelled"));
  if (isStats && s.scan) {
    $("#statsBar").style.width = s.scan.percent.toFixed(1) + "%";
    $("#statsProgText").textContent = fmtInt(s.scan.packets) + " packets · " + fmtBytes(s.scan.bytes) + (s.scan.total ? " of " + fmtBytes(s.scan.total) : "") + " · " + fmtDur(s.elapsedSec);
  }
  if (isStats) {
    showErr("#statsError", s.state === "failed" ? s.error : "");
    const key = s.kind + "|" + s.elapsedSec + "|" + (s.summary ? s.summary.packets : "");
    if (s.summary && !running && key !== summaryKey) { summaryKey = key; renderSummary(s.summary, s.state === "cancelled"); }
  }

  // step 4: live replay status
  $("#runReplay").hidden = isReplay && running; $("#stopReplay").hidden = !(isReplay && running);
  const pill = $("#pill"); pill.textContent = isReplay ? s.state : "idle"; pill.className = "pill " + (isReplay ? s.state : "");
  if (isReplay) {
    showErr("#replayError", s.state === "failed" ? s.error : "");
    const r = s.replay, g = $("#liveGrid"); g.replaceChildren();
    if (r) for (const [v, l] of [[fmtInt(r.sent), "packets sent"], [fmtBytes(r.bytes), "bytes sent"], [fmtInt(r.pps) + " pps", "rate"], [r.mbps.toFixed(2) + " Mbit/s", "throughput"],
      [fmtInt(r.read), "read from file"], [fmtInt(r.skipped), "skipped"], [fmtInt(r.sendErrs), "send errors"], [fmtDur(s.elapsedSec), "elapsed"]]) {
      const d = el("div"); d.append(el("b", "", v), el("span", "", l)); g.append(d);
    }
    const ti = $("#tcpInfo"); ti.hidden = !s.tcp; ti.replaceChildren();
    if (s.tcp) for (const [k, v] of [["Flow", s.tcp.flow], ["Live source", s.tcp.localIp + ":" + s.tcp.localPort],
      ["Handshake", s.tcp.handshakeUs ? s.tcp.handshakeUs.toFixed(0) + " µs" : "–"], ["Retransmits", String(s.tcp.retransmits)],
      ["Server sent", fmtBytes(s.tcp.rxBytes) + " / " + s.tcp.rxSegments + " segs"], ["Ended", s.tcp.finalState || "–"]]) {
      const d = el("div"); d.append(el("span", "", k), el("span", "mono", v)); ti.append(d);
    }
    const ri = $("#recInfo"); ri.hidden = !s.recording; ri.replaceChildren();
    if (s.recording) for (const [k, v] of [["Recording", s.recording.path], ["Packets", fmtInt(s.recording.packets)], ["Bytes", fmtBytes(s.recording.bytes)]]) {
      const d = el("div"); d.append(el("span", "", k), el("span", "mono", v)); ri.append(d);
    }
    const log = $("#log"), atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    log.hidden = !s.log.length; log.textContent = s.log.join("\n");
    if (atEnd) log.scrollTop = log.scrollHeight;
  }
  renderConversations();
  refreshUI();
  if (!running) { clearInterval(poller); poller = null; }
}

// any form edit updates the summary and button state
document.addEventListener("input", refreshUI);
document.addEventListener("change", refreshUI);
for (const id of ["#path", "#filter", "#start", "#count"]) $(id).addEventListener("input", renderConversations);

// ---------- init ----------
(async function init() {
  try {
    info = await api("/api/info");
    $("#ver").textContent = (info.version || "dev") + " · " + info.os + "/" + info.arch;
    const b = $("#elev");
    b.textContent = info.elevated ? "Elevated: raw injection available" : "Not elevated: dry run / analysis only";
    b.className = "badge " + (info.elevated ? "ok" : "warn");
    if (!info.elevated) $("#backend").value = "null"; // raw injection would just fail without privileges
  } catch (e) { showErr("#statsError", e.message); }
  renderConversations(); renderSelection(); refreshUI();
  poll(); // pick up a job that is already running (page reload)
})();
