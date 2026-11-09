(() => {
  "use strict";
  if (window.__scamguardLoaded) return;
  window.__scamguardLoaded = true;

  const LABEL = { scam: "Scam", likely_scam: "Likely scam", suspicious: "Suspicious" };
  const ICON = { scam: "🚨", likely_scam: "🚨", suspicious: "⚠️" };
  const listCache = new Map();   // key -> quick result (inbox rows)
  const deepCache = new Map();   // key -> deep result (opened emails)
  let enabled = true, timer = null, running = false, failUntil = 0;

  const send = (msg) =>
    new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r));
      } catch (e) {
        resolve(null);   // extension was reloaded; the page just needs a refresh
      }
    });

  const hash = (s) => {
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    return String(h >>> 0);
  };
  const flagged = (r) => r && LABEL[r.verdict];
  const css = (r) => (r.verdict === "suspicious" ? "susp" : "scam");

  /* ---------------- inbox list: badge next to each flagged email ---------------- */

  function rowInfo(tr) {
    const s = tr.querySelector("span[email]");
    const email = (s && s.getAttribute("email")) || "";
    const name = (s && (s.getAttribute("name") || s.textContent)) || "";
    const subject = (tr.querySelector(".bog") || {}).textContent || "";
    const snippet = ((tr.querySelector(".y2") || {}).textContent || "").replace(/^\s*-\s*/, "");
    if (!email && !subject) return null;
    const t = tr.querySelector("[data-legacy-thread-id]");
    const tid = (t && t.getAttribute("data-legacy-thread-id")) || "";
    return { tid, name: name.trim(), email: email.toLowerCase(), subject: subject.trim(), snippet: snippet.trim() };
  }

  function removeBadge(tr) {
    tr.querySelectorAll(".sg-badge").forEach((n) => n.remove());
    tr.classList.remove("sg-row-scam", "sg-row-susp");
  }

  function applyBadge(tr, res) {
    removeBadge(tr);
    if (!flagged(res)) return;
    const host = tr.querySelector(".y6") || tr.querySelector(".xY");
    if (!host) return;
    const b = document.createElement("span");
    b.className = "sg-badge sg-" + css(res);
    b.textContent = `${ICON[res.verdict]} ${LABEL[res.verdict]} · ${res.type}`;
    b.title = `ScamGuard risk ${res.score}/100\n` + (res.reasons || []).map((x) => "• " + x).join("\n");
    host.insertBefore(b, host.firstChild);
    tr.classList.add("sg-row-" + css(res));
  }

  async function scanList() {
    const pending = new Map();
    for (const tr of document.querySelectorAll("tr.zA")) {
      const info = rowInfo(tr);
      if (!info) continue;
      const key = hash([info.email, info.subject, info.snippet.slice(0, 150)].join("|"));
      if (tr.dataset.sgKey !== key) removeBadge(tr);          // Gmail recycles rows: clear stale badges
      tr.dataset.sgKey = key;
      const hit = listCache.get(key);
      if (hit && (hit.source === "full" || Date.now() - hit.ts < 90000)) {
        if (!tr.querySelector(".sg-badge")) applyBadge(tr, hit);
      } else {
        pending.set(key, { key, thread_id: info.tid, sender_name: info.name, sender_email: info.email,
                           subject: info.subject, snippet: info.snippet });
      }
    }
    if (!pending.size || Date.now() < failUntil) return;
    const resp = await send({ type: "api", path: "/check-batch", body: { items: [...pending.values()] } });
    if (!resp || !resp.ok) { failUntil = Date.now() + 15000; return; }   // server not running: retry later
    for (const r of resp.data.results || []) listCache.set(r.key, { ...r, ts: Date.now() });
    for (const tr of document.querySelectorAll("tr.zA")) {
      const r = listCache.get(tr.dataset.sgKey);
      if (r) applyBadge(tr, r);
    }
  }

  /* ---------------- opened email: banner with reasons ---------------- */

  const unwrap = (href) => {
    try {   // Gmail sometimes wraps links as google.com/url?q=REAL
      const u = new URL(href);
      if (/(^|\.)google\.com$/.test(u.hostname) && u.pathname === "/url") return u.searchParams.get("q") || href;
    } catch (e) {}
    return href;
  };

  function add(parent, tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    el.textContent = text;           // textContent only: email content is untrusted
    parent.appendChild(el);
    return el;
  }

  function renderBanner(msg, anchor, d) {
    msg.querySelectorAll(".sg-banner").forEach((n) => n.remove());
    const b = document.createElement("div");
    if (!flagged(d)) {
      b.className = "sg-banner sg-ok";
      add(b, "div", "sg-b-head", "✅ ScamGuard: no strong red flags found");
    } else {
      b.className = "sg-banner sg-b-" + css(d);
      const head = add(b, "div", "sg-b-head", `${ICON[d.verdict]} ScamGuard: ${d.label.replace(/^\S+\s/, "")} · ${d.type}`);
      add(head, "span", "sg-b-score", `${d.score}/100`);
      add(b, "div", "sg-b-sum", d.summary);
      const ul = add(b, "ul", "sg-b-list", "");
      (d.signals || []).slice(0, 4).forEach((s) => add(ul, "li", "", `${s.title}: ${s.detail}`));
      if (d.actions && d.actions[0]) add(b, "div", "sg-b-act", d.actions[0]);
    }
    anchor.parentElement.insertBefore(b, anchor);
  }

  async function scanOpen() {
    const subject = ((document.querySelector("h2.hP") || {}).textContent || "").trim();
    for (const body of document.querySelectorAll("div.a3s")) {
      const anchor = body.closest(".ii") || body;
      const msg = body.closest(".adn") || anchor.parentElement;
      if (!msg || !anchor.parentElement) continue;
      const text = ((body.innerText ?? body.textContent) || "").trim().slice(0, 5000);
      if (!text) continue;
      const se = msg.querySelector("span.gD[email], .gD[email]");
      const sender_email = ((se && se.getAttribute("email")) || "").toLowerCase();
      const sender_name = (se && (se.getAttribute("name") || se.textContent) || "").trim();
      const key = hash([sender_email, subject, text.slice(0, 300)].join("|"));

      if (msg.dataset.sgDeep === key) {
        if (!msg.querySelector(".sg-banner") && deepCache.has(key)) renderBanner(msg, anchor, deepCache.get(key));
        continue;
      }
      if (Date.now() < failUntil) continue;
      msg.dataset.sgDeep = key;

      const links = [...body.querySelectorAll("a[href]")].slice(0, 30)
        .map((a) => ({ text: (a.textContent || "").trim().slice(0, 200), href: unwrap(a.href) }))
        .filter((l) => /^https?:/i.test(l.href));
      const attachments = [...msg.querySelectorAll(".aV3")].map((n) => (n.textContent || "").trim()).filter(Boolean);

      const resp = await send({ type: "api", path: "/check-email",
        body: { sender_name, sender_email, subject, body: text, links, attachments } });
      if (!resp || !resp.ok) { delete msg.dataset.sgDeep; failUntil = Date.now() + 15000; continue; }
      deepCache.set(key, resp.data);
      renderBanner(msg, anchor, resp.data);
    }
  }

  /* ---------------- wiring ---------------- */

  async function run() {
    if (!enabled || running) return;
    running = true;
    try { await scanList(); await scanOpen(); } finally { running = false; }
  }
  const schedule = () => { clearTimeout(timer); timer = setTimeout(run, 500); };

  function clearAll() {
    document.querySelectorAll(".sg-badge, .sg-banner").forEach((n) => n.remove());
    document.querySelectorAll(".sg-row-scam, .sg-row-susp").forEach((n) => n.classList.remove("sg-row-scam", "sg-row-susp"));
    document.querySelectorAll("[data-sg-key],[data-sg-deep]").forEach((n) => { delete n.dataset.sgKey; delete n.dataset.sgDeep; });
  }

  chrome.storage.sync.get({ enabled: true }, (v) => { enabled = v.enabled; schedule(); });
  chrome.storage.onChanged.addListener((c) => {
    if (c.enabled) { enabled = c.enabled.newValue; enabled ? schedule() : clearAll(); }
  });
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
  schedule();
})();