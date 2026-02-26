import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// =====================================================
// SUPER SIMPLE TOKEN STORAGE (nur für Test!)
// =====================================================
let stravaTokens = null;

// =====================================================
// HEALTH CHECK
// =====================================================
app.get("/health", (req, res) => res.json({ status: "ok" }));

// =====================================================
// HELPER
// =====================================================
function mustGetEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

async function getValidAccessToken() {
  if (!stravaTokens) {
    throw new Error("Not connected to Strava. Open /auth/strava/start first.");
  }

  const now = Math.floor(Date.now() / 1000);

  // Token noch gültig?
  if (stravaTokens.expires_at && now < stravaTokens.expires_at - 60) {
    return stravaTokens.access_token;
  }

  // Refresh Token
  const clientId = mustGetEnv("STRAVA_CLIENT_ID");
  const clientSecret = mustGetEnv("STRAVA_CLIENT_SECRET");

  const refreshResp = await fetch("https://www.strava.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: stravaTokens.refresh_token,
    }),
  });

  const refreshJson = await refreshResp.json();

  if (!refreshResp.ok) {
    console.error("Refresh failed:", refreshJson);
    throw new Error("Refresh token failed");
  }

  stravaTokens = refreshJson;
  return stravaTokens.access_token;
}

// =====================================================
// STRAVA OAUTH START
// =====================================================
app.get("/auth/strava/start", (req, res) => {
  const clientId = mustGetEnv("STRAVA_CLIENT_ID");
  const redirectUri = mustGetEnv("STRAVA_REDIRECT_URI");

  const state = crypto.randomBytes(16).toString("hex");
  const scope = "read,activity:read_all";

  const url =
    "https://www.strava.com/oauth/authorize" +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&approval_prompt=auto` +
    `&scope=${encodeURIComponent(scope)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(url);
});

// =====================================================
// STRAVA CALLBACK
// =====================================================
app.get("/auth/strava/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.status(400).json({
        error: "Strava returned an error",
        details: req.query
      });
    }

    const code = req.query.code;
    const scope = req.query.scope;

    if (!code) {
      return res.status(400).json({
        error: "Missing code",
        details: req.query
      });
    }

    const clientId = mustGetEnv("STRAVA_CLIENT_ID");
    const clientSecret = mustGetEnv("STRAVA_CLIENT_SECRET");

    const tokenResp = await fetch("https://www.strava.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        grant_type: "authorization_code",
      }),
    });

    const tokenJson = await tokenResp.json();

    if (!tokenResp.ok) {
      console.error("Token exchange failed:", tokenJson);
      return res.status(500).json({ error: "Token exchange failed", details: tokenJson });
    }

    stravaTokens = tokenJson;

    return res.send(`
      <h2>Strava verbunden ✅</h2>
      <p>Athlete ID: ${tokenJson.athlete?.id}</p>
      <p>Scope: ${scope}</p>
      <p><a href="/strava/activities">Letzte Aktivitäten anzeigen</a></p>
    `);
  } catch (err) {
    console.error(err);
    return res.status(500).send("Callback error");
  }
});

// =====================================================
// LETZTE AKTIVITÄTEN
// =====================================================
app.get("/strava/activities", async (req, res) => {
  try {
    const accessToken = await getValidAccessToken();

    const r = await fetch(
      "https://www.strava.com/api/v3/athlete/activities?per_page=10&page=1",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({ error: "Strava API error", details: data });
    }

    const items = data.map(a => {
      const km = a.distance ? (a.distance / 1000).toFixed(2) : "0.00";
      return `
        <li>
          <b>${a.type}</b> — ${a.name} — ${km} km —
          <a href="/strava/activity/${a.id}">Details</a> |
          <a href="/strava/activity/${a.id}/streams">Streams</a>
        </li>
      `;
    }).join("");

    return res.send(`<h2>Letzte Aktivitäten</h2><ul>${items}</ul>`);
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// =====================================================
// ACTIVITY DETAILS
// =====================================================
app.get("/strava/activity/:id", async (req, res) => {
  try {
    const accessToken = await getValidAccessToken();
    const id = req.params.id;

    const r = await fetch(
      `https://www.strava.com/api/v3/activities/${id}`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({ error: "Strava API error", details: data });
    }

    return res.json(data);
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// =====================================================
// ACTIVITY STREAMS (Pseudo-FIT Daten)
// =====================================================
app.get("/strava/activity/:id/streams", async (req, res) => {
  try {
    const accessToken = await getValidAccessToken();
    const id = req.params.id;

    const keys = [
      "time",
      "distance",
      "heartrate",
      "watts",
      "cadence",
      "velocity_smooth",
      "altitude",
      "grade_smooth",
      "temp"
    ].join(",");

    const r = await fetch(
      `https://www.strava.com/api/v3/activities/${id}/streams?keys=${encodeURIComponent(keys)}&key_by_type=true`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({ error: "Strava API error", details: data });
    }

    const summary = Object.keys(data).reduce((acc, k) => {
      acc[k] = {
        points: Array.isArray(data[k]?.data) ? data[k].data.length : 0
      };
      return acc;
    }, {});

    return res.json({ summary });
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// =====================================================
// SERVER START
// =====================================================
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
