import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// 1) Health check (zum Testen ob Server lebt)
app.get("/health", (req, res) => res.json({ status: "ok" }));

// Helper: env safe read
function mustGetEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

// 2) Start OAuth: Redirect zu Strava
app.get("/auth/strava/start", (req, res) => {
  const clientId = mustGetEnv("STRAVA_CLIENT_ID");
  const redirectUri = mustGetEnv("STRAVA_REDIRECT_URI");

  // State = Schutz gegen Fake-Callbacks
  const state = crypto.randomBytes(16).toString("hex");

  // TODO (später): state pro user speichern (DB). Für den ersten Test reicht das so.
  // Wir senden es als Cookie zurück (super simpel)
  res.cookie?.("strava_oauth_state", state); // falls cookie middleware nicht da ist, egal

  const scope = "read,activity:read_all"; // <- HIER setzt du die Scopes!

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

// 3) Callback: code -> token exchange
app.get("/auth/strava/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const scope = req.query.scope;

    if (!code) {
      return res.status(400).send("Missing ?code from Strava");
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
        grant_type: "authorization_code"
      })
    });

    const tokenJson = await tokenResp.json();

    if (!tokenResp.ok) {
      console.error("Token exchange failed:", tokenJson);
      return res.status(500).json({ error: "Token exchange failed", details: tokenJson });
    }

    // tokenJson enthält: access_token, refresh_token, expires_at, athlete {...}
    // TODO (später): hier speichern wir es in Base44 Entities
    return res.json({
      ok: true,
      received_scope: scope,
      athlete_id: tokenJson.athlete?.id,
      expires_at: tokenJson.expires_at
      // NICHT tokens im Browser anzeigen in Produktion!
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Callback error");
  }
});

// Render gibt PORT vor
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on port", port));
