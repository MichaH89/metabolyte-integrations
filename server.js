import express from "express";
import crypto from "crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(express.json());

// ===============================
// DB
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render Postgres braucht oft SSL intern nicht; wenn du External URL nutzt ggf. ssl: { rejectUnauthorized: false }
});

async function dbInit() {
  await pool.query(`
    create table if not exists oauth_states (
      id bigserial primary key,
      provider text not null,
      user_email text not null,
      state text not null,
      expires_at timestamptz not null,
      created_at timestamptz not null default now()
    );
  `);

  await pool.query(`
    create index if not exists idx_oauth_states_lookup
    on oauth_states (provider, state);
  `);

  await pool.query(`
    create table if not exists provider_accounts (
      id bigserial primary key,
      provider text not null,
      user_email text not null,
      athlete_id bigint,
      access_token text not null,
      refresh_token text not null,
      expires_at bigint not null,
      scope text,
      updated_at timestamptz not null default now(),
      unique (provider, user_email)
    );
  `);
}

function mustGetEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

// ===============================
// HEALTH
// ===============================
app.get("/health", async (_req, res) => {
  try {
    await pool.query("select 1 as ok");
    res.json({ status: "ok", db: "ok" });
  } catch (e) {
    res.status(500).json({ status: "error", db: "error", message: String(e?.message ?? e) });
  }
});

// ===============================
// TOKEN HELPERS (pro User)
// ===============================
async function loadAccount(user_email) {
  const r = await pool.query(
    `select * from provider_accounts where provider='strava' and user_email=$1`,
    [user_email]
  );
  return r.rows[0] || null;
}

async function saveAccount({
  user_email,
  athlete_id,
  access_token,
  refresh_token,
  expires_at,
  scope,
}) {
  await pool.query(
    `
    insert into provider_accounts (provider, user_email, athlete_id, access_token, refresh_token, expires_at, scope)
    values ('strava', $1, $2, $3, $4, $5, $6)
    on conflict (provider, user_email)
    do update set
      athlete_id=excluded.athlete_id,
      access_token=excluded.access_token,
      refresh_token=excluded.refresh_token,
      expires_at=excluded.expires_at,
      scope=excluded.scope,
      updated_at=now()
    `,
    [user_email, athlete_id ?? null, access_token, refresh_token, expires_at, scope ?? null]
  );
}

async function getValidAccessTokenForUser(user_email) {
  const acc = await loadAccount(user_email);
  if (!acc) throw new Error("Not connected. User has no Strava tokens.");

  const now = Math.floor(Date.now() / 1000);

  // Token gültig?
  if (acc.expires_at && now < Number(acc.expires_at) - 60) {
    return acc.access_token;
  }

  // Refresh
  const clientId = mustGetEnv("STRAVA_CLIENT_ID");
  const clientSecret = mustGetEnv("STRAVA_CLIENT_SECRET");

  const refreshResp = await fetch("https://www.strava.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: acc.refresh_token,
    }),
  });

  const refreshJson = await refreshResp.json();
  if (!refreshResp.ok) {
    console.error("Refresh failed:", refreshJson);
    throw new Error("Refresh token failed");
  }

  await saveAccount({
    user_email,
    athlete_id: refreshJson.athlete?.id ?? acc.athlete_id,
    access_token: refreshJson.access_token,
    refresh_token: refreshJson.refresh_token,
    expires_at: refreshJson.expires_at,
    scope: acc.scope,
  });

  return refreshJson.access_token;
}

// ===============================
// OAUTH START (Multi-User)
// Öffnen: /auth/strava/start?u=user@email.de
// ===============================
app.get("/auth/strava/start", async (req, res) => {
  try {
    const user_email = String(req.query.u || "").trim().toLowerCase();
    if (!user_email || !user_email.includes("@")) {
      return res.status(400).send("Missing or invalid ?u=user_email");
    }

    const clientId = mustGetEnv("STRAVA_CLIENT_ID");
    const redirectUri = mustGetEnv("STRAVA_REDIRECT_URI");

    const state = crypto.randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // state speichern -> damit callback weiß, zu welchem user das gehört
    await pool.query(
      `insert into oauth_states (provider, user_email, state, expires_at)
       values ('strava', $1, $2, $3)`,
      [user_email, state, expiresAt]
    );

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
  } catch (e) {
    console.error(e);
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ===============================
// OAUTH CALLBACK
// ===============================
app.get("/auth/strava/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.status(400).json({ error: "Strava returned an error", details: req.query });
    }

    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    const scope = String(req.query.scope || "");

    if (!code) return res.status(400).json({ error: "Missing code", details: req.query });
    if (!state) return res.status(400).json({ error: "Missing state", details: req.query });

    // state -> user_email lookup
    const st = await pool.query(
      `select user_email, expires_at from oauth_states where provider='strava' and state=$1 order by id desc limit 1`,
      [state]
    );

    const row = st.rows[0];
    if (!row) return res.status(400).send("Invalid state (not found).");
    if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).send("State expired.");

    const user_email = row.user_email;

    // optional: state cleanup
    await pool.query(`delete from oauth_states where provider='strava' and state=$1`, [state]);

    // exchange code -> token
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

    await saveAccount({
      user_email,
      athlete_id: tokenJson.athlete?.id,
      access_token: tokenJson.access_token,
      refresh_token: tokenJson.refresh_token,
      expires_at: tokenJson.expires_at,
      scope,
    });

    return res.send(`
      <h2>Strava verbunden ✅</h2>
      <p>User: ${user_email}</p>
      <p>Athlete ID: ${tokenJson.athlete?.id}</p>
      <p>Scope: ${scope}</p>
      <p><a href="/strava/activities?u=${encodeURIComponent(user_email)}">Letzte Aktivitäten anzeigen</a></p>
    `);
  } catch (e) {
    console.error(e);
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ===============================
// ACTIVITIES (pro User)
// Aufrufen: /strava/activities?u=user@email.de
// ===============================
app.get("/strava/activities", async (req, res) => {
  try {
    const user_email = String(req.query.u || "").trim().toLowerCase();
    if (!user_email || !user_email.includes("@")) {
      return res.status(400).send("Missing or invalid ?u=user_email");
    }

    const accessToken = await getValidAccessTokenForUser(user_email);

    const r = await fetch(
      "https://www.strava.com/api/v3/athlete/activities?per_page=10&page=1",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const items = data.map(a => {
      const km = a.distance ? (a.distance / 1000).toFixed(2) : "0.00";
      return `
        <li>
          <b>${a.type}</b> — ${a.name} — ${km} km —
          <a href="/strava/activity/${a.id}?u=${encodeURIComponent(user_email)}">Details</a> |
          <a href="/strava/activity/${a.id}/streams?u=${encodeURIComponent(user_email)}">Streams</a>
        </li>
      `;
    }).join("");

    return res.send(`<h2>Letzte Aktivitäten (${user_email})</h2><ul>${items}</ul>`);
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ===============================
// ACTIVITY DETAILS (pro User)
// ===============================
app.get("/strava/activity/:id", async (req, res) => {
  try {
    const user_email = String(req.query.u || "").trim().toLowerCase();
    if (!user_email || !user_email.includes("@")) {
      return res.status(400).send("Missing or invalid ?u=user_email");
    }

    const accessToken = await getValidAccessTokenForUser(user_email);
    const id = req.params.id;

    const r = await fetch(`https://www.strava.com/api/v3/activities/${id}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    return res.json(data);
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ===============================
// ACTIVITY STREAMS (pro User)
// ===============================
app.get("/strava/activity/:id/streams", async (req, res) => {
  try {
    const user_email = String(req.query.u || "").trim().toLowerCase();
    if (!user_email || !user_email.includes("@")) {
      return res.status(400).send("Missing or invalid ?u=user_email");
    }

    const accessToken = await getValidAccessTokenForUser(user_email);
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
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const summary = Object.keys(data).reduce((acc, k) => {
      acc[k] = { points: Array.isArray(data[k]?.data) ? data[k].data.length : 0 };
      return acc;
    }, {});

    return res.json({ user_email, activity_id: id, summary });
  } catch (e) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ===============================
// START SERVER
// ===============================
const port = process.env.PORT || 3000;
dbInit()
  .then(() => {
    app.listen(port, () => console.log("Server running on port", port));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
