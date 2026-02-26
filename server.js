import express from "express";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { Pool } from "pg";

const app = express();
app.use(express.json({ type: "*/*" }));
app.use(cookieParser());

// ---------- ENV ----------
function mustGetEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

const STRAVA_CLIENT_ID = mustGetEnv("STRAVA_CLIENT_ID");
const STRAVA_CLIENT_SECRET = mustGetEnv("STRAVA_CLIENT_SECRET");
const STRAVA_REDIRECT_URI = mustGetEnv("STRAVA_REDIRECT_URI");
const STRAVA_WEBHOOK_VERIFY_TOKEN = mustGetEnv("STRAVA_WEBHOOK_VERIFY_TOKEN");
const PUBLIC_BASE_URL = mustGetEnv("PUBLIC_BASE_URL");
const BASE44_INGEST_SECRET = mustGetEnv("BASE44_INGEST_SECRET");

// ---------- DB ----------
const pool = new Pool({
  connectionString: mustGetEnv("DATABASE_URL"),
  ssl: process.env.DATABASE_URL?.includes("render.com") ? { rejectUnauthorized: false } : undefined,
});

// Create tables if not exist (super simple migration)
async function ensureSchema() {
  await pool.query(`
    create table if not exists strava_connections (
      id bigserial primary key,
      user_email text not null,
      athlete_id bigint not null unique,
      access_token text not null,
      refresh_token text not null,
      expires_at bigint not null,
      scope text,
      created_at timestamptz default now(),
      updated_at timestamptz default now()
    );

    create index if not exists idx_strava_connections_user_email on strava_connections(user_email);

    create table if not exists oauth_state (
      id bigserial primary key,
      state text not null unique,
      user_email text not null,
      provider text not null,
      expires_at timestamptz not null,
      created_at timestamptz default now()
    );

    create table if not exists workouts_raw (
      id bigserial primary key,
      provider text not null,              -- "strava"
      athlete_id bigint not null,
      activity_id bigint not null,
      aspect_type text,
      object_type text,
      event_time bigint,
      raw_event jsonb,
      raw_activity jsonb,
      raw_streams jsonb,
      analysis jsonb,
      status text not null default 'received',  -- received|fetched|analyzed|written_to_calendar|error
      error text,
      created_at timestamptz default now(),
      updated_at timestamptz default now(),
      unique(provider, activity_id)
    );
  `);
}

async function dbNow() {
  const r = await pool.query("select now() as now");
  return r.rows[0].now;
}

// ---------- HELPERS ----------
function randomState(): string {
  return crypto.randomBytes(16).toString("hex");
}

async function saveOAuthState(state: string, userEmail: string) {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await pool.query(
    `insert into oauth_state(state, user_email, provider, expires_at)
     values($1,$2,'strava',$3)`,
    [state, userEmail, expiresAt.toISOString()]
  );
}

async function consumeOAuthState(state: string): Promise<{ user_email: string } | null> {
  const r = await pool.query(
    `select user_email from oauth_state where state=$1 and provider='strava' and expires_at > now()`,
    [state]
  );
  if (r.rowCount === 0) return null;
  await pool.query(`delete from oauth_state where state=$1`, [state]);
  return { user_email: r.rows[0].user_email };
}

async function upsertConnection(params: {
  user_email: string;
  athlete_id: number;
  access_token: string;
  refresh_token: string;
  expires_at: number;
  scope?: string;
}) {
  await pool.query(
    `
    insert into strava_connections(user_email, athlete_id, access_token, refresh_token, expires_at, scope)
    values($1,$2,$3,$4,$5,$6)
    on conflict (athlete_id) do update set
      user_email=excluded.user_email,
      access_token=excluded.access_token,
      refresh_token=excluded.refresh_token,
      expires_at=excluded.expires_at,
      scope=excluded.scope,
      updated_at=now()
    `,
    [params.user_email, params.athlete_id, params.access_token, params.refresh_token, params.expires_at, params.scope ?? null]
  );
}

async function getConnectionByAthleteId(athleteId: number) {
  const r = await pool.query(
    `select * from strava_connections where athlete_id=$1`,
    [athleteId]
  );
  return r.rows[0] ?? null;
}

async function refreshTokenIfNeeded(conn: any): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (conn.expires_at && now < Number(conn.expires_at) - 60) {
    return conn.access_token;
  }

  const resp = await fetch("https://www.strava.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: STRAVA_CLIENT_ID,
      client_secret: STRAVA_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: conn.refresh_token,
    }),
  });

  const json = await resp.json();
  if (!resp.ok) throw new Error(`Refresh failed: ${JSON.stringify(json)}`);

  await upsertConnection({
    user_email: conn.user_email,
    athlete_id: Number(conn.athlete_id),
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    expires_at: json.expires_at,
    scope: conn.scope,
  });

  return json.access_token;
}

// ---------- HEALTH ----------
app.get("/health", async (req, res) => {
  try {
    await ensureSchema();
    const now = await dbNow();
    return res.json({ status: "ok", db: "ok", now });
  } catch (e: any) {
    return res.status(500).json({ status: "error", error: String(e?.message ?? e) });
  }
});

// ---------- OAUTH (multi-user) ----------
// Base44 wird später hier die echte user_email mitschicken.
// Für den Dummy-Test gibst du sie als Query mit: /auth/strava/start?email=...
app.get("/auth/strava/start", async (req, res) => {
  const userEmail = String(req.query.email ?? "").trim().toLowerCase();
  if (!userEmail) return res.status(400).send("Missing ?email=...");

  const state = randomState();
  await saveOAuthState(state, userEmail);

  const scope = "read,activity:read_all";

  const url =
    "https://www.strava.com/oauth/authorize" +
    `?client_id=${encodeURIComponent(STRAVA_CLIENT_ID)}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(STRAVA_REDIRECT_URI)}` +
    `&approval_prompt=auto` +
    `&scope=${encodeURIComponent(scope)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(url);
});

app.get("/auth/strava/callback", async (req, res) => {
  try {
    const code = String(req.query.code ?? "");
    const state = String(req.query.state ?? "");
    const scope = String(req.query.scope ?? "");

    if (!code) return res.status(400).send("Missing ?code from Strava");
    if (!state) return res.status(400).send("Missing ?state from Strava");

    const stateRow = await consumeOAuthState(state);
    if (!stateRow) return res.status(400).send("Invalid/expired state. Please retry /auth/strava/start.");

    const tokenResp = await fetch("https://www.strava.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: STRAVA_CLIENT_ID,
        client_secret: STRAVA_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
      }),
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      return res.status(500).json({ error: "Token exchange failed", details: tokenJson });
    }

    const athleteId = Number(tokenJson?.athlete?.id);
    await upsertConnection({
      user_email: stateRow.user_email,
      athlete_id: athleteId,
      access_token: tokenJson.access_token,
      refresh_token: tokenJson.refresh_token,
      expires_at: tokenJson.expires_at,
      scope,
    });

    return res.send(`
      <h2>Strava verbunden ✅</h2>
      <p>User: ${stateRow.user_email}</p>
      <p>Athlete ID: ${athleteId}</p>
      <p>Scope: ${scope}</p>
      <p><a href="/strava/activities?athlete_id=${athleteId}">Letzte Aktivitäten</a></p>
      <p><a href="/webhooks/strava/test">Webhook Test Event senden</a></p>
    `);
  } catch (e: any) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ---------- STRAVA API (per athlete) ----------
app.get("/strava/activities", async (req, res) => {
  try {
    const athleteId = Number(req.query.athlete_id);
    if (!athleteId) return res.status(400).send("Missing ?athlete_id=...");

    const conn = await getConnectionByAthleteId(athleteId);
    if (!conn) return res.status(400).send("Athlete not connected.");

    const accessToken = await refreshTokenIfNeeded(conn);

    const r = await fetch("https://www.strava.com/api/v3/athlete/activities?per_page=10&page=1", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const items = data
      .map((a: any) => {
        const km = a.distance ? (a.distance / 1000).toFixed(2) : "0.00";
        return `<li><b>${a.type}</b> — ${a.name} — ${km} km — <a href="/strava/activity/${a.id}?athlete_id=${athleteId}">Details</a> — <a href="/strava/activity/${a.id}/streams?athlete_id=${athleteId}">Streams</a></li>`;
      })
      .join("");

    return res.send(`<h2>Letzte Aktivitäten</h2><ul>${items}</ul>`);
  } catch (e: any) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

app.get("/strava/activity/:id", async (req, res) => {
  try {
    const athleteId = Number(req.query.athlete_id);
    if (!athleteId) return res.status(400).send("Missing ?athlete_id=...");

    const conn = await getConnectionByAthleteId(athleteId);
    if (!conn) return res.status(400).send("Athlete not connected.");

    const accessToken = await refreshTokenIfNeeded(conn);

    const id = req.params.id;
    const r = await fetch(`https://www.strava.com/api/v3/activities/${id}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });
    return res.json(data);
  } catch (e: any) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

app.get("/strava/activity/:id/streams", async (req, res) => {
  try {
    const athleteId = Number(req.query.athlete_id);
    if (!athleteId) return res.status(400).send("Missing ?athlete_id=...");

    const conn = await getConnectionByAthleteId(athleteId);
    if (!conn) return res.status(400).send("Athlete not connected.");

    const accessToken = await refreshTokenIfNeeded(conn);
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
      "temp",
    ].join(",");

    const r = await fetch(
      `https://www.strava.com/api/v3/activities/${id}/streams?keys=${encodeURIComponent(keys)}&key_by_type=true`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const summary = Object.keys(data).reduce((acc: any, k: string) => {
      acc[k] = {
        hasData: Array.isArray(data[k]?.data),
        points: Array.isArray(data[k]?.data) ? data[k].data.length : 0,
      };
      return acc;
    }, {});

    return res.json({ summary, streams: data });
  } catch (e: any) {
    return res.status(500).send(String(e?.message ?? e));
  }
});

// ---------- WEBHOOKS ----------
// 1) Verify (Strava macht GET mit hub.challenge)
app.get("/webhooks/strava", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === STRAVA_WEBHOOK_VERIFY_TOKEN) {
    return res.json({ "hub.challenge": challenge });
  }
  return res.sendStatus(403);
});

// 2) Events (Strava sendet POST wenn Activity erstellt/updated/deleted)
app.post("/webhooks/strava", async (req, res) => {
  try {
    // Wichtig: sofort 200 zurückgeben (Strava mag schnelle Antworten)
    res.sendStatus(200);

    const event = req.body;
    const ownerId = Number(event?.owner_id);
    const activityId = Number(event?.object_id);

    // speichern "roh"
    await pool.query(
      `
      insert into workouts_raw(provider, athlete_id, activity_id, aspect_type, object_type, event_time, raw_event, status)
      values('strava',$1,$2,$3,$4,$5,$6,'received')
      on conflict (provider, activity_id) do update set
        raw_event=excluded.raw_event,
        updated_at=now()
      `,
      [ownerId, activityId, event.aspect_type ?? null, event.object_type ?? null, event.event_time ?? null, JSON.stringify(event)]
    );

    // Nur wenn es eine neue/aktualisierte activity ist:
    if (event.object_type !== "activity") return;
    if (!["create", "update"].includes(event.aspect_type)) return;

    // => hol Activity + Streams und markiere als fetched
    await fetchAndStoreActivity(ownerId, activityId);

    // => analysieren (Dummy) und dann an Base44 pushen
    await analyzeAndPushToBase44(ownerId, activityId);
  } catch (e) {
    console.error("Webhook error:", e);
  }
});

// Kleiner Test: du kannst dir selbst ein Event schicken
app.get("/webhooks/strava/test", async (req, res) => {
  const fake = {
    aspect_type: "create",
    event_time: Math.floor(Date.now() / 1000),
    object_id: 1234567890,
    object_type: "activity",
    owner_id: 8401174,
    subscription_id: 1,
    updates: {},
  };
  await fetch(`${PUBLIC_BASE_URL}/webhooks/strava`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fake),
  });
  return res.send("Sent test event (fake). Check DB logs.");
});

async function fetchAndStoreActivity(athleteId: number, activityId: number) {
  const conn = await getConnectionByAthleteId(athleteId);
  if (!conn) throw new Error(`No connection for athlete_id=${athleteId}`);

  const accessToken = await refreshTokenIfNeeded(conn);

  const actResp = await fetch(`https://www.strava.com/api/v3/activities/${activityId}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const actJson = await actResp.json();
  if (!actResp.ok) throw new Error(`Activity fetch failed: ${JSON.stringify(actJson)}`);

  const keys = ["time", "distance", "heartrate", "watts", "cadence", "velocity_smooth", "altitude", "grade_smooth", "temp"].join(",");
  const streamResp = await fetch(
    `https://www.strava.com/api/v3/activities/${activityId}/streams?keys=${encodeURIComponent(keys)}&key_by_type=true`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const streamJson = await streamResp.json();
  if (!streamResp.ok) throw new Error(`Streams fetch failed: ${JSON.stringify(streamJson)}`);

  await pool.query(
    `
    update workouts_raw
    set raw_activity=$1, raw_streams=$2, status='fetched', updated_at=now()
    where provider='strava' and activity_id=$3
    `,
    [JSON.stringify(actJson), JSON.stringify(streamJson), activityId]
  );
}

async function analyzeAndPushToBase44(athleteId: number, activityId: number) {
  const conn = await getConnectionByAthleteId(athleteId);
  if (!conn) throw new Error(`No connection for athlete_id=${athleteId}`);

  // --- Minimal-Analyse (Dummy): nur Summary aus raw_activity ziehen ---
  const r = await pool.query(
    `select raw_activity from workouts_raw where provider='strava' and activity_id=$1`,
    [activityId]
  );
  const rawActivity = r.rows?.[0]?.raw_activity;
  if (!rawActivity) throw new Error("No raw_activity found to analyze");

  const analysis = {
    type: rawActivity.type,
    name: rawActivity.name,
    start_date: rawActivity.start_date,
    moving_time: rawActivity.moving_time,
    distance_m: rawActivity.distance,
    avg_hr: rawActivity.average_heartrate,
    avg_watts: rawActivity.average_watts,
  };

  await pool.query(
    `
    update workouts_raw
    set analysis=$1, status='analyzed', updated_at=now()
    where provider='strava' and activity_id=$2
    `,
    [JSON.stringify(analysis), activityId]
  );

  // --- Push zu Base44 (DEIN Endpoint in Base44) ---
  // Hier brauchst du in Base44 eine Function, die Kalender-Items anlegt.
  // Beispiel: POST https://metabolyte.de/functions/ingestWorkout
  //
  // Das ist der einzige Teil, den wir noch in Base44 anlegen müssen.
  const base44IngestUrl = "https://metabolyte.de/functions/ingestWorkout";

  const pushResp = await fetch(base44IngestUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-ingest-secret": BASE44_INGEST_SECRET,
    },
    body: JSON.stringify({
      provider: "strava",
      user_email: conn.user_email,
      athlete_id: athleteId,
      activity_id: activityId,
      analysis,
      raw_activity: rawActivity, // optional – für spätere KI
    }),
  });

  const pushJson = await pushResp.json().catch(() => ({}));
  if (!pushResp.ok) {
    await pool.query(
      `update workouts_raw set status='error', error=$1, updated_at=now() where provider='strava' and activity_id=$2`,
      [`Base44 ingest failed: ${JSON.stringify(pushJson)}`, activityId]
    );
    return;
  }

  await pool.query(
    `update workouts_raw set status='written_to_calendar', updated_at=now() where provider='strava' and activity_id=$1`,
    [activityId]
  );
}

// ---------- START ----------
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  await ensureSchema();
  console.log("Server running on port", port);
  console.log("Health:", `${PUBLIC_BASE_URL}/health`);
  console.log("Strava OAuth start example:", `${PUBLIC_BASE_URL}/auth/strava/start?email=test@example.com`);
});
