import express from "express";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { Pool } from "pg";

const app = express();
app.use(express.json({ type: "*/*" }));
app.use(cookieParser());

// ---------- ENV ----------
function mustGetEnv(name) {
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
const BASE44_INGEST_URL = mustGetEnv("BASE44_INGEST_URL");

// ✅ NEU: Plan lookup function in Base44
// z.B. https://metabolyte.de/functions/getPlannedSessionForDate
const BASE44_PLAN_LOOKUP_URL = process.env.BASE44_PLAN_LOOKUP_URL || "";

// ---------- DB ----------
const pool = new Pool({
  connectionString: mustGetEnv("DATABASE_URL"),
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
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
function randomState() {
  return crypto.randomBytes(16).toString("hex");
}

async function saveOAuthState(state, userEmail) {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await pool.query(
    `insert into oauth_state(state, user_email, provider, expires_at)
     values($1,$2,'strava',$3)`,
    [state, userEmail, expiresAt.toISOString()]
  );
}

async function consumeOAuthState(state) {
  const r = await pool.query(
    `select user_email from oauth_state
     where state=$1 and provider='strava' and expires_at > now()`,
    [state]
  );
  if (r.rowCount === 0) return null;
  await pool.query(`delete from oauth_state where state=$1`, [state]);
  return { user_email: r.rows[0].user_email };
}

async function upsertConnection(params) {
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
    [
      params.user_email,
      params.athlete_id,
      params.access_token,
      params.refresh_token,
      params.expires_at,
      params.scope ?? null,
    ]
  );
}

async function getConnectionByAthleteId(athleteId) {
  const r = await pool.query(`select * from strava_connections where athlete_id=$1`, [
    Number(athleteId),
  ]);
  return r.rows[0] ?? null;
}

async function refreshTokenIfNeeded(conn) {
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
  } catch (e) {
    return res.status(500).json({ status: "error", error: String(e?.message ?? e) });
  }
});

// ---------- DEBUG ----------
app.get("/debug/connections", async (req, res) => {
  const r = await pool.query(
    "select user_email, athlete_id, expires_at, scope, updated_at from strava_connections order by updated_at desc limit 50"
  );
  res.json(r.rows);
});

app.get("/debug/workouts", async (req, res) => {
  const r = await pool.query(`
    select id, athlete_id, activity_id, aspect_type, status, error, created_at, updated_at
    from workouts_raw
    order by updated_at desc
    limit 50
  `);
  res.json(r.rows);
});

// ---------- OAUTH (multi-user) ----------
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
    if (!stateRow) {
      return res.status(400).send("Invalid/expired state. Please retry /auth/strava/start.");
    }

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
    `);
  } catch (e) {
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

    const r = await fetch(
      "https://www.strava.com/api/v3/athlete/activities?per_page=10&page=1",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const items = data
      .map((a) => {
        const km = a.distance ? (a.distance / 1000).toFixed(2) : "0.00";
        return `<li><b>${a.type}</b> — ${a.name} — ${km} km — <a href="/strava/activity/${a.id}?athlete_id=${athleteId}">Details</a> — <a href="/strava/activity/${a.id}/streams?athlete_id=${athleteId}">Streams</a></li>`;
      })
      .join("");

    return res.send(`<h2>Letzte Aktivitäten</h2><ul>${items}</ul>`);
  } catch (e) {
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
  } catch (e) {
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
      `https://www.strava.com/api/v3/activities/${id}/streams?keys=${encodeURIComponent(
        keys
      )}&key_by_type=true`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: "Strava API error", details: data });

    const summary = Object.keys(data).reduce((acc, k) => {
      acc[k] = {
        hasData: Array.isArray(data[k]?.data),
        points: Array.isArray(data[k]?.data) ? data[k].data.length : 0,
      };
      return acc;
    }, {});

    return res.json({ summary, streams: data });
  } catch (e) {
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
    return res.status(200).json({ "hub.challenge": challenge });
  }
  return res.sendStatus(403);
});

// 2) Events (Strava sendet POST wenn Activity erstellt/updated/deleted)
app.post("/webhooks/strava", async (req, res) => {
  // WICHTIG: sofort 200 zurückgeben
  res.sendStatus(200);

  try {
    const event = req.body;
    const ownerId = Number(event?.owner_id);
    const activityId = Number(event?.object_id);

    // roh speichern
    await pool.query(
      `
      insert into workouts_raw(provider, athlete_id, activity_id, aspect_type, object_type, event_time, raw_event, status)
      values('strava',$1,$2,$3,$4,$5,$6,'received')
      on conflict (provider, activity_id) do update set
        raw_event=excluded.raw_event,
        updated_at=now()
      `,
      [
        ownerId,
        activityId,
        event.aspect_type ?? null,
        event.object_type ?? null,
        event.event_time ?? null,
        JSON.stringify(event),
      ]
    );

    // Nur Activity create/update weiterverarbeiten
    if (event.object_type !== "activity") return;
    if (!["create", "update"].includes(event.aspect_type)) return;

    // Pipeline mit sauberem Error-Handling
    try {
      await fetchAndStoreActivity(ownerId, activityId);
      await analyzeAndPushToBase44(ownerId, activityId);
    } catch (e) {
      console.error("Processing pipeline error:", e);
      await pool.query(
        `update workouts_raw
         set status='error', error=$1, updated_at=now()
         where provider='strava' and activity_id=$2`,
        [String(e?.message ?? e), activityId]
      );
    }
  } catch (e) {
    console.error("Webhook processing error:", e);
  }
});

// Kleiner Test: Fake Event an deinen eigenen Webhook schicken
app.get("/webhooks/strava/test", async (req, res) => {
  const fake = {
    aspect_type: "create",
    event_time: Math.floor(Date.now() / 1000),
    object_id: 1234567890,
    object_type: "activity",
    owner_id: 8401174, // deine Test-Athlete ID
    subscription_id: 1,
    updates: {},
  };

  await fetch(`${PUBLIC_BASE_URL}/webhooks/strava`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fake),
  });

  return res.send("Sent test event (fake). Check Render logs + DB.");
});

async function fetchAndStoreActivity(athleteId, activityId) {
  const conn = await getConnectionByAthleteId(athleteId);
  if (!conn) {
    console.warn(`Webhook for athlete_id=${athleteId} but no OAuth connection yet.`);
    return;
  }

  const accessToken = await refreshTokenIfNeeded(conn);

  const actResp = await fetch(`https://www.strava.com/api/v3/activities/${activityId}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const actJson = await actResp.json();
  if (!actResp.ok) throw new Error(`Activity fetch failed: ${JSON.stringify(actJson)}`);

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

  const streamResp = await fetch(
    `https://www.strava.com/api/v3/activities/${activityId}/streams?keys=${encodeURIComponent(
      keys
    )}&key_by_type=true`,
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
    [JSON.stringify(actJson), JSON.stringify(streamJson), Number(activityId)]
  );
}

// ---------- ANALYSIS + PUSH (mit Plan-Lookup + Soll/Ist + Coach Decision) ----------
async function analyzeAndPushToBase44(athleteId, activityId) {
  const conn = await getConnectionByAthleteId(athleteId);
  if (!conn) throw new Error(`No connection for athlete_id=${athleteId}`);

  const rr = await pool.query(
    `select raw_activity, raw_streams
     from workouts_raw
     where provider='strava' and activity_id=$1`,
    [Number(activityId)]
  );

  const rawActivity = rr.rows?.[0]?.raw_activity;
  const rawStreams = rr.rows?.[0]?.raw_streams;

  if (!rawActivity) throw new Error("No raw_activity found to analyze");

  // -------- Helpers --------
  function safeNum(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  function round2(n) {
    if (n == null) return null;
    return Math.round(n * 100) / 100;
  }

  function secondsToHhMmSs(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    const hh = Math.floor(s / 3600);
    const mm = Math.floor((s % 3600) / 60);
    const ss = s % 60;
    if (hh > 0) return `${hh}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
    return `${mm}:${String(ss).padStart(2, "0")}`;
  }

  function paceSecPerKm(distanceM, movingTimeS) {
    if (!distanceM || !movingTimeS || distanceM <= 0 || movingTimeS <= 0) return null;
    const km = distanceM / 1000;
    return movingTimeS / km;
  }

  function detectIntervalsFromSeries(series, opts) {
    if (!Array.isArray(series) || series.length < 80) {
      return { peakCount: 0, hardFraction: 0, baseline: null, threshold: null };
    }
    const values = series.map(Number).filter((x) => Number.isFinite(x) && x > 0);
    if (values.length < 80) return { peakCount: 0, hardFraction: 0, baseline: null, threshold: null };

    const sorted = [...values].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];

    const multiplier = opts?.multiplier ?? 1.18;
    const threshold = median * multiplier;

    let hard = 0;
    for (const v of values) if (v >= threshold) hard++;
    const hardFraction = hard / values.length;

    const minSeg = opts?.minSeg ?? 20;
    let peakCount = 0;
    let runLen = 0;
    let inHard = false;

    for (let i = 0; i < values.length; i++) {
      const isHard = values[i] >= threshold;
      if (isHard) {
        runLen++;
        if (!inHard) inHard = true;
      } else {
        if (inHard && runLen >= minSeg) peakCount++;
        inHard = false;
        runLen = 0;
      }
    }
    if (inHard && runLen >= minSeg) peakCount++;

    return { peakCount, hardFraction, baseline: median, threshold };
  }

  function classifyWorkout({ type, moving_time }, streams) {
    const durationS = safeNum(moving_time) ?? 0;

    const isRun = String(type || "").toLowerCase() === "run";
    const isRide = String(type || "").toLowerCase() === "ride";

    const velocity = streams?.velocity_smooth?.data;
    const watts = streams?.watts?.data;

    const intervalSource = isRide ? watts : velocity;
    const intervals = detectIntervalsFromSeries(intervalSource, {
      multiplier: isRide ? 1.22 : 1.18,
      minSeg: isRide ? 25 : 20,
    });

    const longThresholdS = isRun ? 90 * 60 : 120 * 60;
    const isLong = durationS >= longThresholdS;

    const hasIntervals = intervals.peakCount >= 3 && intervals.hardFraction >= 0.08;
    const isSteadyHard = intervals.hardFraction >= 0.18 && intervals.peakCount < 3;

    let category = "Aerobic Base";
    let confidence = 0.65;
    const tags = [];
    const signals = {
      hasIntervals,
      peakCount: intervals.peakCount,
      hardFraction: round2(intervals.hardFraction),
      isLong,
      isSteadyHard,
    };

    if (hasIntervals) {
      category = "VO2 / Intervals";
      confidence = 0.8;
      tags.push("key_session");
    } else if (isSteadyHard) {
      category = "Threshold / Tempo";
      confidence = 0.7;
      tags.push("quality");
    } else if (isLong) {
      category = "Long Endurance";
      confidence = 0.75;
      tags.push("endurance");
    } else {
      category = "Aerobic Base";
      confidence = 0.65;
      tags.push("base");
    }

    // Map to CalendarSession.sport enum
    const sport = isRide ? "bike" : isRun ? "run" : "run";
    tags.push(sport);

    return { category, tags, confidence, signals, sport };
  }

  function toDateYYYYMMDD(iso) {
    if (!iso) return null;
    return String(iso).slice(0, 10);
  }

  function nextSunday18BerlinIso() {
    const now = new Date();
    const d = new Date(now);
    const day = d.getDay(); // 0=Sun
    const addDays = (7 - day) % 7;
    d.setDate(d.getDate() + addDays);
    d.setHours(18, 0, 0, 0);
    if (addDays === 0 && now.getTime() > d.getTime()) d.setDate(d.getDate() + 7);
    return d.toISOString();
  }

  async function fetchPlannedSessionForDate(userEmail, dateYYYYMMDD) {
    if (!BASE44_PLAN_LOOKUP_URL) return null;

    try {
      const resp = await fetch(BASE44_PLAN_LOOKUP_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-ingest-secret": BASE44_INGEST_SECRET,
        },
        body: JSON.stringify({ user_email: userEmail, date: dateYYYYMMDD }),
      });

      const json = await resp.json().catch(() => null);
      if (!resp.ok) return null;
      return json?.planned ?? null;
    } catch {
      return null;
    }
  }

  function computeDeviation(plannedSession, analysis) {
    if (!plannedSession) {
      return {
        has_plan: false,
        deviation_score: null,
        severity: "unknown",
        reasons: ["no_plan_found"],
      };
    }

    const reasons = [];
    const plannedMin = safeNum(plannedSession.duration_min);
    const actualMin = analysis.duration_min;

    let durationDev = 0;
    if (plannedMin && actualMin) {
      durationDev = Math.abs(actualMin - plannedMin) / plannedMin;
      if (durationDev >= 0.25) reasons.push("duration_off_25pct");
      if (durationDev >= 0.4) reasons.push("duration_off_40pct");
    } else {
      reasons.push("duration_missing");
    }

    // planned category should be stored in intensity_json.category (recommended)
    const plannedCategory = String(
      plannedSession?.intensity_json?.category ??
      plannedSession?.structure_json?.category ??
      ""
    ).trim();

    const actualCategory = String(analysis.classification?.category ?? "").trim();

    const typeMismatch = plannedCategory && actualCategory && plannedCategory !== actualCategory ? 1 : 0;
    if (typeMismatch) reasons.push("session_type_mismatch");

    const deviationScore = Math.min(1, 0.7 * durationDev + 0.3 * typeMismatch);

    let severity = "low";
    if (deviationScore >= 0.35) severity = "high";
    else if (deviationScore >= 0.15) severity = "moderate";

    return {
      has_plan: true,
      deviation_score: round2(deviationScore),
      severity,
      reasons,
      planned: {
        planned_duration_min: plannedMin ?? null,
        planned_category: plannedCategory || null,
        planned_status: plannedSession.status ?? null,
      },
    };
  }

  function decideCoachAction(deviation) {
    if (!deviation?.has_plan) {
      return {
        action: "comment_only",
        requires_confirmation: false,
        update_weekly_plan: true,
        message:
          "Einheit importiert und klassifiziert. Für Soll/Ist-Vergleich fehlt noch eine geplante Session für diesen Tag.",
      };
    }

    if (deviation.severity === "low") {
      return {
        action: "comment_only",
        requires_confirmation: false,
        update_weekly_plan: true,
        message:
          "Einheit entspricht dem Plan (nur kleine Abweichungen). Wochenplan wird Sonntag konsolidiert aktualisiert.",
      };
    }

    if (deviation.severity === "moderate") {
      return {
        action: "comment_only",
        requires_confirmation: false,
        update_weekly_plan: true,
        message:
          "Moderate Abweichung vom Plan. Ich berücksichtige das beim Wochenupdate am Sonntag.",
      };
    }

    return {
      action: "ask_to_restructure_week",
      requires_confirmation: true,
      update_weekly_plan: false,
      message:
        "Die Einheit weicht deutlich vom Plan ab (z.B. Dauer/Intensität). Soll ich die Wochenstruktur anpassen, damit die Schlüsselsessions sinnvoll bleiben?",
    };
  }

  // -------- Metrics + Classification --------
  const durationS = safeNum(rawActivity.moving_time) ?? 0;
  const distanceM = safeNum(rawActivity.distance) ?? 0;
  const distanceKm = distanceM ? distanceM / 1000 : null;

  const pace = paceSecPerKm(distanceM, durationS);
  const classification = classifyWorkout(
    { type: rawActivity.type, moving_time: rawActivity.moving_time },
    rawStreams
  );

  const dateYYYYMMDD = toDateYYYYMMDD(rawActivity.start_date);

  const analysis = {
    provider: "strava",
    type: rawActivity.type,
    name: rawActivity.name,
    start_date: rawActivity.start_date,
    date: dateYYYYMMDD,
    moving_time: durationS,
    moving_time_hms: secondsToHhMmSs(durationS),
    duration_min: durationS ? Math.round(durationS / 60) : null,
    distance_m: distanceM,
    distance_km: distanceKm != null ? round2(distanceKm) : null,
    avg_hr: safeNum(rawActivity.average_heartrate),
    avg_watts: safeNum(rawActivity.average_watts),
    avg_pace_sec_per_km: pace != null ? Math.round(pace) : null,
    avg_pace_min_per_km:
      pace != null
        ? `${Math.floor(pace / 60)}:${String(Math.round(pace % 60)).padStart(2, "0")}`
        : null,
    classification: {
      category: classification.category,
      confidence: classification.confidence,
      tags: classification.tags,
      signals: classification.signals,
    },
    inferred_sport: classification.sport, // run|bike
  };

  // -------- Plan Lookup + Deviation + Coach decision --------
  const planned = dateYYYYMMDD
    ? await fetchPlannedSessionForDate(conn.user_email, dateYYYYMMDD)
    : null;

  const deviation = computeDeviation(planned, analysis);
  const coachDecision = decideCoachAction(deviation);

  analysis.planned = deviation.has_plan ? deviation.planned : null;
  analysis.deviation = {
    has_plan: deviation.has_plan,
    deviation_score: deviation.deviation_score,
    severity: deviation.severity,
    reasons: deviation.reasons,
  };
  analysis.coach = {
    action: coachDecision.action,
    requires_confirmation: coachDecision.requires_confirmation,
    update_weekly_plan: coachDecision.update_weekly_plan,
    message: coachDecision.message,
    next_sunday_update_at: nextSunday18BerlinIso(),
  };

  // Save analysis
  await pool.query(
    `
    update workouts_raw
    set analysis=$1, status='analyzed', updated_at=now()
    where provider='strava' and activity_id=$2
    `,
    [JSON.stringify(analysis), Number(activityId)]
  );

  // Push to Base44
  const pushResp = await fetch(BASE44_INGEST_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-ingest-secret": BASE44_INGEST_SECRET,
    },
    body: JSON.stringify({
      provider: "strava",
      user_email: conn.user_email,
      athlete_id: Number(athleteId),
      activity_id: Number(activityId),
      analysis,
      raw_activity: rawActivity,
      // raw_streams: rawStreams, // optional
    }),
  });

  const pushJson = await pushResp.json().catch(() => ({}));
  if (!pushResp.ok) {
    await pool.query(
      `update workouts_raw set status='error', error=$1, updated_at=now()
       where provider='strava' and activity_id=$2`,
      [`Base44 ingest failed: ${JSON.stringify(pushJson)}`, Number(activityId)]
    );
    return;
  }

  await pool.query(
    `update workouts_raw set status='written_to_calendar', updated_at=now()
     where provider='strava' and activity_id=$1`,
    [Number(activityId)]
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
