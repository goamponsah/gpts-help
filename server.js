// server.js (ESM)
// Node 18+
// Ensure package.json has: { "type": "module", "scripts": { "start": "node server.js" } }

import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import axios from "axios";
import pg from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Environment ----------
const {
  NODE_ENV = "production",
  PORT = 3000,
  DATABASE_URL,
  OPENAI_API_KEY,                 // optional here (stub chat)
  PAYSTACK_SECRET,                // your Paystack secret key (sk_...)
  PAYSTACK_PUBLIC,                // your Paystack public key (pk_...)
  PAYSTACK_PLAN_PREMIUM,          // e.g. plan code from Paystack dashboard
  PAYSTACK_PLAN_PRO,              // e.g. plan code from Paystack dashboard
} = process.env;

// ---------- Express ----------
const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: false }));

// ---------- Postgres ----------
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL || "")
    ? false
    : { rejectUnauthorized: false },
});

// ---------- Schema Migration (idempotent) ----------
async function ensureSchema() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 1) device_quotas table
    await client.query(`
      CREATE TABLE IF NOT EXISTS device_quotas (
        id           BIGSERIAL PRIMARY KEY,
        device_id    TEXT        NOT NULL,
        period_start TIMESTAMPTZ NOT NULL,
        period_end   TIMESTAMPTZ NOT NULL,
        used         INTEGER     NOT NULL DEFAULT 0,
        quota_limit  INTEGER     NOT NULL DEFAULT 1000,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (device_id, period_start)
      );
    `);

    // 2) Add missing columns safely if an older table exists
    await client.query(`
      ALTER TABLE device_quotas
        ADD COLUMN IF NOT EXISTS period_start TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS period_end   TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS used         INTEGER     NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS quota_limit  INTEGER     NOT NULL DEFAULT 1000,
        ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ NOT NULL DEFAULT now();
    `);

    // 3) If someone ever created a "limit" column (reserved keyword), rename it
    await client.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='device_quotas' AND column_name='limit'
        ) THEN
          EXECUTE 'ALTER TABLE device_quotas RENAME COLUMN "limit" TO quota_limit';
        END IF;
      END$$;
    `);

    // 4) Update trigger for updated_at
    await client.query(`
      CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
      BEGIN
        NEW.updated_at = now();
        RETURN NEW;
      END$$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS trg_device_quotas_updated_at ON device_quotas;
      CREATE TRIGGER trg_device_quotas_updated_at
      BEFORE UPDATE ON device_quotas
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    `);

    // 5) Helpful index
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_device_quotas_device_period
      ON device_quotas (device_id, period_start);
    `);

    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Schema migration failed:", e);
    throw e;
  } finally {
    client.release();
  }
}

// ---------- Quota Helpers ----------
function startOfUtcDay(d = new Date()) {
  const iso = new Date(d.toISOString().slice(0, 10) + "T00:00:00.000Z");
  return iso;
}
function endOfUtcDay(d = new Date()) {
  const start = startOfUtcDay(d);
  return new Date(start.getTime() + 24 * 60 * 60 * 1000); // +1 day
}

async function upsertQuotaRow(deviceId, when = new Date()) {
  const periodStart = startOfUtcDay(when);
  const periodEnd = endOfUtcDay(when);
  const quotaLimitDefault = 1000; // tweak as needed

  await pool.query(
    `
    INSERT INTO device_quotas (device_id, period_start, period_end, used, quota_limit)
    VALUES ($1, $2, $3, 0, $4)
    ON CONFLICT (device_id, period_start)
    DO NOTHING;
    `,
    [deviceId, periodStart, periodEnd, quotaLimitDefault]
  );

  return { periodStart, periodEnd };
}

async function bumpQuota(deviceId, delta = 1) {
  const { periodStart } = await upsertQuotaRow(deviceId);
  // We rely on the trigger to set updated_at; but it's fine to set it explicitly too
  const res = await pool.query(
    `
    UPDATE device_quotas
       SET used = used + $1,
           updated_at = now()
     WHERE device_id = $2 AND period_start = $3
     RETURNING device_id, used, quota_limit, period_start, period_end, updated_at;
    `,
    [delta, deviceId, periodStart]
  );
  return res.rows[0] || null;
}

async function getQuota(deviceId) {
  const periodStart = startOfUtcDay();
  const row = await pool.query(
    `
    SELECT device_id, used, quota_limit, period_start, period_end, updated_at
      FROM device_quotas
     WHERE device_id = $1 AND period_start = $2
     LIMIT 1;
    `,
    [deviceId, periodStart]
  );
  if (row.rows.length === 0) {
    // Initialize row lazily
    await upsertQuotaRow(deviceId);
    return {
      device_id: deviceId,
      used: 0,
      quota_limit: 1000,
      period_start: periodStart,
      period_end: endOfUtcDay(),
      updated_at: new Date(),
    };
  }
  return row.rows[0];
}

// ---------- Paystack ----------
const PAYSTACK_BASE = "https://api.paystack.co";

// Initialize a subscription/transaction (plan-based)
app.post("/api/paystack/initialize", async (req, res) => {
  try {
    const { email, plan } = req.body;

    if (!PAYSTACK_SECRET) {
      return res.status(500).json({ error: "Missing PAYSTACK_SECRET" });
    }

    if (!email || !plan) {
      return res.status(400).json({ error: "email and plan are required" });
    }

    // Map logical plan names → env plan codes
    const planCodeMap = {
      premium: PAYSTACK_PLAN_PREMIUM,
      pro: PAYSTACK_PLAN_PRO,
      PAYSTACK_PLAN_PREMIUM: PAYSTACK_PLAN_PREMIUM,
      PAYSTACK_PLAN_PRO: PAYSTACK_PLAN_PRO,
    };
    const planCode = planCodeMap[plan] || plan; // allow direct code as well

    if (!planCode) {
      return res.status(400).json({ error: "Unknown or missing plan code" });
    }

    const initPayload = {
      email,
      plan: planCode,
      // Optionally include metadata, callback_url, etc.
      // callback_url: "https://your-domain.com/paystack/callback"
    };

    const r = await axios.post(`${PAYSTACK_BASE}/transaction/initialize`, initPayload, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` },
      timeout: 15000,
    });

    return res.json(r.data);
  } catch (err) {
    console.error("Paystack init error:", err?.response?.data || err.message);
    return res
      .status(500)
      .json({ error: "Payment init failed", detail: err?.response?.data || err.message });
  }
});

// Paystack webhook (verifies signature)
app.post("/api/paystack/webhook", express.raw({ type: "*/*" }), (req, res) => {
  try {
    if (!PAYSTACK_SECRET) return res.sendStatus(500);
    const signature = req.headers["x-paystack-signature"];
    const expected = crypto
      .createHmac("sha512", PAYSTACK_SECRET)
      .update(req.body)
      .digest("hex");

    if (signature !== expected) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    // Parse event
    const event = JSON.parse(req.body.toString("utf8"));
    // TODO: handle subscription.charge.success, charge.success, invoice events, etc.
    console.log("Paystack event:", event?.event || "unknown", event?.data?.status);

    // Always 200 quickly
    return res.sendStatus(200);
  } catch (e) {
    console.error("Webhook error:", e);
    return res.sendStatus(200);
  }
});

// ---------- Quota API ----------
app.get("/api/quota/:deviceId", async (req, res) => {
  try {
    const { deviceId } = req.params;
    const q = await getQuota(deviceId);
    res.json({
      deviceId,
      used: q.used,
      limit: q.quota_limit,
      remaining: Math.max(0, q.quota_limit - q.used),
      periodStart: q.period_start,
      periodEnd: q.period_end,
      updatedAt: q.updated_at,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch quota" });
  }
});

app.post("/api/track-usage", async (req, res) => {
  try {
    const { deviceId, delta = 1 } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    const row = await bumpQuota(deviceId, Number(delta) || 1);
    res.json({
      deviceId: row.device_id,
      used: row.used,
      limit: row.quota_limit,
      remaining: Math.max(0, row.quota_limit - row.used),
      updatedAt: row.updated_at,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to update quota" });
  }
});

// ---------- Minimal Chat Stub (increment quota, return echo) ----------
// Replace with your real OpenAI call if desired.
app.post("/api/chat", async (req, res) => {
  try {
    const { deviceId = "anon", message = "" } = req.body || {};
    await bumpQuota(deviceId, 1);

    // If you want to wire OpenAI here, do so. Stub returns a simple response.
    return res.json({
      ok: true,
      reply:
        message?.trim()
          ? `You said: ${message.trim()}`
          : "Hello! Send a message to start.",
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Chat failed" });
  }
});

// ---------- Health ----------
app.get("/healthz", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, env: NODE_ENV });
  } catch {
    res.status(500).json({ ok: false });
  }
});

// ---------- Static (Frontend) ----------
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.get("/", (_req, res) => {
  const indexPath = path.join(publicDir, "index.html");
  res.sendFile(indexPath, (err) => {
    if (err) res.status(200).send("OK"); // fallback if no index.html
  });
});

// ---------- Boot ----------
(async () => {
  try {
    await ensureSchema();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (e) {
    console.error("Server failed to start:", e);
    process.exit(1);
  }
})();