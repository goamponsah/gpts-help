// server.js (ESM)
// package.json => { "type": "module" }
// Install: npm i express cookie-parser cors jsonwebtoken multer pg
// Required ENV (Railway): DATABASE_URL, JWT_SECRET, OPENAI_API_KEY
// Optional ENV: PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY, PLAN_CODE_PLUS_MONTHLY, PLAN_CODE_PRO_ANNUAL, OPENAI_MODEL, FRONTEND_ORIGIN

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import util from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";
import pg from "pg";

const { Pool } = pg;

/* ----------------------------- Paths / App ----------------------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* --------------------------------- ENV -------------------------------- */
const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  FRONTEND_ORIGIN,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL is missing.");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET is missing; sessions will reset on deploy.");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY is missing; chat/photo-solve will fail.");

const MODEL = OPENAI_MODEL || "gpt-4o-mini";

/* --------------------------- Middleware / Static ----------------------- */
if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: "12mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* ---------------------------- Upload (images) -------------------------- */
const upload = multer({ storage: multer.memoryStorage() });

/* --------------------------------- DB --------------------------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Make schema creation idempotent and safe to re-run
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id           BIGSERIAL PRIMARY KEY,
      email        TEXT NOT NULL UNIQUE,
      plan         TEXT NOT NULL DEFAULT 'FREE',
      pass_salt    TEXT,
      pass_hash    TEXT,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- In case table existed before without password columns
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pass_salt TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pass_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'FREE';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

    CREATE TABLE IF NOT EXISTS conversations (
      id           BIGSERIAL PRIMARY KEY,
      user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title        TEXT NOT NULL,
      archived     BOOLEAN NOT NULL DEFAULT false,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS conversations_user_idx ON conversations(user_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS messages (
      id              BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role            TEXT NOT NULL,  -- 'user' | 'assistant'
      content         TEXT NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS messages_conv_idx ON messages(conversation_id, id);

    CREATE TABLE IF NOT EXISTS share_links (
      id              BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      token           TEXT NOT NULL UNIQUE,
      revoked         BOOLEAN NOT NULL DEFAULT false,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS paystack_receipts (
      id         BIGSERIAL PRIMARY KEY,
      email      TEXT,
      reference  TEXT NOT NULL UNIQUE,
      plan_code  TEXT,
      status     TEXT,
      raw        JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}
await ensureSchema();

/* ------------------------------ Sessions ------------------------------ */
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
function cookieOptions() {
  const cross = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true,
    sameSite: cross ? "None" : "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  };
}
function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, SJWT, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}
function clearSessionCookie(res) {
  res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 });
}
function readSession(req) {
  const { sid } = req.cookies || {};
  if (!sid) return null;
  try {
    return jwt.verify(sid, SJWT);
  } catch {
    return null;
  }
}

/* ---------------------------- DB Utilities ---------------------------- */
async function upsertUser(email, plan = "FREE") {
  const r = await pool.query(
    `INSERT INTO users(email, plan)
       VALUES ($1, $2)
     ON CONFLICT(email) DO UPDATE
       SET plan = COALESCE(users.plan, 'FREE')
     RETURNING id, email, plan`,
    [email, plan]
  );
  return r.rows[0];
}
async function getUserByEmail(email) {
  const r = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
  return r.rows[0] || null;
}

/* --------------------------- Password helpers ------------------------- */
const scrypt = util.promisify(crypto.scrypt);
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const buf = await scrypt(pw, salt, 64);
  return { salt, hash: buf.toString("hex") };
}
async function verifyPassword(pw, salt, hash) {
  if (!salt || !hash) return false;
  const buf = await scrypt(pw, salt, 64);
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(buf.toString("hex"), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function setUserPassword(email, pass) {
  const { salt, hash } = await hashPassword(pass);
  await pool.query(
    `UPDATE users
        SET pass_salt=$2, pass_hash=$3, updated_at=now()
      WHERE email=$1`,
    [email, salt, hash]
  );
}

/* --------------------------- OpenAI Utilities ------------------------- */
async function openaiChat(messages) {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: MODEL,
      messages,
      temperature: 0.2,
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`OpenAI ${r.status}: ${t}`);
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

/* ------------------------------ Helpers ------------------------------ */
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}
function needUser(req, res) {
  const s = readSession(req);
  if (!s?.email) {
    res.status(401).json({ status: "unauthenticated" });
    return null;
  }
  return s.email;
}

/* ------------------------- Health / Public Config --------------------- */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

/* --------------------------------- Auth ------------------------------- */
// Sign up (free). If password provided (>=8), set it; otherwise account can be created
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    const user = await upsertUser(email, "FREE");
    if (password && password.length >= 8) await setUserPassword(email, password);
    setSessionCookie(res, { email: user.email, plan: user.plan });
    res.json({ status: "success", user: { email: user.email } });
  } catch (e) {
    console.error("signup-free error:", e);
    res.status(500).json({ status: "error", message: "Could not create user" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ status: "error", message: "Email and password required" });
    }
    const u = await getUserByEmail(email);
    if (!u) return res.status(401).json({ status: "error", message: "No account found. Please sign up." });

    // If user existed without password, first login sets it
    if (!u.pass_hash) {
      if (password.length < 8) {
        return res.status(400).json({ status: "error", message: "Password must be at least 8 characters." });
      }
      await setUserPassword(email, password);
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password." });
    }

    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status: "ok", user: { email: u.email } });
  } catch (e) {
    console.error("login error:", e);
    res.status(500).json({ status: "error", message: "Login failed" });
  }
});

app.get("/api/me", async (req, res) => {
  const s = readSession(req);
  if (!s?.email) return res.status(401).json({ status: "unauthenticated" });
  const u = await getUserByEmail(s.email);
  if (!u) return res.status(401).json({ status: "unauthenticated" });
  res.json({ status: "ok", user: { email: u.email, plan: u.plan } });
});

app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

/* ------------------------------- Paystack ----------------------------- */
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) {
      return res.status(400).json({ status: "error", message: "Missing reference" });
    }

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await psRes.json();

    await pool.query(
      `INSERT INTO paystack_receipts(email, reference, plan_code, status, raw)
       VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(reference) DO NOTHING`,
      [
        data?.data?.customer?.email || null,
        reference,
        data?.data?.plan?.plan_code || null,
        data?.data?.status || null,
        data,
      ]
    );

    if (data?.status && data?.data?.status === "success") {
      const customerEmail = data.data?.customer?.email || null;
      const planCode = data.data?.plan?.plan_code || null;
      const label = mapPlanCodeToLabel(planCode);
      if (customerEmail) {
        await upsertUser(customerEmail);
        if (label !== "ONE_TIME") {
          await pool.query(`UPDATE users SET plan=$2, updated_at=now() WHERE email=$1`, [customerEmail, label]);
        }
        setSessionCookie(res, { email: customerEmail, plan: label === "ONE_TIME" ? "FREE" : label });
      }
      return res.json({ status: "success", email: customerEmail, plan: label, reference });
    }

    res.json({ status: "pending", data });
  } catch (e) {
    console.error("verify error:", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

/* ---------------------------- Auth Guard util -------------------------- */
async function requireUser(req, res) {
  const email = needUser(req, res);
  if (!email) return null;
  const u = await getUserByEmail(email);
  if (!u) {
    res.status(401).json({ status: "unauthenticated" });
    return null;
  }
  return u;
}

/* ---------------------------- Conversations API ----------------------- */
// List conversations
app.get("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const r = await pool.query(
    `SELECT id, title, archived
       FROM conversations
      WHERE user_id=$1
      ORDER BY created_at DESC`,
    [u.id]
  );
  res.json(r.rows);
});

// Create conversation
app.post("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const title = (req.body?.title || "New chat").trim();
  const r = await pool.query(
    `INSERT INTO conversations(user_id, title) VALUES($1,$2)
     RETURNING id, title`,
    [u.id, title]
  );
  res.json(r.rows[0]);
});

// Rename / Archive
app.patch("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const { title, archived } = req.body || {};
  const fields = [];
  const values = [id, u.id];
  let p = 2;

  if (typeof title === "string") { fields.push(`title=$${++p}`); values.push(title.trim() || "Untitled"); }
  if (typeof archived === "boolean") { fields.push(`archived=$${++p}`); values.push(!!archived); }

  if (!fields.length) return res.json({ ok: true });

  await pool.query(
    `UPDATE conversations
        SET ${fields.join(", ")}, updated_at=now()
      WHERE id=$1 AND user_id=$2`,
    values
  );
  res.json({ ok: true });
});

// Delete conversation
app.delete("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  await pool.query(`DELETE FROM conversations WHERE id=$1 AND user_id=$2`, [id, u.id]);
  res.json({ ok: true });
});

// Get messages for a conversation
app.get("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const conv = await pool.query(
    `SELECT id, title FROM conversations WHERE id=$1 AND user_id=$2`,
    [id, u.id]
  );
  if (!conv.rowCount) return res.status(404).json({ error: "not found" });

  const msgs = await pool.query(
    `SELECT role, content, created_at FROM messages
      WHERE conversation_id=$1 ORDER BY id`,
    [id]
  );
  res.json({ id, title: conv.rows[0].title, messages: msgs.rows });
});

/* ------------------------------- Sharing ------------------------------ */
// Create or reuse share token (owner only)
app.post("/api/conversations/:id/share", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);

  const own = await pool.query(
    `SELECT id FROM conversations WHERE id=$1 AND user_id=$2`,
    [id, u.id]
  );
  if (!own.rowCount) return res.status(404).json({ error: "not found" });

  const existing = await pool.query(
    `SELECT token FROM share_links
      WHERE conversation_id=$1 AND revoked=false
   ORDER BY id DESC LIMIT 1`,
   [id]
  );
  if (existing.rowCount) return res.json({ token: existing.rows[0].token });

  const token = crypto.randomBytes(20).toString("hex");
  await pool.query(
    `INSERT INTO share_links(conversation_id, token) VALUES($1,$2)`,
    [id, token]
  );
  res.json({ token });
});

// Public read-only fetch
app.get("/api/share/:token", async (req, res) => {
  const { token } = req.params;
  const s = await pool.query(
    `SELECT c.id, c.title
       FROM share_links sl
       JOIN conversations c ON c.id = sl.conversation_id
      WHERE sl.token=$1 AND sl.revoked=false`,
    [token]
  );
  if (!s.rowCount) return res.status(404).json({ error: "invalid_or_revoked" });

  const convId = s.rows[0].id;
  const msgs = await pool.query(
    `SELECT role, content, created_at FROM messages
      WHERE conversation_id=$1 ORDER BY id`,
    [convId]
  );
  res.json({ title: s.rows[0].title, messages: msgs.rows });
});

/* --------------------------------- Chat ------------------------------- */
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // Ensure conversation exists & belongs to user
    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(
        `SELECT id FROM conversations WHERE id=$1 AND user_id=$2`,
        [convId, u.id]
      );
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `INSERT INTO conversations(user_id, title) VALUES($1,$2)
         RETURNING id`,
        [u.id, (message.slice(0, 40) || "New chat")]
      );
      convId = r.rows[0].id;
    }

    // Load history
    const hist = await pool.query(
      `SELECT role, content FROM messages
        WHERE conversation_id=$1 ORDER BY id`,
      [convId]
    );
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning and show your workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [{ role: "system", content: system }, ...hist.rows, { role: "user", content: message }];

    // Store user message
    await pool.query(
      `INSERT INTO messages(conversation_id, role, content) VALUES($1,$2,$3)`,
      [convId, "user", message]
    );

    // Call OpenAI
    const answer = await openaiChat(msgs);

    // Store assistant answer
    await pool.query(
      `INSERT INTO messages(conversation_id, role, content) VALUES($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

/* ------------------------------ Photo Solve --------------------------- */
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(
        `SELECT id FROM conversations WHERE id=$1 AND user_id=$2`,
        [convId, u.id]
      );
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `INSERT INTO conversations(user_id, title) VALUES($1,$2)
         RETURNING id`,
        [u.id, "Photo solve"]
      );
      convId = r.rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    // Store a small note for the photo in history
    await pool.query(
      `INSERT INTO messages(conversation_id, role, content) VALUES($1,$2,$3)`,
      [convId, "user", attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]
    );

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the math problem from the image and solve it step-by-step. Be neat and rigorous."
        : "You are a helpful assistant. Describe and analyze the image and answer the user's request.";

    // Vision via Chat Completions with image_url
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [
          { role: "system", content: system },
          {
            role: "user",
            content: [
              { type: "text", text: attempt ? `Note from user: ${attempt}\nSolve:` : "Solve this problem step-by-step:" },
              { type: "image_url", image_url: { url: dataUrl } },
            ],
          },
        ],
        temperature: 0.2,
      }),
    });

    if (!r.ok) {
      const t = await r.text();
      throw new Error(`OpenAI vision ${r.status}: ${t}`);
    }
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    await pool.query(
      `INSERT INTO messages(conversation_id, role, content) VALUES($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve error:", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

/* ------------------------------- Start -------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
  if (!JWT_SECRET) {
    console.warn("[WARN] JWT_SECRET not set. A random secret was used; sessions reset on redeploy.");
  }
});
