// server.js (Node 18+/22+, ESM)
// package.json: { "type": "module" }
// ENV (Railway):
//  - DATABASE_URL
//  - OPENAI_API_KEY, OPENAI_MODEL (optional, defaults to 'gpt-4o-mini')
//  - PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY (optional)
//  - PLAN_CODE_PLUS_MONTHLY, PLAN_CODE_PRO_ANNUAL (optional)
//  - JWT_SECRET (recommended)
//  - FRONTEND_ORIGIN (if FE/BE split; enables cross-site cookie)
//  - SITE_URL (for building password reset + share links)
//  - RESEND_API_KEY, FROM_EMAIL (optional; for password reset emails)

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";
import bcrypt from "bcryptjs";
import { Pool } from "pg";

// ---------- Resolve __dirname (ESM) ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- App & Middleware ----------
const app = express();
app.disable("x-powered-by");

const {
  DATABASE_URL,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  FRONTEND_ORIGIN,
  JWT_SECRET,
  SITE_URL,
  RESEND_API_KEY,
  FROM_EMAIL,
} = process.env;

if (!DATABASE_URL) {
  console.warn("[WARN] DATABASE_URL is not set. App will fail to persist data.");
}
if (!OPENAI_API_KEY) {
  console.warn("[WARN] OPENAI_API_KEY is not set. /api/chat and /api/photo-solve will fail.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

if (FRONTEND_ORIGIN) {
  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
    })
  );
}

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

// Serve static site from /public
app.use(express.static(path.join(__dirname, "public")));

// Multer for image uploads (kept in memory)
const upload = multer({ storage: multer.memoryStorage() });

// ---------- JWT Session ----------
const JWT_SECRET_FINAL = JWT_SECRET || crypto.randomBytes(48).toString("hex");

function cookieOptions() {
  const crossSite = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true, // Railway is HTTPS
    sameSite: crossSite ? "None" : "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  };
}
function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET_FINAL, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}
function clearSessionCookie(res) {
  res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 });
}
function verifySession(req) {
  const { sid } = req.cookies || {};
  if (!sid) return null;
  try {
    return jwt.verify(sid, JWT_SECRET_FINAL);
  } catch {
    return null;
  }
}
function requireAuth(req, res, next) {
  const s = verifySession(req);
  if (!s?.uid || !s?.email) return res.status(401).json({ status: "unauthenticated" });
  req.user = { uid: s.uid, email: s.email, plan: s.plan || "FREE" };
  next();
}

// ---------- DB bootstrap ----------
async function ensureSchema() {
  // Create tables if not exist (idempotent)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            BIGSERIAL PRIMARY KEY,
      email         TEXT NOT NULL,
      password_hash TEXT,
      plan          TEXT NOT NULL DEFAULT 'FREE',
      reset_token   TEXT,
      reset_expires TIMESTAMPTZ,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- unique (lower(email)) via index (works even if table already existed)
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

    CREATE TABLE IF NOT EXISTS conversations (
      id          BIGSERIAL PRIMARY KEY,
      user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title       TEXT NOT NULL DEFAULT 'New chat',
      archived    BOOLEAN NOT NULL DEFAULT false,
      share_token TEXT UNIQUE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS conv_user_updated_idx ON conversations(user_id, updated_at DESC);

    CREATE TABLE IF NOT EXISTS messages (
      id               BIGSERIAL PRIMARY KEY,
      conversation_id  BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role             TEXT NOT NULL CHECK (role IN ('user','assistant')),
      content          TEXT NOT NULL,
      created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS msg_conv_created_idx ON messages(conversation_id, created_at);
  `);

  // Add missing columns safely (for existing DBs without recent columns)
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='users' AND column_name='password_hash') THEN
        ALTER TABLE users ADD COLUMN password_hash TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='users' AND column_name='plan') THEN
        ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'FREE';
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='users' AND column_name='reset_token') THEN
        ALTER TABLE users ADD COLUMN reset_token TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='users' AND column_name='reset_expires') THEN
        ALTER TABLE users ADD COLUMN reset_expires TIMESTAMPTZ;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='conversations' AND column_name='archived') THEN
        ALTER TABLE conversations ADD COLUMN archived BOOLEAN NOT NULL DEFAULT false;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='conversations' AND column_name='share_token') THEN
        ALTER TABLE conversations ADD COLUMN share_token TEXT UNIQUE;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name='conversations' AND column_name='updated_at') THEN
        ALTER TABLE conversations ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
      END IF;
    END$$;
  `);

  // Trigger to keep updated_at current on conversations
  await pool.query(`
    CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = now();
      RETURN NEW;
    END$$ LANGUAGE plpgsql;

    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_conversations_touch'
      ) THEN
        CREATE TRIGGER trg_conversations_touch
        BEFORE UPDATE ON conversations
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END$$;
  `);
}

// ---------- Helpers ----------
const SITE = SITE_URL || "https://gptshelp.online"; // adjust for your domain

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function findUserByEmail(email) {
  const { rows } = await pool.query(
    "SELECT id, email, password_hash, plan FROM users WHERE lower(email) = lower($1) LIMIT 1",
    [email]
  );
  return rows[0] || null;
}

async function createUserEmailPassword(email, password) {
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    "INSERT INTO users (email, password_hash, plan) VALUES ($1, $2, 'FREE') RETURNING id, email, plan",
    [email, hash]
  );
  return rows[0];
}

async function updateUserPassword(uid, password) {
  const hash = await bcrypt.hash(password, 10);
  await pool.query("UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2", [hash, uid]);
}

function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

async function openaiChat(messages) {
  const model = OPENAI_MODEL || "gpt-4o-mini";
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.2,
    }),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`OpenAI error ${r.status}: ${t}`);
  }
  const data = await r.json().catch(() => ({}));
  return data?.choices?.[0]?.message?.content || "";
}

// ---------- Core Routes ----------

// Health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Public config for frontend (safe: public key + plan codes)
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

// --- Auth: signup (email/password)
app.post("/api/signup", async (req, res) => {
  try {
    const emailRaw = req.body?.email || "";
    const password = req.body?.password || "";
    const email = normalizeEmail(emailRaw);
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ status: "error", message: "Valid email required" });
    if (!password || password.length < 6) return res.status(400).json({ status: "error", message: "Password too short" });

    const existing = await findUserByEmail(email);
    if (existing) {
      if (existing.password_hash) {
        return res.status(409).json({ status: "error", message: "Account already exists" });
      } else {
        // Convert passwordless to password account
        await updateUserPassword(existing.id, password);
        setSessionCookie(res, { uid: existing.id, email, plan: existing.plan || "FREE" });
        return res.json({ status: "success" });
      }
    }

    const u = await createUserEmailPassword(email, password);
    setSessionCookie(res, { uid: u.id, email: u.email, plan: u.plan || "FREE" });
    return res.json({ status: "success" });
  } catch (e) {
    console.error("signup error:", e);
    return res.status(500).json({ status: "error", message: "Could not create account" });
  }
});

// --- Auth: login
app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    const password = req.body?.password || "";
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ status: "error", message: "Valid email required" });

    const u = await findUserByEmail(email);
    if (!u || !u.password_hash) {
      return res.status(401).json({ status: "error", message: "Invalid email or password" });
    }
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password" });

    setSessionCookie(res, { uid: u.id, email: u.email, plan: u.plan || "FREE" });
    return res.json({ status: "success" });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ status: "error", message: "Could not log in" });
  }
});

// --- Auth: logout
app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// --- Auth: me
app.get("/api/me", (req, res) => {
  const s = verifySession(req);
  if (!s?.email || !s?.uid) return res.status(401).json({ status: "unauthenticated" });
  res.json({ status: "ok", user: { id: s.uid, email: s.email, plan: s.plan || "FREE" } });
});

// --- Free signup (email only; creates account if missing, no password)
app.post("/api/signup-free", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ status: "error", message: "Valid email required" });

    let u = await findUserByEmail(email);
    if (!u) {
      const { rows } = await pool.query(
        "INSERT INTO users (email, plan) VALUES ($1, 'FREE') RETURNING id, email, plan",
        [email]
      );
      u = rows[0];
    }
    setSessionCookie(res, { uid: u.id, email: u.email, plan: u.plan || "FREE" });
    return res.json({ status: "success" });
  } catch (e) {
    console.error("signup-free error:", e);
    return res.status(500).json({ status: "error", message: "Could not create free user" });
  }
});

// --- Password reset: request
app.post("/api/auth/request-reset", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email || "");
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.json({ status: "ok" }); // don't leak
    const u = await findUserByEmail(email);
    if (!u) return res.json({ status: "ok" }); // don't leak

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min
    await pool.query(
      "UPDATE users SET reset_token=$1, reset_expires=$2, updated_at=now() WHERE id=$3",
      [token, expires, u.id]
    );

    const resetUrl = `${SITE}/reset-password.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;

    if (RESEND_API_KEY && FROM_EMAIL) {
      // Send via Resend
      try {
        const r = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${RESEND_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: FROM_EMAIL, // e.g. "GPTs Help <no-reply@gptshelp.online>"
            to: [email],
            subject: "Reset your GPTs Help password",
            html: `
              <p>Hello,</p>
              <p>Click the button below to reset your password:</p>
              <p><a href="${resetUrl}" style="background:#5865f2;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">Reset Password</a></p>
              <p>Or open this link:<br>${resetUrl}</p>
              <p>This link expires in 30 minutes.</p>
            `,
          }),
        });
        if (!r.ok) {
          const t = await r.text().catch(() => "");
          console.error("Resend send error:", r.status, t);
        }
      } catch (e) {
        console.error("Resend error:", e);
      }
    } else {
      console.log("[DEV] Password reset link:", resetUrl);
    }

    return res.json({ status: "ok" });
  } catch (e) {
    console.error("request-reset error:", e);
    return res.status(200).json({ status: "ok" }); // don't leak
  }
});

// --- Password reset: confirm
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, email: emailRaw, password } = req.body || {};
    const email = normalizeEmail(emailRaw);
    if (!token || !email || !password) return res.status(400).json({ status: "error", message: "Bad request" });

    const { rows } = await pool.query(
      "SELECT id, reset_expires FROM users WHERE lower(email)=lower($1) AND reset_token=$2 LIMIT 1",
      [email, token]
    );
    const u = rows[0];
    if (!u) return res.status(400).json({ status: "error", message: "Invalid or expired link" });
    if (!u.reset_expires || new Date(u.reset_expires) < new Date()) {
      return res.status(400).json({ status: "error", message: "Invalid or expired link" });
    }
    await updateUserPassword(u.id, password);
    await pool.query("UPDATE users SET reset_token=NULL, reset_expires=NULL, updated_at=now() WHERE id=$1", [u.id]);
    return res.json({ status: "success" });
  } catch (e) {
    console.error("reset error:", e);
    return res.status(500).json({ status: "error", message: "Could not reset password" });
  }
});

// --- Paystack verification (optional)
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ status: "error", message: "Paystack not configured" });

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await psRes.json().catch(() => ({}));

    if (data?.status && data?.data?.status === "success") {
      const customerEmail = normalizeEmail(data.data?.customer?.email || "");
      const planCode = data.data?.plan?.plan_code || null;
      const newPlan = mapPlanCodeToLabel(planCode);

      if (customerEmail) {
        let u = await findUserByEmail(customerEmail);
        if (!u) {
          const r = await pool.query(
            "INSERT INTO users (email, plan) VALUES ($1, $2) RETURNING id, email, plan",
            [customerEmail, newPlan]
          );
          u = r.rows[0];
        } else {
          await pool.query("UPDATE users SET plan=$1, updated_at=now() WHERE id=$2", [newPlan, u.id]);
        }
        setSessionCookie(res, { uid: u.id, email: u.email, plan: newPlan });
      }

      return res.json({ status: "success", email: customerEmail, plan: newPlan, reference });
    }

    return res.json({ status: "pending", data });
  } catch (e) {
    console.error("verify error:", e);
    return res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// ---------- Conversations API (auth) ----------

// List conversations
app.get("/api/conversations", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, title, archived FROM conversations WHERE user_id=$1 ORDER BY updated_at DESC",
    [req.user.uid]
  );
  res.json(rows);
});

// Create conversation
app.post("/api/conversations", requireAuth, async (req, res) => {
  const title = String(req.body?.title || "New chat").trim() || "New chat";
  const { rows } = await pool.query(
    "INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id, title",
    [req.user.uid, title]
  );
  res.json(rows[0]);
});

// Rename/archive conversation
app.patch("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "bad request" });

  // ownership check
  const own = await pool.query("SELECT id FROM conversations WHERE id=$1 AND user_id=$2", [id, req.user.uid]);
  if (!own.rows.length) return res.status(404).json({ error: "not found" });

  const fields = [];
  const vals = [];
  let idx = 1;

  if (typeof req.body?.title === "string") {
    fields.push(`title = $${++idx}`);
    vals.push(req.body.title.trim() || "Untitled");
  }
  if (typeof req.body?.archived === "boolean") {
    fields.push(`archived = $${++idx}`);
    vals.push(!!req.body.archived);
  }

  if (!fields.length) return res.json({ ok: true });

  await pool.query(
    `UPDATE conversations SET ${fields.join(", ")}, updated_at=now() WHERE id=$1`,
    [id, ...vals]
  );
  res.json({ ok: true });
});

// Delete conversation
app.delete("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "bad request" });
  await pool.query("DELETE FROM conversations WHERE id=$1 AND user_id=$2", [id, req.user.uid]);
  res.json({ ok: true });
});

// Get messages in a conversation
app.get("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "bad request" });
  const own = await pool.query("SELECT id, title FROM conversations WHERE id=$1 AND user_id=$2", [id, req.user.uid]);
  if (!own.rows.length) return res.status(404).json({ error: "not found" });

  const msgs = await pool.query(
    "SELECT role, content, created_at FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC",
    [id]
  );
  res.json({ id, title: own.rows[0].title, messages: msgs.rows });
});

// Create share link
app.post("/api/conversations/:id/share", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "bad request" });

  const own = await pool.query("SELECT id, share_token FROM conversations WHERE id=$1 AND user_id=$2", [id, req.user.uid]);
  if (!own.rows.length) return res.status(404).json({ error: "not found" });

  let token = own.rows[0].share_token;
  if (!token) {
    token = crypto.randomBytes(24).toString("base64url");
    await pool.query("UPDATE conversations SET share_token=$1, updated_at=now() WHERE id=$2", [token, id]);
  }
  res.json({ token });
});

// Public: view shared conversation (read-only)
app.get("/api/share/:token", async (req, res) => {
  const token = req.params.token || "";
  if (!token) return res.status(404).json({ error: "not found" });

  const conv = await pool.query("SELECT id, title FROM conversations WHERE share_token=$1 LIMIT 1", [token]);
  const c = conv.rows[0];
  if (!c) return res.status(404).json({ error: "not found" });

  const msgs = await pool.query(
    "SELECT role, content, created_at FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC",
    [c.id]
  );
  res.json({ title: c.title, messages: msgs.rows });
});

// ---------- Chat & Photo Solve ----------

// /api/chat
app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const { message, gptType, conversationId } = req.body || {};
    if (!message || !String(message).trim()) {
      return res.status(400).json({ error: "message required" });
    }

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query("SELECT id FROM conversations WHERE id=$1 AND user_id=$2", [convId, req.user.uid]);
      if (!own.rows.length) return res.status(404).json({ error: "not found" });
    } else {
      const r = await pool.query(
        "INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id",
        [req.user.uid, (message.slice(0, 40) || "New chat")]
      );
      convId = r.rows[0].id;
    }

    // Build system prompt
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    // Fetch prior messages
    const prior = await pool.query(
      "SELECT role, content FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC",
      [convId]
    );
    const msgs = [
      { role: "system", content: system },
      ...prior.rows.map(m => ({ role: m.role, content: m.content })),
      { role: "user", content: message },
    ];

    // Persist user message first
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2)",
      [convId, message]
    );

    // Call OpenAI
    const answer = await openaiChat(msgs);

    const finalAnswer = String(answer || "").trim() || "I couldn't produce a response. Please try again.";
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)",
      [convId, finalAnswer]
    );
    await pool.query("UPDATE conversations SET updated_at=now() WHERE id=$1", [convId]);

    res.json({ response: finalAnswer, conversationId: convId });
  } catch (e) {
    console.error("Chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// /api/photo-solve (robust; ensures non-empty response)
app.post("/api/photo-solve", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    const okTypes = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
    const mime = (req.file.mimetype || "").toLowerCase();
    if (!okTypes.includes(mime)) {
      return res.status(400).json({ error: "Unsupported image type" });
    }

    // find or create conversation
    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query("SELECT id FROM conversations WHERE id=$1 AND user_id=$2", [convId, req.user.uid]);
      if (!own.rows.length) return res.status(404).json({ error: "not found" });
    } else {
      const r = await pool.query(
        "INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id",
        [req.user.uid, "Photo solve"]
      );
      convId = r.rows[0].id;
    }

    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step with clear reasoning."
        : "You are a helpful assistant. Describe and analyze the image, then answer the user's request.";

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OPENAI_MODEL || "gpt-4o-mini",
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
      const t = await r.text().catch(() => "");
      console.error("OpenAI vision error:", r.status, t);
      return res.status(502).json({ error: "Vision model call failed" });
    }

    const data = await r.json().catch(() => ({}));
    let answer = String(data?.choices?.[0]?.message?.content || "").trim();
    if (!answer) {
      answer = "I couldn’t extract a readable problem from that image. Try a clearer photo or add a short note describing the question.";
    }

    // persist messages
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2)",
      [convId, attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]
    );
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)",
      [convId, answer]
    );
    await pool.query("UPDATE conversations SET updated_at = now() WHERE id = $1", [convId]);

    return res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve error:", e);
    return res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------- Reset page fallback (serve static file if user hits /reset-password) ----------
app.get("/reset-password", (_req, res) => {
  // For legacy links; serve your SPA/HTML from public
  res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
await ensureSchema().catch((e) => {
  console.error("Failed to ensure schema:", e);
  process.exit(1);
});
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
  if (!process.env.JWT_SECRET) {
    console.warn("[WARN] JWT_SECRET not set. Using a random secret; sessions will reset on redeploy.");
  }
});
