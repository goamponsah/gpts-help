// server.js (Node 18+/22+, ESM)
// package.json: { "type": "module" }

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";
import { Pool } from "pg";

// ---------- Resolve __dirname in ESM ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- ENV ----------
const {
  DATABASE_URL,
  FRONTEND_ORIGIN,
  JWT_SECRET: JWT_SECRET_ENV,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  RESEND_API_KEY,
  RESEND_FROM,
  APP_ORIGIN, // if set, used to build absolute links (e.g., reset passwords)
} = process.env;

// ---------- App ----------
const app = express();
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
app.use(express.static(path.join(__dirname, "public")));
const upload = multer({ storage: multer.memoryStorage() });

// ---------- Postgres ----------
const useSSL =
  !!DATABASE_URL && !/localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : undefined,
});
const q = (text, params) => pool.query(text, params);

// ---------- JWT ----------
const JWT_SECRET = JWT_SECRET_ENV || crypto.randomBytes(48).toString("hex");

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
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}
function clearSessionCookie(res) {
  res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 });
}
function verifySession(req) {
  const { sid } = req.cookies || {};
  if (!sid) return null;
  try {
    return jwt.verify(sid, JWT_SECRET);
  } catch {
    return null;
  }
}

// ---------- Utils ----------
const PLAN_PLUS = "PLUS";
const PLAN_PRO = "PRO";
const PLAN_FREE = "FREE";

function mapPlanCodeToLabel(planCode) {
  if (!planCode) return PLAN_FREE;
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return PLAN_PLUS;
  if (planCode === PLAN_CODE_PRO_ANNUAL) return PLAN_PRO;
  return PLAN_FREE;
}

function getOrigin(req) {
  if (APP_ORIGIN) return APP_ORIGIN;
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function titleFrom(text, fallback = "New chat") {
  const t0 = (text || "").replace(/\s+/g, " ").trim();
  if (!t0) return fallback;
  let t = t0
    .replace(/^#{1,6}\s*/gm, "")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/\*(.*?)\*/g, "$1")
    .replace(/`{1,3}([\s\S]*?)`{1,3}/g, "$1")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1")
    .replace(/!\[(.*?)\]\((.*?)\)/g, "$1");
  t = t.split(/[\n\.!?]/)[0].trim() || t0;
  t = t.charAt(0).toUpperCase() + t.slice(1);
  const MAX = 50;
  if (t.length > MAX) t = t.slice(0, MAX - 1).trim() + "…";
  return t;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await new Promise((res, rej) =>
    crypto.scrypt(password, salt, 64, (err, dk) =>
      err ? rej(err) : res(dk)
    )
  );
  return `s$${salt.toString("base64")}$${Buffer.from(hash).toString(
    "base64"
  )}`;
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("s$")) return false;
  const [, saltB64, hashB64] = stored.split("$");
  const salt = Buffer.from(saltB64, "base64");
  const hash = Buffer.from(hashB64, "base64");
  const calc = await new Promise((res, rej) =>
    crypto.scrypt(password, salt, 64, (err, dk) =>
      err ? rej(err) : res(dk)
    )
  );
  return crypto.timingSafeEqual(hash, Buffer.from(calc));
}

function randomToken(n = 32) {
  return crypto.randomBytes(n).toString("hex");
}

// ---------- Schema (idempotent) ----------
async function ensureSchema() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      plan TEXT NOT NULL DEFAULT 'FREE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'New chat',
      archived BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user','assistant')),
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS shares (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Helpful indexes (idempotent)
  await q(`CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, id);`);
}

// ---------- OpenAI ----------
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
    const t = await r.text();
    throw new Error(`OpenAI error ${r.status}: ${t}`);
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

// ---------- Email (Resend) ----------
async function sendResetEmail(to, resetUrl) {
  if (!RESEND_API_KEY || !RESEND_FROM) {
    console.warn("[reset] RESEND_API_KEY or RESEND_FROM not set; printing link:", resetUrl);
    return { ok: true, info: "no-email-config" };
  }
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: RESEND_FROM, // e.g. "GPTs Help <no-reply@yourdomain.com>"
      to: [to],
      subject: "Reset your GPTs Help password",
      html: `
        <div style="font-family:system-ui,Segoe UI,Roboto,Arial">
          <h2>Reset your password</h2>
          <p>Click the button below to reset your password. This link expires in 1 hour.</p>
          <p><a href="${resetUrl}" style="background:#6f42c1;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Reset Password</a></p>
          <p>If the button doesn't work, copy and paste this URL into your browser:<br/>
          <a href="${resetUrl}">${resetUrl}</a></p>
        </div>
      `,
      text: `Reset your password: ${resetUrl}`,
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    console.error("Resend error:", t);
    throw new Error("Email send failed");
  }
  return { ok: true };
}

// ---------- Middleware ----------
function requireAuth(req, res, next) {
  const s = verifySession(req);
  if (!s?.email || !s?.uid) return res.status(401).json({ status: "unauthenticated" });
  req.user = s;
  next();
}

// ---------- Routes ----------

// Health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Public config
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

// Who am I
app.get("/api/me", async (req, res) => {
  const s = verifySession(req);
  if (!s?.email || !s?.uid) return res.status(401).json({ status: "unauthenticated" });
  try {
    const u = await q(`SELECT id, email, plan FROM users WHERE id=$1`, [s.uid]);
    if (!u.rows[0]) return res.status(401).json({ status: "unauthenticated" });
    return res.json({ status: "ok", user: { email: u.rows[0].email, plan: u.rows[0].plan } });
  } catch {
    return res.status(500).json({ status: "error" });
  }
});

// Sign up (free)
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ status: "error", message: "Password must be at least 8 characters" });
    }

    const existing = await q(`SELECT id, password_hash FROM users WHERE email=$1`, [email.toLowerCase()]);
    if (existing.rows[0]?.password_hash) {
      return res.status(409).json({ status: "error", message: "Account already exists. Please sign in." });
    }

    const pwHash = await hashPassword(password);
    let uid;
    if (existing.rows[0]) {
      const upd = await q(`UPDATE users SET password_hash=$1, plan='FREE' WHERE email=$2 RETURNING id`, [pwHash, email.toLowerCase()]);
      uid = upd.rows[0].id;
    } else {
      const ins = await q(
        `INSERT INTO users(email, password_hash, plan) VALUES($1,$2,'FREE') RETURNING id`,
        [email.toLowerCase(), pwHash]
      );
      uid = ins.rows[0].id;
    }

    setSessionCookie(res, { uid, email: email.toLowerCase(), plan: "FREE" });
    res.json({ status: "success" });
  } catch (e) {
    console.error("signup-free error:", e);
    res.status(500).json({ status: "error", message: "Could not create account" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ status: "error", message: "Missing credentials" });
    const u = await q(`SELECT id, email, password_hash, plan FROM users WHERE email=$1`, [email.toLowerCase()]);
    const row = u.rows[0];
    if (!row || !row.password_hash) {
      return res.status(401).json({ status: "error", message: "Invalid email or password" });
    }
    const ok = await verifyPassword(password, row.password_hash);
    if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password" });
    setSessionCookie(res, { uid: row.id, email: row.email, plan: row.plan || "FREE" });
    res.json({ status: "ok" });
  } catch (e) {
    console.error("login error:", e);
    res.status(500).json({ status: "error", message: "Login failed" });
  }
});

// Logout
app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// Password reset: request
app.post("/api/reset/request", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.json({ status: "ok" }); // do not leak existence
    const u = await q(`SELECT id FROM users WHERE email=$1`, [email.toLowerCase()]);
    if (!u.rows[0]) return res.json({ status: "ok" });

    const token = randomToken(32);
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1h
    await q(
      `INSERT INTO password_resets(user_id, token, expires_at) VALUES ($1,$2,$3)`,
      [u.rows[0].id, token, expires]
    );

    const origin = APP_ORIGIN || "https://"+(process.env.RAILWAY_STATIC_URL || "your-domain");
    const resetUrl = `${getOrigin(req)}/reset-password.html?token=${encodeURIComponent(token)}`;

    try { await sendResetEmail(email.toLowerCase(), resetUrl); } catch (e) { console.warn("email send failed:", e.message); }
    res.json({ status: "ok" });
  } catch (e) {
    console.error("reset request error:", e);
    res.json({ status: "ok" }); // always OK to avoid enumeration
  }
});

// Password reset: confirm
app.post("/api/reset/confirm", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ status: "error", message: "Invalid request" });

    const r = await q(
      `SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at
       FROM password_resets pr
       WHERE pr.token=$1`,
      [token]
    );
    const row = r.rows[0];
    if (!row || row.used_at || new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ status: "error", message: "Invalid or expired token" });
    }

    const pwHash = await hashPassword(password);
    await q(`UPDATE users SET password_hash=$1 WHERE id=$2`, [pwHash, row.user_id]);
    await q(`UPDATE password_resets SET used_at=NOW() WHERE id=$1`, [row.id]);

    res.json({ status: "ok" });
  } catch (e) {
    console.error("reset confirm error:", e);
    res.status(500).json({ status: "error", message: "Could not reset password" });
  }
});

// ---------- Conversations (auth required) ----------

// List
app.get("/api/conversations", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const r = await q(
    `SELECT id, title, archived
     FROM conversations
     WHERE user_id=$1
     ORDER BY updated_at DESC, id DESC`,
    [uid]
  );
  res.json(r.rows);
});

// Create
app.post("/api/conversations", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const { title } = req.body || {};
  const t = titleFrom(title || "New chat");
  const r = await q(
    `INSERT INTO conversations(user_id, title)
     VALUES ($1,$2) RETURNING id, title`,
    [uid, t]
  );
  res.json(r.rows[0]);
});

// Rename / Archive
app.patch("/api/conversations/:id", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const id = Number(req.params.id);
  const { title, archived } = req.body || {};
  const sets = [];
  const vals = [];
  let i = 1;
  if (typeof title === "string") { sets.push(`title=$${i++}`); vals.push(titleFrom(title || "Untitled")); }
  if (typeof archived === "boolean") { sets.push(`archived=$${i++}`); vals.push(archived); }
  sets.push(`updated_at=NOW()`);
  vals.push(uid, id);
  const sql = `UPDATE conversations SET ${sets.join(", ")} WHERE user_id=$${i++} AND id=$${i} RETURNING id`;
  const r = await q(sql, vals);
  if (!r.rows[0]) return res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// Delete
app.delete("/api/conversations/:id", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const id = Number(req.params.id);
  await q(`DELETE FROM conversations WHERE user_id=$1 AND id=$2`, [uid, id]);
  res.json({ ok: true });
});

// Get messages
app.get("/api/conversations/:id", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const id = Number(req.params.id);
  const c = await q(`SELECT id, title FROM conversations WHERE user_id=$1 AND id=$2`, [uid, id]);
  if (!c.rows[0]) return res.status(404).json({ error: "not found" });
  const m = await q(
    `SELECT role, content, created_at FROM messages
     WHERE conversation_id=$1 ORDER BY id ASC`,
    [id]
  );
  res.json({ id, title: c.rows[0].title, messages: m.rows });
});

// Share: create or return token
app.post("/api/conversations/:id/share", requireAuth, async (req, res) => {
  const { uid } = req.user;
  const id = Number(req.params.id);
  const own = await q(`SELECT id FROM conversations WHERE user_id=$1 AND id=$2`, [uid, id]);
  if (!own.rows[0]) return res.status(404).json({ error: "not found" });

  const existing = await q(`SELECT token FROM shares WHERE conversation_id=$1 AND revoked=FALSE`, [id]);
  if (existing.rows[0]) return res.json({ token: existing.rows[0].token });

  const token = randomToken(24);
  await q(`INSERT INTO shares(conversation_id, token) VALUES ($1,$2)`, [id, token]);
  res.json({ token });
});

// Public read-only
app.get("/api/share/:token", async (req, res) => {
  const { token } = req.params;
  const s = await q(
    `SELECT s.id, s.revoked, c.id AS conversation_id, c.title
     FROM shares s
     JOIN conversations c ON c.id = s.conversation_id
     WHERE s.token=$1`,
    [token]
  );
  const row = s.rows[0];
  if (!row || row.revoked) return res.status(404).json({ error: "invalid" });

  const m = await q(
    `SELECT role, content, created_at
     FROM messages WHERE conversation_id=$1 ORDER BY id ASC`,
    [row.conversation_id]
  );
  res.json({ title: row.title, messages: m.rows });
});

// ---------- Chat ----------

app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const { uid } = req.user;
    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // find or create conversation
    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await q(`SELECT id FROM conversations WHERE id=$1 AND user_id=$2`, [convId, uid]);
      if (!own.rows[0]) return res.status(404).json({ error: "not found" });
    } else {
      const t = titleFrom(message);
      const r = await q(`INSERT INTO conversations(user_id, title) VALUES ($1,$2) RETURNING id`, [uid, t]);
      convId = r.rows[0].id;
    }

    // build context
    const past = await q(
      `SELECT role, content FROM messages WHERE conversation_id=$1 ORDER BY id ASC LIMIT 50`,
      [convId]
    );
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [
      { role: "system", content: system },
      ...past.rows.map((m) => ({ role: m.role, content: m.content })),
      { role: "user", content: message },
    ];

    // store user message
    await q(`INSERT INTO messages(conversation_id, role, content) VALUES ($1,'user',$2)`, [convId, message]);
    await q(`UPDATE conversations SET updated_at=NOW() WHERE id=$1`, [convId]);

    // call OpenAI
    const answer = await openaiChat(msgs);

    // store assistant message
    await q(`INSERT INTO messages(conversation_id, role, content) VALUES ($1,'assistant',$2)`, [convId, answer]);
    await q(`UPDATE conversations SET updated_at=NOW() WHERE id=$1`, [convId]);

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("Chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// Photo solve (vision)
app.post("/api/photo-solve", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const { uid } = req.user;
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await q(`SELECT id FROM conversations WHERE id=$1 AND user_id=$2`, [convId, uid]);
      if (!own.rows[0]) return res.status(404).json({ error: "not found" });
    } else {
      const r = await q(`INSERT INTO conversations(user_id, title) VALUES ($1,'Photo solve') RETURNING id`, [uid]);
      convId = r.rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly."
        : "You are a helpful assistant. Describe and analyze the content of the image, then answer the user's request.";

    const model = OPENAI_MODEL || "gpt-4o-mini";
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
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
      throw new Error(`OpenAI vision error ${r.status}: ${t}`);
    }
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    await q(`INSERT INTO messages(conversation_id, role, content) VALUES ($1,'user',$2)`, [
      convId,
      attempt ? `(Photo) ${attempt}` : "(Photo uploaded)",
    ]);
    await q(`INSERT INTO messages(conversation_id, role, content) VALUES ($1,'assistant',$2)`, [convId, answer]);
    await q(`UPDATE conversations SET updated_at=NOW() WHERE id=$1`, [convId]);

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("Photo solve error:", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------- Paystack ----------
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await psRes.json();

    if (data?.status && data?.data?.status === "success") {
      const customerEmail = (data.data?.customer?.email || "").toLowerCase();
      const planCode = data.data?.plan?.plan_code || null;
      const newPlan = mapPlanCodeToLabel(planCode);

      if (customerEmail) {
        // upsert user if needed
        const u = await q(`SELECT id, email FROM users WHERE email=$1`, [customerEmail]);
        let uid;
        if (u.rows[0]) {
          const r = await q(`UPDATE users SET plan=$1 WHERE id=$2 RETURNING id`, [newPlan, u.rows[0].id]);
          uid = r.rows[0].id;
        } else {
          const r = await q(
            `INSERT INTO users(email, plan) VALUES($1,$2) RETURNING id`,
            [customerEmail, newPlan]
          );
          uid = r.rows[0].id;
        }
        setSessionCookie(res, { uid, email: customerEmail, plan: newPlan });
      }

      return res.json({ status: "success", email: customerEmail, plan: newPlan, reference });
    }

    return res.json({ status: "pending", data });
  } catch (e) {
    console.error("verify error:", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// Optional webhook placeholder
app.post("/api/paystack/webhook", express.raw({ type: "*/*" }), (_req, res) => {
  // Verify signature & handle as needed
  res.sendStatus(200);
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`GPTs Help server running on :${PORT}`);
      if (!JWT_SECRET_ENV) {
        console.warn("[WARN] JWT_SECRET not set. Using an ephemeral secret; sessions reset on deploy.");
      }
      if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY is not set.");
      if (!PAYSTACK_PUBLIC_KEY) console.warn("[WARN] PAYSTACK_PUBLIC_KEY is not set.");
      if (!DATABASE_URL) console.warn("[WARN] DATABASE_URL is not set (required for persistence).");
    });
  })
  .catch((e) => {
    console.error("Failed to ensure schema:", e);
    process.exit(1);
  });

