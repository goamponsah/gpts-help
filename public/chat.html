// server.js (Node 18/20/22, ESM)
// package.json should have: "type": "module"

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";
import { Pool } from "pg";

// ---------- Resolve __dirname (ESM) ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- ENV ----------
const {
  DATABASE_URL,
  JWT_SECRET = crypto.randomBytes(48).toString("hex"),
  OPENAI_API_KEY,
  OPENAI_MODEL = "gpt-4o-mini",
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PAYSTACK_CURRENCY = "GHS",
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  RESEND_API_KEY,
  MAIL_FROM = "GPTs Help <no-reply@gptshelp.online>",
  FRONTEND_ORIGIN,
  CANONICAL_HOST, // e.g. https://gptshelp.online
} = process.env;

// ---------- App ----------
const app = express();

if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}

app.use(express.json({ limit: "12mb" }));
app.use(cookieParser());

// Serve static site
app.use(express.static(path.join(__dirname, "public")));

// Multer for image uploads (kept in memory)
const upload = multer({ storage: multer.memoryStorage() });

// ---------- DB ----------
if (!DATABASE_URL) {
  console.warn("[WARN] DATABASE_URL not set — server will fail to start.");
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false,
});

// Create / fix tables & columns idempotently
async function ensureSchema() {
  // users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            BIGSERIAL PRIMARY KEY,
      email         TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      plan          TEXT NOT NULL DEFAULT 'FREE',
      email_verified BOOLEAN NOT NULL DEFAULT false,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Lower(email) unique index (case-insensitive email uniqueness)
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'idx_users_email_lower'
      ) THEN
        CREATE UNIQUE INDEX idx_users_email_lower ON users ((lower(email)));
      END IF;
    END $$;
  `);
  // conversations
  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id         BIGSERIAL PRIMARY KEY,
      user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT NOT NULL DEFAULT 'New chat',
      archived   BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'idx_conversations_user_updated'
      ) THEN
        CREATE INDEX idx_conversations_user_updated
          ON conversations(user_id, updated_at DESC);
      END IF;
    END $$;
  `);
  // messages
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id              BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role            TEXT NOT NULL CHECK (role IN ('user','assistant')),
      content         TEXT NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'idx_messages_convo_created'
      ) THEN
        CREATE INDEX idx_messages_convo_created
          ON messages(conversation_id, created_at);
      END IF;
    END $$;
  `);
  // share links
  await pool.query(`
    CREATE TABLE IF NOT EXISTS share_links (
      id               BIGSERIAL PRIMARY KEY,
      token            TEXT NOT NULL UNIQUE,
      conversation_id  BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      creator_user_id  BIGINT REFERENCES users(id) ON DELETE SET NULL,
      revoked          BOOLEAN NOT NULL DEFAULT false,
      created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // password resets
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id          BIGSERIAL PRIMARY KEY,
      user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash  TEXT NOT NULL UNIQUE,
      expires_at  TIMESTAMPTZ NOT NULL,
      used        BOOLEAN NOT NULL DEFAULT false,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // payments (optional minimal; safe to exist for future)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id          BIGSERIAL PRIMARY KEY,
      user_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
      provider    TEXT NOT NULL DEFAULT 'paystack',
      reference   TEXT,
      status      TEXT,
      raw         JSONB,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // In case older DBs are missing columns (no-ops if already present)
  await pool.query(`ALTER TABLE users        ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
  await pool.query(`ALTER TABLE users        ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'FREE';`);
  await pool.query(`ALTER TABLE users        ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE users        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE users        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE messages     ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
}
await ensureSchema();

// ---------- Session helpers ----------
function cookieOptions() {
  const crossSite = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true, // Railway -> HTTPS
    sameSite: crossSite ? "None" : "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  };
}
function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}
function clearSessionCookie(res) {
  res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 });
}
function getSession(req) {
  const tok = req.cookies?.sid;
  if (!tok) return null;
  try { return jwt.verify(tok, JWT_SECRET); }
  catch { return null; }
}
function requireAuth(req, res, next) {
  const s = getSession(req);
  if (!s?.uid) return res.status(401).json({ status: "unauthenticated" });
  req.user = s;
  next();
}

// ---------- Crypto: password hash (scrypt) ----------
const scryptAsync = (password, salt, N = 16384, r = 8, p = 1, keylen = 64) =>
  new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N, r, p }, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt);
  return `s2$${salt.toString("hex")}$${key.toString("hex")}`;
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("s2$")) return false;
  const [, saltHex, keyHex] = stored.split("$");
  const salt = Buffer.from(saltHex, "hex");
  const key = Buffer.from(keyHex, "hex");
  const test = await scryptAsync(password, salt, 16384, 8, 1, key.length);
  return crypto.timingSafeEqual(key, test);
}

// ---------- Utilities ----------
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}
function originFor(req) {
  if (CANONICAL_HOST) return CANONICAL_HOST;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
  return `${proto}://${req.get("host")}`;
}
function genToken(n = 32) {
  return crypto.randomBytes(n).toString("base64url");
}
async function openaiChat(messages) {
  if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY missing");
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ model: OPENAI_MODEL, messages, temperature: 0.2 }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`OpenAI error ${r.status}: ${t}`);
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}
async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) throw new Error("RESEND_API_KEY missing");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`Resend error ${r.status}: ${t}`);
  }
  return r.json();
}

// ---------- Public / config ----------
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: PAYSTACK_CURRENCY,
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

// ---------- Auth ----------
app.get("/api/me", async (req, res) => {
  const s = getSession(req);
  if (!s?.uid) return res.status(401).json({ status: "unauthenticated" });
  const { rows } = await pool.query(
    "SELECT id, email, plan FROM users WHERE id = $1",
    [s.uid]
  );
  if (!rows.length) return res.status(401).json({ status: "unauthenticated" });
  res.json({ status: "ok", user: { id: rows[0].id, email: rows[0].email, plan: rows[0].plan } });
});

// Sign up (email + password)
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 6) {
      return res.status(400).json({ status: "error", message: "Valid email & 6+ char password required" });
    }
    const pass = await hashPassword(password);
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, plan)
       VALUES (LOWER($1), $2, 'FREE')
       ON CONFLICT (email) DO NOTHING
       RETURNING id, email, plan`,
      [email, pass]
    );
    if (!rows.length) {
      // email exists already
      return res.status(409).json({ status: "error", message: "Email already registered" });
    }
    setSessionCookie(res, { uid: rows[0].id, email: rows[0].email, plan: rows[0].plan });
    return res.json({ status: "success" });
  } catch (e) {
    console.error("signup error:", e);
    return res.status(500).json({ status: "error", message: "Could not create account" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ status: "error", message: "Email and password required" });
    }
    const { rows } = await pool.query(
      "SELECT id, email, password_hash, plan FROM users WHERE lower(email) = lower($1) LIMIT 1",
      [email]
    );
    if (!rows.length || !(await verifyPassword(password, rows[0].password_hash))) {
      return res.status(401).json({ status: "error", message: "Invalid credentials" });
    }
    setSessionCookie(res, { uid: rows[0].id, email: rows[0].email, plan: rows[0].plan });
    return res.json({ status: "success" });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ status: "error", message: "Login failed" });
  }
});

// Logout
app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// Request password reset (email link)
app.post("/api/password/request-reset", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.json({ status: "ok" }); // don't leak
    }
    const { rows } = await pool.query(
      "SELECT id FROM users WHERE lower(email) = lower($1) LIMIT 1",
      [email]
    );
    if (!rows.length) {
      return res.json({ status: "ok" }); // silent
    }
    const userId = rows[0].id;
    const raw = genToken(32);
    const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 60); // 1h
    await pool.query(
      `INSERT INTO password_resets (user_id, token_hash, expires_at, used)
       VALUES ($1, $2, $3, false)`,
      [userId, tokenHash, expires]
    );
    const link = `${originFor(req)}/reset.html?token=${encodeURIComponent(raw)}`;
    try {
      await sendEmail({
        to: email,
        subject: "Reset your GPTs Help password",
        html: `
          <p>Click the button below to reset your password.</p>
          <p><a href="${link}" style="display:inline-block;padding:10px 16px;background:#5865f2;color:#fff;border-radius:8px;text-decoration:none">Reset password</a></p>
          <p>Or open this link: <a href="${link}">${link}</a></p>
          <p>This link expires in 1 hour.</p>
        `,
      });
    } catch (e) {
      console.error("Resend send error:", e);
      // still reply ok to avoid enumeration
    }
    return res.json({ status: "ok" });
  } catch (e) {
    console.error("request-reset error:", e);
    return res.json({ status: "ok" });
  }
});

// Perform reset
app.post("/api/password/perform-reset", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password || password.length < 6) {
      return res.status(400).json({ status: "error", message: "Bad request" });
    }
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const { rows } = await pool.query(
      `SELECT id, user_id, expires_at, used
       FROM password_resets
       WHERE token_hash = $1
       LIMIT 1`,
      [tokenHash]
    );
    if (!rows.length || rows[0].used || new Date(rows[0].expires_at) < new Date()) {
      return res.status(400).json({ status: "error", message: "Invalid or expired link" });
    }
    const pass = await hashPassword(password);
    await pool.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [
      pass,
      rows[0].user_id,
    ]);
    await pool.query("UPDATE password_resets SET used = true WHERE id = $1", [rows[0].id]);
    return res.json({ status: "success" });
  } catch (e) {
    console.error("perform-reset error:", e);
    return res.status(500).json({ status: "error", message: "Could not reset password" });
  }
});

// ---------- Paystack verification ----------
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });

    const r = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await r.json();

    if (data?.status && data?.data?.status === "success") {
      const email = data.data?.customer?.email || null;
      const planCode = data.data?.plan?.plan_code || null;
      const newPlan = mapPlanCodeToLabel(planCode);

      let uid;
      if (email) {
        // upsert user on successful payment
        const up = await pool.query(
          `INSERT INTO users (email, plan)
           VALUES (LOWER($1), $2)
           ON CONFLICT (email) DO UPDATE SET plan = EXCLUDED.plan, updated_at = now()
           RETURNING id`,
          [email, newPlan]
        );
        uid = up.rows[0].id;
        setSessionCookie(res, { uid, email, plan: newPlan });
      }
      await pool.query(
        `INSERT INTO payments (user_id, provider, reference, status, raw)
         VALUES ($1, 'paystack', $2, 'success', $3)`,
        [uid || null, reference, data]
      );
      return res.json({ status: "success", email, plan: newPlan, reference });
    }
    return res.json({ status: "pending", data });
  } catch (e) {
    console.error("paystack verify error:", e);
    return res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// ---------- Conversations API (session-based) ----------

// List conversations
app.get("/api/conversations", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, title, archived
     FROM conversations
     WHERE user_id = $1
     ORDER BY updated_at DESC, id DESC`,
    [req.user.uid]
  );
  res.json(rows);
});

// Create conversation
app.post("/api/conversations", requireAuth, async (req, res) => {
  const title = (req.body?.title || "New chat").trim();
  const { rows } = await pool.query(
    `INSERT INTO conversations (user_id, title)
     VALUES ($1, $2)
     RETURNING id, title`,
    [req.user.uid, title]
  );
  res.json(rows[0]);
});

// Rename / archive
app.patch("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const { title, archived } = req.body || {};
  // Ensure ownership
  const { rows: own } = await pool.query(
    "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
    [id, req.user.uid]
  );
  if (!own.length) return res.status(404).json({ error: "not found" });

  if (typeof archived === "boolean") {
    await pool.query(
      "UPDATE conversations SET archived = $1, updated_at = now() WHERE id = $2",
      [archived, id]
    );
  }
  if (typeof title === "string" && title.trim()) {
    await pool.query(
      "UPDATE conversations SET title = $1, updated_at = now() WHERE id = $2",
      [title.trim(), id]
    );
  }
  res.json({ ok: true });
});

// Delete
app.delete("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  await pool.query("DELETE FROM conversations WHERE id = $1 AND user_id = $2", [
    id,
    req.user.uid,
  ]);
  res.json({ ok: true });
});

// Get messages
app.get("/api/conversations/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const { rows: conv } = await pool.query(
    "SELECT id, title FROM conversations WHERE id = $1 AND user_id = $2",
    [id, req.user.uid]
  );
  if (!conv.length) return res.status(404).json({ error: "not found" });
  const { rows: msgs } = await pool.query(
    "SELECT role, content, created_at FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC, id ASC",
    [id]
  );
  res.json({ id, title: conv[0].title, messages: msgs });
});

// Share link (create)
app.post("/api/conversations/:id/share", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const { rows: own } = await pool.query(
    "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
    [id, req.user.uid]
  );
  if (!own.length) return res.status(404).json({ error: "not found" });

  const token = genToken(24);
  await pool.query(
    `INSERT INTO share_links (token, conversation_id, creator_user_id)
     VALUES ($1, $2, $3)`,
    [token, id, req.user.uid]
  );
  res.json({ token });
});

// Read-only shared conversation
app.get("/api/share/:token", async (req, res) => {
  const token = String(req.params.token || "");
  const { rows: link } = await pool.query(
    `SELECT s.conversation_id, s.revoked, c.title
     FROM share_links s
     JOIN conversations c ON c.id = s.conversation_id
     WHERE s.token = $1
     LIMIT 1`,
    [token]
  );
  if (!link.length || link[0].revoked) {
    return res.status(404).json({ error: "invalid" });
  }
  const cid = link[0].conversation_id;
  const { rows: msgs } = await pool.query(
    "SELECT role, content, created_at FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC, id ASC",
    [cid]
  );
  res.json({ title: link[0].title, messages: msgs });
});

// ---------- Chat & Photo Solve ----------

// /api/chat
app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // find or create conversation
    let convId = conversationId;
    if (convId) {
      const { rows } = await pool.query(
        "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
        [convId, req.user.uid]
      );
      if (!rows.length) return res.status(404).json({ error: "not found" });
    } else {
      const { rows } = await pool.query(
        "INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id",
        [req.user.uid, (message.slice(0, 40) || "New chat")]
      );
      convId = rows[0].id;
    }

    // prior context
    const { rows: prior } = await pool.query(
      "SELECT role, content FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC, id ASC",
      [convId]
    );

    const system =
      gptType === "math"
        ? "You are Math GPT. Solve problems step-by-step with clear reasoning."
        : "You are a helpful writing assistant. Be clear and structured.";

    const msgs = [
      { role: "system", content: system },
      ...prior,
      { role: "user", content: message },
    ];

    // persist user message
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2)",
      [convId, message]
    );

    // call OpenAI
    const answer = await openaiChat(msgs);

    // persist assistant message & bump updated_at
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)",
      [convId, answer]
    );
    await pool.query(
      "UPDATE conversations SET updated_at = now() WHERE id = $1",
      [convId]
    );

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// /api/photo-solve
app.post("/api/photo-solve", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    // find or create conversation
    let convId = conversationId;
    if (convId) {
      const { rows } = await pool.query(
        "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
        [convId, req.user.uid]
      );
      if (!rows.length) return res.status(404).json({ error: "not found" });
    } else {
      const { rows } = await pool.query(
        "INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id",
        [req.user.uid, "Photo solve"]
      );
      convId = rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step."
        : "You are a helpful assistant. Describe and analyze the image, then answer the user's request.";

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OPENAI_MODEL,
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

    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2)",
      [convId, attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]
    );
    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)",
      [convId, answer]
    );
    await pool.query("UPDATE conversations SET updated_at = now() WHERE id = $1", [convId]);

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve error:", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------- Fallback (SPA-ish deep links for reset etc.) ----------
app.get("/reset.html", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset.html"));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
  if (!process.env.JWT_SECRET) {
    console.warn("[WARN] JWT_SECRET not set. Using a random secret; sessions reset on deploy.");
  }
});
