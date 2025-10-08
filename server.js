// server.js (ESM)
// package.json: { "type": "module" }
// npm i express cookie-parser cors jsonwebtoken multer pg

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

/* ----------------------- paths / app ----------------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

/* ----------------------- env ----------------------- */
const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  FRONTEND_ORIGIN,
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL missing");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET missing (sessions reset on deploy)");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY missing (chat/photo will fail)");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";
const FREE_MONTHLY_LIMIT = 10; // Free plan allowance (prompts+photo solves combined)

/* ----------------------- middleware ----------------------- */
if (FRONTEND_ORIGIN) app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
const upload = multer({ storage: multer.memoryStorage() });

/* ----------------------- db & schema ----------------------- */
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function ensureSchema() {
  // Create tables if not present.
  await pool.query(`
    create table if not exists users (
      id           bigserial primary key,
      email        text not null unique,
      pass_salt    text,
      pass_hash    text,
      plan         text not null default 'FREE',
      created_at   timestamptz not null default now(),
      updated_at   timestamptz not null default now()
    );

    create table if not exists conversations (
      id           bigserial primary key,
      -- user_id may be null in legacy rows; app enforces ownership, but new rows will set it
      user_id      bigint references users(id) on delete cascade,
      -- legacy column some installs had:
      user_email   text,
      title        text not null default 'New chat',
      archived     boolean not null default false,
      created_at   timestamptz not null default now(),
      updated_at   timestamptz not null default now()
    );
    create index if not exists conversations_user_idx on conversations(user_id, created_at desc);

    create table if not exists messages (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role            text not null,  -- 'user' | 'assistant'
      content         text not null,
      created_at      timestamptz not null default now()
    );
    create index if not exists messages_conv_idx on messages(conversation_id, id);

    create table if not exists share_links (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token           text not null unique,
      revoked         boolean not null default false,
      created_at      timestamptz not null default now()
    );

    create table if not exists paystack_receipts (
      id          bigserial primary key,
      email       text,
      reference   text not null unique,
      plan_code   text,
      status      text,
      raw         jsonb,
      created_at  timestamptz not null default now()
    );
  `);

  // Best-effort backfill: if conversations has user_email but user_id is null, set it from users.email
  await pool.query(`
    update conversations c
       set user_id = u.id
      from users u
     where c.user_id is null
       and c.user_email is not null
       and lower(u.email) = lower(c.user_email);
  `);
}
await ensureSchema();

/* ----------------------- jwt sessions ----------------------- */
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
  try { return jwt.verify(sid, SJWT); } catch { return null; }
}

/* ----------------------- password helpers ----------------------- */
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

/* ----------------------- small db helpers ----------------------- */
async function getUserByEmail(email) {
  const r = await pool.query(`select * from users where lower(email)=lower($1)`, [email]);
  return r.rows[0] || null;
}
async function upsertUser(email, plan = "FREE") {
  const r = await pool.query(
    `insert into users(email, plan) values($1,$2)
       on conflict(email) do update set email=excluded.email
     returning *`,
    [email, plan]
  );
  return r.rows[0];
}
async function setUserPassword(email, pw) {
  const { salt, hash } = await hashPassword(pw);
  await pool.query(
    `update users set pass_salt=$2, pass_hash=$3, updated_at=now() where lower(email)=lower($1)`,
    [email, salt, hash]
  );
}
function mapPlan(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

/* ----------------------- openai ----------------------- */
async function openaiChat(messages) {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: OPENAI_DEFAULT_MODEL,
      messages,
      temperature: 0.2,
    }),
  });
  if (!r.ok) throw new Error(`OpenAI ${r.status}: ${await r.text()}`);
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

/* ----------------------- health & public config ----------------------- */
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

/* ----------------------- auth ----------------------- */
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    const u = await upsertUser(email, "FREE");
    if (password && password.length >= 8) await setUserPassword(email, password);
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status: "success", user: { email: u.email, plan: u.plan || "FREE" } });
  } catch (e) {
    console.error("signup-free", e);
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
    if (!u) return res.status(401).json({ status: "error", message: "No account found. Sign up first." });

    if (!u.pass_hash) {
      if (password.length < 8) return res.status(400).json({ status: "error", message: "Password must be at least 8 characters." });
      await setUserPassword(email, password);
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password." });
    }
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status: "ok", user: { email: u.email, plan: u.plan || "FREE" } });
  } catch (e) {
    console.error("login", e);
    res.status(500).json({ status: "error", message: "Login failed" });
  }
});

app.get("/api/me", async (req, res) => {
  const s = readSession(req);
  if (!s?.email) return res.status(401).json({ status: "unauthenticated" });
  const u = await getUserByEmail(s.email);
  if (!u) return res.status(401).json({ status: "unauthenticated" });
  res.json({ status: "ok", user: { email: u.email, plan: u.plan || "FREE" } });
});

app.post("/api/logout", (_req, res) => { clearSessionCookie(res); res.json({ status: "ok" }); });

/* ----------------------- paystack ----------------------- */
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await psRes.json();

    // Store raw receipt (best-effort)
    await pool.query(
      `insert into paystack_receipts(email, reference, plan_code, status, raw)
       values($1,$2,$3,$4,$5)
       on conflict(reference) do nothing`,
      [data?.data?.customer?.email || null, reference, data?.data?.plan?.plan_code || null, data?.data?.status || null, data]
    );

    if (data?.status && data?.data?.status === "success") {
      const email = data?.data?.customer?.email || null;
      const planCode = data?.data?.plan?.plan_code || null;
      const label = mapPlan(planCode); // 'PLUS' | 'PRO' | 'ONE_TIME'

      if (email) {
        const u = await upsertUser(email);
        const newPlan = label === "ONE_TIME" ? (u.plan || "FREE") : label;
        await pool.query(`update users set plan=$2, updated_at=now() where lower(email)=lower($1)`, [email, newPlan]);
        setSessionCookie(res, { email, plan: newPlan }); // refresh cookie so UI reflects upgrade immediately
      }
      return res.json({ status: "success", email, plan: label, reference });
    }

    res.json({ status: "pending", data });
  } catch (e) {
    console.error("paystack verify", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

/* ----------------------- auth guard ----------------------- */
async function requireUser(req, res) {
  const s = readSession(req);
  if (!s?.email) { res.status(401).json({ status: "unauthenticated" }); return null; }
  const u = await getUserByEmail(s.email);
  if (!u) { res.status(401).json({ status: "unauthenticated" }); return null; }
  return u;
}

/* ----------------------- usage limit (Free) ----------------------- */
async function getMonthlyUsageCount(userId) {
  // Count *user* messages this calendar month across all conversations for this user.
  const r = await pool.query(`
    select count(m.id) as n
      from messages m
      join conversations c on c.id = m.conversation_id
     where c.user_id = $1
       and m.role = 'user'
       and m.created_at >= date_trunc('month', now())
  `, [userId]);
  return Number(r.rows?.[0]?.n || 0);
}

/* ----------------------- conversations ----------------------- */
app.get("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const r = await pool.query(
    `select id, title, archived from conversations
      where user_id = $1
      order by created_at desc`,
    [u.id]
  );
  res.json(r.rows);
});

app.post("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const title = (req.body?.title || "New chat").trim();
  const r = await pool.query(
    `insert into conversations(user_id, user_email, title)
     values($1, $2, $3)
     returning id, title`,
    [u.id, u.email, title]
  );
  res.json(r.rows[0]);
});

app.patch("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const { title, archived } = req.body || {};
  const fields = [];
  const values = [id, u.id];

  if (typeof title === "string") { fields.push(`title = $${fields.length + 3}`); values.push(title.trim() || "Untitled"); }
  if (typeof archived === "boolean") { fields.push(`archived = $${fields.length + 3}`); values.push(!!archived); }
  if (!fields.length) return res.json({ ok: true });

  await pool.query(
    `update conversations set ${fields.join(", ")}, updated_at=now()
       where id = $1 and user_id = $2`,
    values
  );
  res.json({ ok: true });
});

app.delete("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  await pool.query(`delete from conversations where id=$1 and user_id=$2`, [id, u.id]);
  res.json({ ok: true });
});

app.get("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const conv = await pool.query(
    `select id, title from conversations where id=$1 and user_id=$2`,
    [id, u.id]
  );
  if (!conv.rowCount) return res.status(404).json({ error: "not found" });
  const msgs = await pool.query(
    `select role, content, created_at from messages
      where conversation_id=$1 order by id`,
    [id]
  );
  res.json({ id, title: conv.rows[0].title, messages: msgs.rows });
});

/* ----------------------- share links ----------------------- */
app.post("/api/conversations/:id/share", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!own.rowCount) return res.status(404).json({ error: "not found" });

  const existing = await pool.query(
    `select token from share_links where conversation_id=$1 and revoked=false order by id desc limit 1`,
    [id]
  );
  if (existing.rowCount) return res.json({ token: existing.rows[0].token });

  const token = crypto.randomBytes(20).toString("hex");
  await pool.query(`insert into share_links(conversation_id, token) values($1,$2)`, [id, token]);
  res.json({ token });
});

app.get("/api/share/:token", async (req, res) => {
  const { token } = req.params;
  const s = await pool.query(
    `select c.id, c.title
       from share_links sl
       join conversations c on c.id = sl.conversation_id
      where sl.token=$1 and sl.revoked=false`,
    [token]
  );
  if (!s.rowCount) return res.status(404).json({ error: "invalid_or_revoked" });

  const convId = s.rows[0].id;
  const msgs = await pool.query(
    `select role, content, created_at
       from messages
      where conversation_id=$1
      order by id`,
    [convId]
  );
  res.json({ title: s.rows[0].title, messages: msgs.rows });
});

/* ----------------------- chat ----------------------- */
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    // Free plan usage cap
    if ((u.plan || "FREE") === "FREE") {
      const used = await getMonthlyUsageCount(u.id);
      if (used >= FREE_MONTHLY_LIMIT) {
        return res.status(429).json({
          error: "limit_reached",
          message: `Free plan limit reached (${FREE_MONTHLY_LIMIT}/month). Upgrade to continue.`,
        });
      }
    }

    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // find or create conversation
    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `insert into conversations(user_id, user_email, title) values($1,$2,$3) returning id`,
        [u.id, u.email, (message.slice(0, 40) || "New chat")]
      );
      convId = r.rows[0].id;
    }

    // history
    const hist = await pool.query(`select role, content from messages where conversation_id=$1 order by id`, [convId]);
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [{ role: "system", content: system }, ...hist.rows, { role: "user", content: message }];

    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`, [convId, "user", message]);

    const answer = await openaiChat(msgs);

    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`, [convId, "assistant", answer]);

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat", e);
    res.status(500).json({ error: "chat_failed", message: String(e?.message || e) });
  }
});

/* ----------------------- photo solve ----------------------- */
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    // Free plan usage cap
    if ((u.plan || "FREE") === "FREE") {
      const used = await getMonthlyUsageCount(u.id);
      if (used >= FREE_MONTHLY_LIMIT) {
        return res.status(429).json({
          error: "limit_reached",
          message: `Free plan limit reached (${FREE_MONTHLY_LIMIT}/month). Upgrade to continue.`,
        });
      }
    }

    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    // find or create conversation
    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `insert into conversations(user_id, user_email, title) values($1,$2,$3) returning id`,
        [u.id, u.email, "Photo solve"]
      );
      convId = r.rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly and neatly. Use LaTeX for math."
        : "You are a helpful assistant. Describe and analyze the content of the image, then answer the user's request.";

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "user", attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]
    );

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
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

    if (!r.ok) throw new Error(`OpenAI vision ${r.status}: ${await r.text()}`);
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "assistant", answer]
    );
    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve", e);
    res.status(500).json({ error: "photo_failed", message: String(e?.message || e) });
  }
});

/* ----------------------- start ----------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
});