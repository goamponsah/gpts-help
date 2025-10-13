// server.js  (ESM)
// package.json must include:  "type": "module"
// Node 18+

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

// ---------------- paths ----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- app & env ----------------
const app = express();

const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,

  // Paystack
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,   // optional explicit plan codes
  PLAN_CODE_PRO_ANNUAL,     // optional

  FRONTEND_ORIGIN,          // optional (if frontend hosted elsewhere)

  // Resend
  RESEND_API_KEY,
  RESEND_FROM               // e.g. 'GPTs Help <no-reply@updates.gptshelp.online>'
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set; a random one will be used (sessions reset on restart).");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY not set (chat will fail).");
if (!RESEND_API_KEY || !RESEND_FROM) {
  console.warn("[WARN] RESEND_* env not fully set; emails will be skipped.");
}
const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

// ---------------- middlewares ----------------
if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ storage: multer.memoryStorage() });

// ---------------- db ----------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create / migrate schema (idempotent)
async function ensureSchema() {
  await pool.query(`
    create table if not exists users (
      id              bigserial primary key,
      email           text not null unique,
      pass_salt       text,
      pass_hash       text,
      plan            text not null default 'FREE',
      verified        boolean not null default false,
      verify_token    text,
      verify_expires  timestamptz,
      reset_token     text,
      reset_expires   timestamptz,
      created_at      timestamptz not null default now(),
      updated_at      timestamptz not null default now()
    );

    create table if not exists conversations (
      id            bigserial primary key,
      user_id       bigint not null references users(id) on delete cascade,
      title         text not null,
      archived      boolean not null default false,
      created_at    timestamptz not null default now(),
      updated_at    timestamptz not null default now()
    );

    create table if not exists messages (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role            text not null,
      content         text not null,
      created_at      timestamptz not null default now()
    );

    create table if not exists share_links (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token           text not null unique,
      created_at      timestamptz not null default now(),
      revoked         boolean not null default false
    );

    create table if not exists paystack_receipts (
      id          bigserial primary key,
      email       text not null,
      reference   text not null unique,
      plan_code   text,
      status      text,
      raw         jsonb,
      created_at  timestamptz not null default now()
    );

    -- Free-tier usage per device (per natural day)
    create table if not exists device_quotas (
      device_id     text not null,
      period_start  date not null,
      text_count    integer not null default 0,
      photo_count   integer not null default 0,
      primary key (device_id, period_start)
    );

    create index if not exists conversations_user_idx on conversations(user_id, created_at desc);
    create index if not exists messages_conv_idx on messages(conversation_id, id);
  `);

  // Backfill columns on users if older installs (safe ALTERs)
  const cols = await pool.query(`
    select column_name from information_schema.columns
    where table_name='users'
  `);
  const have = new Set(cols.rows.map(r => r.column_name));
  async function add(colSql) { try { await pool.query(colSql); } catch {} }
  if (!have.has("verified"))       await add(`alter table users add column verified boolean not null default false`);
  if (!have.has("verify_token"))   await add(`alter table users add column verify_token text`);
  if (!have.has("verify_expires")) await add(`alter table users add column verify_expires timestamptz`);
  if (!have.has("reset_token"))    await add(`alter table users add column reset_token text`);
  if (!have.has("reset_expires"))  await add(`alter table users add column reset_expires timestamptz`);
}
await ensureSchema();

// ---------------- auth helpers ----------------
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
function cookieOptions() {
  const cross = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true,
    sameSite: cross ? "None" : "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000
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
function needEmail(req, res) {
  const s = readSession(req);
  if (!s?.email) { res.status(401).json({ status: "unauthenticated" }); return null; }
  return s.email;
}

// Ensure device cookie for per-device quotas
function ensureDevice(req, res) {
  let { did } = req.cookies || {};
  if (!did) {
    did = crypto.randomUUID();
    res.cookie("did", did, { ...cookieOptions(), httpOnly: false }); // readable by frontend if needed
  }
  return did;
}
app.use((req, res, next) => { ensureDevice(req, res); next(); });

// password hashing (scrypt)
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

// db helpers
async function upsertUser(email, plan = "FREE") {
  const r = await pool.query(
    `insert into users(email, plan) values($1,$2)
       on conflict(email) do update set email=excluded.email
     returning id, email, plan, verified`,
    [email, plan]
  );
  return r.rows[0];
}
async function getUserByEmail(email) {
  const r = await pool.query(`select * from users where email=$1`, [email]);
  return r.rows[0] || null;
}
async function setUserPassword(email, pass) {
  const { salt, hash } = await hashPassword(pass);
  await pool.query(
    `update users set pass_salt=$2, pass_hash=$3, updated_at=now() where email=$1`,
    [email, salt, hash]
  );
}

// ---------------- Resend (HTTP API) ----------------
async function resendSend({ to, subject, html, text }) {
  if (!RESEND_API_KEY || !RESEND_FROM) {
    console.warn("[MAIL] Skipped (RESEND env incomplete)");
    return { ok: false, skipped: true };
  }
  const url = `https://api.resend.com/emails`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: [to],
      subject,
      html,
      text
    })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    console.error("[MAIL] send failed:", r.status, data);
    return { ok: false, status: r.status, data };
  }
  return { ok: true, data };
}

function verificationEmailHtml(link) {
  return `
  <div style="font-family:system-ui,Segoe UI,Arial,sans-serif;line-height:1.5;">
    <h2>Verify your email</h2>
    <p>Thanks for signing up for <strong>GPTs Help</strong>. Please confirm your email by clicking the button below.</p>
    <p><a href="${link}" style="display:inline-block;background:#5865f2;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;">Verify email</a></p>
    <p style="color:#777">If the button doesn’t work, copy and paste this link:<br>${link}</p>
  </div>`;
}
function resetEmailHtml(link) {
  return `
  <div style="font-family:system-ui,Segoe UI,Arial,sans-serif;line-height:1.5;">
    <h2>Reset your password</h2>
    <p>We received a request to reset your password for <strong>GPTs Help</strong>.</p>
    <p><a href="${link}" style="display:inline-block;background:#0d6efd;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;">Reset password</a></p>
    <p style="color:#777">This link expires in 60 minutes. If you didn’t request a reset, you can ignore this email.</p>
  </div>`;
}

// ---------------- small utils for Paystack ----------------
function extractPlanCode(ps) {
  return (
    ps?.data?.plan?.plan_code ||
    ps?.data?.plan_object?.plan_code ||
    ps?.data?.plan ||
    ps?.data?.subscription?.plan?.plan_code ||
    null
  );
}
function mapPlanCodeToLabel(code) {
  if (!code) return "ONE_TIME";
  const c = String(code).toLowerCase();

  if (PLAN_CODE_PLUS_MONTHLY && code === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (PLAN_CODE_PRO_ANNUAL  && code === PLAN_CODE_PRO_ANNUAL)  return "PRO";

  if (c.includes("plus")) return "PLUS";
  if (c.includes("pro"))  return "PRO";
  return "ONE_TIME";
}

// ---------------- health & public config ----------------
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null
  });
});

// ---------------- auth ----------------
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    const u = await upsertUser(email, "FREE");
    if (password && password.length >= 8) await setUserPassword(email, password);

    // create verify token (24h)
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 24*60*60*1000);
    await pool.query(
      `update users set verify_token=$2, verify_expires=$3, verified=false, updated_at=now()
        where email=$1`,
      [email, until.toISOString() ? email : email, until.toISOString()] // placeholder to keep array length; will be replaced below
    );
    // Fix parameter order (avoid mistakes if edited): 
    await pool.query(
      `update users set verify_token=$2, verify_expires=$3, verified=false, updated_at=now()
        where email=$1`,
      [email, token, until.toISOString()]
    );

    const base = req.headers.origin || (FRONTEND_ORIGIN || "");
    const host = base || `${req.protocol}://${req.get("host")}`;
    const link = `${host}/api/verify-email?token=${encodeURIComponent(token)}`;

    // send email (best-effort)
    await resendSend({
      to: email,
      subject: "Verify your email — GPTs Help",
      html: verificationEmailHtml(link),
      text: `Verify your email: ${link}`
    });

    setSessionCookie(res, { email: u.email, plan: u.plan });
    res.json({ status: "success", user: { email: u.email }, verifySent: true });
  } catch (e) {
    console.error("signup-free", e);
    res.status(500).json({ status: "error", message: "Could not create user" });
  }
});

app.get("/api/verify-email", async (req, res) => {
  try {
    const { token } = req.query || {};
    if (!token) return res.status(400).send("Missing token");
    const r = await pool.query(
      `update users
          set verified=true, verify_token=null, verify_expires=null, updated_at=now()
        where verify_token=$1 and (verify_expires is null or now() <= verify_expires)
        returning email`,
      [token]
    );
    if (!r.rowCount) return res.status(400).send("Invalid or expired token");
    // Land them in chat after verify
    res.redirect("/chat.html");
  } catch (e) {
    console.error("verify-email", e);
    res.status(500).send("Verification failed");
  }
});

// Password reset (request)
app.post("/api/request-password-reset", async (req, res) => {
  try {
    const email = (req.body?.email || "").trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    const u = await getUserByEmail(email);
    // Respond success even if not found (don’t leak users)
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 60*60*1000); // 60 mins
    if (u) {
      await pool.query(
        `update users set reset_token=$2, reset_expires=$3, updated_at=now() where email=$1`,
        [email, token, until.toISOString()]
      );
      const base = req.headers.origin || (FRONTEND_ORIGIN || "");
      const host = base || `${req.protocol}://${req.get("host")}`;
      const link = `${host}/reset.html?token=${encodeURIComponent(token)}`;
      await resendSend({
        to: email,
        subject: "Reset your password — GPTs Help",
        html: resetEmailHtml(link),
        text: `Reset your password (expires in 60 minutes): ${link}`
      });
    }
    res.json({ status: "ok" });
  } catch (e) {
    console.error("request-password-reset", e);
    res.status(500).json({ status: "error", message: "Could not send reset link" });
  }
});

// Password reset (apply)
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password || password.length < 8) {
      return res.status(400).json({ status: "error", message: "Invalid request" });
    }
    const r = await pool.query(
      `select email from users where reset_token=$1 and now() <= coalesce(reset_expires, now())`,
      [token]
    );
    if (!r.rowCount) return res.status(400).json({ status: "error", message: "Invalid or expired token" });
    const email = r.rows[0].email;

    await setUserPassword(email, password);
    await pool.query(
      `update users set reset_token=null, reset_expires=null, updated_at=now() where email=$1`,
      [email]
    );
    res.json({ status: "ok" });
  } catch (e) {
    console.error("reset-password", e);
    res.status(500).json({ status: "error", message: "Could not reset password" });
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

    if (!u.pass_hash) {
      if (password.length < 8) return res.status(400).json({ status: "error", message: "Password must be at least 8 characters." });
      await setUserPassword(email, password); // first-time password set
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password." });
    }
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status: "ok", user: { email: u.email } });
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
  res.json({ status: "ok", user: { email: u.email, plan: (u.plan || "FREE"), verified: !!u.verified } });
});

app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// ---------------- paystack verify ----------------
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const data = await psRes.json();

    const email = data?.data?.customer?.email || null;
    const planCode = extractPlanCode(data);
    const status = data?.data?.status || null;

    await pool.query(
      `insert into paystack_receipts(email, reference, plan_code, status, raw)
       values($1,$2,$3,$4,$5)
       on conflict(reference) do nothing`,
      [email, reference, planCode, status, data]
    );

    if (data?.status && status === "success" && email) {
      const label = mapPlanCodeToLabel(planCode);
      await upsertUser(email);
      if (label !== "ONE_TIME") {
        await pool.query(`update users set plan=$2, updated_at=now() where email=$1`, [email, label]);
      }
      setSessionCookie(res, { email, plan: label === "ONE_TIME" ? "FREE" : label });
      return res.json({ status: "success", email, plan: label, reference });
    }
    res.json({ status: "pending", data });
  } catch (e) {
    console.error("paystack verify", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// ---------------- auth-required helper ----------------
async function requireUser(req, res) {
  const email = needEmail(req, res);
  if (!email) return null;
  const u = await getUserByEmail(email);
  if (!u) { res.status(401).json({ status: "unauthenticated" }); return null; }
  return u;
}

// ---------------- quotas ----------------
const FREE_TEXT_LIMIT = 10;
const FREE_PHOTO_LIMIT = 2;

async function getQuota(deviceId) {
  const period = new Date().toISOString().slice(0,10); // yyyy-mm-dd
  const r = await pool.query(
    `insert into device_quotas(device_id, period_start)
       values($1,$2)
       on conflict (device_id, period_start) do update set device_id=excluded.device_id
     returning text_count, photo_count`,
    [deviceId, period]
  );
  return { period, ...r.rows[0] };
}
async function bumpQuota(deviceId, kind) {
  const period = new Date().toISOString().slice(0,10);
  if (kind === "text") {
    await pool.query(
      `update device_quotas set text_count=text_count+1 where device_id=$1 and period_start=$2`,
      [deviceId, period]
    );
  } else {
    await pool.query(
      `update device_quotas set photo_count=photo_count+1 where device_id=$1 and period_start=$2`,
      [deviceId, period]
    );
  }
}

// ---------------- auto-title helper ----------------
async function retitleConversation(convId, userMsg, assistantMsg) {
  try {
    if (!OPENAI_API_KEY) return;

    const { rows } = await pool.query(
      `select title from conversations where id=$1`,
      [convId]
    );
    if (!rows.length) return;
    const current = (rows[0].title || "").trim();

    const looksFinal =
      current !== "New chat" &&
      current.length <= 60 &&
      /^[A-Z].+/.test(current);

    if (looksFinal) return;

    const prompt = [
      {
        role: "system",
        content:
          "Create a short, clear chat title (max 6 words). No quotes. Title case. Avoid punctuation unless needed."
      },
      {
        role: "user",
        content:
          `User message:\n${userMsg}\n\nAssistant reply:\n${assistantMsg}\n\nReturn only the title.`
      }
    ];

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        messages: prompt,
        temperature: 0.2
      })
    });

    if (!r.ok) return;
    const j = await r.json();
    const title = (j?.choices?.[0]?.message?.content || "")
      .replace(/["“”]/g, "")
      .trim()
      .slice(0, 60);

    if (!title) return;

    await pool.query(
      `update conversations set title=$2, updated_at=now() where id=$1`,
      [convId, title]
    );
  } catch {
    // best-effort
  }
}

// ---------------- conversations ----------------
app.get("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const r = await pool.query(
    `select id, title, archived
       from conversations
      where user_id=$1
      order by created_at desc`,
    [u.id]
  );
  res.json(r.rows);
});

app.post("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const title = (req.body?.title || "New chat").trim();
  const r = await pool.query(
    `insert into conversations(user_id, title) values($1,$2) returning id, title`,
    [u.id, title]
  );
  res.json(r.rows[0]);
});

app.patch("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "invalid id" });

  const { title, archived } = req.body || {};
  const fields = [];
  const values = [id, u.id];
  let idx = 2;

  if (typeof title === "string") { fields.push(`title=$${++idx}`); values.push(title.trim() || "Untitled"); }
  if (typeof archived === "boolean") { fields.push(`archived=$${++idx}`); values.push(!!archived); }
  if (!fields.length) return res.json({ ok: true });

  await pool.query(
    `update conversations
        set ${fields.join(", ")}, updated_at=now()
      where id=$1 and user_id=$2`,
    values
  );
  res.json({ ok: true });
});

app.delete("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "invalid id" });
  await pool.query(`delete from conversations where id=$1 and user_id=$2`, [id, u.id]);
  res.json({ ok: true });
});

app.get("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "invalid id" });
  const conv = await pool.query(`select id, title from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!conv.rowCount) return res.status(404).json({ error: "not found" });
  const msgs = await pool.query(
    `select role, content, created_at
       from messages
      where conversation_id=$1
      order by id`,
    [id]
  );
  res.json({ id, title: conv.rows[0].title, messages: msgs.rows });
});

// ---------------- share links ----------------
app.post("/api/conversations/:id/share", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "invalid id" });
  const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!own.rowCount) return res.status(404).json({ error: "not found" });

  const existing = await pool.query(
    `select token from share_links
      where conversation_id=$1 and revoked=false
      order by id desc limit 1`,
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
       join conversations c on c.id=sl.conversation_id
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

// ---------------- chat (text) ----------------
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    // Require verified email
    if (!u.verified) {
      return res.status(403).json({ status: "verify_required", message: "Please verify your email to use chat." });
    }

    const deviceId = ensureDevice(req, res);
    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // free-tier quota (device-based)
    if ((u.plan || "FREE") === "FREE") {
      const q = await getQuota(deviceId);
      if (q.text_count >= FREE_TEXT_LIMIT) {
        return res.status(402).json({
          status: "limit",
          kind: "text",
          message: "You’ve reached the free text limit.",
          upgradeUrl: "/index.html#pricing"
        });
      }
    }

    let convId = Number(conversationId);
    if (!Number.isFinite(convId)) convId = null;

    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `insert into conversations(user_id, title) values($1,$2) returning id`,
        [u.id, (message.slice(0, 40) || "New chat")]
      );
      convId = r.rows[0].id;
    }

    const hist = await pool.query(
      `select role, content from messages where conversation_id=$1 order by id`,
      [convId]
    );

    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [{ role: "system", content: system }, ...hist.rows, { role: "user", content: message }];

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "user", message]
    );

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        messages: msgs,
        temperature: 0.2
      })
    });
    if (!r.ok) throw new Error(`OpenAI ${r.status}: ${await r.text()}`);
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "";

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    // bump quota on success for FREE
    if ((u.plan || "FREE") === "FREE") await bumpQuota(deviceId, "text");

    // auto-title (best-effort)
    retitleConversation(convId, message, answer).catch(()=>{});

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// ---------------- photo solve ----------------
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    // Require verified email
    if (!u.verified) {
      return res.status(403).json({ status: "verify_required", message: "Please verify your email to use photo solve." });
    }

    const deviceId = ensureDevice(req, res);
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    // free-tier quota (device-based)
    if ((u.plan || "FREE") === "FREE") {
      const q = await getQuota(deviceId);
      if (q.photo_count >= FREE_PHOTO_LIMIT) {
        return res.status(402).json({
          status: "limit",
          kind: "photo",
          message: "You’ve reached the free photo-solve limit.",
          upgradeUrl: "/index.html#pricing"
        });
      }
    }

    let convId = Number(conversationId);
    if (!Number.isFinite(convId)) convId = null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `insert into conversations(user_id, title) values($1,$2) returning id`,
        [u.id, "Photo solve"]
      );
      convId = r.rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly."
        : "You are a helpful assistant. Describe and analyze the content of the image, then answer the user's request.";

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "user", attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]
    );

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        messages: [
          { role: "system", content: system },
          {
            role: "user",
            content: [
              { type: "text", text: attempt ? `Note from user: ${attempt}\nSolve:` : "Solve this problem step-by-step:" },
              { type: "image_url", image_url: { url: dataUrl } }
            ]
          }
        ],
        temperature: 0.2
      })
    });
    if (!r.ok) throw new Error(`OpenAI vision ${r.status}: ${await r.text()}`);
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    // bump quota on success for FREE
    if ((u.plan || "FREE") === "FREE") await bumpQuota(deviceId, "photo");

    // auto-title (best-effort)
    retitleConversation(convId, attempt || "Photo solve", answer).catch(()=>{});

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------------- start ----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
});