// server.js  (ESM)
// package.json must include:  "type": "module"
// Node 18+
//
// npm i express cookie-parser cors jsonwebtoken multer pg nodemailer

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
import nodemailer from "nodemailer";

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
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,   // optional, explicit plan codes
  PLAN_CODE_PRO_ANNUAL,     // optional
  FRONTEND_ORIGIN,          // optional, if hosting frontend elsewhere

  // FREE plan limits (defaults used if not set)
  FREE_MAX_TEXT = "10",
  FREE_MAX_PHOTO = "2",

  // Email verification / SMTP
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  APP_BASE_URL = "http://localhost:3000",
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set; a random one will be used (sessions reset on restart).");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY not set.");
if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
  console.warn("[WARN] SMTP_* env not fully set; email verification won't send.");
}
const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

// FREE limits as numbers
const LIMIT_TEXT = Number(FREE_MAX_TEXT) || 10;
const LIMIT_PHOTO = Number(FREE_MAX_PHOTO) || 2;

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

// Create base tables if missing (plus usage + email verification)
async function createBaseSchema() {
  await pool.query(`
    create table if not exists users (
      id               bigserial primary key,
      email            text not null unique,
      pass_salt        text,
      pass_hash        text,
      plan             text not null default 'FREE',
      email_verified   boolean not null default false,
      created_at       timestamptz not null default now(),
      updated_at       timestamptz not null default now()
    );

    create table if not exists conversations (
      id            bigserial primary key,
      user_id       bigint,
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

    -- Monthly usage, by user and YYYY-MM period
    create table if not exists user_usage (
      user_id     bigint not null,
      period      text   not null,    -- e.g. '2025-10'
      text_used   int not null default 0,
      photo_used  int not null default 0,
      updated_at  timestamptz not null default now(),
      primary key (user_id, period)
    );

    -- Email verification tokens
    create table if not exists verify_tokens (
      id          bigserial primary key,
      email       text not null,
      token       text not null unique,
      expires_at  timestamptz not null,
      used        boolean not null default false,
      created_at  timestamptz not null default now()
    );

    create index if not exists conversations_user_idx on conversations(user_id, created_at desc);
    create index if not exists messages_conv_idx on messages(conversation_id, id);
    create index if not exists verify_tokens_email_idx on verify_tokens(email);
  `);
}

// Migrate legacy schema (if conversations has user_email column)
async function migrateLegacyConversations() {
  const colCheck = await pool.query(`
    select column_name
      from information_schema.columns
     where table_name='conversations'
       and column_name in ('user_email','user_id')
  `);
  const hasUserEmail = colCheck.rows.some(r => r.column_name === "user_email");
  const hasUserId    = colCheck.rows.some(r => r.column_name === "user_id");

  if (!hasUserEmail) {
    return;
  }

  console.log("[MIGRATE] Found legacy conversations.user_email. Migrating to user_id …");

  await pool.query("begin");
  try {
    if (!hasUserId) {
      await pool.query(`alter table conversations add column user_id bigint`);
    }

    await pool.query(`
      insert into users (email, plan)
      select distinct coalesce(user_email,'') as email, 'FREE'
        from conversations
       where user_email is not null and user_email <> ''
      on conflict (email) do nothing
    `);

    await pool.query(`
      update conversations c
         set user_id = u.id
        from users u
       where c.user_id is null
         and c.user_email = u.email
    `);

    const placeholderEmail = `legacy+${crypto.randomBytes(6).toString("hex")}@gptshelp.local`;
    const u = await pool.query(
      `insert into users(email, plan) values ($1, 'FREE')
       on conflict(email) do update set email=excluded.email
       returning id`,
      [placeholderEmail]
    );
    await pool.query(
      `update conversations set user_id=$1 where user_id is null`,
      [u.rows[0].id]
    );

    await pool.query(`alter table conversations drop column user_email`);

    await pool.query("commit");
    console.log("[MIGRATE] conversations.user_email -> user_id migration complete.");
  } catch (e) {
    await pool.query("rollback");
    console.error("[MIGRATE] Failed; leaving legacy columns as-is:", e);
  }
}

async function ensureSchema() {
  await createBaseSchema();
  await migrateLegacyConversations();
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
     returning id, email, plan, email_verified`,
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

// ---------------- monthly usage helpers ----------------
function currentPeriod() {
  const d = new Date();
  const m = `${d.getMonth() + 1}`.padStart(2, "0");
  return `${d.getFullYear()}-${m}`;
}
async function getOrCreateUsage(userId) {
  const period = currentPeriod();
  const sel = await pool.query(
    `select user_id, period, text_used, photo_used from user_usage where user_id=$1 and period=$2`,
    [userId, period]
  );
  if (sel.rowCount) return sel.rows[0];
  const ins = await pool.query(
    `insert into user_usage(user_id, period) values($1,$2)
       on conflict (user_id, period) do nothing
     returning user_id, period, text_used, photo_used`,
    [userId, period]
  );
  if (ins.rowCount) return ins.rows[0];
  // race-safe: reselect
  const again = await pool.query(
    `select user_id, period, text_used, photo_used from user_usage where user_id=$1 and period=$2`,
    [userId, period]
  );
  return again.rows[0];
}
async function canConsume(u, kind /* 'text' | 'photo' */) {
  if ((u.plan || "FREE").toUpperCase() !== "FREE") return { ok: true };
  const usage = await getOrCreateUsage(u.id);
  if (kind === "text") {
    const remaining = Math.max(0, LIMIT_TEXT - (usage?.text_used || 0));
    return { ok: remaining > 0, remaining };
  }
  const remaining = Math.max(0, LIMIT_PHOTO - (usage?.photo_used || 0));
  return { ok: remaining > 0, remaining };
}
async function consume(u, kind) {
  const period = currentPeriod();
  if ((u.plan || "FREE").toUpperCase() !== "FREE") return;
  if (kind === "text") {
    await pool.query(
      `insert into user_usage(user_id, period, text_used)
       values($1,$2,1)
       on conflict (user_id, period)
       do update set text_used = user_usage.text_used + 1, updated_at=now()`,
      [u.id, period]
    );
  } else {
    await pool.query(
      `insert into user_usage(user_id, period, photo_used)
       values($1,$2,1)
       on conflict (user_id, period)
       do update set photo_used = user_usage.photo_used + 1, updated_at=now()`,
      [u.id, period]
    );
  }
}

// ---------------- OpenAI ----------------
async function openaiChat(messages) {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: OPENAI_DEFAULT_MODEL,
      messages,
      temperature: 0.2
    })
  });
  if (!r.ok) throw new Error(`OpenAI ${r.status}: ${await r.text()}`);
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
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

// ---------------- nodemailer (SMTP) ----------------
const mailer = (SMTP_HOST && SMTP_USER) ? nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 465),
  secure: String(SMTP_SECURE || "true").toLowerCase() === "true",
  auth: { user: SMTP_USER, pass: SMTP_PASS }
}) : null;

async function sendVerificationEmail(toEmail, token) {
  if (!mailer) return;
  const url = `${APP_BASE_URL.replace(/\/+$/,'')}/api/verify-email?token=${encodeURIComponent(token)}`;
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;line-height:1.6;color:#1b1f2a">
      <h2>Verify your email</h2>
      <p>Thanks for creating an account with GPTs Help. Please confirm your email by clicking the button below:</p>
      <p><a href="${url}" style="display:inline-block;background:#6f42c1;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Verify Email</a></p>
      <p>If the button doesn't work, copy and paste this link into your browser:</p>
      <p style="word-break:break-all"><a href="${url}">${url}</a></p>
      <p>This link expires in 24 hours.</p>
    </div>
  `;
  await mailer.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject: "Verify your email — GPTs Help",
    html
  });
}

// ---------------- health & public config ----------------
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
    freeLimits: { text: LIMIT_TEXT, photo: LIMIT_PHOTO }
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

    // create verify token
    const token = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 24*60*60*1000); // 24h
    await pool.query(
      `insert into verify_tokens(email, token, expires_at) values($1,$2,$3)`,
      [email, token, expiresAt]
    );
    // best-effort send
    try { await sendVerificationEmail(email, token); } catch (e) { console.warn("[MAIL] send failed:", e.message); }

    setSessionCookie(res, { email: u.email, plan: u.plan });
    res.json({ status: "success", user: { email: u.email }, needsVerification: true });
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
    if (!u) return res.status(401).json({ status: "error", message: "No account found. Please sign up." });

    if (!u.pass_hash) {
      if (password.length < 8) return res.status(400).json({ status: "error", message: "Password must be at least 8 characters." });
      await setUserPassword(email, password); // first-time password set
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password." });
    }
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status: "ok", user: { email: u.email }, needsVerification: !u.email_verified });
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
  res.json({
    status: "ok",
    user: { email: u.email, plan: (u.plan || "FREE"), emailVerified: !!u.email_verified }
  });
});

app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// ---------------- email verification endpoints ----------------
app.post("/api/send-verify", async (req, res) => {
  try {
    const email = needEmail(req, res); if (!email) return;
    const u = await getUserByEmail(email);
    if (!u) return res.status(401).json({ status: "unauthenticated" });
    if (u.email_verified) return res.json({ status: "ok", alreadyVerified: true });

    const token = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 24*60*60*1000);
    await pool.query(
      `insert into verify_tokens(email, token, expires_at) values($1,$2,$3)`,
      [email, token, expiresAt]
    );
    try { await sendVerificationEmail(email, token); } catch (e) { console.warn("[MAIL] send failed:", e.message); }
    res.json({ status: "ok" });
  } catch (e) {
    console.error("send-verify", e);
    res.status(500).json({ status: "error" });
  }
});

app.get("/api/verify-email", async (req, res) => {
  try {
    const token = (req.query.token || "").trim();
    if (!token) return res.redirect("/verify.html?status=missing");

    const r = await pool.query(
      `select email, expires_at, used from verify_tokens where token=$1`,
      [token]
    );
    if (!r.rowCount) return res.redirect("/verify.html?status=invalid");
    const row = r.rows[0];
    if (row.used) return res.redirect("/verify.html?status=used");
    if (new Date(row.expires_at).getTime() < Date.now()) return res.redirect("/verify.html?status=expired");

    await pool.query(`update users set email_verified=true, updated_at=now() where email=$1`, [row.email]);
    await pool.query(`update verify_tokens set used=true where token=$1`, [token]);

    return res.redirect("/verify.html?status=ok");
  } catch (e) {
    console.error("verify-email", e);
    return res.redirect("/verify.html?status=error");
  }
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
  const { title, archived } = req.body || {};
  const fields = [];
  const values = [];
  let idx = 1;

  if (typeof title === "string") { fields.push(`title=$${++idx}`); values.push(title.trim() || "Untitled"); }
  if (typeof archived === "boolean") { fields.push(`archived=$${++idx}`); values.push(!!archived); }
  if (!fields.length) return res.json({ ok: true });

  await pool.query(
    `update conversations
        set ${fields.join(", ")}, updated_at=now()
      where id=$1 and user_id=$${++idx}`,
    [id, ...values, u.id]
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

// ---------------- chat ----------------
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;
    // OPTIONAL: block unverified from chatting. If you want to allow, comment next two lines.
    // if (!u.email_verified) return res.status(403).json({ status: "unverified", message: "Please verify your email to continue." });

    const plan = (u.plan || "FREE").toUpperCase();

    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

    // FREE limit check (text)
    if (plan === "FREE") {
      const gate = await canConsume(u, "text");
      if (!gate.ok) {
        return res.json({
          status: "limit",
          kind: "text",
          remaining: 0,
          plan: "FREE",
          upgrade: true,
          freeLimits: { text: LIMIT_TEXT, photo: LIMIT_PHOTO }
        });
      }
    }

    let convId = conversationId ? Number(conversationId) : null;
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

    // consume a text usage unit for FREE users
    if (plan === "FREE") await consume(u, "text");

    const answer = await openaiChat(msgs);

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    res.json({ status: "ok", response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// ---------------- photo solve ----------------
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;
    // OPTIONAL: block unverified here as well. Comment to allow before verification.
    // if (!u.email_verified) return res.status(403).json({ status: "unverified", message: "Please verify your email to continue." });

    const plan = (u.plan || "FREE").toUpperCase();

    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

    // FREE limit check (photo)
    if (plan === "FREE") {
      const gate = await canConsume(u, "photo");
      if (!gate.ok) {
        return res.json({
          status: "limit",
          kind: "photo",
          remaining: 0,
          plan: "FREE",
          upgrade: true,
          freeLimits: { text: LIMIT_TEXT, photo: LIMIT_PHOTO }
        });
      }
    }

    let convId = conversationId ? Number(conversationId) : null;
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

    // consume a photo usage unit for FREE users
    if (plan === "FREE") await consume(u, "photo");

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
    res.json({ status: "ok", response: answer, conversationId: convId });
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