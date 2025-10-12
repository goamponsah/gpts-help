// server.js  (ESM)
// package.json must include: "type": "module"
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

/* ---------------- paths ---------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ---------------- app & env ---------------- */
const app = express();

const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,   // optional
  PLAN_CODE_PRO_ANNUAL,     // optional
  FRONTEND_ORIGIN,          // optional CORS origin
  APP_BASE_URL,             // e.g., https://gptshelp.online

  // SMTP (Mailgun)
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set; a random one will be used (sessions reset on restart).");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY not set.");
if (!(SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS && SMTP_FROM)) {
  console.warn("[WARN] SMTP_* env not fully set; email verification will not send.");
}
const BASE_URL = APP_BASE_URL || "http://localhost:3000";
const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

// Free tier limits (per account)
const MAX_TEXT_FREE  = 10;
const MAX_PHOTO_FREE = 2;

/* ---------------- middlewares ---------------- */
if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ storage: multer.memoryStorage() });

/* ---------------- db ---------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function createBaseSchema() {
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
      created_at      timestamptz not null default now(),
      updated_at      timestamptz not null default now()
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

    create index if not exists conversations_user_idx on conversations(user_id, created_at desc);
    create index if not exists messages_conv_idx on messages(conversation_id, id);
  `);

  // Ensure new columns exist if DB was created earlier
  await pool.query(`alter table users add column if not exists verified boolean not null default false;`);
  await pool.query(`alter table users add column if not exists verify_token text;`);
  await pool.query(`alter table users add column if not exists verify_expires timestamptz;`);
}

async function migrateLegacyConversations() {
  const colCheck = await pool.query(`
    select column_name
      from information_schema.columns
     where table_name='conversations'
       and column_name in ('user_email','user_id')
  `);
  const hasUserEmail = colCheck.rows.some(r => r.column_name === "user_email");
  const hasUserId    = colCheck.rows.some(r => r.column_name === "user_id");
  if (!hasUserEmail) return;

  console.log("[MIGRATE] conversations.user_email -> user_id …");
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
    const placeholderEmail = `legacy_${crypto.randomBytes(6).toString("hex")}@gptshelp.local`;
    const u = await pool.query(
      `insert into users(email, plan) values ($1, 'FREE')
       on conflict(email) do update set email=excluded.email
       returning id`,
      [placeholderEmail]
    );
    await pool.query(`update conversations set user_id=$1 where user_id is null`, [u.rows[0].id]);
    await pool.query(`alter table conversations drop column user_email`);
    await pool.query("commit");
    console.log("[MIGRATE] done.");
  } catch (e) {
    await pool.query("rollback");
    console.error("[MIGRATE] failed:", e);
  }
}

async function ensureSchema() {
  await createBaseSchema();
  await migrateLegacyConversations();
}
await ensureSchema();

/* ---------------- auth helpers ---------------- */
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

/* ---------------- nodemailer (Mailgun SMTP) ---------------- */
const mailer =
  SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS && SMTP_FROM
    ? nodemailer.createTransport({
        host: SMTP_HOST,
        port: Number(SMTP_PORT),
        auth: { user: SMTP_USER, pass: SMTP_PASS },
        secure: Number(SMTP_PORT) === 465 // SSL if 465
      })
    : null;

async function sendVerificationEmail(email, token) {
  if (!mailer) {
    console.warn("[MAIL] transporter not configured; skipping send for", email);
    return;
  }
  const link = `${BASE_URL.replace(/\/+$/,'')}/verify-email?token=${encodeURIComponent(token)}`;
  try {
    await mailer.sendMail({
      from: SMTP_FROM,
      to: email,
      subject: "Verify your GPTs Help email",
      html: `
        <div style="font-family:Inter,Arial,sans-serif;padding:20px">
          <h2>Welcome to GPTs Help 👋</h2>
          <p>Please verify your email to start using Math GPT.</p>
          <p><a href="${link}" style="display:inline-block;background:#5865f2;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">Verify my email</a></p>
          <p style="font-size:12px;color:#777">Link: ${link}</p>
        </div>`
    });
    console.log(`[MAIL] Verification email sent to ${email}`);
  } catch (e) {
    console.error("[MAIL] send failed:", e.message);
  }
}

/* ---------------- OpenAI ---------------- */
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

/* ---------------- Paystack helpers ---------------- */
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

/* ---------------- health & public config ---------------- */
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null
  });
});

/* ---------------- auth ---------------- */
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }

    // create/update user
    const u = await upsertUser(email, "FREE");
    if (password && password.length >= 8) await setUserPassword(email, password);

    // set verification token
    const token = crypto.randomBytes(24).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24h
    await pool.query(
      `update users set verify_token=$2, verify_expires=$3, verified=false, updated_at=now() where email=$1`,
      [email, token, expires]
    );

    // send email (best-effort)
    await sendVerificationEmail(email, token);

    // set session
    setSessionCookie(res, { email: u.email, plan: u.plan, verified: false });
    res.json({ status: "success", user: { email: u.email, verified: false } });
  } catch (e) {
    console.error("signup-free error:", e);
    res.status(500).json({ status: "error", message: "Could not create user" });
  }
});

app.get("/api/verify-email", async (req, res) => {
  try {
    const token = (req.query.token || "").toString();
    if (!token) return res.status(400).json({ status: "error", message: "Missing token" });

    const r = await pool.query(
      `update users
          set verified=true, verify_token=null, verify_expires=null, updated_at=now()
        where verify_token=$1 and (verify_expires is null or verify_expires>now())
      returning email, plan, verified`,
      [token]
    );
    if (!r.rowCount) return res.status(400).json({ status: "error", message: "Invalid or expired token" });

    // auto-login after verify
    setSessionCookie(res, { email: r.rows[0].email, plan: r.rows[0].plan, verified: true });

    // redirect to chat
    res.redirect("/chat.html");
  } catch (e) {
    console.error("verify-email", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
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
      await setUserPassword(email, password); // first-time set
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status: "error", message: "Invalid email or password." });
    }
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE", verified: !!u.verified });
    res.json({ status: "ok", user: { email: u.email, verified: !!u.verified } });
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

/* ---------------- paystack verify ---------------- */
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
      setSessionCookie(res, { email, plan: label === "ONE_TIME" ? "FREE" : label, verified: true });
      return res.json({ status: "success", email, plan: label, reference });
    }
    res.json({ status: "pending", data });
  } catch (e) {
    console.error("paystack verify", e);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

/* ---------------- helpers (auth-required) ---------------- */
async function requireUser(req, res) {
  const email = needEmail(req, res);
  if (!email) return null;
  const u = await getUserByEmail(email);
  if (!u) { res.status(401).json({ status: "unauthenticated" }); return null; }
  return u;
}

// count helpers for soft free limits
async function countTextForUser(userId) {
  const r = await pool.query(
    `select count(*)::int as n
       from messages m
      join conversations c on c.id=m.conversation_id
      where c.user_id=$1 and m.role='user'
        and m.content not like '(Photo%'`,
    [userId]
  );
  return r.rows[0].n || 0;
}
async function countPhotoForUser(userId) {
  const r = await pool.query(
    `select count(*)::int as n
       from messages m
      join conversations c on c.id=m.conversation_id
      where c.user_id=$1 and m.role='user'
        and m.content like '(Photo%'`,
    [userId]
  );
  return r.rows[0].n || 0;
}

/* ---------------- conversations ---------------- */
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

/* ---------------- share links ---------------- */
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

/* ---------------- chat ---------------- */
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    if (!u.verified) {
      return res.status(403).json({
        error: "email_not_verified",
        message: "Please verify your email to start chatting. Check your inbox for the verification link."
      });
    }

    // free-tier soft limits
    if ((u.plan || "FREE") === "FREE") {
      const usedText = await countTextForUser(u.id);
      if (usedText >= MAX_TEXT_FREE) {
        return res.status(402).json({
          error: "limit_reached",
          message: `You've used all ${MAX_TEXT_FREE} free text messages. Upgrade to continue.`,
          upgradeUrl: "/index.html#pricing"
        });
      }
    }

    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error: "message required" });

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
      gptType === "math" || !gptType
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful assistant.";

    const msgs = [{ role: "system", content: system }, ...hist.rows, { role: "user", content: message }];

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "user", message]
    );

    const answer = await openaiChat(msgs);

    await pool.query(
      `insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "assistant", answer]
    );

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

/* ---------------- photo solve ---------------- */
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;

    if (!u.verified) {
      return res.status(403).json({
        error: "email_not_verified",
        message: "Please verify your email to use Photo Solve. Check your inbox.",
      });
    }

    // free-tier soft limits
    if ((u.plan || "FREE") === "FREE") {
      const usedPhoto = await countPhotoForUser(u.id);
      if (usedPhoto >= MAX_PHOTO_FREE) {
        return res.status(402).json({
          error: "limit_reached",
          message: `You've used all ${MAX_PHOTO_FREE} free photo solves. Upgrade to continue.`,
          upgradeUrl: "/index.html#pricing"
        });
      }
    }

    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

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
      gptType === "math" || !gptType
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly."
        : "You are a helpful assistant.";

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
    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

/* ---------------- start ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
});