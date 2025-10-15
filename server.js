// server.js (ESM)
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

/* ===================== Env & App ===================== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  FRONTEND_ORIGIN,

  // Email (Resend)
  RESEND_API_KEY,
  RESEND_FROM,

  // Paystack
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY missing");
if (!RESEND_API_KEY || !RESEND_FROM) console.warn("[WARN] RESEND_* missing");
if (!PAYSTACK_PUBLIC_KEY) console.warn("[WARN] PAYSTACK_PUBLIC_KEY missing");
if (!PAYSTACK_SECRET_KEY) console.warn("[WARN] PAYSTACK_SECRET_KEY missing");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
const upload = multer({ storage: multer.memoryStorage() });

/* ===================== Postgres ===================== */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ===================== Schema (auto-migrate, legacy-safe) ===================== */
async function ensureSchema() {
  // Core tables
  await pool.query(`
    create table if not exists users (
      id bigserial primary key,
      email text not null unique,
      pass_salt text,
      pass_hash text,
      plan text not null default 'FREE',
      verified boolean not null default false,
      verify_token text,
      verify_expires timestamptz,
      reset_token text,
      reset_expires timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    create table if not exists device_quotas (
      id bigserial primary key,
      device_hash text not null,
      period_start date not null,
      text_count integer not null default 0,
      photo_count integer not null default 0,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      unique (device_hash, period_start)
    );
  `);

  // Legacy migrations for device_quotas
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='device_quotas' AND column_name='day'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='device_quotas' AND column_name='period_start'
      ) THEN
        ALTER TABLE device_quotas RENAME COLUMN day TO period_start;
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='device_quotas' AND column_name='device_id'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='device_quotas' AND column_name='device_hash'
      ) THEN
        ALTER TABLE device_quotas RENAME COLUMN device_id TO device_hash;
      END IF;
    END $$;
  `);

  // Safety add columns on users
  const qUsers = await pool.query(`
    select column_name from information_schema.columns where table_name='users'
  `);
  const haveUsers = new Set(qUsers.rows.map(r => r.column_name));
  async function addUsers(sql){ try { await pool.query(sql); } catch {} }
  if (!haveUsers.has("verified"))       await addUsers(`alter table users add column verified boolean not null default false`);
  if (!haveUsers.has("verify_token"))   await addUsers(`alter table users add column verify_token text`);
  if (!haveUsers.has("verify_expires")) await addUsers(`alter table users add column verify_expires timestamptz`);
  if (!haveUsers.has("reset_token"))    await addUsers(`alter table users add column reset_token text`);
  if (!haveUsers.has("reset_expires"))  await addUsers(`alter table users add column reset_expires timestamptz`);

  /* ---------- Conversations / Messages / Shares ---------- */

  // Create conversations table if missing (minimal, then normalize below)
  await pool.query(`
    create table if not exists conversations (
      id bigserial primary key
      -- other columns normalized below
    );
  `);

  // 1) Rename legacy "email" -> "user_email" if needed (BEFORE FKs)
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='conversations' AND column_name='email'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='conversations' AND column_name='user_email'
      ) THEN
        EXECUTE 'ALTER TABLE conversations RENAME COLUMN email TO user_email';
      END IF;
    END $$;
  `);

  // 2) Ensure required columns exist (including user_id for legacy DBs that require it)
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS user_email   text;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS user_id      bigint;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS title        text not null default 'New chat';`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS archived     boolean not null default false;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS created_at   timestamptz not null default now();`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS updated_at   timestamptz not null default now();`);

  // 3) Backfill user_id from user_email if missing
  await pool.query(`
    UPDATE conversations c
       SET user_id = u.id
      FROM users u
     WHERE c.user_id IS NULL
       AND c.user_email = u.email
  `);

  // 4) Indexes (idempotent)
  await pool.query(`create index if not exists idx_conversations_user_email on conversations(user_email);`);
  await pool.query(`create index if not exists idx_conversations_user_id    on conversations(user_id);`);
  await pool.query(`create index if not exists idx_conversations_archived   on conversations(archived);`);

  // 5) Add FKs only if missing
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='conversations' AND column_name='user_email'
      ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name='conversations'
          AND tc.constraint_type='FOREIGN KEY'
          AND kcu.column_name='user_email'
      ) THEN
        ALTER TABLE conversations
          ADD CONSTRAINT conversations_user_email_fkey
          FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE;
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='conversations' AND column_name='user_id'
      ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name='conversations'
          AND tc.constraint_type='FOREIGN KEY'
          AND kcu.column_name='user_id'
      ) THEN
        ALTER TABLE conversations
          ADD CONSTRAINT conversations_user_id_fkey
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
      END IF;
    END $$;
  `);

  // Messages table
  await pool.query(`
    create table if not exists messages (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role            text not null check (role in ('user','assistant','system')),
      content         text not null,
      created_at      timestamptz not null default now()
    );
  `);
  await pool.query(`create index if not exists idx_messages_conversation_id on messages(conversation_id);`);

  // Share links table
  await pool.query(`
    create table if not exists conversation_shares (
      id              bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token           text not null unique,
      created_at      timestamptz not null default now()
    );
  `);

  // Trigger to update conversations.updated_at
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at') THEN
        CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $f$
        BEGIN
          NEW.updated_at = now();
          RETURN NEW;
        END;
        $f$ language plpgsql;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'conversations_set_updated_at') THEN
        CREATE TRIGGER conversations_set_updated_at
        BEFORE UPDATE ON conversations
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
      END IF;
    END $$;
  `);
}
await ensureSchema();

/* ===================== Helpers ===================== */
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
const scrypt = util.promisify(crypto.scrypt);

function cookieOpts() {
  const cross = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true,
    sameSite: cross ? "None" : "Lax",
    path: "/",
    maxAge: 30*24*60*60*1000
  };
}
function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, SJWT, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOpts());
}
function readSession(req) {
  const { sid } = req.cookies || {};
  try { return sid ? jwt.verify(sid, SJWT) : null; } catch { return null; }
}
function clearSession(res){ res.clearCookie("sid", { ...cookieOpts(), maxAge: 0 }); }

function ensureDevice(req,res){
  let { did } = req.cookies || {};
  if(!did){
    did = crypto.randomUUID();
    res.cookie("did", did, { ...cookieOpts(), httpOnly:false });
  }
  return did;
}

async function hashPassword(pw){
  const salt = crypto.randomBytes(16).toString("hex");
  const buf = await scrypt(pw, salt, 64);
  return { salt, hash: buf.toString("hex") };
}
async function verifyPassword(pw,salt,hash){
  if(!salt||!hash) return false;
  const buf = await scrypt(pw, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(hash,"hex"), Buffer.from(buf.toString("hex"),"hex"));
}

async function upsertUser(email,plan="FREE"){
  const r = await pool.query(`
    insert into users(email,plan) values($1,$2)
    on conflict(email) do update set plan=excluded.plan
    returning *
  `,[email,plan]);
  return r.rows[0];
}
async function getUserByEmail(email){
  const r = await pool.query(`select * from users where email=$1`,[email]);
  return r.rows[0]||null;
}
async function setUserPassword(email,pw){
  const {salt,hash} = await hashPassword(pw);
  await pool.query(`update users set pass_salt=$2, pass_hash=$3, updated_at=now() where email=$1`,[email,salt,hash]);
}

/* ----- Resend mail ----- */
async function resendSend({to,subject,html,text}){
  if(!RESEND_API_KEY || !RESEND_FROM){ console.warn("[RESEND] Missing"); return; }
  const r = await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      Authorization:`Bearer ${RESEND_API_KEY}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({ from: RESEND_FROM, to:[to], subject, html, text })
  });
  if(!r.ok){ console.error("[RESEND] send failed", await r.text()); }
}
function verificationEmailHtml(link){ return `<h3>Verify your email</h3><p>Click below:</p><a href="${link}">${link}</a>`; }
function resetEmailHtml(link){ return `<h3>Reset your password</h3><p>Click below:</p><a href="${link}">${link}</a>`; }

/* ----- Quotas ----- */
const FREE_TEXT_LIMIT=10, FREE_PHOTO_LIMIT=2;
async function getQuota(deviceHash){
  const today = new Date().toISOString().slice(0,10);
  await pool.query(`
    insert into device_quotas(device_hash, period_start)
    values($1,$2)
    on conflict (device_hash,period_start) do nothing
  `,[deviceHash,today]);
  const {rows} = await pool.query(`
    select * from device_quotas where device_hash=$1 and period_start=$2
  `,[deviceHash,today]);
  return rows[0];
}
async function bumpQuota(deviceHash,kind){
  const today = new Date().toISOString().slice(0,10);
  if(kind==="text"){
    await pool.query(`update device_quotas set text_count=text_count+1 where device_hash=$1 and period_start=$2`,[deviceHash,today]);
  }else{
    await pool.query(`update device_quotas set photo_count=photo_count+1 where device_hash=$1 and period_start=$2`,[deviceHash,today]);
  }
}

/* ===================== Auth APIs ===================== */

// public-config (for Paystack public key)
app.get("/api/public-config", (req,res)=>{
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null
  });
});

// me
app.get("/api/me", async (req,res)=>{
  const s = readSession(req);
  if(!s?.email) return res.json({ status:"anon" });
  const u = await getUserByEmail(s.email);
  if(!u) return res.json({ status:"anon" });
  res.json({ status:"ok", user:{ email:u.email, plan:u.plan, verified:u.verified }});
});

// signup
app.post("/api/signup-free", async (req,res)=>{
  try{
    const {email,password} = req.body || {};
    if(!email) return res.status(400).json({error:"Email required"});
    const u = await upsertUser(email,"FREE");
    if(password && password.length>=8) await setUserPassword(email,password);
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 24*3600e3);
    await pool.query(`
      update users set verify_token=$2, verify_expires=$3, verified=false where email=$1
    `,[email,token,until]);
    const link = `${req.headers.origin || FRONTEND_ORIGIN || ''}/api/verify-email?token=${token}`;
    await resendSend({to:email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    setSessionCookie(res,{email,plan:u.plan});
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({error:"Signup failed"}); }
});

// verify email (redirects to chat)
app.get("/api/verify-email", async (req,res)=>{
  try{
    const { token } = req.query || {};
    if(!token) return res.status(400).send("Missing token");
    const r = await pool.query(`
      update users set verified=true, verify_token=null, verify_expires=null
      where verify_token=$1 and (verify_expires is null or now()<=verify_expires)
      returning email
    `,[token]);
    if(!r.rowCount) return res.status(400).send("Invalid or expired token");
    res.redirect("/chat.html");
  }catch(e){ console.error(e); res.status(500).send("Verification failed"); }
});

// login
app.post("/api/login", async (req,res)=>{
  try{
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({status:"error", message:"Missing credentials"});
    const u = await getUserByEmail(email);
    if(!u || !u.pass_hash || !u.pass_salt) return res.status(401).json({status:"error", message:"Invalid email or password"});
    const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
    if(!ok) return res.status(401).json({status:"error", message:"Invalid email or password"});
    setSessionCookie(res, { email:u.email, plan:u.plan });
    res.json({ status:"ok", user:{ email:u.email, plan:u.plan, verified:u.verified }});
  }catch(e){ console.error("login error",e); res.status(500).json({status:"error", message:"Login failed"}); }
});

// logout
app.post("/api/logout", async (req,res)=>{
  try{ clearSession(res); }catch{}
  res.json({ status:"ok" });
});

// resend verify
app.post("/api/resend-verify", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({status:"error", message:"Not signed in"});
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 24*3600e3);
    await pool.query(`update users set verify_token=$2, verify_expires=$3 where email=$1`,[s.email,token,until]);
    const link = `${req.headers.origin || FRONTEND_ORIGIN || ''}/api/verify-email?token=${token}`;
    await resendSend({to:s.email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    res.json({ status:"ok" });
  }catch(e){ console.error(e); res.status(500).json({status:"error"}); }
});

// forgot password
// forgot password
app.post("/api/forgot-password", async (req,res)=>{
  try{
    const { email } = req.body || {};
    if(!email) return res.status(400).json({status:"error", message:"Email required"});
    const u = await getUserByEmail(email);
    // Don't leak user existence
    if(u){
      const token = crypto.randomBytes(24).toString("hex");
      const until = new Date(Date.now() + 2*3600e3); // 2 hours
      await pool.query(`update users set reset_token=$2, reset_expires=$3 where email=$1`,[email,token,until]);
      // NOTE: point to reset-password.html and use ?t=
      const link = `${req.headers.origin || FRONTEND_ORIGIN || ''}/reset-password.html?t=${encodeURIComponent(token)}`;
      await resendSend({to:email,subject:"Reset your GPTs Help password",html:resetEmailHtml(link)});
    }
    res.json({ status:"ok" });
  }catch(e){ console.error(e); res.status(500).json({status:"error"}); }
});

// reset password (for reset.html)
app.post("/api/reset-password", async (req,res)=>{
  try{
    const { token, password } = req.body || {};
    if(!token || typeof password!=="string" || password.length<8){
      return res.status(400).json({status:"error", message:"Invalid input"});
    }
    const r = await pool.query(
      `select email from users where reset_token=$1 and (reset_expires is null or now()<=reset_expires)`,
      [token]
    );
    if(!r.rowCount) return res.status(400).json({status:"error", message:"Invalid or expired token"});
    const email = r.rows[0].email;
    const { salt, hash } = await hashPassword(password);
    await pool.query(`
      update users set pass_salt=$2, pass_hash=$3, reset_token=null, reset_expires=null, updated_at=now() where email=$1
    `,[email, salt, hash]);
    const u = await getUserByEmail(email);
    setSessionCookie(res, { email, plan: u?.plan || "FREE" });
    res.json({ status:"ok" });
  }catch(e){ console.error("reset-password error",e); res.status(500).json({status:"error", message:"Reset failed"}); }
});

/* ===================== Conversations & Messages ===================== */

// helper to get user id fast
async function getUserIdByEmail(email){
  const r = await pool.query(`select id from users where email=$1`,[email]);
  return r.rows?.[0]?.id || null;
}

// List conversations
app.get("/api/conversations", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    // Either filter works; keep by email for compatibility
    const { rows } = await pool.query(
      `select id, title, archived, created_at, updated_at
         from conversations
        where user_email=$1
        order by updated_at desc`,
      [s.email]
    );
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

// Create conversation
app.post("/api/conversations", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const { title="New chat" } = req.body || {};
    // Insert with BOTH user_email and user_id to satisfy legacy NOT NULL constraints
    const { rows } = await pool.query(
      `insert into conversations(user_email, user_id, title)
       select $1, u.id, $2
         from users u
        where u.email=$1
       returning *`,
      [s.email, title]
    );
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

// Update conversation (rename / archive)
app.patch("/api/conversations/:id", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const id = Number(req.params.id);
    const { title, archived } = req.body || {};
    const fields = [];
    const vals = [];
    let idx = 1;
    if(typeof title === "string"){ fields.push(`title=$${idx++}`); vals.push(title); }
    if(typeof archived === "boolean"){ fields.push(`archived=$${idx++}`); vals.push(archived); }
    if(!fields.length) return res.json({status:"noop"});
    vals.push(s.email); vals.push(id);
    const { rows } = await pool.query(
      `update conversations set ${fields.join(", ")}, updated_at=now()
        where user_email=$${idx++} and id=$${idx++}
        returning id, title, archived, created_at, updated_at`,
      vals
    );
    if(!rows.length) return res.status(404).json({error:"not found"});
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

// Delete conversation
app.delete("/api/conversations/:id", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const id = Number(req.params.id);
    await pool.query(`delete from conversations where user_email=$1 and id=$2`,[s.email,id]);
    res.json({ status:"ok" });
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

// Get conversation messages
app.get("/api/conversations/:id", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const id = Number(req.params.id);
    const ok = await pool.query(`select 1 from conversations where id=$1 and user_email=$2`,[id,s.email]);
    if(!ok.rowCount) return res.status(404).json({error:"not found"});
    const msgs = await pool.query(
      `select role, content, created_at
         from messages
        where conversation_id=$1
        order by id asc`,
      [id]
    );
    res.json({ id, messages: msgs.rows });
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

/* ===================== Shareable Links ===================== */

// Create a share token
app.post("/api/conversations/:id/share", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const id = Number(req.params.id);
    const own = await pool.query(`select 1 from conversations where id=$1 and user_email=$2`,[id,s.email]);
    if(!own.rowCount) return res.status(404).json({error:"not found"});

    // reuse existing if any
    let tokenRow = await pool.query(`select token from conversation_shares where conversation_id=$1`,[id]);
    if(!tokenRow.rowCount){
      const token = crypto.randomBytes(16).toString("hex");
      tokenRow = await pool.query(
        `insert into conversation_shares(conversation_id, token) values($1,$2) returning token`,
        [id, token]
      );
    }
    res.json({ token: tokenRow.rows[0].token });
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

// Read shared conversation (public)
app.get("/api/share/:token", async (req,res)=>{
  try{
    const { token } = req.params;
    const { rows } = await pool.query(`
      select c.title, c.id
        from conversation_shares s
        join conversations c on c.id=s.conversation_id
       where s.token=$1
    `,[token]);
    if(!rows.length) return res.status(404).json({error:"not found"});
    const { id, title } = rows[0];
    const msgs = await pool.query(
      `select role, content, created_at from messages where conversation_id=$1 order by id asc`,
      [id]
    );
    res.json({ title, messages: msgs.rows });
  }catch(e){ console.error(e); res.status(500).json({error:"failed"}); }
});

/* ===================== Chat & Photo Solve ===================== */

// OpenAI helpers
async function openaiChat(messages){
  const r = await fetch("https://api.openai.com/v1/chat/completions",{
    method:"POST",
    headers:{
      Authorization:`Bearer ${OPENAI_API_KEY}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      model: OPENAI_DEFAULT_MODEL,
      messages,
      temperature: 0.2
    })
  });
  if(!r.ok){
    const t = await r.text().catch(()=> "");
    throw new Error(`OpenAI error: ${r.status} ${t}`);
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

// Chat (text)
app.post("/api/chat", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const u = await getUserByEmail(s.email);
    if(!u?.verified) return res.status(403).json({status:"verify_required"});

    const deviceHash = ensureDevice(req,res);
    if((u.plan||"FREE").toUpperCase()==="FREE"){
      const q = await getQuota(deviceHash);
      if(q.text_count >= FREE_TEXT_LIMIT){
        return res.status(402).json({status:"limit", message:"You've reached your free daily text limit.", upgradeLink:"/index.html#pricing"});
      }
    }

    const { message, conversationId } = req.body || {};
    if(!message || typeof message!=="string") return res.status(400).json({error:"message required"});

    // ensure conversation
    let convId = conversationId;
    if(!convId){
      const r = await pool.query(
        `insert into conversations(user_email, user_id, title)
         select $1, u.id, $2
           from users u
          where u.email=$1
         returning id`,
        [s.email, "New chat"]
      );
      convId = r.rows[0].id;
    }else{
      await pool.query(`update conversations set updated_at=now() where id=$1 and user_email=$2`,[convId,s.email]);
    }

    // store user message
    await pool.query(`insert into messages(conversation_id, role, content) values($1,'user',$2)`,[convId, message]);

    const system = "You are Math GPT. Solve step-by-step clearly.";
    const answer = await openaiChat([
      { role:"system", content: system },
      { role:"user", content: message }
    ]);

    // store assistant message
    await pool.query(`insert into messages(conversation_id, role, content) values($1,'assistant',$2)`,[convId, answer]);

    if((u.plan||"FREE").toUpperCase()==="FREE") await bumpQuota(deviceHash,"text");

    res.json({ response: answer, conversationId: convId });
  }catch(e){
    console.error("chat error",e);
    res.status(500).json({error:"Chat failed"});
  }
});

// Photo solve (image -> reasoning)
app.post("/api/photo-solve", upload.single("image"), async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const u = await getUserByEmail(s.email);
    if(!u?.verified) return res.status(403).json({status:"verify_required"});

    const deviceHash = ensureDevice(req,res);
    if((u.plan||"FREE").toUpperCase()==="FREE"){
      const q = await getQuota(deviceHash);
      if(q.photo_count >= FREE_PHOTO_LIMIT){
        return res.status(402).json({status:"limit", message:"You've reached your free photo limit.", upgradeLink:"/index.html#pricing"});
      }
    }

    const file = req.file;
    if(!file) return res.status(400).json({error:"image required"});
    const mimeOk = ["image/png","image/jpeg","image/jpg","image/webp"].includes(file.mimetype);
    if(!mimeOk) return res.status(400).json({error:"unsupported image type"});
    const b64 = file.buffer.toString("base64");
    const dataUrl = `data:${file.mimetype};base64,${b64}`;

    const { attempt="", conversationId } = req.body || {};

    // ensure conversation
    let convId = conversationId;
    if(!convId){
      const r = await pool.query(
        `insert into conversations(user_email, user_id, title)
         select $1, u.id, $2
           from users u
          where u.email=$1
         returning id`,
        [s.email, "New chat"]
      );
      convId = r.rows[0].id;
    }else{
      await pool.query(`update conversations set updated_at=now() where id=$1 and user_email=$2`,[convId,s.email]);
    }

    const userPrompt = attempt
      ? `Solve this math problem step-by-step. Note: ${attempt}`
      : `Solve this math problem step-by-step.`;

    // store synthetic user message (note that an image was attached)
    await pool.query(`insert into messages(conversation_id, role, content) values($1,'user',$2)`,
      [convId, `${userPrompt}\n\n[Photo attached]`]);

    const system = "You are Math GPT. Be precise and show steps. If the image is unclear, state assumptions.";
    // Vision chat with image_url content
    const r = await fetch("https://api.openai.com/v1/chat/completions",{
      method:"POST",
      headers:{ Authorization:`Bearer ${OPENAI_API_KEY}`, "Content-Type":"application/json" },
      body:JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        temperature: 0.2,
        messages: [
          { role:"system", content: system },
          {
            role:"user",
            content: [
              { type:"text", text: userPrompt },
              { type:"image_url", image_url: { url: dataUrl } }
            ]
          }
        ]
      })
    });

    if(!r.ok){
      const t = await r.text().catch(()=> "");
      throw new Error(`OpenAI error: ${r.status} ${t}`);
    }
    const data = await r.json();
    const out = data?.choices?.[0]?.message?.content || "No response text returned.";

    await pool.query(`insert into messages(conversation_id, role, content) values($1,'assistant',$2)`,[convId,out]);

    if((u.plan||"FREE").toUpperCase()==="FREE") await bumpQuota(deviceHash,"photo");

    res.json({ response: out, conversationId: convId });
  }catch(e){
    console.error("photo-solve error",e);
    res.status(500).json({error:"Photo solve failed"});
  }
});

/* ===================== Paystack ===================== */

// Verify a Paystack transaction reference and upgrade plan
app.post("/api/paystack/verify", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({status:"error", message:"Not signed in"});
    const { reference } = req.body || {};
    if(!reference) return res.status(400).json({status:"error", message:"Missing reference"});

    const r = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{
      headers:{ Authorization:`Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const j = await r.json();
    if(!r.ok || !j || j.status !== true){
      return res.status(400).json({status:"error", message:"Verification failed"});
    }

    const data = j.data || {};
    if(data.status !== "success"){
      return res.status(400).json({status:"error", message:"Payment not successful"});
    }

    // If using Plans on Paystack, map plan codes
    const planCode = data.plan || data?.subscription?.plan || data?.authorization?.plan || null;
    let newPlan = null;
    if(planCode){
      if(PLAN_CODE_PLUS_MONTHLY && planCode === PLAN_CODE_PLUS_MONTHLY) newPlan = "PLUS";
      if(PLAN_CODE_PRO_ANNUAL  && planCode === PLAN_CODE_PRO_ANNUAL ) newPlan = "PRO";
    }

    if(newPlan){
      await pool.query(`update users set plan=$2, updated_at=now() where email=$1`,[s.email,newPlan]);
      setSessionCookie(res, { email:s.email, plan:newPlan });
    }

    res.json({ status:"success", plan:newPlan || undefined });
  }catch(e){
    console.error("paystack verify error",e);
    res.status(500).json({status:"error", message:"Verification error"});
  }
});

/* ===================== Server ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`GPTs Help server running on :${PORT}`));
