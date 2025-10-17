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
app.set("trust proxy", 1);

const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  FRONTEND_ORIGIN,

  // Email (Resend)
  RESEND_API_KEY,
  RESEND_FROM,

  // Paystack (SUBSCRIPTIONS with PLAN CODES – price in dashboard)
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PAYSTACK_CURRENCY,                 // optional, e.g. "GHS" or "NGN"
  PLAN_CODE_PLUS_MONTHLY,            // e.g. PLN_xxxxx (from Paystack Dashboard)
  PLAN_CODE_PRO_ANNUAL,              // e.g. PLN_yyyyy (from Paystack Dashboard)

} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY missing");
if (!PAYSTACK_PUBLIC_KEY) console.warn("[WARN] PAYSTACK_PUBLIC_KEY missing");
if (!PAYSTACK_SECRET_KEY) console.warn("[WARN] PAYSTACK_SECRET_KEY missing");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
} else {
  app.use(cors({ origin: "*", credentials: true }));
}

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
const upload = multer({ storage: multer.memoryStorage() });

/* ---------- Static files ---------- */
const PUB = path.join(__dirname, "public");
app.get("/robots.txt", (req, res) => res.sendFile(path.join(PUB, "robots.txt")));
app.get("/sitemap.xml", (req, res) => res.sendFile(path.join(PUB, "sitemap.xml")));
app.get("/manifest.webmanifest", (req, res) => {
  res.type("application/manifest+json");
  res.sendFile(path.join(PUB, "manifest.webmanifest"));
});
app.use(
  express.static(PUB, {
    setHeaders: (res, filePath) => {
      const p = filePath.toLowerCase();
      const noCache =
        p.endsWith(".html") || p.endsWith("service-worker.js") ||
        p.endsWith("/service-worker.js") || p.endsWith("\\service-worker.js");
      res.setHeader(
        "Cache-Control",
        noCache ? "no-store, no-cache, must-revalidate" : "public, max-age=31536000, immutable"
      );
    },
  })
);

/* ===================== Postgres ===================== */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ===================== Schema ===================== */
async function ensureSchema() {
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

  await pool.query(`create table if not exists conversations ( id bigserial primary key );`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS user_email   text;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS user_id      bigint;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS title        text not null default 'New chat';`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS archived     boolean not null default false;`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS created_at   timestamptz not null default now();`);
  await pool.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS updated_at   timestamptz not null default now();`);
  await pool.query(`
    UPDATE conversations c SET user_id = u.id
      FROM users u
     WHERE c.user_id IS NULL AND c.user_email = u.email
  `);
  await pool.query(`create index if not exists idx_conversations_user_email on conversations(user_email);`);
  await pool.query(`create index if not exists idx_conversations_user_id on conversations(user_id);`);
  await pool.query(`create index if not exists idx_conversations_archived on conversations(archived);`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at') THEN
        CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $f$
        BEGIN NEW.updated_at = now(); RETURN NEW; END; $f$ language plpgsql;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'conversations_set_updated_at') THEN
        CREATE TRIGGER conversations_set_updated_at
        BEFORE UPDATE ON conversations
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
      END IF;
    END $$;
  `);

  await pool.query(`
    create table if not exists messages (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role text not null check (role in ('user','assistant','system')),
      content text not null,
      created_at timestamptz not null default now()
    );
  `);
  await pool.query(`create index if not exists idx_messages_conversation_id on messages(conversation_id);`);

  await pool.query(`
    create table if not exists conversation_shares (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token text not null unique,
      created_at timestamptz not null default now()
    );
  `);

  await pool.query(`
    create table if not exists message_feedback (
      id bigserial primary key,
      conversation_id bigint,
      message_index integer,
      kind text not null check (kind in ('like','dislike')),
      user_email text,
      created_at timestamptz not null default now()
    );
  `);
  await pool.query(`create index if not exists idx_feedback_conv on message_feedback(conversation_id);`);
}
await ensureSchema();

/* ===================== Helpers ===================== */
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
const scrypt = util.promisify(crypto.scrypt);

function cookieOpts() {
  const cross = Boolean(FRONTEND_ORIGIN);
  return { httpOnly: true, secure: true, sameSite: cross ? "None" : "Lax", path: "/", maxAge: 30*24*60*60*1000 };
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
  if(!did){ did = crypto.randomUUID(); res.cookie("did", did, { ...cookieOpts(), httpOnly:false }); }
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
    headers:{ Authorization:`Bearer ${RESEND_API_KEY}`,"Content-Type":"application/json" },
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
  const {rows} = await pool.query(`select * from device_quotas where device_hash=$1 and period_start=$2`,[deviceHash,today]);
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

/* ===================== Public Config (for UI hints) ===================== */
app.get("/api/public-config", (req,res)=>{
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: (PAYSTACK_CURRENCY || "GHS").toUpperCase(),
    plans: {
      hasPlus: !!PLAN_CODE_PLUS_MONTHLY,
      hasPro:  !!PLAN_CODE_PRO_ANNUAL
    }
  });
});

/* ===================== Auth APIs ===================== */
app.get("/api/me", async (req,res)=>{
  const s = readSession(req);
  if(!s?.email) return res.json({ status:"anon" });
  const u = await getUserByEmail(s.email);
  if(!u) return res.json({ status:"anon" });
  res.json({ status:"ok", user:{ email:u.email, plan:u.plan, verified:u.verified }});
});

app.post("/api/signup-free", async (req,res)=>{
  try{
    const {email,password} = req.body || {};
    if(!email) return res.status(400).json({error:"Email required"});
    const u = await upsertUser(email,"FREE");
    if(password && password.length>=8) await setUserPassword(email,password);
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 24*3600e3);
    await pool.query(`update users set verify_token=$2, verify_expires=$3, verified=false where email=$1`,[email,token,until]);
    const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
    const link = `${origin}/api/verify-email?token=${token}`;
    await resendSend({to:email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    setSessionCookie(res,{email,plan:u.plan});
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({error:"Signup failed"}); }
});

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

app.post("/api/logout", async (req,res)=>{
  try{ clearSession(res); }catch{}
  res.json({ status:"ok" });
});

app.post("/api/resend-verify", async (req,res)=>{
  try{
    const s = readSession(req);
    if(!s?.email) return res.status(401).json({status:"error", message:"Not signed in"});
    const token = crypto.randomBytes(24).toString("hex");
    const until = new Date(Date.now() + 24*3600e3);
    await pool.query(`update users set verify_token=$2, verify_expires=$3 where email=$1`,[s.email,token,until]);
    const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
    const link = `${origin}/api/verify-email?token=${token}`;
    await resendSend({to:s.email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    res.json({ status:"ok" });
  }catch(e){ console.error(e); res.status(500).json({status:"error"}); }
});

app.post("/api/forgot-password", async (req,res)=>{
  try{
    const { email } = req.body || {};
    if(!email) return res.status(400).json({status:"error", message:"Email required"});
    const u = await getUserByEmail(email);
    if(u){
      const token = crypto.randomBytes(24).toString("hex");
      const until = new Date(Date.now() + 2*3600e3);
      await pool.query(`update users set reset_token=$2, reset_expires=$3 where email=$1`,[email,token,until]);
      const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
      const link = `${origin}/reset-password.html?token=${token}`;
      await resendSend({to:email,subject:"Reset your GPTs Help password",html:resetEmailHtml(link)});
    }
    res.json({ status:"ok" });
  }catch(e){ console.error(e); res.status(500).json({status:"error"}); }
});

app.get("/api/reset/validate", async (req,res)=>{
  try{
    const token = (req.query?.token || "").toString();
    if(!token) return res.json({ valid:false });
    const r = await pool.query(
      `select 1 from users where reset_token=$1 and (reset_expires is null or now()<=reset_expires)`,
      [token]
    );
    res.json({ valid: !!r.rowCount });
  }catch(e){ console.error(e); res.json({ valid:false }); }
});

app.post("/api/reset/confirm", async (req,res)=>{
  try{
    const { token, newPassword } = req.body || {};
    if(!token || typeof newPassword!=="string" || newPassword.length<8){
      return res.status(400).json({status:"error", message:"Invalid input"});
    }
    const r = await pool.query(
      `select email from users where reset_token=$1 and (reset_expires is null or now()<=reset_expires)`,
      [token]
    );
    if(!r.rowCount) return res.status(400).json({status:"error", message:"Invalid or expired token"});
    const email = r.rows[0].email;
    const { salt, hash } = await hashPassword(newPassword);
    await pool.query(`
      update users set pass_salt=$2, pass_hash=$3, reset_token=null, reset_expires=null, updated_at=now() where email=$1
    `,[email, salt, hash]);
    const u = await getUserByEmail(email);
    setSessionCookie(res, { email, plan: u?.plan || "FREE" });
    res.json({ status:"ok" });
  }catch(e){ console.error("reset/confirm error",e); res.status(500).json({status:"error", message:"Reset failed"}); }
});

/* ===================== Conversations, Shares, Chat (unchanged) ===================== */
// ... (kept same as your current build for brevity; no changes needed to these sections)

/* ===================== Paystack (Plans — price controlled in Dashboard) ===================== */

// Simple logger so you can confirm env on boot
(function logPaystackStartup(){
  const info = {
    has_public_key: !!PAYSTACK_PUBLIC_KEY,
    has_secret_key: !!PAYSTACK_SECRET_KEY,
    has_plus_plan: !!PLAN_CODE_PLUS_MONTHLY,
    has_pro_plan:  !!PLAN_CODE_PRO_ANNUAL,
    currency: PAYSTACK_CURRENCY || "default"
  };
  console.log("[PAYSTACK] startup", JSON.stringify(info));
})();

// Force success landing here; server will then redirect to /chat.html
function getSuccessCallbackUrl(){
  return "https://gptshelp.online/payment-success";
}

// Initialize Paystack with PLAN CODE (no amount passed)
app.post("/api/paystack/init", async (req, res) => {
  try {
    const s = readSession(req);
    if (!s?.email) return res.status(401).json({ status: "error", message: "Not signed in" });

    const { plan } = req.body || {};
    const label = String(plan || "").toUpperCase();
    let planCode = null;
    if (label === "PLUS") planCode = PLAN_CODE_PLUS_MONTHLY;
    if (label === "PRO")  planCode = PLAN_CODE_PRO_ANNUAL;

    if (!planCode) {
      return res.status(400).json({ status: "error", message: "Missing plan configuration" });
    }

    const payload = {
      email: s.email,
      plan: planCode,                                        // <-- Paystack decides price from dashboard
      callback_url: getSuccessCallbackUrl(),
      currency: PAYSTACK_CURRENCY || undefined,              // optional
      metadata: { plan_label: label, site: "gptshelp.online" }
      // NOTE: Paystack will decide what channels are available for subscription plans.
    };

    console.log("[PAYSTACK][INIT] request ->", JSON.stringify({
      plan: planCode, callback_url: payload.callback_url, metadata: payload.metadata
    }));

    const initRes = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const text = await initRes.text();
    let j = {};
    try { j = JSON.parse(text); } catch {}

    console.log("[PAYSTACK][INIT] response -> status=%s ok=%s", initRes.status, initRes.ok);
    if (!initRes.ok || j.status !== true) {
      console.log("[PAYSTACK][INIT] body:", text);
      return res.status(400).json({ status: "error", message: j?.message || "Init failed" });
    }

    res.json({
      status: "ok",
      authorization_url: j.data.authorization_url,
      reference: j.data.reference,
      access_code: j.data.access_code,
    });
  } catch (e) {
    console.error("paystack init error", e);
    res.status(500).json({ status: "error", message: "Initialization error" });
  }
});

// Paystack success landing -> verify -> redirect to chat
app.get("/payment-success", async (req, res) => {
  try {
    const reference = (req.query.reference || req.query.trxref || "").toString();
    if (!reference) return res.redirect("/chat.html");

    const verifyRes = await fetch(`${req.protocol}://${req.get("host")}/api/paystack/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", cookie: req.headers.cookie || "" },
      body: JSON.stringify({ reference }),
    });

    if (!verifyRes.ok) {
      const j = await verifyRes.json().catch(() => ({}));
      console.warn("[PAYSTACK][SUCCESS] verify failed:", j?.message || verifyRes.status);
    }
  } catch (e) {
    console.error("[PAYSTACK][SUCCESS] error:", e);
  } finally {
    res.redirect("/chat.html");
  }
});

// Verify & upgrade plan
app.post("/api/paystack/verify", async (req,res)=>{
  try{
    const { reference } = req.body || {};
    if(!reference) return res.status(400).json({status:"error", message:"Missing reference"});

    const r = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{
      headers:{ Authorization:`Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const text = await r.text();
    let j = {};
    try { j = JSON.parse(text); } catch {}
    console.log("[PAYSTACK][VERIFY] status=%s ok=%s", r.status, r.ok);
    if(!r.ok || !j || j.status !== true){
      console.log("[PAYSTACK][VERIFY] body:", text);
      return res.status(400).json({status:"error", message:"Verification failed"});
    }

    const data = j.data || {};
    if(data.status !== "success"){
      return res.status(400).json({status:"error", message:"Payment not successful"});
    }

    const paidEmail = data?.customer?.email || null;
    // Identify which plan by the plan code returned
    const planCode = data.plan || data?.subscription?.plan || data?.authorization?.plan || null;

    let newPlan = null;
    if (paidEmail && planCode) {
      if (PLAN_CODE_PLUS_MONTHLY && planCode === PLAN_CODE_PLUS_MONTHLY) newPlan = "PLUS";
      if (PLAN_CODE_PRO_ANNUAL  && planCode === PLAN_CODE_PRO_ANNUAL ) newPlan = "PRO";
    }

    if(newPlan){
      await pool.query(`update users set plan=$2, updated_at=now() where email=$1`,[paidEmail,newPlan]);
      // Refresh session if it's the same user currently signed in
      const s = readSession(req);
      if (s?.email && s.email === paidEmail) {
        setSessionCookie(res, { email: paidEmail, plan: newPlan });
      }
    }

    res.json({ status:"success", plan:newPlan || undefined });
  }catch(e){
    console.error("paystack verify error",e);
    res.status(500).json({status:"error", message:"Verification error"});
  }
});

/* ===================== Server ===================== */
const PORT = process.env.PORT || 3000;
app.use((req, res) => res.status(404).send("Not Found"));
app.listen(PORT, ()=> console.log(`GPTs Help server running on :${PORT}`));