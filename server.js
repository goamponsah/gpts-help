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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const {
  DATABASE_URL, JWT_SECRET, OPENAI_API_KEY, OPENAI_MODEL,
  PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY, PLAN_CODE_PRO_ANNUAL,
  FRONTEND_ORIGIN, RESEND_API_KEY, RESEND_FROM
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY missing");
if (!RESEND_API_KEY || !RESEND_FROM) console.warn("[WARN] RESEND_* missing");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

if (FRONTEND_ORIGIN) app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
const upload = multer({ storage: multer.memoryStorage() });

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------- SCHEMA ----------
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

    create table if not exists conversations (
      id bigserial primary key,
      user_id bigint not null references users(id) on delete cascade,
      title text not null,
      archived boolean not null default false,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    create table if not exists messages (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role text not null,
      content text not null,
      created_at timestamptz not null default now()
    );

    create table if not exists share_links (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token text not null unique,
      created_at timestamptz not null default now(),
      revoked boolean not null default false
    );

    create table if not exists paystack_receipts (
      id bigserial primary key,
      email text not null,
      reference text not null unique,
      plan_code text,
      status text,
      raw jsonb,
      created_at timestamptz not null default now()
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

  // migrate old column "day" -> "period_start" if present
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='device_quotas' AND column_name='day'
      ) THEN
        ALTER TABLE device_quotas RENAME COLUMN day TO period_start;
      END IF;
    END $$;
  `);
}
await ensureSchema();// ---------- HELPERS ----------
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
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
function clearSession(res){res.clearCookie("sid",{...cookieOpts(),maxAge:0})}

function ensureDevice(req,res){
  let {did}=req.cookies||{};
  if(!did){did=crypto.randomUUID();res.cookie("did",did,{...cookieOpts(),httpOnly:false})}
  return did;
}
app.use((req,res,next)=>{ensureDevice(req,res);next()});

const scrypt = util.promisify(crypto.scrypt);
async function hashPassword(pw){
  const salt=crypto.randomBytes(16).toString("hex");
  const buf=await scrypt(pw,salt,64);
  return {salt,hash:buf.toString("hex")};
}
async function verifyPassword(pw,salt,hash){
  if(!salt||!hash)return false;
  const buf=await scrypt(pw,salt,64);
  return crypto.timingSafeEqual(Buffer.from(hash,"hex"),Buffer.from(buf.toString("hex"),"hex"));
}

async function upsertUser(email,plan="FREE"){
  const r=await pool.query(`insert into users(email,plan) values($1,$2)
     on conflict(email) do update set plan=excluded.plan returning *`,[email,plan]);
  return r.rows[0];
}
async function getUserByEmail(email){
  const r=await pool.query(`select * from users where email=$1`,[email]);return r.rows[0]||null;
}
async function setUserPassword(email,pw){
  const {salt,hash}=await hashPassword(pw);
  await pool.query(`update users set pass_salt=$2,pass_hash=$3,updated_at=now() where email=$1`,[email,salt,hash]);
}

// ---- Resend ----
async function resendSend({to,subject,html,text}){
  if(!RESEND_API_KEY||!RESEND_FROM){console.warn("[RESEND] Missing");return;}
  const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{
    Authorization:`Bearer ${RESEND_API_KEY}`,"Content-Type":"application/json"},
    body:JSON.stringify({from:RESEND_FROM,to:[to],subject,html,text})});
  if(!r.ok){console.error("[RESEND] send failed",await r.text());}
}
function verificationEmailHtml(link){return `<h3>Verify your email</h3><p>Click below:</p><a href="${link}">${link}</a>`}

// ---- Quota helpers ----
const FREE_TEXT_LIMIT=10, FREE_PHOTO_LIMIT=2;
async function getQuota(deviceHash){
  const today=new Date().toISOString().slice(0,10);
  await pool.query(`insert into device_quotas(device_hash,period_start)
                    values($1,$2)
                    on conflict (device_hash,period_start) do nothing`,[deviceHash,today]);
  const {rows}=await pool.query(`select * from device_quotas where device_hash=$1 and period_start=$2`,[deviceHash,today]);
  return rows[0];
}
async function bumpQuota(deviceHash,kind){
  const today=new Date().toISOString().slice(0,10);
  if(kind==="text")
    await pool.query(`update device_quotas set text_count=text_count+1 where device_hash=$1 and period_start=$2`,[deviceHash,today]);
  else
    await pool.query(`update device_quotas set photo_count=photo_count+1 where device_hash=$1 and period_start=$2`,[deviceHash,today]);
}// ---------- AUTH ----------
app.post("/api/signup-free", async (req,res)=>{
  try{
    const {email,password}=req.body||{};
    if(!email)return res.status(400).json({error:"Email required"});
    const u=await upsertUser(email,"FREE");
    if(password&&password.length>=8)await setUserPassword(email,password);
    const token=crypto.randomBytes(24).toString("hex");
    const until=new Date(Date.now()+24*3600e3);
    await pool.query(`update users set verify_token=$2,verify_expires=$3,verified=false where email=$1`,
                     [email,token,until]);
    const link=`${req.headers.origin||FRONTEND_ORIGIN}/api/verify-email?token=${token}`;
    await resendSend({to:email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    setSessionCookie(res,{email,plan:"FREE"});
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"Signup failed"});}
});

app.get("/api/verify-email", async (req,res)=>{
  try{
    const {token}=req.query||{};
    if(!token)return res.status(400).send("Missing token");
    const r=await pool.query(`update users set verified=true,verify_token=null,verify_expires=null
                               where verify_token=$1 and (verify_expires is null or now()<=verify_expires)
                               returning email`,[token]);
    if(!r.rowCount)return res.status(400).send("Invalid or expired token");
    res.redirect("/chat.html");
  }catch(e){console.error(e);res.status(500).send("Verification failed");}
});

// ---------- CHAT ----------
app.post("/api/chat", async (req,res)=>{
  try{
    const s=readSession(req);
    if(!s?.email)return res.status(401).json({error:"unauthenticated"});
    const u=await getUserByEmail(s.email);
    if(!u?.verified)return res.status(403).json({error:"verify_required"});
    const deviceHash=ensureDevice(req,res);
    if(u.plan==="FREE"){
      const q=await getQuota(deviceHash);
      if(q.text_count>=FREE_TEXT_LIMIT)
        return res.status(402).json({error:"limit",upgradeLink:"/index.html#pricing"});
    }
    const {message}=req.body||{};
    const system="You are Math GPT. Solve step-by-step clearly.";
    const r=await fetch("https://api.openai.com/v1/chat/completions",{
      method:"POST",
      headers:{Authorization:`Bearer ${OPENAI_API_KEY}`,"Content-Type":"application/json"},
      body:JSON.stringify({model:OPENAI_DEFAULT_MODEL,messages:[{role:"system",content:system},{role:"user",content:message}],temperature:0.2})
    });
    const data=await r.json();
    const ans=data?.choices?.[0]?.message?.content||"";
    if(u.plan==="FREE")await bumpQuota(deviceHash,"text");
    res.json({response:ans});
  }catch(e){console.error("chat error",e);res.status(500).json({error:"Chat failed"});}
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`GPTs Help server running on :${PORT}`));

