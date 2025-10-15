// server.js (ESM, Node >=18)
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

// ---------- BOOTSTRAP ----------
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
if (!PAYSTACK_SECRET_KEY) console.warn("[WARN] PAYSTACK_SECRET_KEY missing");
if (!PAYSTACK_PUBLIC_KEY) console.warn("[WARN] PAYSTACK_PUBLIC_KEY missing");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

// CORS only if you’re splitting front/back domains
if (FRONTEND_ORIGIN) app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
app.use(express.json({ limit: "15mb" }));
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

    create table if not exists conversations (
      id bigserial primary key,
      user_email text not null,
      title text not null default 'New chat',
      archived boolean not null default false,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    create table if not exists messages (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      role text not null check (role in ('user','assistant')),
      content text not null,
      created_at timestamptz not null default now()
    );

    create table if not exists share_links (
      id bigserial primary key,
      conversation_id bigint not null references conversations(id) on delete cascade,
      token text not null unique,
      revoked boolean not null default false,
      created_at timestamptz not null default now()
    );
  `);

  // Migration helpers from your earlier file (keep compatibility)
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
}
await ensureSchema();

// ---------- HELPERS ----------
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
function clearSession(res){ res.clearCookie("sid",{...cookieOpts(),maxAge:0}); }

function ensureDevice(req,res){
  let {did}=req.cookies||{};
  if(!did){did=crypto.randomUUID();res.cookie("did",did,{...cookieOpts(),httpOnly:false})}
  return did;
}
app.use((req,res,next)=>{ ensureDevice(req,res); next(); });

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
     on conflict(email) do update set plan=coalesce(users.plan, excluded.plan) returning *`,[email,plan]);
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
function resetEmailHtml(link){return `<h3>Reset your password</h3><p>Click below:</p><a href="${link}">${link}</a>`}

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
}

// ---------- PUBLIC CONFIG ----------
app.get("/api/public-config", (req,res)=>{
  res.json({ paystackPublicKey: PAYSTACK_PUBLIC_KEY || null });
});

// ---------- AUTH ----------
app.post("/api/signup-free", async (req,res)=>{
  try{
    const {email,password}=req.body||{};
    if(!email) return res.status(400).json({error:"Email required"});
    const u=await upsertUser(email,"FREE");
    if(password&&password.length>=8)await setUserPassword(email,password);
    const token=crypto.randomBytes(24).toString("hex");
    const until=new Date(Date.now()+24*3600e3);
    await pool.query(`update users set verify_token=$2,verify_expires=$3,verified=false where email=$1`,
                     [email,token,until]);
    const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
    const link=`${origin}/api/verify-email?token=${token}`;
    await resendSend({to:email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    setSessionCookie(res,{email,plan:"FREE"});
    res.json({status:"ok"});
  }catch(e){console.error(e);res.status(500).json({error:"Signup failed"});}
});

app.get("/api/verify-email", async (req,res)=>{
  try{
    const {token}=req.query||{};
    if(!token) return res.status(400).send("Missing token");
    const r=await pool.query(`update users set verified=true,verify_token=null,verify_expires=null
                               where verify_token=$1 and (verify_expires is null or now()<=verify_expires)
                               returning email`,[token]);
    if(!r.rowCount) return res.status(400).send("Invalid or expired token");
    res.redirect("/chat.html");
  }catch(e){console.error(e);res.status(500).send("Verification failed");}
});

app.post("/api/resend-verify", async (req,res)=>{
  try{
    const s=readSession(req); if(!s?.email) return res.json({status:"ok"});
    const token=crypto.randomBytes(24).toString("hex");
    const until=new Date(Date.now()+24*3600e3);
    await pool.query(`update users set verify_token=$2,verify_expires=$3 where email=$1`,
      [s.email, token, until]);
    const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
    const link=`${origin}/api/verify-email?token=${token}`;
    await resendSend({to:s.email,subject:"Verify your GPTs Help email",html:verificationEmailHtml(link)});
    res.json({status:"ok"});
  }catch{ res.json({status:"ok"}); }
});

app.post("/api/forgot-password", async (req,res)=>{
  try{
    const {email} = req.body||{};
    if(!email) return res.json({status:"ok"});
    const token=crypto.randomBytes(24).toString("hex");
    const until=new Date(Date.now()+3600e3);
    await pool.query(`update users set reset_token=$2,reset_expires=$3 where email=$1`,[email,token,until]);
    const origin = req.headers.origin || FRONTEND_ORIGIN || `${req.protocol}://${req.get("host")}`;
    const link=`${origin}/reset.html?token=${token}`;
    await resendSend({to:email,subject:"Reset your GPTs Help password",html:resetEmailHtml(link)});
    res.json({status:"ok"});
  }catch{ res.json({status:"ok"}); }
});

app.post("/api/login", async (req,res)=>{
  try{
    const {email,password}=req.body||{};
    const u=await getUserByEmail(email);
    if(!u) return res.json({status:"error",message:"Invalid email or password"});
    const ok=await verifyPassword(password,u.pass_salt,u.pass_hash);
    if(!ok) return res.json({status:"error",message:"Invalid email or password"});
    setSessionCookie(res,{email:u.email,plan:u.plan});
    res.json({status:"ok",user:{email:u.email,verified:u.verified,plan:u.plan}});
  }catch(e){console.error(e);res.json({status:"error",message:"Login failed"});}
});

app.post("/api/logout", async (req,res)=>{ try{ clearSession(res); res.json({status:"ok"}); }catch{ res.json({status:"ok"}); } });

app.get("/api/me", async (req,res)=>{
  try{
    const s=readSession(req); 
    if(!s?.email) return res.json({status:"anon"});
    const u=await getUserByEmail(s.email);
    if(!u) return res.json({status:"anon"});
    res.json({status:"ok",user:{email:u.email,verified:u.verified,plan:u.plan}});
  }catch{ res.json({status:"anon"}); }
});

// ---------- CONVERSATIONS & MESSAGES ----------
async function assertOwner(email, convId){
  const r=await pool.query(`select id from conversations where id=$1 and user_email=$2`,[convId,email]);
  return r.rowCount>0;
}

app.get("/api/conversations", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.json([]);
  const {rows}=await pool.query(`select id,title,archived,created_at from conversations
                                 where user_email=$1 order by updated_at desc limit 200`,[s.email]);
  res.json(rows);
});

app.post("/api/conversations", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
  const title = (req.body?.title || "New chat").trim() || "New chat";
  const r=await pool.query(`insert into conversations(user_email,title) values($1,$2) returning id,title`,[s.email,title]);
  res.json({id:r.rows[0].id,title:r.rows[0].title});
});

app.get("/api/conversations/:id", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
  const id=Number(req.params.id);
  if(!(await assertOwner(s.email,id))) return res.status(404).json({error:"not_found"});
  const mr=await pool.query(`select role,content,created_at from messages where conversation_id=$1 order by id asc`,[id]);
  res.json({id, messages: mr.rows});
});

app.patch("/api/conversations/:id", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
  const id=Number(req.params.id);
  if(!(await assertOwner(s.email,id))) return res.status(404).json({error:"not_found"});
  const {title, archived} = req.body||{};
  if (typeof archived === "boolean"){
    await pool.query(`update conversations set archived=$2,updated_at=now() where id=$1`,[id,archived]);
  }
  if (typeof title === "string"){
    const t = title.trim() || "New chat";
    await pool.query(`update conversations set title=$2,updated_at=now() where id=$1`,[id,t]);
  }
  res.json({status:"ok"});
});

app.delete("/api/conversations/:id", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
  const id=Number(req.params.id);
  if(!(await assertOwner(s.email,id))) return res.status(404).json({error:"not_found"});
  await pool.query(`delete from conversations where id=$1`,[id]);
  res.json({status:"ok"});
});

// ---------- SHARING ----------
app.post("/api/conversations/:id/share", async (req,res)=>{
  const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
  const id=Number(req.params.id);
  if(!(await assertOwner(s.email,id))) return res.status(404).json({error:"not_found"});
  const token = crypto.randomBytes(20).toString("hex");
  await pool.query(`insert into share_links(conversation_id, token) values($1,$2)`,[id,token]);
  res.json({token});
});

app.get("/api/share/:token", async (req,res)=>{
  const {token}=req.params||{};
  const r=await pool.query(`select c.title, m.role, m.content
                            from share_links s
                            join conversations c on c.id=s.conversation_id
                            join messages m on m.conversation_id=c.id
                            where s.token=$1 and s.revoked=false
                            order by m.id asc`,[token]);
  if(!r.rowCount) return res.status(404).json({error:"not_found"});
  const title = r.rows[0].title;
  const messages = r.rows.map(x=>({role:x.role,content:x.content}));
  res.json({title,messages});
});

// ---------- OPENAI HELPERS ----------
async function chatOnce(messages){
  const r = await fetch("https://api.openai.com/v1/chat/completions",{
    method:"POST",
    headers:{Authorization:`Bearer ${OPENAI_API_KEY}`,"Content-Type":"application/json"},
    body:JSON.stringify({model:OPENAI_DEFAULT_MODEL,messages,temperature:0.2})
  });
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

// ---------- CHAT ----------
app.post("/api/chat", async (req,res)=>{
  try{
    const s=readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const u=await getUserByEmail(s.email);
    if(!u?.verified) return res.status(403).json({status:"verify_required", message:"Please verify your email"});

    const deviceHash=ensureDevice(req,res);
    if(u.plan==="FREE"){
      const q=await getQuota(deviceHash);
      if(q.text_count>=FREE_TEXT_LIMIT)
        return res.status(402).json({status:"limit", message:"Free text limit reached", upgradeLink:"/index.html#pricing"});
    }

    const { message, conversationId, gptType } = req.body||{};
    let convId = conversationId;

    if(!convId){
      const r=await pool.query(`insert into conversations(user_email,title) values($1,$2) returning id`,[u.email,"New chat"]);
      convId = r.rows[0].id;
    }else{
      const ok = await assertOwner(u.email, convId);
      if(!ok) return res.status(404).json({error:"not_found"});
    }

    // store user message
    await pool.query(`insert into messages(conversation_id,role,content) values($1,'user',$2)`,[convId,message]);
    await pool.query(`update conversations set updated_at=now() where id=$1`,[convId]);

    const system="You are Math GPT. Solve step-by-step clearly.";
    const answer = await chatOnce([{role:"system",content:system},{role:"user",content:message}]);

    // store assistant message
    await pool.query(`insert into messages(conversation_id,role,content) values($1,'assistant',$2)`,[convId,answer]);

    if(u.plan==="FREE") await bumpQuota(deviceHash,"text");
    res.json({response:answer, conversationId: convId});
  }catch(e){console.error("chat error",e);res.status(500).json({error:"Chat failed"});}
});

// ---------- PHOTO SOLVE ----------
app.post("/api/photo-solve", upload.single("image"), async (req,res)=>{
  try{
    const s=readSession(req);
    if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const u=await getUserByEmail(s.email);
    if(!u?.verified) return res.status(403).json({status:"verify_required", message:"Please verify your email"});

    const deviceHash=ensureDevice(req,res);
    if(u.plan==="FREE"){
      const q=await getQuota(deviceHash);
      if(q.photo_count>=FREE_PHOTO_LIMIT)
        return res.status(402).json({status:"limit", message:"Free photo limit reached", upgradeLink:"/index.html#pricing"});
    }

    const { buffer, mimetype } = req.file || {};
    if(!buffer) return res.status(400).json({error:"No image"});

    const { conversationId, attempt } = req.body||{};
    let convId = conversationId;
    if(!convId){
      const r=await pool.query(`insert into conversations(user_email,title) values($1,$2) returning id`,[u.email,"New chat"]);
      convId = r.rows[0].id;
    }else{
      const ok = await assertOwner(u.email, convId);
      if(!ok) return res.status(404).json({error:"not_found"});
    }

    // convert to base64 data url for vision
    const b64 = buffer.toString("base64");
    const dataUrl = `data:${mimetype||"image/png"};base64,${b64}`;

    const userPrompt = (attempt && String(attempt).trim())
      ? `Here is a math problem image. User note: ${attempt}. Provide step-by-step solution.`
      : `Here is a math problem image. Provide step-by-step solution.`;

    // store user "image" message (as note)
    await pool.query(`insert into messages(conversation_id,role,content) values($1,'user',$2)`,
      [convId, attempt ? `📷 Photo uploaded — Note: ${attempt}` : `📷 Photo uploaded`]);

    // Call OpenAI Vision-style via chat.completions (image_url content part)
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method:"POST",
      headers:{ Authorization:`Bearer ${OPENAI_API_KEY}`, "Content-Type":"application/json" },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        temperature: 0.2,
        messages: [
          { role: "system", content: "You are Math GPT. Solve step-by-step clearly." },
          { role: "user", content: [
              { type: "text", text: userPrompt },
              { type: "image_url", image_url: { url: dataUrl } }
            ]}
        ]
      })
    });
    const data = await r.json();
    const out = data?.choices?.[0]?.message?.content || "No response text returned.";

    await pool.query(`insert into messages(conversation_id,role,content) values($1,'assistant',$2)`,[convId,out]);
    await pool.query(`update conversations set updated_at=now() where id=$1`,[convId]);

    if(u.plan==="FREE") await bumpQuota(deviceHash,"photo");
    res.json({response:out, conversationId: convId});
  }catch(e){console.error("photo-solve error",e);res.status(500).json({error:"Photo solve failed"});}
});

// ---------- PAYSTACK VERIFY ----------
/**
 * Frontend opens Inline, Paystack hits charge → callback returns a reference.
 * We verify that reference here, confirm the plan, and upgrade the user.
 * IMPORTANT: When using Paystack 'plan', DO NOT send 'amount' in the same transaction.
 * Currency mismatch is what commonly causes "Invalid Amount Sent".
 */
app.post("/api/paystack/verify", async (req,res)=>{
  try{
    const s=readSession(req); if(!s?.email) return res.status(401).json({error:"unauthenticated"});
    const { reference } = req.body||{};
    if(!reference) return res.status(400).json({error:"Missing reference"});

    const vr = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{
      headers:{ Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const data = await vr.json();
    if(!vr.ok || data?.data?.status !== "success"){
      return res.json({status:"error",message: (data?.message || "Verification failed")});
    }

    // Inspect data for plan code
    const planCode = data?.data?.plan || data?.data?.subscription?.plan?.plan_code || null;

    // Map your plan codes to labels stored in DB
    let newPlan = null;
    if (planCode && PLAN_CODE_PLUS_MONTHLY && planCode === PLAN_CODE_PLUS_MONTHLY) {
      newPlan = "PLUS_MONTHLY";
    } else if (planCode && PLAN_CODE_PRO_ANNUAL && planCode === PLAN_CODE_PRO_ANNUAL) {
      newPlan = "PRO_ANNUAL";
    } else {
      // Fallback: if plan not present (one-off charge), consider amount mapping or leave as null
      // For safety, leave as null and return error so you can investigate
      return res.json({status:"error",message:"Plan not recognized on verification response"});
    }

    await pool.query(`update users set plan=$2, updated_at=now() where email=$1`,[s.email, newPlan]);
    res.json({status:"success", plan:newPlan});
  }catch(e){ console.error("paystack verify error",e); res.json({status:"error",message:"Verification exception"}); }
});

// ---------- MISC ----------
app.get("/healthz",(req,res)=>res.send("ok"));

// ---------- START ----------
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`GPTs Help server running on :${PORT}`));