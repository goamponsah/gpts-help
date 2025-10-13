// server.js  (ESM, Node 18+)
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
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use(cors({ origin: true, credentials: true }));

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
  RESEND_API_KEY,
  RESEND_FROM
} = process.env;

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ---------------- ensure schema (Option B) ----------------
async function ensureSchema() {
  await pool.query(`
    create table if not exists users (
      id bigserial primary key,
      email text unique not null,
      pass_salt text,
      pass_hash text,
      plan text default 'FREE',
      verified boolean default false,
      verify_token text,
      verify_expires timestamptz,
      reset_token text,
      reset_expires timestamptz,
      created_at timestamptz default now(),
      updated_at timestamptz default now()
    );
    create table if not exists device_quotas (
      device_id text not null,
      period_start date not null,
      text_count int default 0,
      photo_count int default 0,
      created_at timestamptz default now(),
      updated_at timestamptz default now(),
      primary key(device_id, period_start)
    );
  `);
  // rename old column if exists
  const cols = await pool.query(`
    select column_name from information_schema.columns where table_name='device_quotas'
  `);
  if (cols.rows.some(r => r.column_name === "day") &&
      !cols.rows.some(r => r.column_name === "period_start")) {
    await pool.query(`alter table device_quotas rename column day to period_start`);
    console.log("[migrate] renamed day → period_start");
  }
}
await ensureSchema();

// ---------------- helpers ----------------
const SJWT = JWT_SECRET || crypto.randomBytes(32).toString("hex");
function cookieOpt() {
  return { httpOnly: true, secure: true, sameSite: "None", path: "/", maxAge: 30*86400*1000 };
}
function setSession(res, payload) {
  res.cookie("sid", jwt.sign(payload, SJWT, { expiresIn: "30d" }), cookieOpt());
}
function readSession(req) {
  try { return jwt.verify(req.cookies.sid, SJWT); } catch { return null; }
}
const scrypt = util.promisify(crypto.scrypt);
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = (await scrypt(pw, salt, 64)).toString("hex");
  return { salt, hash };
}
async function verifyPassword(pw, salt, hash) {
  const buf = await scrypt(pw, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(buf.toString("hex"), "hex"));
}
async function getUser(email) {
  const r = await pool.query(`select * from users where email=$1`, [email]);
  return r.rows[0] || null;
}
async function setUserPass(email, pw) {
  const { salt, hash } = await hashPassword(pw);
  await pool.query(`update users set pass_salt=$2, pass_hash=$3 where email=$1`, [email, salt, hash]);
}

// ---------------- resend email util ----------------
async function resendSend({ to, subject, html, text }) {
  if (!RESEND_API_KEY || !RESEND_FROM) {
    console.warn("[MAIL] skipped; missing env");
    return;
  }
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from: RESEND_FROM, to: [to], subject, html, text })
  });
  if (!r.ok) console.error("[MAIL] fail", r.status, await r.text());
}
function verifyHtml(link) {
  return `<h2>Verify your email</h2><p>Click below:</p>
          <a href="${link}" style="background:#5865f2;color:#fff;padding:8px 14px;border-radius:6px;">Verify Email</a>`;
}
function resetHtml(link) {
  return `<h2>Reset Password</h2><p><a href="${link}">Reset here</a></p>`;
}

// ---------------- auth + verification ----------------
app.post("/api/signup-free", async (req, res) => {
  const { email, password } = req.body;
  if (!email) return res.status(400).json({ error: "email required" });
  const token = crypto.randomBytes(20).toString("hex");
  const until = new Date(Date.now() + 24*3600*1000);
  const u = await pool.query(
    `insert into users(email, verified, verify_token, verify_expires)
     values($1,false,$2,$3)
     on conflict(email) do update set verify_token=$2,verify_expires=$3 returning email,plan`,
    [email, token, until]
  );
  if (password?.length >= 8) await setUserPass(email, password);
  const link = `${req.protocol}://${req.get("host")}/api/verify-email?token=${token}`;
  await resendSend({ to: email, subject: "Verify your email", html: verifyHtml(link), text: link });
  setSession(res, { email, plan: u.rows[0].plan });
  res.json({ ok: true, verifySent: true });
});

app.get("/api/verify-email", async (req, res) => {
  const { token } = req.query;
  const r = await pool.query(
    `update users set verified=true, verify_token=null where verify_token=$1 returning email`,
    [token]
  );
  if (!r.rowCount) return res.status(400).send("Invalid or expired");
  res.redirect("/chat.html");
});

// resend verification
app.post("/api/verify/resend", async (req, res) => {
  const s = readSession(req);
  if (!s?.email) return res.status(401).json({ status: "unauthenticated" });
  const u = await getUser(s.email);
  if (!u) return res.status(401).json({ status: "unauthenticated" });
  if (u.verified) return res.json({ ok: true, already: true });
  const token = crypto.randomBytes(20).toString("hex");
  const until = new Date(Date.now() + 24*3600*1000);
  await pool.query(
    `update users set verify_token=$2,verify_expires=$3 where email=$1`,
    [u.email, token, until]
  );
  const link = `${req.protocol}://${req.get("host")}/api/verify-email?token=${token}`;
  await resendSend({ to: u.email, subject: "Verify your email", html: verifyHtml(link), text: link });
  res.json({ ok: true, sent: true });
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const u = await getUser(email);
  if (!u) return res.status(401).json({ error: "no account" });
  const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
  if (!ok) return res.status(401).json({ error: "bad credentials" });
  setSession(res, { email, plan: u.plan });
  res.json({ ok: true });
});
