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
// ---------- more schema (conversations, messages, sharing, receipts) ----------
await pool.query(`
  create table if not exists conversations (
    id bigserial primary key,
    user_id bigint not null,
    title text not null,
    archived boolean default false,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
  );

  create table if not exists messages (
    id bigserial primary key,
    conversation_id bigint not null,
    role text not null,
    content text not null,
    created_at timestamptz default now()
  );

  create table if not exists share_links (
    id bigserial primary key,
    conversation_id bigint not null,
    token text unique not null,
    created_at timestamptz default now(),
    revoked boolean default false
  );

  create table if not exists paystack_receipts (
    id bigserial primary key,
    email text not null,
    reference text unique not null,
    plan_code text,
    status text,
    raw jsonb,
    created_at timestamptz default now()
  );
`);

// ---------- small utils ----------
function deviceCookieOptions() {
  return { ...cookieOpt(), httpOnly: false }; // readable by frontend
}
function ensureDevice(req, res) {
  let { did } = req.cookies || {};
  if (!did) {
    did = crypto.randomUUID();
    res.cookie("did", did, deviceCookieOptions());
  }
  return did;
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

// ---------- public config / health ----------
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null
  });
});

// ---------- me / logout ----------
app.get("/api/me", async (req, res) => {
  const s = readSession(req);
  if (!s?.email) return res.status(401).json({ status: "unauthenticated" });
  const u = await getUser(s.email);
  if (!u) return res.status(401).json({ status: "unauthenticated" });
  res.json({ status: "ok", user: { email: u.email, plan: u.plan || "FREE", verified: !!u.verified } });
});
app.post("/api/logout", (_req, res) => { res.clearCookie("sid", cookieOpt()); res.json({ ok: true }); });

// ---------- password reset (Resend) ----------
app.post("/api/password/forgot", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });
  const u = await getUser(email);
  if (!u) return res.json({ ok: true }); // do not reveal account existence
  const token = crypto.randomBytes(24).toString("hex");
  const until = new Date(Date.now() + 2 * 3600 * 1000);
  await pool.query(`update users set reset_token=$2, reset_expires=$3 where email=$1`, [email, token, until]);
  const link = `${req.protocol}://${req.get("host")}/reset.html?token=${token}`;
  await resendSend({ to: email, subject: "Reset your password — GPTs Help", html: resetHtml(link), text: link });
  res.json({ ok: true });
});

app.post("/api/password/reset", async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password || password.length < 8) return res.status(400).json({ error: "bad input" });
  const r = await pool.query(
    `select email from users where reset_token=$1 and (reset_expires is null or now()<=reset_expires)`,
    [token]
  );
  if (!r.rowCount) return res.status(400).json({ error: "invalid or expired" });
  const email = r.rows[0].email;
  await setUserPass(email, password);
  await pool.query(`update users set reset_token=null, reset_expires=null where email=$1`, [email]);
  res.json({ ok: true });
});

// ---------- Paystack verify ----------
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

app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ error: "missing reference" });
    const ps = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    }).then(r => r.json());

    const email = ps?.data?.customer?.email || null;
    const planCode = extractPlanCode(ps);
    const status = ps?.data?.status || null;

    await pool.query(
      `insert into paystack_receipts(email, reference, plan_code, status, raw)
       values($1,$2,$3,$4,$5)
       on conflict(reference) do nothing`,
      [email, reference, planCode, status, ps]
    );

    if (ps?.status && status === "success" && email) {
      const label = mapPlanCodeToLabel(planCode);
      await upsertUser(email);
      if (label !== "ONE_TIME")
        await pool.query(`update users set plan=$2 where email=$1`, [email, label]);
      setSession(res, { email, plan: label === "ONE_TIME" ? "FREE" : label });
      return res.json({ status: "success", email, plan: label, reference });
    }
    res.json({ status: "pending", data: ps });
  } catch (e) {
    console.error("paystack verify", e);
    res.status(500).json({ error: "verify failed" });
  }
});

// ---------- quotas ----------
const FREE_TEXT_LIMIT = 10;
const FREE_PHOTO_LIMIT = 2;

async function getQuota(deviceId) {
  const day = new Date().toISOString().slice(0,10);
  const r = await pool.query(
    `insert into device_quotas(device_id, period_start)
     values($1,$2)
     on conflict(device_id, period_start) do update set device_id=excluded.device_id
     returning text_count, photo_count`,
    [deviceId, day]
  );
  return { day, ...r.rows[0] };
}
async function bumpQuota(deviceId, kind) {
  const day = new Date().toISOString().slice(0,10);
  if (kind === "text") {
    await pool.query(
      `update device_quotas set text_count=text_count+1, updated_at=now()
       where device_id=$1 and period_start=$2`,
      [deviceId, day]
    );
  } else {
    await pool.query(
      `update device_quotas set photo_count=photo_count+1, updated_at=now()
       where device_id=$1 and period_start=$2`,
      [deviceId, day]
    );
  }
}

// ---------- auth-required helper (forces verification) ----------
async function requireVerifiedUser(req, res) {
  const s = readSession(req);
  if (!s?.email) { res.status(401).json({ status: "unauthenticated" }); return null; }
  const u = await getUser(s.email);
  if (!u) { res.status(401).json({ status: "unauthenticated" }); return null; }
  if (!u.verified) { res.status(403).json({ status: "verify_required" }); return null; }
  return u;
}

// ---------- (optional) title helper ----------
async function makeTitleFromOpenAI(prompt) {
  try {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        temperature: 0.2,
        messages: [
          { role: "system", content: "Create a short, 3–6 word title for a chat based on the user's latest message. No quotes." },
          { role: "user", content: prompt.slice(0, 300) }
        ]
      })
    });
    if (!r.ok) throw new Error("title api");
    const j = await r.json();
    return j?.choices?.[0]?.message?.content?.trim()?.slice(0, 60) || prompt.slice(0, 40);
  } catch {
    return prompt.slice(0, 40);
  }
}
// ---------- conversations ----------
app.get("/api/conversations", async (req, res) => {
  const u = await requireVerifiedUser(req, res); if (!u) return;
  const r = await pool.query(
    `select id, title, archived from conversations where user_id=$1 order by created_at desc`,
    [u.id]
  );
  res.json(r.rows);
});

app.post("/api/conversations", async (req, res) => {
  const u = await requireVerifiedUser(req, res); if (!u) return;
  const title = (req.body?.title || "New chat").trim();
  const r = await pool.query(
    `insert into conversations(user_id, title) values($1,$2) returning id, title`,
    [u.id, title]
  );
  res.json(r.rows[0]);
});

app.patch("/api/conversations/:id", async (req, res) => {
  const u = await requireVerifiedUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const { title, archived } = req.body || {};
  const fields = [], values = [];
  let i = 1;
  if (typeof title === "string") { fields.push(`title=$${++i}`); values.push(title.trim() || "Untitled"); }
  if (typeof archived === "boolean") { fields.push(`archived=$${++i}`); values.push(!!archived); }
  if (!fields.length) return res.json({ ok: true });
  await pool.query(
    `update conversations set ${fields.join(", ")}, updated_at=now()
     where id=$1 and user_id=$${++i}`,
    [id, ...values, u.id]
  );
  res.json({ ok: true });
});

app.delete("/api/conversations/:id", async (req, res) => {
  const u = await requireVerifiedUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  await pool.query(`delete from conversations where id=$1 and user_id=$2`, [id, u.id]);
  res.json({ ok: true });
});

app.get("/api/conversations/:id", async (req, res) => {
  const u = await requireVerifiedUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const conv = await pool.query(`select id, title from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!conv.rowCount) return res.status(404).json({ error: "not found" });
  const msgs = await pool.query(
    `select role, content, created_at from messages where conversation_id=$1 order by id`,
    [id]
  );
  res.json({ id, title: conv.rows[0].title, messages: msgs.rows });
});

// ---------- chat ----------
const upload = multer({ storage: multer.memoryStorage() });

app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireVerifiedUser(req, res); if (!u) return;
    const deviceId = ensureDevice(req, res);

    const { message, gptType, conversationId } = (req.body || {});
    if (!message) return res.status(400).json({ error: "message required" });

    // free-tier quota
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

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const title = await makeTitleFromOpenAI(message);
      const r = await pool.query(
        `insert into conversations(user_id, title) values($1,$2) returning id`,
        [u.id, title]
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

    if ((u.plan || "FREE") === "FREE") await bumpQuota(deviceId, "text");
    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// ---------- photo solve ----------
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireVerifiedUser(req, res); if (!u) return;
    const deviceId = ensureDevice(req, res);
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "image required" });

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

    if ((u.plan || "FREE") === "FREE") await bumpQuota(deviceId, "photo");
    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------- start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
});

