// server.js (ESM, Node 18+)
// package.json: { "type": "module" }
// npm i express cookie-parser cors jsonwebtoken multer pg
// ENV required: DATABASE_URL, JWT_SECRET, OPENAI_API_KEY, PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY
// Optional: PLAN_CODE_PLUS_MONTHLY, PLAN_CODE_PRO_ANNUAL, OPENAI_MODEL, PAYSTACK_CURRENCY, FRONTEND_ORIGIN

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

// ---------- Resolve __dirname ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- App ----------
const app = express();

// ---------- ENV ----------
const {
  DATABASE_URL,
  JWT_SECRET,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  PAYSTACK_CURRENCY = "GHS",
  FRONTEND_ORIGIN,
  NODE_ENV
} = process.env;

if (!DATABASE_URL) console.error("[ERROR] DATABASE_URL not set");
if (!JWT_SECRET) console.warn("[WARN] JWT_SECRET not set; set a stable value!");
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY not set");

const OPENAI_DEFAULT_MODEL = OPENAI_MODEL || "gpt-4o-mini";

// ---------- CORS / JSON / Cookies ----------
if (FRONTEND_ORIGIN) {
  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
}
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

// ---------- Static ----------
app.use(express.static(path.join(__dirname, "public")));

// Pretty URL for reset page
app.get("/reset-password", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});

// ---------- Uploads ----------
const upload = multer({ storage: multer.memoryStorage() });

// ---------- DB ----------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

// ---- Robust, idempotent schema setup (handles existing partial tables) ----
async function ensureSchema() {
  // 1) Create tables if missing (minimal columns; we add/alter next)
  await pool.query(`
    create table if not exists users (
      id            bigserial primary key,
      email         text not null unique,
      pass_salt     text,
      pass_hash     text,
      plan          text not null default 'FREE',
      created_at    timestamptz not null default now(),
      updated_at    timestamptz not null default now()
    );

    create table if not exists conversations (
      id            bigserial primary key,
      title         text not null,
      archived      boolean not null default false,
      created_at    timestamptz not null default now(),
      updated_at    timestamptz not null default now()
    );

    create table if not exists messages (
      id            bigserial primary key,
      role          text,
      content       text,
      created_at    timestamptz not null default now()
    );

    create table if not exists share_links (
      id               bigserial primary key,
      conversation_id  bigint,
      token            text not null unique,
      revoked          boolean not null default false,
      created_at       timestamptz not null default now()
    );

    create table if not exists paystack_receipts (
      id            bigserial primary key,
      email         text,
      reference     text not null unique,
      plan_code     text,
      status        text,
      raw           jsonb,
      created_at    timestamptz not null default now()
    );

    create table if not exists password_resets (
      id            bigserial primary key,
      user_id       bigint,
      token_hash    text not null,
      expires_at    timestamptz not null,
      used          boolean not null default false,
      created_at    timestamptz not null default now()
    );
  `);

  // 2) Add any missing columns on legacy tables
  await pool.query(`
    alter table if exists conversations
      add column if not exists user_id    bigint,
      add column if not exists title      text not null default 'New chat',
      add column if not exists archived   boolean not null default false,
      add column if not exists created_at timestamptz not null default now(),
      add column if not exists updated_at timestamptz not null default now();

    alter table if exists messages
      add column if not exists conversation_id bigint,
      add column if not exists role           text,
      add column if not exists content        text,
      add column if not exists created_at     timestamptz not null default now();

    alter table if exists share_links
      add column if not exists conversation_id bigint,
      add column if not exists token           text,
      add column if not exists revoked         boolean not null default false,
      add column if not exists created_at      timestamptz not null default now();

    alter table if exists password_resets
      add column if not exists user_id    bigint,
      add column if not exists token_hash text,
      add column if not exists expires_at timestamptz,
      add column if not exists used       boolean not null default false,
      add column if not exists created_at timestamptz not null default now();
  `);

  // 3) Add foreign keys idempotently (safe even if duplicates)
  await pool.query(`
    DO $$ BEGIN
      ALTER TABLE conversations
        ADD CONSTRAINT conversations_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE messages
        ADD CONSTRAINT messages_conversation_fk
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE share_links
        ADD CONSTRAINT share_links_conversation_fk
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE password_resets
        ADD CONSTRAINT password_resets_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
  `);

  // 4) Create indexes after columns exist
  await pool.query(`
    create index if not exists conversations_user_idx
      on conversations(user_id, created_at desc);

    create index if not exists messages_conv_idx
      on messages(conversation_id, id);

    create index if not exists password_resets_token_idx
      on password_resets(token_hash);
  `);
}
await ensureSchema();

// ---------- JWT ----------
const SJWT = JWT_SECRET || crypto.randomBytes(48).toString("hex");
function cookieOptions() {
  const cross = Boolean(FRONTEND_ORIGIN);
  return { httpOnly: true, secure: true, sameSite: cross ? "None" : "Lax", path: "/", maxAge: 30*24*60*60*1000 };
}
function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, SJWT, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}
function clearSessionCookie(res) { res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 }); }
function session(req) {
  const { sid } = req.cookies || {};
  if (!sid) return null;
  try { return jwt.verify(sid, SJWT); } catch { return null; }
}
function needEmail(req, res) {
  const s = session(req);
  if (!s?.email) { res.status(401).json({ status: "unauthenticated" }); return null; }
  return s.email;
}

// ---------- Password helpers ----------
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

// ---------- Misc helpers ----------
function sha256Hex(str){ return crypto.createHash('sha256').update(str).digest('hex'); }
function absoluteBaseUrl(req){
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host  = req.get('x-forwarded-host') || req.get('host');
  return `${proto}://${host}`;
}
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

async function upsertUser(email, plan = "FREE") {
  const r = await pool.query(
    `insert into users(email, plan) values($1,$2)
       on conflict(email) do update set email = excluded.email
     returning id, email, plan`,
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
  await pool.query(`update users set pass_salt=$2, pass_hash=$3, updated_at=now() where email=$1`, [email, salt, hash]);
}

async function openaiChat(messages) {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: OPENAI_DEFAULT_MODEL, messages, temperature: 0.2 })
  });
  if (!r.ok) throw new Error(`OpenAI ${r.status}: ${await r.text()}`);
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

// ---------- Health / Config ----------
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: PAYSTACK_CURRENCY || "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

// ---------- Auth ----------
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "Valid email required" });
    }
    const u = await upsertUser(email, "FREE");
    if (password && password.length >= 8) await setUserPassword(email, password);
    setSessionCookie(res, { email: u.email, plan: u.plan });
    res.json({ status: "success", user: { email: u.email }});
  } catch (e) {
    console.error("signup-free", e);
    res.status(500).json({ status: "error", message: "Could not create user" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ status:"error", message:"Email and password required" });
    const u = await getUserByEmail(email);
    if (!u) return res.status(401).json({ status:"error", message:"No account found. Please sign up." });

    // First password login sets the password (if migrating email-only users)
    if (!u.pass_hash) {
      if (password.length < 8) return res.status(400).json({ status:"error", message:"Password must be at least 8 characters." });
      await setUserPassword(email, password);
    } else {
      const ok = await verifyPassword(password, u.pass_salt, u.pass_hash);
      if (!ok) return res.status(401).json({ status:"error", message:"Invalid email or password." });
    }
    setSessionCookie(res, { email: u.email, plan: u.plan || "FREE" });
    res.json({ status:"ok", user: { email: u.email }});
  } catch (e) {
    console.error("login", e); res.status(500).json({ status:"error", message:"Login failed" });
  }
});

app.get("/api/me", async (req, res) => {
  const s = session(req);
  if (!s?.email) return res.status(401).json({ status:"unauthenticated" });
  const u = await getUserByEmail(s.email);
  if (!u) return res.status(401).json({ status:"unauthenticated" });
  res.json({ status:"ok", user:{ email: u.email, plan: u.plan }});
});

app.post("/api/logout", (_req, res) => { clearSessionCookie(res); res.json({ status:"ok" }); });

// ---------- Password reset ----------
app.post("/api/reset/request", async (req, res) => {
  try{
    const { email } = req.body || {};
    // Always return OK to avoid user enumeration
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.json({ status:"ok" });

    const u = await pool.query(`select id from users where email=$1`, [email]);
    if (!u.rowCount) return res.json({ status:"ok" });

    const userId = u.rows[0].id;
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = sha256Hex(token);
    const expires = new Date(Date.now() + 30*60*1000); // 30 mins

    await pool.query(
      `insert into password_resets(user_id, token_hash, expires_at) values($1,$2,$3)`,
      [userId, tokenHash, expires]
    );

    const link = `${absoluteBaseUrl(req)}/reset-password?t=${token}`;

    // TODO: email 'link' via provider; return dev link for now
    res.json({ status:"ok", devLink: link });
  }catch(e){
    console.error("reset/request", e);
    res.json({ status:"ok" });
  }
});

app.get("/api/reset/validate", async (req, res) => {
  try{
    const token = String(req.query.token || "");
    if (!token) return res.json({ valid:false });
    const tokenHash = sha256Hex(token);
    const r = await pool.query(
      `select 1 from password_resets
        where token_hash=$1 and used=false and expires_at>now() limit 1`,
      [tokenHash]
    );
    res.json({ valid: r.rowCount > 0 });
  }catch(e){ res.json({ valid:false }); }
});

app.post("/api/reset/confirm", async (req, res) => {
  try{
    const { token, newPassword } = req.body || {};
    if (!token || typeof newPassword !== "string" || newPassword.length < 8) {
      return res.status(400).json({ status:"error", message:"Invalid request" });
    }
    const tokenHash = sha256Hex(token);
    const r = await pool.query(
      `select pr.id, pr.user_id, u.email, u.plan
         from password_resets pr
         join users u on u.id = pr.user_id
        where pr.token_hash=$1 and pr.used=false and pr.expires_at>now()
        order by pr.id desc limit 1`,
      [tokenHash]
    );
    if (!r.rowCount) return res.status(400).json({ status:"error", message:"Invalid or expired token" });

    const { id: prId, user_id: userId, email, plan } = r.rows[0];
    const { salt, hash } = await (async ()=>{
      const s = crypto.randomBytes(16).toString("hex");
      const buf = await scrypt(newPassword, s, 64);
      return { salt: s, hash: buf.toString("hex") };
    })();

    await pool.query(`update users set pass_salt=$2, pass_hash=$3, updated_at=now() where id=$1`, [userId, salt, hash]);
    await pool.query(`update password_resets set used=true where id=$1`, [prId]);

    setSessionCookie(res, { email, plan: plan || "FREE" });
    res.json({ status:"ok" });
  }catch(e){
    console.error("reset/confirm", e);
    res.status(500).json({ status:"error", message:"Could not reset password" });
  }
});

// ---------- Paystack ----------
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status:"error", message:"Missing reference" });

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const data = await psRes.json();

    await pool.query(
      `insert into paystack_receipts(email, reference, plan_code, status, raw)
       values($1,$2,$3,$4,$5)
       on conflict(reference) do nothing`,
      [data?.data?.customer?.email || null, reference, data?.data?.plan?.plan_code || null, data?.data?.status || null, data]
    );

    if (data?.status && data?.data?.status === "success") {
      const customerEmail = data.data?.customer?.email || null;
      const planCode = data.data?.plan?.plan_code || null;
      const label = mapPlanCodeToLabel(planCode);
      if (customerEmail) {
        await upsertUser(customerEmail);
        if (label !== "ONE_TIME") {
          await pool.query(`update users set plan=$2, updated_at=now() where email=$1`, [customerEmail, label]);
        }
        setSessionCookie(res, { email: customerEmail, plan: label === "ONE_TIME" ? "FREE" : label });
      }
      return res.json({ status:"success", email: customerEmail, plan: label, reference });
    }
    res.json({ status:"pending", data });
  } catch (e) {
    console.error("paystack verify", e); res.status(500).json({ status:"error", message:"Verification failed" });
  }
});

// ---------- Auth guard helper ----------
async function requireUser(req, res) {
  const email = needEmail(req, res);
  if (!email) return null;
  const u = await getUserByEmail(email);
  if (!u) { res.status(401).json({ status:"unauthenticated" }); return null; }
  return u;
}

// ---------- Conversations ----------
app.get("/api/conversations", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const r = await pool.query(
    `select id, title, archived from conversations
     where user_id=$1 order by created_at desc`,
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
  if (!fields.length) return res.json({ ok:true });

  await pool.query(
    `update conversations set ${fields.join(", ")}, updated_at=now()
     where id=$1 and user_id=$${++idx}`,
    [id, ...values, u.id]
  );
  res.json({ ok:true });
});

app.delete("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  await pool.query(`delete from conversations where id=$1 and user_id=$2`, [id, u.id]);
  res.json({ ok:true });
});

app.get("/api/conversations/:id", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const conv = await pool.query(`select id, title from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!conv.rowCount) return res.status(404).json({ error:"not found" });
  const msgs = await pool.query(`select role, content, created_at from messages where conversation_id=$1 order by id`, [id]);
  res.json({ id, title: conv.rows[0].title, messages: msgs.rows });
});

// ---------- Share links (public, read-only consumer uses /api/share/:token) ----------
app.post("/api/conversations/:id/share", async (req, res) => {
  const u = await requireUser(req, res); if (!u) return;
  const id = Number(req.params.id);
  const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [id, u.id]);
  if (!own.rowCount) return res.status(404).json({ error:"not found" });

  const existing = await pool.query(`select token from share_links where conversation_id=$1 and revoked=false order by id desc limit 1`, [id]);
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
  if (!s.rowCount) return res.status(404).json({ error:"invalid_or_revoked" });
  const convId = s.rows[0].id;
  const msgs = await pool.query(`select role, content, created_at from messages where conversation_id=$1 order by id`, [convId]);
  res.json({ title: s.rows[0].title, messages: msgs.rows });
});

// ---------- Chat ----------
app.post("/api/chat", async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;
    const { message, gptType, conversationId } = req.body || {};
    if (!message) return res.status(400).json({ error:"message required" });

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(
        `insert into conversations(user_id, title) values($1,$2) returning id`,
        [u.id, (message.slice(0,40) || "New chat")]
      );
      convId = r.rows[0].id;
    }

    const hist = await pool.query(`select role, content from messages where conversation_id=$1 order by id`, [convId]);
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [{ role:"system", content: system }, ...hist.rows, { role:"user", content: message }];

    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`, [convId, "user", message]);

    const answer = await openaiChat(msgs);

    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`, [convId, "assistant", answer]);

    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("chat", e); res.status(500).json({ error:"Chat failed" });
  }
});

// ---------- Photo Solve ----------
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const u = await requireUser(req, res); if (!u) return;
    const { gptType, conversationId, attempt } = req.body || {};
    if (!req.file) return res.status(400).json({ error:"image required" });

    let convId = conversationId ? Number(conversationId) : null;
    if (convId) {
      const own = await pool.query(`select id from conversations where id=$1 and user_id=$2`, [convId, u.id]);
      if (!own.rowCount) convId = null;
    }
    if (!convId) {
      const r = await pool.query(`insert into conversations(user_id, title) values($1,$2) returning id`, [u.id, "Photo solve"]);
      convId = r.rows[0].id;
    }

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly."
        : "You are a helpful assistant. Describe and analyze the content of the image, then answer the user's request.";

    // record user "photo" note
    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`,
      [convId, "user", attempt ? `(Photo) ${attempt}` : "(Photo uploaded)"]);

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type":"application/json" },
      body: JSON.stringify({
        model: OPENAI_DEFAULT_MODEL,
        messages: [
          { role:"system", content: system },
          { role:"user",
            content: [
              { type:"text", text: attempt ? `Note from user: ${attempt}\nSolve:` : "Solve this problem step-by-step:" },
              { type:"image_url", image_url: { url: dataUrl } },
            ]
          }
        ],
        temperature: 0.2
      })
    });
    if (!r.ok) throw new Error(`OpenAI vision ${r.status}: ${await r.text()}`);
    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    await pool.query(`insert into messages(conversation_id, role, content) values($1,$2,$3)`, [convId, "assistant", answer]);
    res.json({ response: answer, conversationId: convId });
  } catch (e) {
    console.error("photo-solve", e); res.status(500).json({ error:"Photo solve failed" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
  if (!JWT_SECRET) {
    console.warn("[WARN] JWT_SECRET not set. Using a random secret; sessions reset on deploy.");
  }
});
