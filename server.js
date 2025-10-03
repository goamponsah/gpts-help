// server.js (Node 18+ / 22+, ESM)
// package.json should have: "type": "module"
// Railway ENV needed:
//  - PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY
//  - PLAN_CODE_PLUS_MONTHLY, PLAN_CODE_PRO_ANNUAL
//  - OPENAI_API_KEY, OPENAI_MODEL
//  - JWT_SECRET (recommended), FRONTEND_ORIGIN (if FE/BE split)

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";

// ---------- Resolve __dirname (ESM) ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- App & Middleware ----------
const app = express();

// ---- ENV
const {
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  OPENAI_API_KEY,
  OPENAI_MODEL,
  FRONTEND_ORIGIN,
} = process.env;

if (!OPENAI_API_KEY) {
  console.warn("[WARN] OPENAI_API_KEY is not set.");
}
if (!OPENAI_MODEL) {
  console.warn("[WARN] OPENAI_MODEL is not set. Falling back to 'gpt-4o-mini'.");
}

if (FRONTEND_ORIGIN) {
  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
    })
  );
}

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

// Serve static site
app.use(express.static(path.join(__dirname, "public")));

// Multer for image uploads (kept in memory)
const upload = multer({ storage: multer.memoryStorage() });

// ---------- JWT Session ----------
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");

function cookieOptions() {
  const crossSite = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true,               // Railway is HTTPS
    sameSite: crossSite ? "None" : "Lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  };
}

function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("sid", token, cookieOptions());
}

function clearSessionCookie(res) {
  res.clearCookie("sid", { ...cookieOptions(), maxAge: 0 });
}

function verifySession(req) {
  const { sid } = req.cookies || {};
  if (!sid) return null;
  try {
    return jwt.verify(sid, JWT_SECRET);
  } catch {
    return null;
  }
}

// ---------- Minimal In-Memory Conversations (replace with DB later) ----------
/*
  conversations: Map<email, Array<{id:number, title:string, messages:Array<{role:'user'|'assistant', content:string}>}>>
*/
const conversations = new Map();
let nextConvId = 1;

function getUserConvs(email) {
  if (!conversations.has(email)) conversations.set(email, []);
  return conversations.get(email);
}

// ---------- Helpers ----------
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

async function openaiChat(messages) {
  const model = OPENAI_MODEL || "gpt-4o-mini";
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.2,
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`OpenAI error ${r.status}: ${t}`);
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || "";
}

// ---------- Core Routes ----------

// Health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Public config for frontend (safe: public key + plan codes)
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY || null,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY || null,
    planProAnnual: PLAN_CODE_PRO_ANNUAL || null,
  });
});

// Free signup: create FREE user + set session cookie
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res
        .status(400)
        .json({ status: "error", message: "Valid email required" });
    }

    // TODO: Upsert into DB if you have one
    setSessionCookie(res, { email, plan: "FREE" });
    return res.json({ status: "success" });
  } catch (err) {
    console.error("signup-free error:", err);
    return res
      .status(500)
      .json({ status: "error", message: "Could not create free user" });
  }
});

// Who am I
app.get("/api/me", (req, res) => {
  const session = verifySession(req);
  if (!session?.email) {
    return res.status(401).json({ status: "unauthenticated" });
  }
  return res.json({
    status: "ok",
    user: { email: session.email, plan: session.plan || "FREE" },
  });
});

// Logout
app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// Verify Paystack transaction → set PLUS/PRO
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) {
      return res
        .status(400)
        .json({ status: "error", message: "Missing reference" });
    }

    const psRes = await fetch(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );
    const data = await psRes.json();

    if (data?.status && data?.data?.status === "success") {
      const customerEmail = data.data?.customer?.email || null;
      const planCode = data.data?.plan?.plan_code || null;
      const newPlan = mapPlanCodeToLabel(planCode);

      // TODO: persist to DB
      if (customerEmail) {
        setSessionCookie(res, { email: customerEmail, plan: newPlan });
      }

      return res.json({
        status: "success",
        email: customerEmail,
        plan: newPlan,
        reference,
      });
    }

    return res.json({ status: "pending", data });
  } catch (e) {
    console.error("verify error:", e);
    return res
      .status(500)
      .json({ status: "error", message: "Verification failed" });
  }
});

// (Optional) Webhook — build out later
app.post("/api/paystack/webhook", express.raw({ type: "*/*" }), (req, res) => {
  try {
    // const signature = req.headers["x-paystack-signature"];
    // Verify + handle charge.success etc.
    res.sendStatus(200);
  } catch (e) {
    console.error("webhook error:", e);
    res.sendStatus(200);
  }
});

// ---------- Conversations API (minimal in-memory) ----------

// List conversations
app.get("/api/conversations", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.json([]);
  const list = getUserConvs(String(userId)).map(({ id, title }) => ({
    id,
    title,
  }));
  res.json(list);
});

// Create conversation
app.post("/api/conversations", (req, res) => {
  const { userId, title } = req.body || {};
  if (!userId) return res.status(400).json({ error: "userId required" });
  const conv = { id: nextConvId++, title: (title || "New chat").trim(), messages: [] };
  getUserConvs(String(userId)).unshift(conv); // newest first
  res.json({ id: conv.id, title: conv.title });
});

// Rename conversation
app.patch("/api/conversations/:id", (req, res) => {
  const { userId, title } = req.body || {};
  const id = Number(req.params.id);
  if (!userId || !id) return res.status(400).json({ error: "bad request" });
  const list = getUserConvs(String(userId));
  const c = list.find(x => x.id === id);
  if (!c) return res.status(404).json({ error: "not found" });
  c.title = (title || "Untitled").trim();
  res.json({ ok: true });
});

// Delete conversation
app.delete("/api/conversations/:id", (req, res) => {
  const { userId } = req.body || {};
  const id = Number(req.params.id);
  if (!userId || !id) return res.status(400).json({ error: "bad request" });
  const list = getUserConvs(String(userId));
  const idx = list.findIndex(x => x.id === id);
  if (idx >= 0) list.splice(idx, 1);
  res.json({ ok: true });
});

// Get messages in a conversation
app.get("/api/conversations/:id", (req, res) => {
  const { userId } = req.query;
  const id = Number(req.params.id);
  if (!userId || !id) return res.status(400).json({ error: "bad request" });
  const list = getUserConvs(String(userId));
  const c = list.find(x => x.id === id);
  if (!c) return res.status(404).json({ error: "not found" });
  res.json({ id: c.id, title: c.title, messages: c.messages });
});

// ---------- Chat & Photo Solve ----------

// /api/chat: forwards to OpenAI chat completion
app.post("/api/chat", async (req, res) => {
  try {
    const { message, gptType, userId, conversationId } = req.body || {};
    if (!userId || !message) {
      return res.status(400).json({ error: "userId and message required" });
    }

    // find or create conversation
    const list = getUserConvs(String(userId));
    let conv = conversationId ? list.find(c => c.id === Number(conversationId)) : null;
    if (!conv) {
      conv = { id: nextConvId++, title: (message.slice(0, 40) || "New chat"), messages: [] };
      list.unshift(conv);
    }

    // build messages for OpenAI
    const system =
      gptType === "math"
        ? "You are Math GPT. Solve math problems step-by-step with clear reasoning, and show workings. Be accurate and concise."
        : "You are a helpful writing assistant. Be clear, structured, and helpful.";

    const msgs = [
      { role: "system", content: system },
      ...conv.messages.map(m => ({ role: m.role, content: m.content })),
      { role: "user", content: message },
    ];

    // store user message
    conv.messages.push({ role: "user", content: message });

    // call OpenAI
    const answer = await openaiChat(msgs);

    // store assistant message
    conv.messages.push({ role: "assistant", content: answer });

    res.json({ response: answer, conversationId: conv.id });
  } catch (e) {
    console.error("Chat error:", e);
    res.status(500).json({ error: "Chat failed" });
  }
});

// /api/photo-solve: accepts FormData image and uses OpenAI vision
app.post("/api/photo-solve", upload.single("image"), async (req, res) => {
  try {
    const { userId, gptType, conversationId, attempt } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId required" });
    if (!req.file) return res.status(400).json({ error: "image required" });

    const mime = req.file.mimetype || "image/png";
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${mime};base64,${b64}`;

    // find or create conversation
    const list = getUserConvs(String(userId));
    let conv = conversationId ? list.find(c => c.id === Number(conversationId)) : null;
    if (!conv) {
      conv = { id: nextConvId++, title: "Photo solve", messages: [] };
      list.unshift(conv);
    }

    const system =
      gptType === "math"
        ? "You are Math GPT. Read the problem from the image and solve it step-by-step. Explain clearly."
        : "You are a helpful assistant. Describe and analyze the content of the image, then answer the user's request.";

    const model = OPENAI_MODEL || "gpt-4o-mini";

    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: system },
          {
            role: "user",
            content: [
              { type: "text", text: attempt ? `Note from user: ${attempt}\nSolve:` : "Solve this problem step-by-step:" },
              { type: "image_url", image_url: { url: dataUrl } },
            ],
          },
        ],
        temperature: 0.2,
      }),
    });

    if (!r.ok) {
      const t = await r.text();
      throw new Error(`OpenAI vision error ${r.status}: ${t}`);
    }

    const data = await r.json();
    const answer = data?.choices?.[0]?.message?.content || "No result";

    conv.messages.push({ role: "user", content: attempt ? `(Photo) ${attempt}` : "(Photo uploaded)" });
    conv.messages.push({ role: "assistant", content: answer });

    res.json({ response: answer, conversationId: conv.id });
  } catch (e) {
    console.error("Photo solve error:", e);
    res.status(500).json({ error: "Photo solve failed" });
  }
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GPTs Help server running on :${PORT}`);
  if (!process.env.JWT_SECRET) {
    console.warn(
      "[WARN] JWT_SECRET not set. Using a random secret; sessions will reset on deploy."
    );
  }
});
