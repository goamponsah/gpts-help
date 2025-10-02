// server.js (Node 18+ / 22+, ESM)
// Start with:  "type": "module"  in package.json
// Env you should set in Railway:
//   PAYSTACK_PUBLIC_KEY=pk_live_...
//   PAYSTACK_SECRET_KEY=sk_live_...
//   PLAN_CODE_PLUS_MONTHLY=PLN_t8tii7sryvwsxxf
//   PLAN_CODE_PRO_ANNUAL=PLN_3gkd3qo1pv8rylt
//   JWT_SECRET=some-long-random-string              (recommended)
//   FRONTEND_ORIGIN=https://gptshelp.online        (set if FE/BE are on different origins)

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ---------- Resolve __dirname (ESM) ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- App & Middleware ----------
const app = express();

// CORS: enable only if you have a separate frontend origin
const {
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
  FRONTEND_ORIGIN,
} = process.env;

if (FRONTEND_ORIGIN) {
  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
    })
  );
}

app.use(express.json());
app.use(cookieParser());

// Serve static files from /public (index.html, chat.html, etc.)
app.use(express.static(path.join(__dirname, "public")));

// ---------- JWT Session ----------
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");

function cookieOptions() {
  // If front and back are on different origins, you need SameSite=None and Secure.
  const crossSite = Boolean(FRONTEND_ORIGIN);
  return {
    httpOnly: true,
    secure: true, // Railway is HTTPS
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

// Map Paystack plan_code to internal plan label
function mapPlanCodeToLabel(planCode) {
  if (!planCode) return "ONE_TIME";
  if (planCode === PLAN_CODE_PLUS_MONTHLY) return "PLUS";
  if (planCode === PLAN_CODE_PRO_ANNUAL) return "PRO";
  return "ONE_TIME";
}

// ---------- Routes ----------

// Health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Public config for frontend (safe to expose PUBLIC key and plan codes)
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

    // TODO: Insert/upsert into your DB here (Prisma example commented)
    // await prisma.user.upsert({
    //   where: { email },
    //   update: { plan: "FREE" },
    //   create: { email, plan: "FREE" },
    // });

    setSessionCookie(res, { email, plan: "FREE" });
    return res.json({ status: "success" });
  } catch (err) {
    console.error("signup-free error:", err);
    return res
      .status(500)
      .json({ status: "error", message: "Could not create free user" });
  }
});

// Who am I: validate session cookie, return user info
app.get("/api/me", (req, res) => {
  const session = verifySession(req);
  if (!session?.email) {
    return res.status(401).json({ status: "unauthenticated" });
  }
  // Optionally fetch from DB to get latest plan; we return cookie payload for now
  return res.json({
    status: "ok",
    user: { email: session.email, plan: session.plan || "FREE" },
  });
});

// Logout: clear session
app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

// Verify Paystack payment and set PLUS/PRO session
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
      {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
      }
    );
    const data = await psRes.json();

    // Expecting: data.status === true and data.data.status === 'success'
    if (data?.status && data?.data?.status === "success") {
      const customerEmail = data.data?.customer?.email || null;
      const planCode = data.data?.plan?.plan_code || null;
      const newPlan = mapPlanCodeToLabel(planCode);

      // TODO: Persist to DB
      // await prisma.user.upsert({
      //   where: { email: customerEmail },
      //   update: { plan: newPlan },
      //   create: { email: customerEmail, plan: newPlan },
      // });

      if (customerEmail) {
        // Set/refresh session cookie with upgraded plan
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

// (Optional) Webhook: handle charge.success / invoices / subscription events
// IMPORTANT: Paystack webhooks require raw body to compute signature.
// If you implement signature verification, use express.raw({ type: "*/*" }) for this route.
// For now, we accept and 200 OK to avoid retries; add your own logic as needed.
app.post("/api/paystack/webhook", express.raw({ type: "*/*" }), (req, res) => {
  try {
    // const signature = req.headers["x-paystack-signature"];
    // Verify signature here if you store the raw body and compute HMAC with secret key.
    // const event = JSON.parse(req.body.toString("utf8"));
    // Handle event: event.event === 'charge.success', etc.
    res.sendStatus(200);
  } catch (e) {
    console.error("webhook error:", e);
    res.sendStatus(200); // Avoid repeated retries while you build logic
  }
});

// ---------- Fallback to SPA (optional) ----------
// If you want unknown routes to fall back to index.html for client-side routing:
// app.get("*", (_req, res) => {
//   res.sendFile(path.join(__dirname, "public", "index.html"));
// });

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
