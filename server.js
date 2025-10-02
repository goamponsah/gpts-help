// server.js
import express from "express";
import bodyParser from "body-parser";
// If you're using Prisma or another ORM, import it here
// import { PrismaClient } from "@prisma/client";
// const prisma = new PrismaClient();

const app = express();
app.use(bodyParser.json());
app.use(express.static("public")); // serve index.html, chat.html, etc.

// Load env vars from Railway
const {
  PAYSTACK_PUBLIC_KEY,
  PAYSTACK_SECRET_KEY,
  PLAN_CODE_PLUS_MONTHLY,
  PLAN_CODE_PRO_ANNUAL,
} = process.env;

// ---------- 1) Public config (safe for frontend) ----------
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY,
    currency: "GHS",
    planPlusMonthly: PLAN_CODE_PLUS_MONTHLY,
    planProAnnual: PLAN_CODE_PRO_ANNUAL,
  });
});

// ---------- 2) Free signup ----------
app.post("/api/signup-free", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ status: "error", message: "Email required" });
    }

    // Example with Prisma (replace with your DB logic)
    /*
    const user = await prisma.user.upsert({
      where: { email },
      update: { plan: "FREE" },
      create: { email, plan: "FREE" },
    });
    */

    console.log(`Free user signup: ${email}`);
    return res.json({ status: "success", message: "Free account created" });
  } catch (err) {
    console.error("Error signing up free user", err);
    return res.status(500).json({ status: "error", message: "Could not create free user" });
  }
});

// ---------- 3) Verify Paystack transaction ----------
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body;
    if (!reference) {
      return res.status(400).json({ status: "error", message: "Missing reference" });
    }

    const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });

    const data = await psRes.json();

    if (data?.status && data?.data?.status === "success") {
      const email = data.data.customer.email;
      const plan = data.data.plan ? data.data.plan.plan_code : "ONE_TIME";

      // Example: mark subscription active in DB
      /*
      await prisma.user.upsert({
        where: { email },
        update: { plan },
        create: { email, plan },
      });
      */

      return res.json({ status: "success", email, plan, reference });
    }

    return res.json({ status: "pending", data });
  } catch (e) {
    console.error("Verification error:", e);
    return res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
