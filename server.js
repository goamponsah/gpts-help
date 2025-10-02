import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());
app.use(express.static("public")); // serves index.html, chat.html, etc.

const { PAYSTACK_PUBLIC_KEY, PAYSTACK_SECRET_KEY } = process.env;

// 1) Public config endpoint (safe to expose public key)
app.get("/api/public-config", (_req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC_KEY,
    currency: "GHS"
  });
});

// 2) Payment verification (server-side, uses SECRET key)
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ status: "error", message: "Missing reference" });

    const ps = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const data = await ps.json();

    if (data?.status && data?.data?.status === "success") {
      // TODO: mark subscription active in your DB (Prisma/SQL)
      // TODO: store plan, customer email, Paystack customer id, next renewal date (if plan)
      return res.json({ status: "success", data: { reference } });
    }
    return res.json({ status: "pending", data });
  } catch (e) {
    return res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// 3) (Optional) Webhook to auto-sync renewals, charge.success etc.
app.post("/api/paystack/webhook", express.raw({ type: "*/*" }), (req, res) => {
  // You can validate the signature if you store the raw body to compute HMAC.
  // Update your DB based on event type: charge.success, invoice.create, subscription.disable, etc.
  res.sendStatus(200);
});

app.listen(process.env.PORT || 3000, () => console.log("Server running"));

