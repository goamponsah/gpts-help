// server.js
const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ENV / CONFIG =====
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL   = process.env.OPENAI_MODEL || 'gpt-4o'; // set to 'gpt-4.1' in Railway to pin to GPT-4.1
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY; // optional, for client use
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_CALLBACK_URL =
  process.env.PAYSTACK_CALLBACK_URL ||
  'https://gpts-help-production.up.railway.app/payment-success';

// ===== STARTUP CHECKS =====
if (!OPENAI_API_KEY) console.warn('[warn] OPENAI_API_KEY is not set.');
if (!PAYSTACK_SECRET_KEY) console.warn('[warn] PAYSTACK_SECRET_KEY is not set. Payments will fail.');
console.log('[info] Using OpenAI model:', OPENAI_MODEL);

// ===== IN-MEMORY STORAGE (use a DB in prod) =====
let users = {};          // { [email]: { subscribed: boolean, subscriptionDate: Date } }
let subscriptions = {};  // { [email]: { active: boolean, plan: string } }

// ===== CORS (incl. preflight) =====
// Tighten Access-Control-Allow-Origin to your frontend origin for production
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // e.g. 'https://your-frontend.com'
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization'
  );
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/**
 * IMPORTANT: Paystack webhook must use RAW body for signature verification.
 * Register BEFORE app.use(express.json()) so JSON parser doesn't alter bytes.
 */
app.post('/api/paystack-webhook', express.raw({ type: '*/*' }), (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    if (!signature || !PAYSTACK_SECRET_KEY) {
      return res.status(400).send('Missing signature or server key');
    }

    const hmac = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY);
    hmac.update(req.body);
    const expected = hmac.digest('hex');
    if (signature !== expected) {
      return res.status(401).send('Invalid signature');
    }

    const event = JSON.parse(req.body.toString('utf8'));
    if (event?.event === 'charge.success') {
      const email = event?.data?.customer?.email || event?.data?.customer_email;
      if (email) {
        users[email] = { subscribed: true, subscriptionDate: new Date() };
        subscriptions[email] = { active: true, plan: 'monthly' };
        console.log(`[paystack] Subscription activated for: ${email}`);
      }
    }

    return res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(400).send('Webhook error');
  }
});

// ===== NORMAL MIDDLEWARE (after webhook) =====
app.use(express.json());
app.use(express.static('public')); // ensure /public exists or remove

// ===== GPT INSTRUCTIONS =====
const gptInstructions = {
  math: `You are Math GPT, a patient and helpful AI math tutor. Your role is to help users understand mathematical concepts, not just provide answers. Always:
1. Provide step-by-step explanations
2. Ask clarifying questions if the problem is unclear
3. Use simple language and examples
4. Encourage learning and understanding
5. Cover topics from basic arithmetic to advanced calculus`,
  content: `You are Content GPT, a versatile AI content creation assistant. Your role is to help users create high-quality content across various formats. Always:
1. Adapt to the user's requested tone (professional, casual, persuasive, etc.)
2. Provide structured, engaging content
3. Offer multiple options or variations when appropriate
4. Suggest improvements and optimizations
5. Help with brainstorming and idea generation`
};

// ===== HELPERS =====
function safeApiError(res, err, fallbackMsg) {
  const status = err?.response?.status || 500;
  const data = err?.response?.data;
  console.error('[server error]', {
    status,
    message: err?.message,
    data: data?.error || data
  });
  return res.status(500).json({
    error: fallbackMsg,
    detail: data?.error?.message || err?.message || 'Unknown error'
  });
}

// ===== ROUTES =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Simple success page (callback after Paystack payment)
app.get('/payment-success', (req, res) => {
  res.type('html').send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Payment Success</title></head>
      <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 40px;">
        <h1>Payment Successful</h1>
        <p>Thank you! Your payment was successful. You can now return to the app.</p>
      </body>
    </html>
  `);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    hasOpenAI: !!OPENAI_API_KEY,
    model: OPENAI_MODEL,
    time: new Date().toISOString()
  });
});

// Quick probe to verify OpenAI key/model from the server
app.get('/api/ping-openai', async (req, res) => {
  try {
    const r = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: OPENAI_MODEL,
        messages: [{ role: 'user', content: 'Say OK' }]
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 20000
      }
    );
    res.json({ ok: true, text: r.data?.choices?.[0]?.message?.content || '' });
  } catch (e) {
    console.error('ping-openai error:', e?.response?.status, e?.response?.data || e?.message);
    res.status(500).json({ ok: false });
  }
});

// Temporary debug login to mark a user as subscribed (remove in production)
app.post('/api/debug-login', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });
  users[email] = { subscribed: true, subscriptionDate: new Date() };
  subscriptions[email] = { active: true, plan: 'monthly' };
  res.json({ ok: true });
});

// OpenAI chat endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const { message, gptType = 'math', userId } = req.body;

    if (!OPENAI_API_KEY) {
      return res.status(500).json({ error: 'Server missing OPENAI_API_KEY' });
    }
    if (typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'Message must be a non-empty string' });
    }
    if (!gptInstructions[gptType]) {
      return res
        .status(400)
        .json({ error: `Invalid gptType. Use one of: ${Object.keys(gptInstructions).join(', ')}` });
    }

    // Canonical user key is email; treat userId as email
    const email = userId;
    if (!email || !users[email]?.subscribed) {
      return res.status(401).json({ error: 'User not authenticated or not subscribed' });
    }

    const ai = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: OPENAI_MODEL,
        messages: [
          { role: 'system', content: gptInstructions[gptType] },
          { role: 'user', content: message }
        ],
        max_tokens: 1000,
        temperature: 0.7
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 45000
      }
    );

    return res.json({
      response: ai.data?.choices?.[0]?.message?.content ?? '',
      usage: ai.data?.usage,
      model: OPENAI_MODEL
    });
  } catch (err) {
    return safeApiError(res, err, 'Failed to get response from AI');
  }
});

// Paystack payment initialization
app.post('/api/create-subscription', async (req, res) => {
  try {
    const { email, amount, currency = 'USD' } = req.body; // change to 'GHS' if billing in Ghana
    if (!email || amount == null) {
      return res.status(400).json({ error: 'email and amount are required' });
    }
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: 'Server missing PAYSTACK_SECRET_KEY' });
    }

    const minorUnits = Math.round(Number(amount) * 100); // cents/USD, pesewas/GHS, kobo/NGN
    if (!Number.isFinite(minorUnits) || minorUnits <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }

    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email,
        amount: minorUnits,
        currency, // 'GHS' for Ghana, 'NGN' for Nigeria, 'USD' if enabled on your account
        callback_url: PAYSTACK_CALLBACK_URL,
        metadata: { plan: 'monthly' }
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );

    // Pre-create user record (not subscribed yet)
    users[email] = users[email] || { subscribed: false };

    return res.json({ authorization_url: response.data?.data?.authorization_url });
  } catch (err) {
    return safeApiError(res, err, 'Payment initialization failed');
  }
});

// Simple user subscription check
app.get('/api/user/:email', (req, res) => {
  const user = users[req.params.email];
  res.json({ subscribed: !!user?.subscribed });
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT}`);
});
