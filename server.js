const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CONFIGURATION - UPDATE THESE WITH YOUR KEYS =====
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_CALLBACK_URL = process.env.PAYSTACK_CALLBACK_URL || 'https://yourdomain.com/payment-success';
// ======================================================

// ---- Basic startup checks ----
if (!OPENAI_API_KEY) {
  console.warn('[warn] OPENAI_API_KEY is not set. /api/chat will fail.');
}
if (!PAYSTACK_SECRET_KEY) {
  console.warn('[warn] PAYSTACK_SECRET_KEY is not set. Payments will fail.');
}

// CORS (incl. preflight)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// JSON body for normal routes
app.use(express.json());

// Static
app.use(express.static('public'));

// In-memory user storage (email is our canonical key)
let users = {};          // { [email]: { subscribed: boolean, subscriptionDate: Date } }
let subscriptions = {};  // { [email]: { active: boolean, plan: string } }

// GPT Instructions
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

// Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---- Helper: standard error payload without leaking secrets ----
function safeApiError(res, err, fallbackMsg) {
  const status = err?.response?.status || 500;
  const data = err?.response?.data;
  console.error('[server error]', {
    status,
    message: err?.message,
    openai: data?.error || data, // may include OpenAI message
  });
  return res.status(500).json({
    error: fallbackMsg,
    detail: data?.error?.message || err?.message || 'Unknown error'
  });
}

// ---- Chat endpoint ----
app.post('/api/chat', async (req, res) => {
  try {
    const { message, gptType = 'math', userId } = req.body;

    // Validate request
    if (typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message must be a non-empty string' });
    }
    if (!gptInstructions[gptType]) {
      return res.status(400).json({ error: `Invalid gptType. Use one of: ${Object.keys(gptInstructions).join(', ')}` });
    }
    if (!OPENAI_API_KEY) {
      return res.status(500).json({ error: 'Server missing OPENAI_API_KEY' });
    }

    // Use email as canonical id everywhere
    const email = userId; // if your frontend sends email as userId, keep this; otherwise rename on the client
    if (!users[email]?.subscribed) {
      return res.status(401).json({ error: 'User not authenticated or not subscribed' });
    }

    // OpenAI call
    const ai = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4o',
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
      usage: ai.data?.usage
    });
  } catch (err) {
    return safeApiError(res, err, 'Failed to get response from AI');
  }
});

// ---- Create subscription (Paystack) ----
app.post('/api/create-subscription', async (req, res) => {
  try {
    const { email, amount, currency = 'GHS' } = req.body;

    if (!email || !amount) {
      return res.status(400).json({ error: 'email and amount are required' });
    }
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: 'Server missing PAYSTACK_SECRET_KEY' });
    }

    const koboLike = Math.round(Number(amount) * 100);
    if (!Number.isFinite(koboLike) || koboLike <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }

    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email,
        amount: koboLike,
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

    // Pre-create user record (not yet subscribed)
    users[email] = users[email] || { subscribed: false };

    return res.json({ authorization_url: response.data?.data?.authorization_url });
  } catch (err) {
    return safeApiError(res, err, 'Payment initialization failed');
  }
});

// ---- Webhook: need raw body for signature verification ----
app.post('/api/paystack-webhook',
  express.raw({ type: '*/*' }), // raw body
  (req, res) => {
    try {
      const signature = req.headers['x-paystack-signature'];
      if (!signature || !PAYSTACK_SECRET_KEY) {
        return res.status(400).send('Missing signature or server key');
      }

      // Verify signature
      const hmac = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY);
      hmac.update(req.body);
      const expected = hmac.digest('hex');
      if (signature !== expected) {
        return res.status(401).send('Invalid signature');
      }

      // Now parse the raw body as JSON
      const event = JSON.parse(req.body.toString('utf8'));

      if (event?.event === 'charge.success') {
        const email = event?.data?.customer?.email || event?.data?.customer_email;
        if (email) {
          users[email] = { subscribed: true, subscriptionDate: new Date() };
          subscriptions[email] = { active: true, plan: 'monthly' };
          console.log(`Subscription activated for: ${email}`);
        }
      }

      return res.status(200).send('OK');
    } catch (err) {
      console.error('Webhook error:', err);
      return res.status(400).send('Webhook error');
    }
  }
);

// ---- User auth check ----
app.get('/api/user/:email', (req, res) => {
  const user = users[req.params.email];
  res.json({ subscribed: !!user?.subscribed });
});

// ---- Start server ----
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT}`);
});
