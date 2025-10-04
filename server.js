import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pkg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import multer from 'multer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pkg;

// --- App & infra ---
const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1); // secure cookies behind proxy

// ES module dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// --- Database ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Config / Secrets ---
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || ''; // optional

// --- Middleware ---
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

// Request log (simple)
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// --- Auth middleware ---
const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ status: 'error', message: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userResult = await pool.query('SELECT id, email, plan FROM users WHERE id = $1', [decoded.userId]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ status: 'error', message: 'User not found' });
    }
    req.user = userResult.rows[0];
    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
};

// --- Utilities ---
const ok = (payload = {}) => ({ status: 'ok', ...payload });

// Multer for photo-solve (in-memory; not storing files on disk)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 6 * 1024 * 1024 } });

// --- HEALTH/DEBUG ---
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    const users = await pool.query('SELECT COUNT(*) AS count FROM users');
    const recent = await pool.query('SELECT email, created_at FROM users ORDER BY created_at DESC LIMIT 5');
    res.json(ok({
      database: 'connected',
      total_users: Number(users.rows[0].count),
      recent_users: recent.rows,
      timestamp: new Date().toISOString(),
    }));
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ status: 'error', database: 'disconnected', message: error.message });
  }
});

app.post('/api/debug/reset-users', async (_req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE email LIKE $1', ['%@%']);
    const remaining = await pool.query('SELECT COUNT(*) as count FROM users');
    res.json(ok({ message: 'Test users cleared', remaining_users: Number(remaining.rows[0].count) }));
  } catch (e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// --- Public config for frontend ---
app.get('/api/public-config', (_req, res) => {
  res.json(ok({ paystackPublicKey: PAYSTACK_PUBLIC_KEY || 'pk_test_placeholder' }));
});

// --- AUTH ---
app.post('/api/signup-free', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ status: 'error', message: 'Email and password are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ status: 'error', message: 'Invalid email format' });
    if (password.length < 8) return res.status(400).json({ status: 'error', message: 'Password must be at least 8 characters' });

    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (existing.rows.length) {
      return res.status(400).json({ status: 'error', message: 'An account with this email already exists. Please try logging in.' });
    }

    const passHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, pass_hash, plan, created_at, updated_at)
       VALUES ($1, $2, $3, NOW(), NOW())
       RETURNING id, email, plan`,
      [email.toLowerCase(), passHash, 'FREE']
    );
    const user = result.rows[0];

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json(ok({ message: 'Account created successfully!', redirect: '/chat.html', user }));
  } catch (e) {
    console.error('SIGNUP ERROR:', e);
    res.status(500).json({ status: 'error', message: 'Unable to create account. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ status: 'error', message: 'Email and password are required' });

    const userResult = await pool.query('SELECT id, email, pass_hash, plan FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (!userResult.rows.length) return res.status(401).json({ status: 'error', message: 'Invalid email or password' });

    const user = userResult.rows[0];
    const valid = await bcrypt.compare(password, user.pass_hash);
    if (!valid) return res.status(401).json({ status: 'error', message: 'Invalid email or password' });

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json(ok({ message: 'Login successful!', redirect: '/chat.html', user: { id: user.id, email: user.email, plan: user.plan } }));
  } catch (e) {
    console.error('LOGIN ERROR:', e);
    res.status(500).json({ status: 'error', message: 'Unable to login. Please try again.' });
  }
});

app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    res.json(ok({ user: { id: req.user.id, email: req.user.email, plan: req.user.plan } }));
  } catch (e) {
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/logout', (_req, res) => {
  res.clearCookie('token');
  res.json(ok({ message: 'Logged out successfully' }));
});

// --- PAYSTACK VERIFY (used by frontend callback) ---
app.post('/api/paystack/verify', authenticateToken, async (req, res) => {
  try {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ status: 'error', message: 'Missing reference' });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ status: 'error', message: 'Server missing PAYSTACK_SECRET_KEY' });

    const resp = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await resp.json();

    if (!data || data.status !== true) {
      return res.status(400).json({ status: 'error', message: 'Verification failed', raw: data });
    }
    const pay = data.data;
    if (pay.status !== 'success') {
      return res.status(400).json({ status: 'error', message: `Payment not successful: ${pay.status}` });
    }

    const planCode = pay.plan || pay.metadata?.plan || null;
    const mappedPlan =
      planCode === 'PLN_t8tii7sryvwsxxf' ? 'PLUS' :
      planCode === 'PLN_3gkd3qo1pv8rylt' ? 'PRO'  : 'PLUS';

    await pool.query('UPDATE users SET plan = $1, updated_at = NOW() WHERE id = $2', [mappedPlan, req.user.id]);

    res.json(ok({ message: 'Payment verified and plan updated', plan: mappedPlan, email: req.user.email }));
  } catch (e) {
    console.error('Verify error:', e);
    res.status(500).json({ status: 'error', message: 'Verification error' });
  }
});

// --- PAYSTACK WEBHOOK (optional but recommended) ---
app.post('/api/paystack/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    if (!PAYSTACK_SECRET_KEY) return res.sendStatus(500);
    const signature = req.headers['x-paystack-signature'];
    const computed = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
    if (!signature || signature !== computed) {
      console.warn('Webhook signature mismatch');
      return res.sendStatus(401);
    }

    const event = JSON.parse(req.body.toString('utf8'));
    const evt = event?.event;

    if (evt === 'charge.success' || String(evt).startsWith('subscription.')) {
      const paidEmail = event?.data?.customer?.email?.toLowerCase();
      const planCode  = event?.data?.plan || event?.data?.subscription_code || null;
      const mappedPlan =
        planCode === 'PLN_t8tii7sryvwsxxf' ? 'PLUS' :
        planCode === 'PLN_3gkd3qo1pv8rylt' ? 'PRO'  : 'PLUS';

      if (paidEmail) {
        const u = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [paidEmail]);
        if (u.rows.length) {
          await pool.query('UPDATE users SET plan = $1, updated_at = NOW() WHERE id = $2', [mappedPlan, u.rows[0].id]);
        }
      }
    }

    res.sendStatus(200);
  } catch (e) {
    console.error('Webhook error:', e);
    res.sendStatus(500);
  }
});

// --- CHAT DATA MODEL ENDPOINTS ---
// IMPORTANT: We DO NOT trust userId from the client; we always use req.user.id.

app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const rows = await pool.query(
      `SELECT id, title, archived, created_at, updated_at
         FROM conversations
        WHERE user_id = $1
        ORDER BY updated_at DESC, id DESC`,
      [req.user.id]
    );
    res.json(rows.rows);
  } catch (e) {
    console.error('/api/conversations error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to list conversations' });
  }
});

app.post('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const title = (req.body?.title || 'New chat').trim();
    const q = await pool.query(
      `INSERT INTO conversations (user_id, title, archived, created_at, updated_at)
       VALUES ($1, $2, false, NOW(), NOW())
       RETURNING id, title, archived`,
      [req.user.id, title]
    );
    res.json(q.rows[0]);
  } catch (e) {
    console.error('create conversation error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to create conversation' });
  }
});

app.patch('/api/conversations/:id', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { title, archived } = req.body || {};
    // ensure ownership
    const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });

    if (typeof title === 'string' && title.trim().length) {
      await pool.query('UPDATE conversations SET title=$1, updated_at=NOW() WHERE id=$2', [title.trim(), id]);
    }
    if (typeof archived === 'boolean') {
      await pool.query('UPDATE conversations SET archived=$1, updated_at=NOW() WHERE id=$2', [archived, id]);
    }
    res.json(ok());
  } catch (e) {
    console.error('rename/archive conversation error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to update conversation' });
  }
});

app.delete('/api/conversations/:id', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    // ensure ownership
    const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });
    await pool.query('DELETE FROM conversations WHERE id=$1', [id]);
    res.json(ok());
  } catch (e) {
    console.error('delete conversation error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to delete conversation' });
  }
});

app.get('/api/conversations/:id', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    // ensure ownership
    const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });

    const msgs = await pool.query(
      `SELECT role, content, created_at
         FROM messages
        WHERE conversation_id=$1
        ORDER BY id ASC`,
      [id]
    );
    res.json({ messages: msgs.rows });
  } catch (e) {
    console.error('get messages error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to get messages' });
  }
});

// --- CHAT COMPLETION (with optional OpenAI) ---
async function modelReply({ message, gptType }) {
  // Simple safe fallback if no OPENAI_API_KEY
  if (!OPENAI_API_KEY) {
    const assistant =
      gptType === 'math'
        ? "I'll walk you through the problem step-by-step. (Dev mode: set OPENAI_API_KEY to enable real solutions.)"
        : "Here's a clean, structured draft. (Dev mode: set OPENAI_API_KEY to enable real generation.)";
    return assistant;
  }

  // Basic OpenAI responses (Responses API or chat.completions). Using fetch for portability.
  const sys = gptType === 'math'
    ? "You are Math GPT. Solve clearly with steps, hints and multiple methods when useful."
    : "You are ContentGPT. Write concise, high-quality content with clear structure.";

  try {
    const resp = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: sys },
          { role: 'user', content: message }
        ],
        temperature: gptType === 'math' ? 0.2 : 0.7,
      }),
    });
    const data = await resp.json();
    const text = data?.choices?.[0]?.message?.content || 'No response.';
    return text;
  } catch (e) {
    console.error('OpenAI error:', e);
    return "I couldn't reach the model right now. Please try again.";
  }
}

app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, gptType = 'math', conversationId } = req.body || {};
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ status: 'error', message: 'Missing message' });
    }

    // ensure conversation or create
    let convId = Number(conversationId) || null;
    if (convId) {
      const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [convId, req.user.id]);
      if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });
    } else {
      const q = await pool.query(
        `INSERT INTO conversations (user_id, title, archived, created_at, updated_at)
         VALUES ($1, $2, false, NOW(), NOW())
         RETURNING id`,
        [req.user.id, 'New chat']
      );
      convId = q.rows[0].id;
    }

    // save user message
    await pool.query(
      `INSERT INTO messages (conversation_id, role, content, created_at)
       VALUES ($1, 'user', $2, NOW())`,
      [convId, message]
    );

    // model reply
    const replyText = await modelReply({ message, gptType });

    // save assistant message
    await pool.query(
      `INSERT INTO messages (conversation_id, role, content, created_at)
       VALUES ($1, 'assistant', $2, NOW())`,
      [convId, replyText]
    );

    // bump conversation updated_at
    await pool.query('UPDATE conversations SET updated_at = NOW() WHERE id = $1', [convId]);

    res.json({ conversationId: convId, response: replyText });
  } catch (e) {
    console.error('/api/chat error:', e);
    res.status(500).json({ status: 'error', message: 'Chat failed' });
  }
});

// --- PHOTO SOLVE ---
app.post('/api/photo-solve', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { gptType = 'math', conversationId, attempt = '' } = req.body || {};
    const file = req.file;
    if (!file) return res.status(400).json({ status: 'error', message: 'Missing image file' });

    // ensure conversation or create
    let convId = Number(conversationId) || null;
    if (convId) {
      const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [convId, req.user.id]);
      if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });
    } else {
      const q = await pool.query(
        `INSERT INTO conversations (user_id, title, archived, created_at, updated_at)
         VALUES ($1, $2, false, NOW(), NOW())
         RETURNING id`,
        [req.user.id, 'Photo: Uploaded']
      );
      convId = q.rows[0].id;
    }

    // save user message (describe image input)
    const note = attempt ? `User note: ${attempt}` : 'Photo uploaded.';
    await pool.query(
      `INSERT INTO messages (conversation_id, role, content, created_at)
       VALUES ($1, 'user', $2, NOW())`,
      [convId, note]
    );

    // Simple fallback text; if you wire image-to-text, replace this block
    let reply = "I received the image. (To enable visual solving, integrate an image-capable model.)";

    if (OPENAI_API_KEY) {
      // Optional: lightweight vision hint using gpt-4o-mini with image URL (you'd need to persist & serve it)
      // For now, we just acknowledge due to no CDN link.
      reply = gptType === 'math'
        ? "I have the photo. Describe the equation or crop the relevant part, and I’ll solve it step-by-step."
        : "I have the photo. Tell me what output you need (caption, blog intro, alt text, etc.).";
    }

    await pool.query(
      `INSERT INTO messages (conversation_id, role, content, created_at)
       VALUES ($1, 'assistant', $2, NOW())`,
      [convId, reply]
    );
    await pool.query('UPDATE conversations SET updated_at = NOW() WHERE id = $1', [convId]);

    res.json({ conversationId: convId, response: reply });
  } catch (e) {
    console.error('/api/photo-solve error:', e);
    res.status(500).json({ status: 'error', message: 'Photo solve failed' });
  }
});

// --- PUBLIC SHARE ---
function randomToken(len = 40) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

app.post('/api/share', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.body || {};
    const id = Number(conversationId);
    if (!id) return res.status(400).json({ status: 'error', message: 'Missing conversationId' });

    const own = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
    if (!own.rows.length) return res.status(404).json({ status: 'error', message: 'Conversation not found' });

    // reuse existing share if any
    const exists = await pool.query('SELECT token FROM shares WHERE conversation_id=$1', [id]);
    let token = exists.rows[0]?.token;
    if (!token) {
      token = randomToken(40);
      await pool.query(
        `INSERT INTO shares (conversation_id, token, created_at)
         VALUES ($1, $2, NOW())`,
        [id, token]
      );
    }
    const url = `${process.env.PUBLIC_BASE_URL || ''}${process.env.PUBLIC_BASE_URL ? '' : ''}/chat.html?t=${token}`;
    // If you deploy at domain root, PUBLIC_BASE_URL can be blank; location.origin will be used by the client anyway.

    res.json(ok({ url }));
  } catch (e) {
    console.error('/api/share error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to create share link' });
  }
});

app.get('/api/public/conversation', async (req, res) => {
  try {
    const token = String(req.query.t || '');
    if (!token) return res.status(400).json({ status: 'error', message: 'Missing token' });

    const s = await pool.query(
      `SELECT c.id, c.title
         FROM shares sh
         JOIN conversations c ON c.id = sh.conversation_id
        WHERE sh.token = $1`,
      [token]
    );
    if (!s.rows.length) return res.status(404).json({ status: 'error', message: 'Not found or expired' });

    const convId = s.rows[0].id;
    const msgs = await pool.query(
      `SELECT role, content, created_at
         FROM messages
        WHERE conversation_id=$1
        ORDER BY id ASC`,
      [convId]
    );
    res.json(ok({ title: s.rows[0].title, messages: msgs.rows }));
  } catch (e) {
    console.error('/api/public/conversation error:', e);
    res.status(500).json({ status: 'error', message: 'Failed to load public conversation' });
  }
});

// --- PAGES ---
app.get('/chat.html', authenticateToken, (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'chat.html'));
});

app.get('/', (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Alias so /reset-password (link in HTML) works
app.get('/reset-password', (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'reset-password.html'));
});
app.get('/reset-password.html', (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'reset-password.html'));
});

// Fallback to index.html (client-side routing, if any)
app.get('*', (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// --- SCHEMA ---
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      pass_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'FREE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      archived BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user','assistant')),
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shares (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_shares_conv ON shares(conversation_id);
  `);

  console.log('DB schema ready');
}

// --- START ---
async function startServer() {
  try {
    await pool.query('SELECT 1');
    console.log('Database connected');
    await ensureSchema();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🔗 Health: http://localhost:${PORT}/api/health`);
    });
  } catch (e) {
    console.error('Failed to start:', e);
    process.exit(1);
  }
}

// --- Error handler ---
app.use((err, _req, res, _next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

process.on('uncaughtException', (e) => console.error('Uncaught Exception:', e));
process.on('unhandledRejection', (r, p) => console.error('Unhandled Rejection at:', p, 'reason:', r));

startServer();

