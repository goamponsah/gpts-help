import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pkg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Get directory name for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// JWT secret - use environment variable in production
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Serve static files from 'public' directory
app.use(express.static(join(__dirname, 'public')));

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ status: 'error', message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userResult = await pool.query(
      'SELECT id, email, plan FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ status: 'error', message: 'User not found' });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
};

// API Routes

// Basic health check route
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    res.json({ 
      status: 'OK', 
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ 
      status: 'ERROR', 
      database: 'disconnected',
      error: error.message 
    });
  }
});

// Public config endpoint for Paystack
app.get('/api/public-config', (req, res) => {
  res.json({
    paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_your_public_key_here'
  });
});

// Sign up for free account
app.post('/api/signup-free', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Signup attempt for:', email);

    // Validation
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ status: 'error', message: 'Invalid email format' });
    }

    if (password.length < 8) {
      return res.status(400).json({ status: 'error', message: 'Password must be at least 8 characters' });
    }

    // Check if user already exists (case-insensitive)
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (existingUser.rows.length > 0) {
      console.log('User already exists:', email);
      return res.status(400).json({ status: 'error', message: 'User with this email already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const passHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (email, pass_hash, plan, created_at, updated_at) 
       VALUES ($1, $2, $3, NOW(), NOW()) 
       RETURNING id, email, plan`,
      [email.toLowerCase(), passHash, 'FREE']
    );

    const user = result.rows[0];
    console.log('User created successfully:', user.email);

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return success with redirect information
    res.json({
      status: 'success',
      message: 'Account created successfully',
      redirect: '/chat.html',
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('Signup error details:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Internal server error during signup',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Login attempt for:', email);

    // Validation
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required' });
    }

    // Find user (case-insensitive)
    const userResult = await pool.query(
      'SELECT id, email, pass_hash, plan FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (userResult.rows.length === 0) {
      console.log('User not found:', email);
      return res.status(401).json({ status: 'error', message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];
    console.log('User found:', user.email);

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.pass_hash);
    if (!isValidPassword) {
      console.log('Invalid password for:', email);
      return res.status(401).json({ status: 'error', message: 'Invalid email or password' });
    }

    console.log('Password valid for:', email);

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return success with redirect information
    res.json({
      status: 'success',
      message: 'Login successful',
      redirect: '/chat.html',
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('Login error details:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Internal server error during login',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get current user
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    res.json({
      status: 'success',
      user: {
        id: req.user.id,
        email: req.user.email,
        plan: req.user.plan
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ status: 'success', message: 'Logged out successfully' });
});

// Check if email exists (for frontend validation)
app.post('/api/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.json({ exists: false });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    res.json({ exists: existingUser.rows.length > 0 });
  } catch (error) {
    console.error('Check email error:', error);
    res.json({ exists: false });
  }
});

// Serve chat.html directly (protected route)
app.get('/chat.html', authenticateToken, (req, res) => {
  res.sendFile(join(__dirname, 'public', 'chat.html'));
});

// Paystack verification (placeholder - implement with actual Paystack API)
app.post('/api/paystack/verify', authenticateToken, async (req, res) => {
  try {
    const { reference } = req.body;

    // Here you would typically verify with Paystack API
    // This is a simplified version
    const paymentResult = await pool.query(
      'INSERT INTO paystack_receipts (email, reference, status, raw, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id',
      [req.user.email, reference, 'success', JSON.stringify({ verified: true })]
    );

    // Update user plan (example: upgrade to PLUS)
    await pool.query(
      'UPDATE users SET plan = $1, updated_at = NOW() WHERE id = $2',
      ['PLUS', req.user.id]
    );

    res.json({
      status: 'success',
      message: 'Payment verified and account upgraded',
      email: req.user.email
    });

  } catch (error) {
    console.error('Paystack verification error:', error);
    res.status(500).json({ status: 'error', message: 'Payment verification failed' });
  }
});

// Serve your main HTML file from public directory
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// For reset-password.html route
app.get('/reset-password.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'reset-password.html'));
});

// For all other routes, serve index.html (for SPA routing)
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// ---- Robust, idempotent schema setup ----
async function ensureSchema() {
  try {
    console.log('Starting database schema setup...');

    // 1) Create tables if missing
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            BIGSERIAL PRIMARY KEY,
        email         TEXT NOT NULL UNIQUE,
        pass_salt     TEXT,
        pass_hash     TEXT,
        plan          TEXT NOT NULL DEFAULT 'FREE',
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id            BIGSERIAL PRIMARY KEY,
        user_id       BIGINT,
        title         TEXT NOT NULL,
        archived      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS messages (
        id            BIGSERIAL PRIMARY KEY,
        conversation_id BIGINT,
        role          TEXT,
        content       TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS share_links (
        id               BIGSERIAL PRIMARY KEY,
        conversation_id  BIGINT,
        token            TEXT NOT NULL UNIQUE,
        revoked          BOOLEAN NOT NULL DEFAULT FALSE,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS paystack_receipts (
        id            BIGSERIAL PRIMARY KEY,
        email         TEXT,
        reference     TEXT NOT NULL UNIQUE,
        plan_code     TEXT,
        status        TEXT,
        raw           JSONB,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS password_resets (
        id            BIGSERIAL PRIMARY KEY,
        user_id       BIGINT,
        token_hash    TEXT NOT NULL,
        expires_at    TIMESTAMPTZ NOT NULL,
        used          BOOLEAN NOT NULL DEFAULT FALSE,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    console.log('Basic tables created/verified');

    // 2) Add any missing columns on legacy tables
    await pool.query(`
      ALTER TABLE IF EXISTS conversations
        ADD COLUMN IF NOT EXISTS user_id    BIGINT,
        ADD COLUMN IF NOT EXISTS title      TEXT NOT NULL DEFAULT 'New chat',
        ADD COLUMN IF NOT EXISTS archived   BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

      ALTER TABLE IF EXISTS messages
        ADD COLUMN IF NOT EXISTS conversation_id BIGINT,
        ADD COLUMN IF NOT EXISTS role           TEXT,
        ADD COLUMN IF NOT EXISTS content        TEXT,
        ADD COLUMN IF NOT EXISTS created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW();

      ALTER TABLE IF EXISTS share_links
        ADD COLUMN IF NOT EXISTS conversation_id BIGINT,
        ADD COLUMN IF NOT EXISTS token           TEXT,
        ADD COLUMN IF NOT EXISTS revoked         BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW();

      ALTER TABLE IF EXISTS password_resets
        ADD COLUMN IF NOT EXISTS user_id    BIGINT,
        ADD COLUMN IF NOT EXISTS token_hash TEXT,
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS used       BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    `);

    console.log('Missing columns added');

    // 3) Foreign keys (safe on duplicates)
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

    console.log('Foreign keys verified');

    // 4) Indexes
    await pool.query(`
      CREATE INDEX IF NOT EXISTS conversations_user_idx
        ON conversations(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS messages_conv_idx
        ON messages(conversation_id, id);
      CREATE INDEX IF NOT EXISTS password_resets_token_idx
        ON password_resets(token_hash);
      CREATE INDEX IF NOT EXISTS users_email_idx 
        ON users(LOWER(email));
    `);

    console.log('Database schema setup completed successfully');
  } catch (error) {
    console.error('Schema setup error:', error);
    throw error;
  }
}

// Initialize database and start server
async function startServer() {
  try {
    // Test database connection
    console.log('Testing database connection...');
    await pool.query('SELECT 1');
    console.log('Database connection successful');

    // Setup schema
    await ensureSchema();

    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server is running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🌐 Website: http://localhost:${PORT}`);
      console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
      console.log(`💬 Chat: http://localhost:${PORT}/chat.html`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
startServer();
