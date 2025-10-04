import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pkg from 'pg';
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

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Serve static files from 'public' directory
app.use(express.static(join(__dirname, 'public')));

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

// User authentication routes (placeholder - implement these)
app.post('/api/login', (req, res) => {
  res.json({ status: 'error', message: 'Login not implemented yet' });
});

app.post('/api/signup-free', (req, res) => {
  res.json({ status: 'error', message: 'Signup not implemented yet' });
});

app.get('/api/me', (req, res) => {
  res.json({ status: 'error', message: 'Session check not implemented' });
});

app.post('/api/paystack/verify', (req, res) => {
  res.json({ status: 'error', message: 'Paystack verification not implemented' });
});

// Serve your main HTML file from public directory
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// For chat.html route
app.get('/chat.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'chat.html'));
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
