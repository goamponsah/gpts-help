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

// JWT secret
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

// Debug middleware to log all API requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

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

// Health check with detailed info
app.get('/api/health', async (req, res) => {
  try {
    const dbTest = await pool.query('SELECT 1 as test');
    const users = await pool.query('SELECT COUNT(*) as count FROM users');
    const userList = await pool.query('SELECT email, created_at FROM users ORDER BY created_at DESC LIMIT 5');
    
    res.json({ 
      status: 'OK', 
      database: 'connected',
      total_users: parseInt(users.rows[0].count),
      recent_users: userList.rows,
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

// Reset users table (for debugging - remove in production)
app.post('/api/debug/reset-users', async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE email LIKE $1', ['%@%']);
    const remaining = await pool.query('SELECT COUNT(*) as count FROM users');
    
    res.json({
      status: 'success',
      message: 'Test users cleared',
      remaining_users: parseInt(remaining.rows[0].count)
    });
  } catch (error) {
    console.error('Reset users error:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
});

// Public config
app.get('/api/public-config', (req, res) => {
  res.json({
    paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_your_public_key_here'
  });
});

// Sign up for free account - SIMPLIFIED VERSION
app.post('/api/signup-free', async (req, res) => {
  console.log('=== SIGNUP REQUEST ===');
  console.log('Body:', JSON.stringify(req.body));
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ status: 'error', message: 'Invalid email format' });
    }

    if (password.length < 8) {
      return res.status(400).json({ status: 'error', message: 'Password must be at least 8 characters' });
    }

    // Check if user exists - with detailed logging
    console.log('Checking if user exists:', email.toLowerCase());
    const existingUser = await pool.query(
      'SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    console.log('Existing users found:', existingUser.rows);

    if (existingUser.rows.length > 0) {
      console.log('User already exists, returning error');
      return res.status(400).json({ 
        status: 'error', 
        message: 'An account with this email already exists. Please try logging in.' 
      });
    }

    // Hash password
    console.log('Hashing password...');
    const passHash = await bcrypt.hash(password, 12);

    // Create user
    console.log('Creating user...');
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
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    console.log('Signup completed successfully for:', user.email);
    
    res.json({
      status: 'success',
      message: 'Account created successfully!',
      redirect: '/chat.html',
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('!!! SIGNUP ERROR !!!:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Unable to create account. Please try again.',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login - SIMPLIFIED VERSION
app.post('/api/login', async (req, res) => {
  console.log('=== LOGIN REQUEST ===');
  console.log('Body:', JSON.stringify(req.body));
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required' });
    }

    console.log('Looking for user:', email.toLowerCase());
    
    // Find user
    const userResult = await pool.query(
      'SELECT id, email, pass_hash, plan FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    console.log('Users found:', userResult.rows.length);

    if (userResult.rows.length === 0) {
      console.log('No user found with email:', email);
      return res.status(401).json({ status: 'error', message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];
    console.log('User found:', user.email);

    // Verify password
    console.log('Verifying password...');
    const isValidPassword = await bcrypt.compare(password, user.pass_hash);
    console.log('Password valid:', isValidPassword);

    if (!isValidPassword) {
      return res.status(401).json({ status: 'error', message: 'Invalid email or password' });
    }

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
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    console.log('Login successful for:', user.email);
    
    res.json({
      status: 'success',
      message: 'Login successful!',
      redirect: '/chat.html',
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('!!! LOGIN ERROR !!!:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Unable to login. Please try again.',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
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

// Serve chat.html (protected)
app.get('/chat.html', authenticateToken, (req, res) => {
  res.sendFile(join(__dirname, 'public', 'chat.html'));
});

// Serve main pages
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.get('/reset-password.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'reset-password.html'));
});

app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Database setup
async function ensureSchema() {
  try {
    console.log('Setting up database schema...');
    
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

    console.log('Users table ready');
    
  } catch (error) {
    console.error('Schema setup error:', error);
    throw error;
  }
}

// Start server
async function startServer() {
  try {
    await pool.query('SELECT 1');
    console.log('Database connected successfully');
    
    await ensureSchema();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🔗 Health: http://localhost:${PORT}/api/health`);
      console.log(`🐛 Debug: http://localhost:${PORT}/api/debug/reset-users (POST)`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

startServer();
