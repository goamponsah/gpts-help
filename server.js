const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CONFIGURATION =====
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Middleware
app.use(express.json());
app.use(express.static('.')); // Serve from root directory, not 'public'

// Enable CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
});

// In-memory user storage (use a real database in production)
let users = {};
let subscriptions = {};

// GPT Instructions
const gptInstructions = {
    'math': `You are Math GPT, a patient and helpful AI math tutor. Your role is to help users understand mathematical concepts, not just provide answers. Always:
1. Provide step-by-step explanations
2. Ask clarifying questions if the problem is unclear
3. Use simple language and examples
4. Encourage learning and understanding
5. Cover topics from basic arithmetic to advanced calculus`,

    'content': `You are Content GPT, a versatile AI content creation assistant. Your role is to help users create high-quality content across various formats. Always:
1. Adapt to the user's requested tone (professional, casual, persuasive, etc.)
2. Provide structured, engaging content
3. Offer multiple options or variations when appropriate
4. Suggest improvements and optimizations
5. Help with brainstorming and idea generation`
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Debug endpoint to check environment variables
app.get('/api/debug-env', (req, res) => {
    res.json({
        openaiKey: process.env.OPENAI_API_KEY ? '✅ Set' : '❌ Missing',
        openaiKeyLength: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.length : 0,
        nodeEnv: process.env.NODE_ENV || 'Not set',
        timestamp: new Date().toISOString()
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// OpenAI API endpoint - UPDATED: Removed authentication for demo
app.post('/api/chat', async (req, res) => {
    try {
        const { message, gptType, userId } = req.body;

        // DEMO MODE: Allow all requests without authentication
        console.log(`Chat request from: ${userId || 'demo-user'}, GPT: ${gptType || 'math'}`);

        if (!OPENAI_API_KEY) {
            return res.status(500).json({ 
                error: 'OpenAI API key not configured on server. Please check Railway environment variables.' 
            });
        }

        // Use gpt-3.5-turbo for cost efficiency instead of gpt-4o
        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'gpt-3.5-turbo',
            messages: [
                { role: 'system', content: gptInstructions[gptType] || gptInstructions['math'] },
                { role: 'user', content: message }
            ],
            max_tokens: 800,
            temperature: 0.7
        }, {
            headers: {
                'Authorization': `Bearer ${OPENAI_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        res.json({
            response: response.data.choices[0].message.content,
            usage: response.data.usage
        });

    } catch (error) {
        console.error('OpenAI API error:', error.response?.data || error.message);
        
        // More detailed error response
        if (error.response?.status === 401) {
            res.status(500).json({ 
                error: 'Invalid OpenAI API key. Please check your Railway environment variables.' 
            });
        } else if (error.response?.status === 429) {
            res.status(500).json({ 
                error: 'OpenAI API rate limit exceeded. Please try again later.' 
            });
        } else {
            res.status(500).json({ 
                error: 'Failed to get response from AI: ' + (error.message || 'Unknown error') 
            });
        }
    }
});

// Simple subscription endpoint (for demo)
app.post('/api/subscribe', (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    // For demo, just mark user as subscribed
    users[email] = { 
        subscribed: true, 
        subscriptionDate: new Date(),
        email: email
    };
    
    console.log(`User subscribed: ${email}`);
    
    res.json({ 
        success: true, 
        message: 'Subscription activated (demo mode)',
        email: email
    });
});

// Check subscription status
app.get('/api/user/:email', (req, res) => {
    const user = users[req.params.email];
    res.json({ 
        subscribed: user?.subscribed || false,
        email: req.params.email
    });
});

// Paystack payment initialization (optional for future)
app.post('/api/create-subscription', async (req, res) => {
    try {
        const { email, amount } = req.body;

        if (!PAYSTACK_SECRET_KEY) {
            return res.status(500).json({ error: 'Paystack not configured' });
        }

        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: email,
            amount: amount * 100, // Convert to kobo
            currency: 'USD',
            callback_url: `https://${req.get('host')}/dashboard`
        }, {
            headers: {
                'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        res.json({
            authorization_url: response.data.data.authorization_url
        });

    } catch (error) {
        console.error('Paystack error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

// Paystack webhook (for payment verification) - optional for future
app.post('/api/paystack-webhook', async (req, res) => {
    try {
        const event = req.body;
        
        if (event.event === 'charge.success') {
            const { customer_email, amount } = event.data;
            
            // Activate user subscription
            users[customer_email] = { subscribed: true, subscriptionDate: new Date() };
            subscriptions[customer_email] = { active: true, plan: 'monthly' };
            
            console.log(`Subscription activated for: ${customer_email}`);
        }
        
        res.status(200).send('Webhook processed');
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(400).send('Webhook error');
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OpenAI API Key configured: ${!!OPENAI_API_KEY}`);
    console.log(`Open http://localhost:${PORT} to view your website`);
    console.log(`Debug endpoint: http://localhost:${PORT}/api/debug-env`);
});
