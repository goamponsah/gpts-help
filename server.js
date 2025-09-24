const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('.')); // Serve current directory

// Enable CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
});

// ===== CONFIGURATION =====
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

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

// OpenAI API endpoint
app.post('/api/chat', async (req, res) => {
    try {
        const { message, gptType, userId } = req.body;

        // For demo purposes, allow all users. In production, add proper authentication
        if (!OPENAI_API_KEY) {
            return res.status(500).json({ error: 'OpenAI API key not configured' });
        }

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'gpt-3.5-turbo', // Using 3.5-turbo for cost efficiency
            messages: [
                { role: 'system', content: gptInstructions[gptType] || gptInstructions['math'] },
                { role: 'user', content: message }
            ],
            max_tokens: 1000,
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
        res.status(500).json({ error: 'Failed to get response from AI' });
    }
});

// Simple subscription endpoint (for demo)
app.post('/api/subscribe', (req, res) => {
    const { email } = req.body;
    
    // For demo, just mark user as subscribed
    users[email] = { 
        subscribed: true, 
        subscriptionDate: new Date(),
        email: email
    };
    
    res.json({ 
        success: true, 
        message: 'Subscription activated (demo mode)',
        redirectUrl: '/dashboard'
    });
});

// Check subscription status
app.get('/api/user/:email', (req, res) => {
    const user = users[req.params.email];
    res.json({ subscribed: user?.subscribed || false });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OpenAI API Key configured: ${!!OPENAI_API_KEY}`);
});
