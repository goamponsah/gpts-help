const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
// Enable CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
});
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// ===== CONFIGURATION - UPDATE THESE WITH YOUR KEYS =====
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
// ======================================================

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
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// OpenAI API endpoint
app.post('/api/chat', async (req, res) => {
    try {
        const { message, gptType, userId } = req.body;

        if (!users[userId]) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'gpt-4o',
            messages: [
                { role: 'system', content: gptInstructions[gptType] },
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

// Paystack payment initialization
app.post('/api/create-subscription', async (req, res) => {
    try {
        const { email, amount } = req.body;

        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: email,
            amount: amount * 100, // Convert to kobo
            currency: 'USD',
            callback_url: 'http://yourwebsite.com/payment-success'
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

// Paystack webhook (for payment verification)
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

// User authentication check
app.get('/api/user/:email', (req, res) => {
    const user = users[req.params.email];
    res.json({ subscribed: user?.subscribed || false });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT} to view your website`);
});

