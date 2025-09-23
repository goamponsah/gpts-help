const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// CORS Middleware - FIXED
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// Environment variables
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// GPT Instructions
const gptInstructions = {
    'math': `You are Math GPT, a patient and helpful AI math tutor. Provide step-by-step explanations for math problems from basic arithmetic to calculus.`,
    'content': `You are Content GPT, a versatile AI content creation assistant. Help create high-quality content across various formats and tones.`
};

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ message: 'API is working!', timestamp: new Date() });
});

// Chat endpoint - FIXED
app.post('/api/chat', async (req, res) => {
    try {
        console.log('Chat request received:', req.body);
        
        const { message, gptType } = req.body;

        if (!OPENAI_API_KEY) {
            return res.json({ 
                response: '⚠️ API key not configured. Please check server setup.',
                error: 'Missing API key'
            });
        }

        // Test response (comment this out later)
        const testResponse = `🔧 Testing ${gptType} GPT: You asked "${message}". \n\nOpenAI integration will work once API key is properly configured.`;
        
        res.json({
            response: testResponse,
            usage: { total_tokens: 10 }
        });

    } catch (error) {
        console.error('API Error:', error);
        res.json({ 
            response: '❌ Sorry, I encountered an error. Please try again.',
            error: error.message 
        });
    }
});

// Serve dashboard
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 API Test: https://gpts-help-production.up.railway.app/api/test`);
    console.log(`🔑 OpenAI Key: ${OPENAI_API_KEY ? '✅ Configured' : '❌ Missing'}`);
});
