const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Debug environment variables immediately
console.log('=== ENVIRONMENT VARIABLES DEBUG ===');
console.log('OPENAI_API_KEY exists:', !!process.env.OPENAI_API_KEY);
console.log('Key length:', process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.length : 0);
console.log('Key starts with:', process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 10) + '...' : 'N/A');
console.log('All env vars:', Object.keys(process.env));
console.log('===================================');

// Middleware
app.use(express.json());
app.use(express.static('public'));

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
});

// Test endpoint with detailed debug info
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API is working!', 
        apiKeyExists: !!process.env.OPENAI_API_KEY,
        keyLength: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.length : 0,
        keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 10) + '...' : 'N/A',
        allEnvVars: Object.keys(process.env),
        timestamp: new Date() 
    });
});

// Chat endpoint - using process.env directly
app.post('/api/chat', async (req, res) => {
    try {
        console.log('🔍 Incoming chat request');
        console.log('🔑 API Key check:', process.env.OPENAI_API_KEY ? `Exists (${process.env.OPENAI_API_KEY.length} chars)` : 'MISSING');
        
        if (!process.env.OPENAI_API_KEY) {
            return res.json({ 
                response: '❌ OPENAI_API_KEY is missing from process.env. Check Railway Variables spelling and redeploy.',
                debug: {
                    keyExists: false,
                    allAvailableVars: Object.keys(process.env)
                }
            });
        }

        const { message, gptType = 'math' } = req.body;
        
        console.log('🤖 Calling OpenAI API...');
        
        // Call OpenAI API directly using process.env
        const openaiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'gpt-3.5-turbo',
            messages: [
                { 
                    role: 'system', 
                    content: gptType === 'math' 
                        ? 'You are a helpful math tutor. Explain concepts step by step.'
                        : 'You are a content creation assistant. Help write engaging content.'
                },
                { role: 'user', content: message }
            ],
            max_tokens: 500,
            temperature: 0.7
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });

        res.json({
            response: openaiResponse.data.choices[0].message.content,
            success: true
        });

    } catch (error) {
        console.error('💥 API Error:', error.response?.data || error.message);
        
        if (error.response?.status === 401) {
            res.json({ 
                response: '❌ Invalid OpenAI API Key. Please check the key in Railway Variables.',
                error: 'Authentication failed'
            });
        } else {
            res.json({ 
                response: '⚠️ Temporary issue: ' + (error.response?.data?.error?.message || error.message),
                error: true
            });
        }
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Test URL: https://gpts-help-production.up.railway.app/api/test`);
});
