const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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

// DEBUG: Check all environment variables
console.log('🔍 Environment Variables Check:');
console.log('OPENAI_API_KEY exists:', !!process.env.OPENAI_API_KEY);
console.log('All env vars:', Object.keys(process.env));

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Simple test
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API is working!', 
        apiKeyExists: !!OPENAI_API_KEY,
        keyLength: OPENAI_API_KEY ? OPENAI_API_KEY.length : 0,
        timestamp: new Date() 
    });
});

// Chat endpoint
app.post('/api/chat', async (req, res) => {
    try {
        console.log('📝 Request received');
        
        if (!OPENAI_API_KEY) {
            return res.json({ 
                response: '❌ OPENAI_API_KEY is missing or empty. Check Railway Variables tab.',
                debug: {
                    keyExists: !!OPENAI_API_KEY,
                    keyLength: OPENAI_API_KEY ? OPENAI_API_KEY.length : 0
                }
            });
        }

        const { message, gptType } = req.body;
        
        // Test with real OpenAI API
        const openaiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'gpt-3.5-turbo',
            messages: [
                { role: 'system', content: `You are a helpful ${gptType} assistant.` },
                { role: 'user', content: message }
            ],
            max_tokens: 150
        }, {
            headers: {
                'Authorization': `Bearer ${OPENAI_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        res.json({
            response: openaiResponse.data.choices[0].message.content,
            success: true
        });

    } catch (error) {
        console.error('OpenAI API Error:', error.response?.data || error.message);
        res.json({ 
            response: '⚠️ API connection issue: ' + (error.response?.data?.error?.message || error.message),
            error: true
        });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔑 API Key Status: ${OPENAI_API_KEY ? '✅ Loaded' : '❌ Missing'}`);
});
