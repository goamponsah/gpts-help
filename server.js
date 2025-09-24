app.get('/api/debug', (req, res) => {
    res.json({
        openaiKey: process.env.OPENAI_API_KEY ? '✅ Set' : '❌ Missing',
        nodeEnv: process.env.NODE_ENV || 'Not set',
        timestamp: new Date().toISOString()
    });
});
