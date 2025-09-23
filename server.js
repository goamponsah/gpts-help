// server.js
const express = require("express");
const cors = require("cors");
const OpenAI = require("openai"); // official SDK

const app = express();
app.use(cors());
app.use(express.json());

// IMPORTANT: Don't hardcode your key. Railway will inject process.env.OPENAI_API_KEY
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post("/api/ask", async (req, res) => {
  try {
    const { prompt } = req.body || {};
    if (!prompt) return res.status(400).json({ error: "Missing prompt" });

    // Use the modern Responses API
    const resp = await client.responses.create({
      model: "gpt-4.1-mini",
      input: prompt
    });

    // output_text is a helper that concatenates the response
    res.json({ output: resp.output_text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

// Railway gives you PORT via env var
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on ${PORT}`));

