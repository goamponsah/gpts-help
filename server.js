// server.js
const express = require("express");
const cors = require("cors");
const OpenAI = require("openai"); // official SDK

const app = express();
app.use(cors());
app.use(express.json());

// Use your OpenAI key from environment variables (set in Railway dashboard)
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

app.post("/api/ask", async (req, res) => {
  try {
    const { prompt } = req.body || {};
    if (!prompt) {
      return res.status(400).json({ error: "Missing prompt" });
    }

    // Call OpenAI Responses API
    const response = await client.responses.create({
      model: "gpt-4.1-mini", // you can also use gpt-4.1 or gpt-3.5 if preferred
      input: prompt,
    });

    // Send back concatenated text output
    res.json({ output: response.output_text });
  } catch (err) {
    console.error("OpenAI API Error:", err.response?.data || err.message);
    res
      .status(500)
      .json({ error: err.response?.data || err.message || "Server error" });
  }
});

// Railway assigns a PORT env var automatically
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ API listening on port ${PORT}`);
});

