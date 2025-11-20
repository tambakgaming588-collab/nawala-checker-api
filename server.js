import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

const SKIDDLE_API = "https://check.skiddle.id/check?domains=";

// Rate limit sederhana (1000 / 10 menit)
let lastReset = Date.now();
let usage = {};

function rateLimit(ip) {
  const now = Date.now();
  if (now - lastReset > 600000) {
    lastReset = now;
    usage = {};
  }
  usage[ip] = (usage[ip] || 0) + 1;

  if (usage[ip] > 1000) return false;
  return true;
}

// API kamu sendiri, mirroring ke Skiddle
app.post("/check", async (req, res) => {
  try {
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.connection.remoteAddress;

    if (!rateLimit(ip)) {
      return res.status(429).json({ error: "Rate limit exceeded" });
    }

    const domains = req.body.domains;
    if (!domains || !domains.length) {
      return res.status(400).json({ error: "No domains provided" });
    }

    const url = SKIDDLE_API + domains.join(",");
    const response = await fetch(url);
    const data = await response.json();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("🔥 Skiddle Mirror API berjalan di port", PORT)
);
