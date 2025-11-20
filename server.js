// server.js - Full NAWALA + KOMINFO Checker API

import express from "express";
import cors from "cors";
import dns from "dns/promises";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

const WINDOW_MS = 10 * 60 * 1000;
const MAX_REQUESTS = 1000;
let rateStore = {};

function checkRateLimit(ip) {
  const now = Date.now();
  if (!rateStore[ip] || now > rateStore[ip].resetTime) {
    rateStore[ip] = { count: 0, resetTime: now + WINDOW_MS };
  }
  if (rateStore[ip].count >= MAX_REQUESTS) {
    return { allowed: false, remaining: 0, resetTime: rateStore[ip].resetTime };
  }
  rateStore[ip].count++;
  return {
    allowed: true,
    remaining: MAX_REQUESTS - rateStore[ip].count,
    resetTime: rateStore[ip].resetTime
  };
}

const BLOCK_IPS = [
  "180.178.101.216",
  "180.178.101.217",
  "36.37.64.13",
  "36.37.64.14"
];

const BLOCK_KEYWORDS = [
  "internet positif",
  "internet sehat",
  "nawala",
  "trust positif",
  "situs ini diblokir",
  "site blocked"
];

function cleanDomain(raw) {
  let d = raw.trim();
  d = d.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  return d.toLowerCase();
}

async function checkSingleDomain(domain) {
  const result = {
    originalUrl: domain,
    blocked: false,
    status: "Not Blocked",
    error: false
  };

  const clean = cleanDomain(domain);

  try {
    let ipBlocked = false;
    try {
      const records = await dns.resolve4(clean);
      for (const ip of records) {
        if (BLOCK_IPS.includes(ip)) ipBlocked = true;
      }
    } catch (_) {}

    let httpBlocked = false;

    async function tryFetch(url) {
      try {
        const res = await fetch(url, { redirect: "follow", timeout: 8000 });
        const status = res.status;
        let text = "";
        try { text = (await res.text()).toLowerCase(); } catch (_) {}
        if (status === 451 || status === 403) return true;
        for (const kw of BLOCK_KEYWORDS) {
          if (text.includes(kw)) return true;
        }
        return false;
      } catch (_) {
        return false;
      }
    }

    if (!ipBlocked) {
      httpBlocked =
        (await tryFetch("http://" + clean)) ||
        (await tryFetch("https://" + clean));
    }

    if (ipBlocked || httpBlocked) {
      result.blocked = true;
      result.status = "Blocked";
    }

  } catch (err) {
    result.error = true;
    result.status = "Error checking";
  }

  return result;
}

app.post("/check", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.connection.remoteAddress;

    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      return res.status(429).json({ error: "Rate limit exceeded", results: [], remaining: 0, resetTime: rate.resetTime });
    }

    const domains = req.body.domains || [];
    const results = await Promise.all(domains.map(checkSingleDomain));

    res.json({ results, remaining: rate.remaining, resetTime: rate.resetTime });

  } catch (e) {
    res.status(500).json({ error: "Server error", results: [] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("NAWALA Checker API running on port", PORT));
