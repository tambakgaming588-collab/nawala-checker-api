// server.js - Full NAWALA + KOMINFO Checker API (GET + POST Ready)

import express from "express";
import cors from "cors";
import dns from "dns/promises";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

// Rate Limit
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
    resetTime: rateStore[ip].resetTime,
  };
}

// Kominfo/Nawala IP block list
const BLOCK_IPS = [
  "180.178.101.216",
  "180.178.101.217",
  "36.37.64.13",
  "36.37.64.14"
];

// Block keywords (internet positif, trust positif, dll)
const BLOCK_KEYWORDS = [
  "internet positif",
  "internet sehat",
  "nawala",
  "trust positif",
  "situs ini diblokir",
  "site blocked"
];

// Cleanup domain
function cleanDomain(raw) {
  let d = raw.trim();
  d = d.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  return d.toLowerCase();
}

// Core function cek domain
async function checkSingleDomain(domain) {
  const result = {
    originalUrl: domain,
    blocked: false,
    status: "Not Blocked",
    error: false
  };

  const clean = cleanDomain(domain);

  try {
    // Check IP block
    let ipBlocked = false;
    try {
      const records = await dns.resolve4(clean);
      for (const ip of records) {
        if (BLOCK_IPS.includes(ip)) ipBlocked = true;
      }
    } catch (_) {}

    // Check HTTP block
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

//
// ==========================
// POST /check (JSON)
// ==========================
//
app.post("/check", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0] ||
               req.connection.remoteAddress;

    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Rate limit exceeded",
        results: [],
        remaining: 0,
        resetTime: rate.resetTime
      });
    }

    const domains = req.body.domains || [];
    const results = await Promise.all(domains.map(checkSingleDomain));

    res.json({
      results,
      remaining: rate.remaining,
      resetTime: rate.resetTime
    });

  } catch (e) {
    res.status(500).json({ error: "Server error", results: [] });
  }
});

//
// ==========================
// GET /check?domains=a.com,b.com
// ==========================
//
app.get("/check", async (req, res) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0] ||
               req.connection.remoteAddress;

    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Rate limit exceeded",
        results: [],
        remaining: 0,
        resetTime: rate.resetTime
      });
    }

    const domainsParam = req.query.domains || "";
    const domains = domainsParam.split(",").map(d => d.trim()).filter(Boolean);

    if (domains.length === 0) {
      return res.json({ error: "No domains provided", results: [] });
    }

    const results = await Promise.all(domains.map(checkSingleDomain));

    res.json({
      results,
      remaining: rate.remaining,
      resetTime: rate.resetTime
    });

  } catch (e) {
    res.status(500).json({ error: "Server error", results: [] });
  }
});

// Run server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("NAWALA Checker API running on port", PORT)
);
