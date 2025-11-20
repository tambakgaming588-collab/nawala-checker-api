import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

app.get("/api/check", async (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({
      status: "error",
      message: "Domain tidak ditemukan"
    });
  }

  const url = "https://nawalacheck.skiddle.id/?domain=" + encodeURIComponent(domain);

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0"
      }
    });

    const result = await response.text();
    res.send(result);

  } catch (err) {
    res.status(500).json({
      status: "error",
      message: "Gagal mengambil data dari skiddle",
      error: err.message
    });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
