# 🛡️ Gaming Account Protector AI Bot

A Discord bot that monitors messages in real time, scans URLs against VirusTotal, runs heuristic analysis tuned for gaming threats (fake mods, crack downloads, phishing links, Nitro scams), and returns an **ALLOW / WARN / BLOCK** verdict automatically.

Built to protect Gen Z gamers on Discord — where most gaming malware is distributed.

---

## How It Works

```
Discord Message → URL Extraction → VirusTotal Scan → Heuristic Analysis → AI Classifier (partial) → ALLOW / WARN / BLOCK
```

| Verdict | When |
|---|---|
| ✅ ALLOW | No threat signals detected |
| ⚠️ WARN | Shortened URL, suspicious keywords, or moderate VT score |
| 🚨 BLOCK | 5+ VT vendors flagged, or known malware pattern matched |

---

## Tech Stack

`Python` · `discord.py` · `VirusTotal API` · `Gemini API (partial)` · `requests` · `cachetools`

---

## Setup

```bash
git clone https://github.com/your-username/gaming-account-protector-bot.git
cd gaming-account-protector-bot
pip install -r requirements.txt
cp .env.example .env   # add your API keys
python bot.py
```

**.env**
```env
DISCORD_TOKEN=your_token
VIRUSTOTAL_API_KEY=your_key
GEMINI_API_KEY=your_key        # optional
VT_BLOCK_THRESHOLD=5
VT_WARN_THRESHOLD=2
```

---

## Features

- Real-time URL extraction and scanning from Discord messages
- VirusTotal threat intelligence with TTL caching (stays within free tier)
- Heuristic engine: gaming keyword detection, shortened URL flagging, domain pattern analysis
- Modular decision engine with configurable thresholds
- Gemini API scaffolded for plain-language threat explanations *(not fully wired)*

---
## Demo

🎥 YouTube Demo:  
https://www.youtube.com/watch?v=YliCNjBy4No&t=1s

### Example Detection

Input:
```text
Free GTA download here: http://example.com/test.exe

Output: ⚠️ WARN — Suspicious gaming-related keywords detected

---

## Limitations

- No file/attachment scanning
- No persistent storage or logging database
- VirusTotal free tier: 4 requests/min
- Gemini integration incomplete
- No slash commands or web dashboard

---

## Roadmap

- [ ] Attachment/file hash scanning
- [ ] Slash commands (`/scan`, `/report`)
- [ ] Persistent threat logging (SQLite)
- [ ] Docker deployment
- [ ] Full Gemini integration for WARN explanations
- [ ] Real-time moderation dashboard

---

## Disclaimer

Academic prototype — not production-ready. Verdicts are probabilistic. Always exercise independent judgment before clicking unknown links.

---

*Open to feedback, internship opportunities, and collaboration in cybersecurity / security engineering.*