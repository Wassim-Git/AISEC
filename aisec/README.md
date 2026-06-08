# 🛡️ AISec – AI Security Assistant

> Protect remote workers from phishing, social engineering, and malicious links. Three layers of defense with explainable AI results.

![AISec Screenshot](docs/screenshot.png)

## ✨ Features

| Tool | What it does |
|------|-------------|
| **URL Scanner** | 21-feature XGBoost classifier + attack story timeline |
| **Email Inspector** | SPF/DKIM/DMARC analysis + NLP urgency detection + link scanning |
| **ChatCheck** | Role impersonation detection + social engineering pattern matching |

- 🧠 **96.2% accuracy** on PhiUSIIL test set
- 🌐 **Explainable AI** — plain English results for non-technical users
- ⚡ **Fallback AI** — uses Anthropic Claude when backend unavailable
- 📊 **Model Card** — full transparency at `/model`
- 🔒 **Zero data storage** — nothing is logged or retained

---
