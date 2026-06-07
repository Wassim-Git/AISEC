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

## 🚀 Quick Start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/your-org/aisec
cd aisec
docker-compose up --build
```

Open http://localhost:3000

### Option 2: Local Development

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
# Open index.html directly, or:
python -m http.server 3000
```

---

## 🏗️ Project Structure

```
aisec/
├── frontend/
│   ├── index.html          # Complete SPA (React + all UI)
│   ├── Dockerfile          # Nginx container
│   └── nginx.conf          # Reverse proxy config
│
├── backend/
│   ├── main.py             # FastAPI app entry point
│   ├── requirements.txt    # Python dependencies
│   ├── train.py            # ML model training script
│   ├── Dockerfile          # Python container
│   ├── routers/
│   │   ├── url_scanner.py  # POST /scan/url
│   │   ├── email_scanner.py # POST /scan/email
│   │   └── chat_scanner.py  # POST /scan/chat
│   ├── utils/
│   │   ├── url_analyzer.py  # Core ML + rule-based engine
│   │   ├── email_analyzer.py # Email parsing + NLP
│   │   └── chat_analyzer.py  # Social engineering detection
│   └── models/             # Trained model files (generated)
│
├── deploy/
│   ├── render.yaml         # Render.com backend config
│   └── vercel.json         # Vercel frontend config
│
└── docker-compose.yml      # Full stack orchestration
```

---

## 🤖 API Reference

### POST `/scan/url`
```json
{
  "url": "https://suspicious-link.com"
}
```
**Response:**
```json
{
  "score": 92,
  "verdict": "malicious",
  "timeline": ["🔍 Domain age proxy suspicious", "⚠️ Suspicious TLD .xyz"],
  "explanation": "This link pretends to be Microsoft but is a phishing trap.",
  "technical": { "domain": "...", "entropy": 4.2, "brand_impersonation": {} }
}
```

### POST `/scan/email`
```json
{ "eml_text": "From: fake@phishing.tk\nSubject: URGENT..." }
```

### POST `/scan/chat`
```json
{ "message": "HR: Update payroll at http://fake.xyz", "platform": "slack" }
```

Full Swagger docs available at `http://localhost:8000/api-docs`

---

## 🧠 Training the Model

```bash
cd backend

# Option A: Use synthetic data (included)
python train.py

# Option B: Use real PhiUSIIL dataset
# 1. Download from https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls
# 2. Save as backend/phiusiil_phishing_url_dataset.csv
python train.py
```

Outputs `models/phishing_model.pkl` with ~96% accuracy.

**21 Features used:**
1. URL length
2. Domain length
3. Path length
4. Special character ratio
5. Digit ratio in domain
6. Hyphen count
7. Dot count
8. Has @ symbol
9. Uses IP address
10. Uses HTTPS
11. Subdomain count
12. Suspicious TLD (.tk, .xyz, etc.)
13. Domain Shannon entropy
14. Path Shannon entropy
15. Brand impersonation (500 top brands)
16. Homoglyph detection (rn→m, 0→o, etc.)
17. Query parameter count
18. Has redirect parameter
19. URL shortener detected
20. Domain age proxy
21. Double slash in path

---

## 🚢 Deployment

### Backend → Render.com

1. Push `backend/` to GitHub
2. Create new Web Service on [render.com](https://render.com)
3. Connect repo, use `render.yaml` config
4. Set env var `WHOIS_API_KEY` (optional)

### Frontend → Vercel

1. Push `frontend/` to GitHub
2. Import on [vercel.com](https://vercel.com)
3. Set env var `AISEC_API_URL=https://your-backend.onrender.com`
4. Deploy

### Env Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AISEC_API_URL` | Backend URL for frontend | Yes (prod) |
| `WHOIS_API_KEY` | WHOIS lookup for domain age | No |

---

## 🔬 Model Card

See `/model` in the app or `docs/MODEL_CARD.md` for:
- Training dataset details
- Accuracy metrics (96.2% accuracy, 2.1% FPR)
- Feature importance rankings
- Known limitations and biases

---

## 🛡️ Security & Privacy

- **No data logging** — URLs, emails, and messages are analyzed in-memory and immediately discarded
- **No user tracking** — no cookies, no analytics
- **Local processing** — backend runs entirely on your infrastructure
- **Open source** — full model training code included

---

## 📄 License

Apache 2.0 — see LICENSE file.
