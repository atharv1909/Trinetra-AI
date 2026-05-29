# 👁 Trinetra AI — Phishing Detection System

> AI/ML-based phishing detection focused on targeted brand impersonation.  
> Detects when a malicious website is pretending to be a real organization — using three independent analysis layers, a trained ML model, and a real-time Chrome extension.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [How It Works](#2-how-it-works)
3. [Project Structure](#3-project-structure)
4. [The Three Eyes](#4-the-three-eyes)
5. [ML Model](#5-ml-model)
6. [Scoring System](#6-scoring-system)
7. [Backend API](#7-backend-api)
8. [Chrome Extension](#8-chrome-extension)
9. [Target Organizations](#9-target-organizations)
10. [Results](#10-results)
11. [Setup](#11-setup)
12. [Tech Stack](#12-tech-stack)

---

## 1. Problem Statement

Phishing attacks work by impersonating trusted organizations. A fake website that looks exactly like SBI's NetBanking login, or a URL like `paypa1.com` that tricks users into thinking it's PayPal.

Generic phishing detectors ask: *"Does this URL look suspicious?"*

**Trinetra asks: "Is this URL specifically trying to impersonate SBI, PayPal, Google, or Microsoft?"**

That targeted approach is the core idea. It combines URL pattern analysis, visual clone detection, behavioral analysis, and a trained ML model — all working together to produce a single risk score.

---

## 2. How It Works

```
User visits a website
        │
        ▼
Chrome Extension (content.js)
  → Captures current URL
  → Sends to background.js
        │
        ▼
background.js
  → POST /scan  →  FastAPI Backend
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
           Eye 1      Eye 3     ML Model
           ~10ms      ~1-2s     ~50ms
           URL        HTML      XGBoost
           Analysis   Behavior  Prediction
              │         │         │
              └─────────┴─────────┘
                        │
                     Scorer
                  (weighted blend)
                        │
                        ▼
               Eye 2 (async background)
               Visual Screenshot Compare
               ~3-5s, updates result when done
                        │
                        ▼
              SAFE / LOW / MEDIUM / HIGH
                        │
                        ▼
         Chrome Extension Popup
         Badge + Score + Flags + Notification
```

Eye 1 + Eye 3 + ML run synchronously and return in under 2 seconds.  
Eye 2 runs in the background and updates the scan result when done — so the user sees a result fast without waiting for the screenshot.

---

## 3. Project Structure

```
trinetra-ai/
│
├── backend/
│   ├── main.py                    # FastAPI server — all endpoints
│   ├── eye1_url.py                # URL + brand intelligence
│   ├── eye2_visual.py             # Visual screenshot comparison
│   ├── eye3_behavior.py           # HTML behavioral analysis
│   ├── ml_model.py                # XGBoost model loader + predictor
│   ├── scorer.py                  # Hybrid weighted scoring
│   ├── database.py                # SQLite storage
│   │
│   └── data/
│       ├── brand_profiles/
│       │   └── profiles.json      # Brand definitions for 6 orgs
│       ├── typosquat_variants/    # Pre-generated dnstwist variants
│       ├── homoglyph_map.json     # Cyrillic/Greek lookalike characters
│       ├── suspicious_tlds.txt    # Known abused TLDs
│       ├── shortener_list.txt     # URL shortener domains
│       ├── screenshots/           # Official org login screenshots
│       ├── model/
│       │   └── phishing_model.pkl # Trained XGBoost model (431KB)
│       └── demo_snapshots/        # Locally mirrored phishing pages
│
└── extension/
    ├── manifest.json              # Chrome extension config (Manifest V3)
    ├── background.js              # Service worker — calls backend, updates badge
    ├── content.js                 # Injected into every page — captures URL
    ├── popup.html                 # Extension popup UI
    ├── popup.js                   # Renders scan result in popup
    └── icons/                     # Extension icons (16, 48, 128px)
```

---

## 4. The Three Eyes

### Eye 1 — URL Intelligence

**File:** `backend/eye1_url.py` | **Speed:** ~10ms | **Network calls:** None

Analyzes the URL string itself for suspicious patterns and brand impersonation signals. Everything runs offline.

#### Lexical Features

| Feature | Why It Matters |
|---|---|
| `url_length` | Phishing URLs tend to be long — brand keywords + fake domain + convincing path |
| `num_dots` | Deep subdomain chains like `paypal.verify.account.secure.evil.com` |
| `num_hyphens` | Legitimate brand domains rarely have more than one hyphen |
| `num_digits` in domain | Real brands almost never use digits in their domain name |
| `entropy` | Random-looking strings (DGA domains, shorteners) have high Shannon entropy |
| `has_ip_address` | No real organization uses a raw IP address as their login URL |
| `has_at_symbol` | `legit.com@evil.com` — browsers go to `evil.com`, ignoring everything before `@` |
| `uses_shortener` | Bit.ly, TinyURL etc. hide the real destination — checked against a local list |
| `suspicious_tld` | `.xyz`, `.tk`, `.ml`, `.ga` are free TLDs massively abused for phishing |
| `has_port` | Real login pages never specify ports explicitly like `:8080` |

#### Brand Similarity Features

These only run when a target organization is selected:

| Feature | How It Works |
|---|---|
| `brand_levenshtein` | Edit distance between submitted domain and official domain. `sbi-login.com` vs `sbi.co.in` — distance of 1–2 is highly suspicious |
| `brand_jaro_winkler` | Better for detecting `micr0soft.com` vs `microsoft.com` type substitutions |
| `brand_in_subdomain` | `paypal.verify-account.com` — "paypal" is in the subdomain, real domain is `verify-account.com` |
| `brand_in_path` | `evil.com/paypal/login` — domain is unrelated but path impersonates PayPal |
| `homoglyph_detected` | `раypal.com` looks identical to `paypal.com` but the `р` is Cyrillic (U+0440). Caught using a hardcoded Cyrillic/Greek lookalike mapping table |
| `typosquat_variant` | Checks against pre-generated dnstwist variants at O(1) — set membership lookup |

#### Domain Intelligence (cached in SQLite)

| Feature | What's Checked |
|---|---|
| `domain_age_days` | Via python-whois, cached. Phishing domains are almost always under 30 days old |
| `ssl_valid` | Self-signed or missing cert on a page claiming to be a bank login is a strong signal |
| `ssl_age_days` | Phishing sites get fresh certs hours before launching. Under 7 days is suspicious |

---

### Eye 2 — Visual Fingerprint

**File:** `backend/eye2_visual.py` | **Speed:** 3–5 seconds (async background)

Takes a screenshot of the suspicious page and compares it visually to the real organization's login page using perceptual hashing.

#### How It Works

Official login page screenshots were captured in advance using Playwright for all 6 target organizations. Each screenshot was hashed using **pHash** — a 64-bit fingerprint that encodes the visual appearance of an image.

At runtime:
1. Playwright opens the suspicious URL in a headless browser (5s timeout)
2. Takes a 1280×800 screenshot
3. Computes the pHash of the screenshot
4. Compares it against the stored official pHash using **Hamming distance**
5. `visual_score = 1 - (hamming_distance / 64)`

A Hamming distance below 10 means high visual similarity. Below 5 means a near-identical clone.

If the page times out or fails to load, `visual_score = 0.5` (unknown) — the scan is never blocked by a failed screenshot.

**Bonus:** Lazy phishing cloners often steal the real org's favicon directly from their servers. The page is `sbi-phish.xyz` but the favicon loads from `sbi.co.in`. This is detected separately and adds to the visual score.

---

### Eye 3 — Behavioral Analysis

**File:** `backend/eye3_behavior.py` | **Speed:** 1–2 seconds

Fetches the raw HTML of the page and checks for credential-harvesting behavior patterns.

> This is static HTML analysis only — no JavaScript execution, no sandboxing needed.

| Signal | Score Weight | What It Catches |
|---|---|---|
| `form_action_external` | +0.50 | Form submits to a different domain. Page claims to be SBI but the password goes to `collect-data.ru` |
| `has_password_field` | +0.20 | `<input type="password">` exists. Combined with external form action = credential harvester |
| `favicon_external_domain` | +0.15 | Favicon loads from the real brand's domain while the page itself is fake |
| `has_hidden_iframe` | +0.10 | `<iframe style="display:none">` used to submit credentials invisibly |
| `num_external_scripts > 10` | +0.05 | Excessive scripts loading from unknown external domains |

All weights are summed and capped at 1.0 to produce the `behavior_score`.

---

## 5. ML Model

**File:** `backend/ml_model.py` | **Model:** XGBoost | **Size:** 431KB | **Features:** 79

### Why XGBoost

- Trains on 200K rows in ~2 minutes on a laptop
- Handles missing values (failed WHOIS lookups, timeouts) natively — no imputation needed
- SHAP gives per-prediction feature contributions: *"This URL scored HIGH because `brand_levenshtein` contributed +0.34, `form_action_external` +0.28, `domain_age_days` +0.19"*
- 431KB model file, loads in milliseconds, runs on any machine

### Performance

| Metric | Score |
|---|---|
| F1 Score | 0.9413 |
| ROC-AUC | 0.9833 |
| CV Mean F1 | 0.9343 ± 0.0032 |

### Training Data

| Source | Data |
|---|---|
| PhishTank bulk CSV | ~80,000 verified phishing URLs |
| OpenPhish free feed | ~1,500 live phishing URLs |
| PhiUSIIL (Kaggle) | 100,945 phishing + 134,850 legitimate URLs |
| Tranco top 1M list | Top 100,000 legitimate domains |

Total: ~200,000 rows, all free sources, no paid APIs.

---

## 6. Scoring System

**File:** `backend/scorer.py`

The final risk score is a weighted ensemble of all four signals:

```
final_score = (0.40 × ml_score)
            + (0.25 × visual_score)
            + (0.20 × behavior_score)
            + (0.15 × blocklist_hit)
```

Each layer catches different attack patterns:
- **ML (40%)** — catches patterns learned from 200K training examples
- **Visual (25%)** — catches page clones that look identical to real login pages
- **Behavioral (20%)** — catches credential harvesters regardless of how the URL looks
- **Blocklist (15%)** — instant flag if the domain is in the local PhishTank/OpenPhish copy

If visual similarity is ≥ 0.80, the visual score overrides the final score upward regardless of other signals.

### Risk Levels

| Score | Level |
|---|---|
| 0.00 – 0.30 | 🟢 SAFE |
| 0.30 – 0.50 | 🔵 LOW |
| 0.50 – 0.70 | 🟡 MEDIUM |
| 0.70 – 1.00 | 🔴 HIGH |

---

## 7. Backend API

**File:** `backend/main.py` | **Framework:** FastAPI

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Full scan — Eye 1 + Eye 3 + ML sync, Eye 2 async. Returns immediately with `visual_pending: true` |
| `GET` | `/scan/{scan_id}` | Poll for the completed result including visual score |
| `GET` | `/orgs` | List available target organizations |
| `GET` | `/history` | Recent scan history (last 50) |
| `DELETE` | `/history` | Clear scan history |
| `GET` | `/docs` | Swagger UI |

### Scan Request

```json
POST /scan
{
  "url": "https://paypa1.com/login",
  "target_org": "paypal"
}
```

`target_org` is optional. If omitted, the system auto-detects based on brand keywords in the URL.

---

## 8. Chrome Extension

**Location:** `extension/` | **Manifest V3**

The extension is intentionally lightweight — all intelligence lives in the backend.

**content.js** — injected into every page. Grabs the current URL and sends it to the background worker.

**background.js** — receives the URL, POSTs to `/scan`, stores the result in `chrome.storage.local` keyed by tab ID.

**popup.js** — on icon click, reads the stored result and renders it.

### What You See

- Badge `!` / `?` / `~` / blank with Red / Amber / Blue / Green background
- Popup with score circle, three eye score cards, and detection signal flags
- Desktop notification auto-fires when a page scores HIGH risk

---

## 9. Target Organizations

| Key | Organization | Official Domain |
|---|---|---|
| `sbi` | State Bank of India | sbi.co.in |
| `microsoft` | Microsoft | microsoft.com |
| `google` | Google | google.com |
| `paypal` | PayPal | paypal.com |
| `hdfc` | HDFC Bank | hdfcbank.com |
| `icici` | ICICI Bank | icicibank.com |

Each org has a full profile: official domain, known subdomains, brand keywords, pre-generated typosquat variants, homoglyph variants, and a stored login page screenshot.

---

## 10. Results

```
URL                             Score    Risk Level
────────────────────────────────────────────────────
google.com                      0.2113   LOW    ✓
paypa1.com  (phishing clone)    0.7000   HIGH   ✓
micosoft.com (typosquat)        0.4853   MEDIUM ✓
```

---

## 11. Setup

### Requirements
- Python 3.10+
- Google Chrome

### Backend

```bash
git clone https://github.com/atharv1909/Trinetra-AI.git
cd Trinetra-AI

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt

cd backend
uvicorn main:app --port 8000
```

API runs at `http://localhost:8000`  
Swagger docs at `http://localhost:8000/docs`

### Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder

The Trinetra icon appears in your toolbar. With the backend running, every page you visit is scanned automatically.

---

## 12. Tech Stack

| Component | Technology |
|---|---|
| ML Model | XGBoost |
| Explainability | SHAP |
| Backend | FastAPI |
| Database | SQLite |
| Visual Analysis | Playwright + imagehash (pHash) |
| HTML Parsing | BeautifulSoup4 + lxml |
| WHOIS Lookup | python-whois (SQLite cached) |
| String Similarity | python-Levenshtein + jellyfish |
| Typosquat Generation | dnstwist (run offline, variants stored) |
| Chrome Extension | Manifest V3 |
