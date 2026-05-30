# Trinetra AI — Phishing Detection System

> Three-layer AI system that detects when a website is impersonating a real organization.  
> Combines URL analysis, visual clone detection, and behavioral analysis into one risk score — with a real-time Chrome extension.

---

## What Problem Does This Solve

Phishing attacks work by pretending to be a trusted organization. Someone gets a link that looks exactly like SBI NetBanking. The URL has "sbi" in it. The page looks identical to the real login page. They type their password. It gets stolen.

Generic phishing detectors ask one question: does this URL look suspicious?

**Trinetra asks a different question: is this URL specifically trying to impersonate SBI, or Microsoft, or HDFC Bank?**

That is the difference. Trinetra is not a generic scanner. It is organization-aware. Every detection layer knows which organization is being targeted and adapts accordingly.

---

## How It Works

```
You visit a website
        ↓
Chrome extension captures the URL
        ↓
Sends to Trinetra backend
        ↓
Three engines analyze it simultaneously
        ↓
      Eye 1              Eye 3            ML Model
   URL Analysis       HTML Behavior       XGBoost
     ~10ms              ~1-2s              ~50ms
  (sync, instant)    (sync, instant)   (sync, instant)
        ↓
   Result returned immediately
        ↓
      Eye 2 (async background)
   Screenshot + Visual Compare
          ~3-5s
   Updates result when done
        ↓
Weighted score calculated
        ↓
  SAFE / LOW / MEDIUM / HIGH
        ↓
Chrome extension badge + popup + notification
```

Eye 1, Eye 3, and the ML model run synchronously and return a result in under 2 seconds.  
Eye 2 runs in the background and updates the scan when done — you never wait for the screenshot.

---

## The Three Eyes

### Eye 1 — URL Intelligence

**File:** `backend/eye1_url.py` | **Speed:** ~10ms | **Network:** None

Analyzes the URL string itself. Runs completely offline. No web requests.

**URL structure signals:**

| Signal | What It Catches |
|---|---|
| URL length | Phishing URLs stuff brand keywords + fake domain + convincing path — they get long |
| Number of dots | Deep subdomain chains like `paypal.verify.account.secure.evil.com` |
| Hyphens in domain | `microsoft-secure-login-verify.com` — legitimate brands rarely hyphenate |
| Digits in domain | Real brands almost never use digits. `sbi123.com` is suspicious |
| Shannon entropy | Random-looking domain strings (DGA, shorteners) have high entropy |
| IP address in URL | No real organization uses a raw IP as their login address |
| At-symbol | `legit.com@evil.com` — browsers go to `evil.com`, ignoring everything before `@` |
| URL shorteners | Bit.ly, TinyURL etc. hide the real destination — checked against a local list |
| Suspicious TLDs | `.xyz` `.tk` `.ml` `.ga` `.cf` `.gq` — free TLDs massively abused for phishing |
| Explicit port | Real login pages never specify ports like `:8080` |

**Brand similarity — the part that makes Trinetra different:**

For each target organization we pre-built a brand profile containing the official domain, known legitimate subdomains, brand keywords, and a complete set of typosquat variants generated offline using dnstwist.

| Signal | How It Works |
|---|---|
| Levenshtein distance | Edit distance between submitted domain and official domain. Distance of 1-2 is highly suspicious |
| Jaro-Winkler similarity | Better at catching prefix substitutions like `micr0soft.com` vs `microsoft.com` |
| Brand in subdomain | `paypal.verify-account.com` — "paypal" in subdomain, real domain is `verify-account.com` |
| Brand in path | `evil.com/paypal/login` — domain is unrelated but path impersonates PayPal |
| Homoglyph detection | `раypal.com` looks identical to `paypal.com` but the `р` is Cyrillic (U+0440). Caught using a 40-character lookalike mapping table |
| Typosquat matching | O(1) set lookup against pre-generated dnstwist variants. This is how `rnicrosoft.com` was caught — the rn→m substitution is pre-generated at setup time |

**Domain intelligence (cached in SQLite, no repeat lookups):**

| Signal | Why It Matters |
|---|---|
| Domain age | Phishing domains are almost always under 30 days old — checked via WHOIS |
| SSL validity | A missing or self-signed cert on a page claiming to be a bank is a strong signal |
| SSL certificate age | Phishing sites get fresh certs hours before launching. Under 7 days is suspicious |

---

### Eye 2 — Visual Fingerprint

**File:** `backend/eye2_visual.py` | **Speed:** 3-5 seconds (async background)

Takes a screenshot of the suspicious page and compares it visually to the real organization's login page using perceptual hashing.

**Why this matters:** URL patterns can be engineered around. Attackers know what makes URLs look suspicious and avoid those patterns. But they cannot avoid making the page look like the real thing — that is the entire point of the attack. Eye 2 catches clones that are completely invisible to URL-based detectors.

**How it works:**

1. Official login page screenshots were captured in advance for all 6 target organizations using Playwright
2. Each screenshot was hashed using pHash — a 64-bit fingerprint that encodes the visual appearance of an image
3. At runtime, Playwright opens the suspicious URL in a headless browser with a 5-second timeout
4. Takes a 1280×800 screenshot
5. Computes the pHash of the screenshot
6. Compares against the stored official pHash using Hamming distance
7. `visual_score = 1 - (hamming_distance / 64)`

A Hamming distance below 10 means high visual similarity. Below 5 means a near-identical clone.

If the page times out or fails to load, `visual_score = 0.5` (unknown) — the scan is never blocked by a failed screenshot.

**Bonus signal:** Lazy phishing cloners often steal the real org's favicon directly from the official server. The page is `sbi-phish.xyz` but the favicon loads from `sbi.co.in`. This is detected separately.

**Official domain bypass:** If the submitted URL is the actual official domain of the target organization, visual comparison is skipped. Without this, scanning `accounts.google.com` would score HIGH because it genuinely looks identical to our stored Google fingerprint.

---

### Eye 3 — Behavioral Analysis

**File:** `backend/eye3_behavior.py` | **Speed:** 1-2 seconds

Fetches the raw HTML of the page and checks for credential-harvesting behavior. This is static HTML analysis only — no JavaScript execution, no sandboxing needed, completely safe.

| Signal | Weight | What It Catches |
|---|---|---|
| Form posts externally | +0.50 | Page claims to be SBI login but the form submits your password to `collect-data.ru` |
| Password field + external form | +0.20 | Combined signal — this pattern is credential harvesting with near certainty |
| Favicon from external domain | +0.15 | Cloned page stealing the real org's favicon directly from their servers |
| Hidden iframe | +0.10 | `<iframe style="display:none">` used to submit credentials invisibly |
| Excessive external scripts | +0.05 | More than 10 scripts loading from unknown external domains |

The form action check alone catches approximately 70% of active credential-harvesting pages.

---

## ML Model

**File:** `backend/ml_model.py` | **Model:** XGBoost | **Size:** 431KB | **Features:** 79

### Why XGBoost and not a neural network

- Trains in ~2 minutes on a laptop — no GPU needed
- Handles missing values natively — if a WHOIS lookup times out, the model routes around it correctly
- SHAP gives per-prediction explanations: *"This URL scored HIGH because brand similarity contributed +0.34, external form action contributed +0.28, domain age contributed +0.19"*
- 431KB model file, loads in milliseconds, runs on any machine
- Cross-validation variance of only 0.0032 — the model genuinely learned patterns, not memorized data

### Performance

| Metric | Score |
|---|---|
| F1 Score | 0.9413 |
| ROC-AUC | 0.9833 |
| Cross-validation Mean F1 | 0.9343 ± 0.0032 |
| False Positive Rate | 5.69% |

### Why these numbers are honest

The first dataset we trained on (PhiUSIIL, 235K rows) gave a perfect 1.0 F1 score. We investigated and found the `URLSimilarityIndex` column had 0.707 feature importance — it was encoding the label directly. We wrote a zero-overlap detection script, identified all leaky columns, dropped them, applied L1/L2 regularization, reduced tree depth, and retrained. The 0.9413 F1 is the honest result on clean features.

### Training Data

All free sources, no paid APIs:

| Source | Data |
|---|---|
| PhishTank bulk CSV | ~80,000 verified phishing URLs (free registration) |
| OpenPhish free feed | Live phishing URLs, updated every 6 hours, no auth needed |
| Kaggle PhiUSIIL | 100,945 phishing + 134,850 legitimate URLs |
| Tranco top 1M list | Top 100,000 legitimate domains for negative class |

---

## Scoring System

**File:** `backend/scorer.py`

The final risk score is a weighted combination of all signals:

```
final_score = (0.40 × url_score)
            + (0.25 × visual_score)
            + (0.20 × behavior_score)
            + (0.15 × blocklist_score)
```

Each layer catches different attack patterns:

- **URL (40%)** — catches lexical and brand similarity signals
- **Visual (25%)** — catches page clones regardless of URL patterns
- **Behavioral (20%)** — catches credential harvesters regardless of appearance
- **Blocklist (15%)** — instant flag if domain appears in local PhishTank/OpenPhish copy

**Override rules:** If visual similarity exceeds 80%, the final score is floored at 0.70 — a page that looks visually identical to a bank login is dangerous regardless of what the URL looks like.

### Risk Levels

| Score Range | Level | Meaning |
|---|---|---|
| 0.00 – 0.30 | SAFE | No significant signals detected |
| 0.30 – 0.50 | LOW | Minor signals — likely legitimate |
| 0.50 – 0.65 | MEDIUM | Multiple signals — exercise caution |
| 0.65 – 1.00 | HIGH | Strong phishing indicators — do not proceed |

---

## Backend API

**File:** `backend/main.py` | **Framework:** FastAPI

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Full scan. Eye 1 + Eye 3 + ML run sync. Eye 2 runs async. Returns immediately with `visual_pending: true` |
| `GET` | `/scan/{scan_id}` | Poll for completed result including visual score |
| `GET` | `/orgs` | List available target organizations |
| `GET` | `/history` | Recent scan history (last 50) |
| `DELETE` | `/history` | Clear scan history |
| `GET` | `/docs` | Interactive Swagger UI — test all endpoints |

**Example request:**

```json
POST /scan
{
  "url": "https://sbi-secure-login.xyz/verify",
  "target_org": "sbi"
}
```

**Example response:**

```json
{
  "scan_id": "abc123-...",
  "url": "https://sbi-secure-login.xyz/verify",
  "target_org": "sbi",
  "final_score": 0.71,
  "risk_level": "HIGH",
  "flags": [
    "SUSPICIOUS_TLD",
    "BRAND_KEYWORD_IN_DOMAIN",
    "MULTIPLE_SUSPICIOUS_KEYWORDS",
    "SSL_INVALID"
  ],
  "url_score": 0.40,
  "behavior_score": 0.50,
  "visual_score": 0.53,
  "visual_pending": false
}
```

---

## Chrome Extension

**Location:** `extension/` | **Standard:** Manifest V3

The extension is intentionally lightweight — all intelligence lives in the backend.

| File | Role |
|---|---|
| `content.js` | Injected into every page. Captures the current URL and sends it to the background worker |
| `background.js` | Receives the URL, POSTs to `/scan`, caches result in `chrome.storage.local` by tab ID |
| `popup.html/js` | On icon click, reads stored result and renders score circle, eye cards, and signal flags |

**What you see:**

- Badge `!` on red background — HIGH risk
- Badge `?` on amber background — MEDIUM risk
- Badge `~` on blue background — LOW risk
- No badge — SAFE
- Desktop notification fires automatically when a page scores HIGH

---

## Target Organizations

| Key | Organization | Official Domain | Typosquat Variants |
|---|---|---|---|
| `sbi` | State Bank of India | sbi.co.in | 548 variants |
| `microsoft` | Microsoft | microsoft.com | 4,353 variants |
| `google` | Google | google.com | 2,965 variants |
| `paypal` | PayPal | paypal.com | 1,369 variants |
| `hdfc` | HDFC Bank | hdfcbank.com | 2,894 variants |
| `icici` | ICICI Bank | icicibank.com | 5,948 variants |

Each organization has: official domain, known subdomains, brand keywords, pre-generated typosquat variants (dnstwist), homoglyph variants, and a stored login page screenshot for visual comparison.

---

## Live Test Results

| URL | Target Org | Final Score | Risk Level | Key Signals |
|---|---|---|---|---|
| `accounts.google.com/signin` | google | 0.2113 | LOW | Official domain — correctly identified safe |
| `yolo-shop.github.io/Paypal-` | paypal | 0.7000 | HIGH | 81.25% visual similarity to PayPal login page |
| `rnicrosoft.com` | microsoft | 0.4853 | MEDIUM | Typosquat detected — rn→m substitution |
| `sbi-secure-login.xyz` | sbi | 0.4965 | MEDIUM | Suspicious TLD + brand keyword in domain |
| `login.microsoftonline.com` | microsoft | 0.3089 | LOW | Official domain — correctly identified safe |

---

## Setup

### Requirements

- Python 3.10 or higher
- Google Chrome

### Backend Setup

```bash
# clone the repo
git clone https://github.com/atharv1909/Trinetra-AI.git
cd Trinetra-AI

# create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# install dependencies
pip install -r requirements.txt

# install Playwright browser
playwright install chromium

# start the backend
cd backend
uvicorn main:app --reload --port 8000
```

Backend runs at: `http://localhost:8000`  
Interactive API docs at: `http://localhost:8000/docs`

### Chrome Extension Setup

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** using the toggle in the top right
3. Click **Load unpacked**
4. Select the `extension/` folder from the project

The Trinetra icon appears in your Chrome toolbar. With the backend running, every page you visit is scanned automatically.

---

## Project Structure

```
trinetra-ai/
├── backend/
│   ├── main.py                  ← FastAPI server, all endpoints
│   ├── eye1_url.py              ← URL + brand intelligence engine
│   ├── eye2_visual.py           ← Visual screenshot comparison
│   ├── eye3_behavior.py         ← HTML behavioral analysis
│   ├── ml_model.py              ← XGBoost model loader + predictor
│   ├── scorer.py                ← Hybrid weighted scoring engine
│   ├── database.py              ← SQLite storage + WHOIS cache
│   ├── models/
│   │   ├── xgb_model.pkl        ← Trained XGBoost model (431KB)
│   │   └── feature_columns.json ← Feature column order for inference
│   └── data/
│       ├── brand_profiles/      ← Brand definitions for 6 orgs
│       ├── typosquat_sets/      ← Pre-generated dnstwist variants
│       ├── org_screenshots/     ← Official login page fingerprints
│       ├── homoglyphs.json      ← Cyrillic/Greek lookalike map
│       ├── suspicious_tlds.json ← Known abused TLDs
│       └── shorteners.json      ← URL shortener domain list
│
├── extension/
│   ├── manifest.json            ← Chrome extension config (MV3)
│   ├── background.js            ← Service worker, calls backend
│   ├── content.js               ← Injected into pages, captures URL
│   ├── popup.html               ← Extension popup UI
│   ├── popup.js                 ← Renders scan result in popup
│   └── icons/                   ← Extension icons (16, 48, 128px)
│
├── training/
│   └── train_model.ipynb        ← Kaggle notebook for model training
│
└── requirements.txt
```

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| ML Model | XGBoost | Fast, explainable, handles missing values, no GPU needed |
| Explainability | SHAP | Per-prediction feature contribution breakdown |
| Backend | FastAPI | Async support for background Eye 2 task |
| Database | SQLite | Zero-config, single file, WHOIS cache + scan history |
| Visual Analysis | Playwright + imagehash | Headless screenshot + perceptual hash comparison |
| HTML Parsing | BeautifulSoup4 + lxml | Static HTML analysis for behavioral signals |
| WHOIS Lookup | python-whois | Domain age check, cached in SQLite |
| String Similarity | jellyfish | Levenshtein + Jaro-Winkler brand similarity |
| Typosquat Generation | dnstwist | Pre-generates all variant domains offline |
| Chrome Extension | Manifest V3 | Real-time browser-level detection |

---

## What Makes This Different

Most phishing detection projects follow the same pattern — download a dataset, train a Random Forest on URL features, wrap it in Flask, show 95% accuracy. The problems with that approach: it is not organization-aware, it has no visual detection, and 95% accuracy on a balanced dataset does not tell you the false positive rate in real usage.

Trinetra is different in four specific ways:

**Organization-targeted** — when you select SBI, every detection layer adapts to SBI specifically. The brand similarity scores are computed against SBI's domain. The visual comparison is against SBI's login page screenshot. The typosquat set is specific to sbi.co.in.

**Visual detection** — catches attacks that are completely invisible to URL scanners. The PayPal clone at `yolo-shop.github.io/Paypal-` has nothing suspicious in the URL. Eye 2 caught it at 81.25% visual similarity.

**Explainable** — every prediction shows exactly why. Not just "94% phishing" — but which features contributed how much to that score, using SHAP values.

**Honest metrics** — we identified and eliminated data leakage that caused false 1.0 accuracy in training. The reported F1 of 0.9413 reflects real performance on clean features.

---

*Built for the AI/ML-Based Phishing Detection for Targeted Organizations problem statement.*
