import json
import joblib
import numpy as np
from pathlib import Path
from urllib.parse import urlparse
import re
import math

# ── load model and feature list once at import ─────────────────────────
MODELS_DIR = Path(__file__).parent / "models"

model         = joblib.load(MODELS_DIR / "xgb_model.pkl")
feature_cols  = json.load(open(MODELS_DIR / "feature_columns.json"))
feat_importance = json.load(open(MODELS_DIR / "feature_columns.json"))

print(f"[ML] Model loaded. Features: {len(feature_cols)}")


# ── feature extraction matching training dataset columns ───────────────

def count_char(text: str, char: str) -> int:
    return text.count(char)


def ratio_digits(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / len(text)


def get_words(text: str) -> list:
    return re.split(r'[\W_]+', text)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c/length)*math.log2(c/length) for c in freq.values())


PHISH_HINTS = [
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "banking", "password", "credential",
    "validate", "recover", "unlock", "webscr", "cmd",
    "paypal", "ebay", "microsoft", "google", "apple",
    "amazon", "netflix", "bank", "support", "service"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "buff.ly", "tiny.cc", "cutt.ly", "rb.gy"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".click", ".work", ".loan", ".win", ".download",
    ".stream", ".racing", ".faith", ".review", ".party"
}

BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "amazon",
    "netflix", "facebook", "instagram", "twitter", "sbi",
    "hdfc", "icici", "axis", "infosys", "tcs"
]


def extract_ml_features(url: str, html: str = "") -> dict:
    """
    Extract the same 79 features the model was trained on.
    html is optional — pass empty string if not available.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    full_url = url.lower()

    # word tokenization
    words_url  = get_words(full_url)
    words_host = get_words(hostname)
    words_path = get_words(path)

    words_url  = [w for w in words_url  if w]
    words_host = [w for w in words_host if w]
    words_path = [w for w in words_path if w]

    # domain parts
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if domain_parts else ""
    domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname

    features = {
        # URL length features
        "length_url":      len(url),
        "length_hostname": len(hostname),

        # IP address
        "ip": int(bool(re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$", hostname
        ))),

        # special character counts
        "nb_dots":        count_char(url, "."),
        "nb_hyphens":     count_char(url, "-"),
        "nb_at":          count_char(url, "@"),
        "nb_qm":          count_char(url, "?"),
        "nb_and":         count_char(url, "&"),
        "nb_or":          count_char(url, "|"),
        "nb_eq":          count_char(url, "="),
        "nb_underscore":  count_char(url, "_"),
        "nb_tilde":       count_char(url, "~"),
        "nb_percent":     count_char(url, "%"),
        "nb_slash":       count_char(url, "/"),
        "nb_star":        count_char(url, "*"),
        "nb_colon":       count_char(url, ":"),
        "nb_comma":       count_char(url, ","),
        "nb_semicolumn":  count_char(url, ";"),
        "nb_dollar":      count_char(url, "$"),
        "nb_space":       count_char(url, " ") + count_char(url, "%20"),

        # token presence
        "nb_www":      int("www." in full_url),
        "nb_com":      int(".com" in full_url),
        "nb_dslash":   int("//" in path),
        "http_in_path":int("http" in path.lower()),
        "https_token": int("https" in domain.lower()),

        # digit ratios
        "ratio_digits_url":  ratio_digits(url),
        "ratio_digits_host": ratio_digits(hostname),

        # encoding
        "punycode": int("xn--" in hostname.lower()),
        "port":     int(parsed.port is not None),

        # TLD tricks
        "tld_in_path":      int(f".{tld}" in path.lower()),
        "tld_in_subdomain": int(
            f".{tld}" in ".".join(domain_parts[:-2]).lower()
            if len(domain_parts) > 2 else False
        ),
        "abnormal_subdomain": int(
            len(domain_parts) > 3 or
            any(part.replace("-","").isdigit()
                for part in domain_parts[:-2])
        ),
        "nb_subdomains": max(0, len(domain_parts) - 2),
        "prefix_suffix": int("-" in domain),
        "random_domain": int(shannon_entropy(domain) > 3.5),
        "shortening_service": int(hostname in SHORTENERS),
        "path_extension": int(
            bool(re.search(r'\.(php|html|htm|asp|aspx|jsp)$',
                           path.lower()))
        ),

        # redirections (from URL only)
        "nb_redirection":          count_char(url, "//") - 1,
        "nb_external_redirection": 0,  # needs live page

        # word length features
        "length_words_raw":   len(words_url),
        "char_repeat":        int(
            bool(re.search(r'(.)\1{3,}', full_url))
        ),
        "shortest_words_raw": min((len(w) for w in words_url),  default=0),
        "shortest_word_host": min((len(w) for w in words_host), default=0),
        "shortest_word_path": min((len(w) for w in words_path), default=0),
        "longest_words_raw":  max((len(w) for w in words_url),  default=0),
        "longest_word_host":  max((len(w) for w in words_host), default=0),
        "longest_word_path":  max((len(w) for w in words_path), default=0),
        "avg_words_raw":  sum(len(w) for w in words_url)  / max(len(words_url),  1),
        "avg_word_host":  sum(len(w) for w in words_host) / max(len(words_host), 1),
        "avg_word_path":  sum(len(w) for w in words_path) / max(len(words_path), 1),

        # phishing hints
        "phish_hints": sum(hint in full_url for hint in PHISH_HINTS),

        # brand features
        "domain_in_brand": int(
            any(brand in domain.lower() for brand in BRAND_KEYWORDS)
        ),
        "brand_in_subdomain": int(
            any(brand in ".".join(domain_parts[:-2]).lower()
                for brand in BRAND_KEYWORDS)
            if len(domain_parts) > 2 else False
        ),
        "brand_in_path": int(
            any(brand in path.lower() for brand in BRAND_KEYWORDS)
        ),
        "suspecious_tld": int(f".{tld}" in SUSPICIOUS_TLDS),

        # page features — from HTML if available, else 0
        "nb_hyperlinks":        0,
        "ratio_intHyperlinks":  0.0,
        "ratio_extHyperlinks":  0.0,
        "ratio_nullHyperlinks": 0.0,
        "nb_extCSS":            0,
        "ratio_intRedirection": 0.0,
        "ratio_extRedirection": 0.0,
        "ratio_intErrors":      0.0,
        "ratio_extErrors":      0.0,
        "login_form":           0,
        "external_favicon":     0,
        "links_in_tags":        0.0,
        "submit_email":         0,
        "ratio_intMedia":       0.0,
        "ratio_extMedia":       0.0,
        "sfh":                  0,
        "iframe":               0,
        "popup_window":         0,
        "safe_anchor":          0.0,
        "onmouseover":          0,
        "right_clic":           0,
        "empty_title":          0,
        "domain_in_title":      0,
        "domain_with_copyright":0,
    }

    # ── enrich with HTML if available ──────────────────────────────────
    if html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
            all_links = soup.find_all("a", href=True)
            total     = max(len(all_links), 1)

            int_links  = [a for a in all_links
                          if urlparse(a["href"]).hostname == hostname
                          or a["href"].startswith("/")]
            ext_links  = [a for a in all_links
                          if urlparse(a["href"]).hostname
                          and urlparse(a["href"]).hostname != hostname]
            null_links = [a for a in all_links
                          if a["href"] in ("#", "", "javascript:void(0)")]

            features["nb_hyperlinks"]       = len(all_links)
            features["ratio_intHyperlinks"] = len(int_links)  / total
            features["ratio_extHyperlinks"] = len(ext_links)  / total
            features["ratio_nullHyperlinks"]= len(null_links) / total

            # login form
            forms = soup.find_all("form")
            features["login_form"] = int(
                any(f.find("input", {"type": "password"})
                    for f in forms)
            )

            # iframe
            features["iframe"] = int(bool(soup.find("iframe")))

            # popup
            page_text = html.lower()
            features["popup_window"] = int("window.open" in page_text)
            features["onmouseover"]  = int("onmouseover" in page_text)
            features["right_clic"]   = int(
                "event.button==2" in page_text or
                "contextmenu" in page_text
            )

            # title checks
            title_tag = soup.find("title")
            if title_tag and title_tag.text:
                title = title_tag.text.lower().strip()
                features["empty_title"]     = int(len(title) == 0)
                features["domain_in_title"] = int(domain.lower() in title)
            else:
                features["empty_title"] = 1

            # external favicon
            favicon = soup.find("link", rel=lambda r: r and "icon" in r)
            if favicon and favicon.get("href"):
                fav_host = urlparse(favicon["href"]).hostname
                features["external_favicon"] = int(
                    bool(fav_host) and fav_host != hostname
                )

            # css
            ext_css = [l for l in soup.find_all("link", rel="stylesheet")
                       if urlparse(l.get("href","")).hostname
                       and urlparse(l.get("href","")).hostname != hostname]
            features["nb_extCSS"] = len(ext_css)

        except Exception as e:
            print(f"[ML] HTML parsing error: {e}")

    return features


def predict(url: str, html: str = "") -> dict:
    """
    Run ML prediction on a URL.
    Returns ml_score (0.0-1.0) and top contributing features.
    """
    raw_features = extract_ml_features(url, html)

    # build feature vector in exact training column order
    vector = []
    for col in feature_cols:
        vector.append(raw_features.get(col, 0))

    X = np.array(vector).reshape(1, -1)

    prob        = model.predict_proba(X)[0][1]  # phishing probability
    prediction  = int(model.predict(X)[0])

    # get SHAP values for explanation
    try:
        import shap
        explainer   = shap.TreeExplainer(model)
        shap_vals   = explainer.shap_values(X)[0]
        top_indices = np.argsort(np.abs(shap_vals))[::-1][:5]
        top_features = [
            {
                "feature":     feature_cols[i],
                "value":       round(float(vector[i]), 4),
                "shap_impact": round(float(shap_vals[i]), 4),
                "direction":   "phishing" if shap_vals[i] > 0 else "legitimate"
            }
            for i in top_indices
        ]
    except Exception as e:
        print(f"[ML] SHAP error: {e}")
        top_features = []

    return {
        "ml_score":    round(float(prob), 4),
        "prediction":  prediction,
        "top_features": top_features,
        "raw_features": raw_features,
    }