import re
import json
import math
import socket
import ssl
from urllib.parse import urlparse
from pathlib import Path
import tldextract
import jellyfish

# ── paths ──────────────────────────────────────────────────────────────
BASE = Path(__file__).parent / "data"
PROFILES_PATH   = BASE / "brand_profiles" / "profiles.json"
HOMOGLYPHS_PATH = BASE / "homoglyphs.json"
SHORTENERS_PATH = BASE / "shorteners.json"
SUSP_TLDS_PATH  = BASE / "suspicious_tlds.json"
TYPOSQUAT_DIR   = BASE / "typosquat_sets"

# ── load data files once at import time ────────────────────────────────
with open(PROFILES_PATH,   encoding="utf-8") as f:
    BRAND_PROFILES = json.load(f)

with open(HOMOGLYPHS_PATH, encoding="utf-8") as f:
    HOMOGLYPHS = json.load(f)

with open(SHORTENERS_PATH, encoding="utf-8") as f:
    SHORTENERS = set(json.load(f))

with open(SUSP_TLDS_PATH,  encoding="utf-8") as f:
    SUSPICIOUS_TLDS = set(json.load(f))

# load typosquat sets — extract just the domain names from dnstwist output
TYPOSQUAT_SETS = {}
for org_key, profile in BRAND_PROFILES.items():
    typo_file = TYPOSQUAT_DIR / profile["typosquat_file"]
    if typo_file.exists():
        with open(typo_file, encoding="utf-8-sig", errors="ignore") as f:
            raw = json.load(f)
        # dnstwist output is a list of dicts with a "domain" key
        TYPOSQUAT_SETS[org_key] = set(
            entry["domain"].lower()
            for entry in raw
            if "domain" in entry
        )

# ── helpers ────────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string. Higher = more random."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def normalize_homoglyphs(text: str) -> str:
    """Replace lookalike characters with their ASCII equivalents."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def extract_domain_parts(url: str):
    """Return (subdomain, domain, suffix) using tldextract."""
    ext = tldextract.extract(url)
    return ext.subdomain, ext.domain, ext.suffix


def is_ip_url(url: str) -> bool:
    """True if the host is a raw IP address."""
    host = urlparse(url).hostname or ""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    return bool(ip_pattern.match(host))


def check_ssl(domain: str) -> dict:
    """
    Try to grab SSL cert info.
    Returns dict with valid (bool) and age_days (int).
    On failure returns valid=False, age_days=-1.
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=3),
            server_hostname=domain
        ) as s:
            cert = s.getpeercert()
        from datetime import datetime
        not_before_str = cert.get("notBefore", "")
        not_before = datetime.strptime(
            not_before_str, "%b %d %H:%M:%S %Y %Z"
        )
        age_days = (datetime.utcnow() - not_before).days
        return {"valid": True, "age_days": age_days}
    except Exception:
        return {"valid": False, "age_days": -1}


# ── main analysis function ─────────────────────────────────────────────

def analyze_url(url: str, target_org: str = None) -> dict:
    """
    Full Eye 1 analysis.
    Returns a dict of all features + a url_score (0.0 - 1.0).
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    full_url = url.lower()

    subdomain, domain, suffix = extract_domain_parts(url)
    full_domain = f"{domain}.{suffix}".lower()
    tld = f".{suffix}".lower() if suffix else ""

    # ── GROUP A: lexical features ──────────────────────────────────────
    url_length      = len(url)
    num_dots        = url.count(".")
    num_hyphens     = domain.count("-")
    num_digits      = sum(c.isdigit() for c in domain)
    digit_ratio     = num_digits / len(domain) if domain else 0
    entropy         = shannon_entropy(domain)
    path_depth      = path.count("/")
    has_ip          = is_ip_url(url)
    is_https        = parsed.scheme == "https"
    has_at          = "@" in url
    has_double_slash= "//" in path
    uses_shortener  = full_domain in SHORTENERS
    suspicious_tld  = tld in SUSPICIOUS_TLDS
    has_port        = parsed.port is not None

    # suspicious keyword check
    SUSP_KEYWORDS = [
        "login", "signin", "verify", "secure",
        "update", "confirm", "banking", "password", "credential",
        "authenticate", "validation", "recover", "unlock"
    ]
    num_susp_keywords = sum(kw in full_url for kw in SUSP_KEYWORDS)

    # ── GROUP B: brand similarity ──────────────────────────────────────
    brand_results = {}

    orgs_to_check = (
        [target_org] if target_org and target_org in BRAND_PROFILES
        else list(BRAND_PROFILES.keys())
    )

    for org_key in orgs_to_check:
        profile        = BRAND_PROFILES[org_key]
        official       = profile["official_domain"].lower()
        keywords       = [k.lower() for k in profile["brand_keywords"]]
        official_subs  = [s.lower() for s in profile["official_subdomains"]]

        # skip if this is the actual official domain or subdomain
        if full_domain == official or hostname.lower() in [
        s.replace("https://", "").replace("http://", "").split("/")[0]
        for s in official_subs
        ]:
            brand_results[org_key] = {
                "is_official": True,
                "levenshtein": 0,
                "jaro_winkler": 1.0,
                "brand_in_subdomain": False,
                "brand_in_path": False,
                "homoglyph_detected": False,
                "typosquat_match": False,
            }
            continue

        # levenshtein distance between submitted domain and official domain
        lev = jellyfish.levenshtein_distance(full_domain, official)

        # jaro-winkler similarity
        jw  = jellyfish.jaro_winkler_similarity(full_domain, official)

        # brand keyword in subdomain
        brand_in_sub = any(kw in subdomain.lower() for kw in keywords)

        brand_in_domain = any(kw in domain.lower() for kw in keywords)
        # brand keyword in path
        brand_in_path = any(kw in path.lower() for kw in keywords)

        # homoglyph attack detection
        normalized = normalize_homoglyphs(full_domain)
        homoglyph_detected = (
            normalized != full_domain and
            jellyfish.levenshtein_distance(normalized, official) <= 2
        )

        # typosquat variant match
        typo_set = TYPOSQUAT_SETS.get(org_key, set())
        typosquat_match = full_domain in typo_set

        brand_results[org_key] = {
            "is_official": False,
            "levenshtein": lev,
            "jaro_winkler": round(jw, 4),
            "brand_in_subdomain": brand_in_sub,
            "brand_in_domain": brand_in_domain,
            "brand_in_path": brand_in_path,
            "homoglyph_detected": homoglyph_detected,
            "typosquat_match": typosquat_match,
        }

    # find most suspicious brand match
    best_org  = None
    best_score = 0.0
    for org_key, res in brand_results.items():
        if res.get("is_official"):
            continue
        # score this org match
        s = 0.0
        s += res["jaro_winkler"] * 0.4
        s += (1 if res["brand_in_subdomain"] else 0) * 0.2
        s += (1 if res["brand_in_path"]      else 0) * 0.1
        s += (1 if res["homoglyph_detected"] else 0) * 0.2
        s += (1 if res["typosquat_match"]    else 0) * 0.3
        # penalize large levenshtein distance
        lev_penalty = min(res["levenshtein"] / 10, 0.3)
        s = max(0.0, s - lev_penalty)
        if s > best_score:
            best_score = s
            best_org   = org_key

    # ── GROUP C: SSL check ─────────────────────────────────────────────
    ssl_info = check_ssl(hostname)

    # ── scoring ────────────────────────────────────────────────────────
    flags = []
    score = 0.0

    # lexical signals
    if url_length > 75:
        score += 0.05; flags.append("URL_TOO_LONG")
    if num_dots > 4:
        score += 0.05; flags.append("EXCESSIVE_DOTS")
    if num_hyphens > 2:
        score += 0.05; flags.append("EXCESSIVE_HYPHENS")
    if entropy > 3.5:
        score += 0.05; flags.append("HIGH_ENTROPY_DOMAIN")
    if has_ip:
        score += 0.15; flags.append("IP_ADDRESS_IN_URL")
    if has_at:
        score += 0.15; flags.append("AT_SYMBOL_IN_URL")
    if uses_shortener:
        score += 0.10; flags.append("URL_SHORTENER")
    if suspicious_tld:
        score += 0.10; flags.append("SUSPICIOUS_TLD")
    if has_port:
        score += 0.05; flags.append("EXPLICIT_PORT")
    if num_susp_keywords >= 2:
        score += 0.10; flags.append("MULTIPLE_SUSPICIOUS_KEYWORDS")
    elif num_susp_keywords == 1:
        score += 0.05; flags.append("SUSPICIOUS_KEYWORD")

    # brand signals
    if best_org and best_score > 0.3:
        score += 0.15; flags.append(f"BRAND_SIMILARITY_{best_org.upper()}")
    if best_org:
        res = brand_results[best_org]
        if res.get("brand_in_subdomain"):
            score += 0.10; flags.append("BRAND_IN_SUBDOMAIN")
        if res.get("brand_in_domain"):
            score += 0.15; flags.append("BRAND_KEYWORD_IN_DOMAIN")
        if res.get("homoglyph_detected"):
            score += 0.20; flags.append("HOMOGLYPH_ATTACK")
        if res.get("typosquat_match"):
            score += 0.20; flags.append("TYPOSQUAT_DETECTED")

    # ssl signals
    if not ssl_info["valid"]:
        score += 0.05; flags.append("SSL_INVALID")
    if 0 <= ssl_info["age_days"] < 7:
        score += 0.10; flags.append("SSL_VERY_NEW")
    elif 0 <= ssl_info["age_days"] < 30:
        score += 0.05; flags.append("SSL_RECENTLY_ISSUED")

    score = min(score, 1.0)

    return {
        "url": url,
        "target_org": target_org,
        "url_score": round(score, 4),
        "flags": flags,
        "features": {
            "url_length": url_length,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_digits": num_digits,
            "digit_ratio": round(digit_ratio, 4),
            "entropy": round(entropy, 4),
            "path_depth": path_depth,
            "has_ip": has_ip,
            "is_https": is_https,
            "has_at": has_at,
            "has_double_slash": has_double_slash,
            "uses_shortener": uses_shortener,
            "suspicious_tld": suspicious_tld,
            "has_port": has_port,
            "num_suspicious_keywords": num_susp_keywords,
            "ssl_valid": ssl_info["valid"],
            "ssl_age_days": ssl_info["age_days"],
        },
        "brand_analysis": {
            "best_match_org": best_org,
            "best_match_score": round(best_score, 4),
            "details": brand_results,
        },
    }