from database import get_whois_cache, save_whois_cache

# weights for final score
WEIGHTS = {
    "url":       0.40,
    "behavior":  0.20,
    "visual":    0.25,
    "blocklist": 0.15,
}


def get_risk_level(score: float) -> str:
    if score >= 0.65:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    elif score >= 0.20:
        return "LOW"
    else:
        return "SAFE"


def compute_final_score(
    url_score: float,
    behavior_score: float,
    visual_score: float = 0.5,
    blocklist_hit: bool = False,
) -> dict:
    blocklist_score = 1.0 if blocklist_hit else 0.0

    final = (
        WEIGHTS["url"]       * url_score +
        WEIGHTS["behavior"]  * behavior_score +
        WEIGHTS["visual"]    * visual_score +
        WEIGHTS["blocklist"] * blocklist_score
    )

    # visual override — if page looks very similar to org, boost score
    if visual_score >= 0.80:
        final = max(final, 0.70)
    elif visual_score >= 0.70:
        final = max(final, 0.55)

    # behavior override — credential harvesting is critical
    if behavior_score >= 0.65:
        final = max(final, 0.65)

    final = round(min(final, 1.0), 4)

    return {
        "final_score":  final,
        "risk_level":   get_risk_level(final),
        "component_scores": {
            "url_score":       round(url_score, 4),
            "behavior_score":  round(behavior_score, 4),
            "visual_score":    round(visual_score, 4),
            "blocklist_score": blocklist_score,
        },
        "weights": WEIGHTS,
    }


def get_whois_age(domain: str) -> int:
    """
    Get domain age in days.
    Checks SQLite cache first, only calls WHOIS if not cached.
    Returns -1 if unavailable.
    """
    cached = get_whois_cache(domain)
    if cached:
        return cached["age_days"]

    try:
        import whois
        from datetime import datetime
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.utcnow() - creation).days
            registrar = str(w.registrar or "unknown")
            save_whois_cache(domain, age_days, registrar)
            return age_days
    except Exception:
        pass

    return -1


def check_local_blocklist(url: str) -> bool:
    """
    Check if URL domain appears in our locally stored
    PhishTank/OpenPhish data. Returns True if found.
    We'll populate this properly after dataset download.
    For now returns False.
    """
    return False