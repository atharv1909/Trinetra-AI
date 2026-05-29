import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# ── constants ──────────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}
TIMEOUT = 6  # seconds


# ── helpers ────────────────────────────────────────────────────────────

def get_domain(url: str) -> str:
    return urlparse(url).hostname or ""


def fetch_html(url: str) -> tuple[str | None, str | None]:
    """
    Fetch page HTML. Returns (html, final_url) or (None, None) on failure.
    final_url accounts for redirects.
    """
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            verify=False,       # many phishing pages have bad certs
            allow_redirects=True
        )
        return resp.text, resp.url
    except Exception:
        return None, None


def analyze_behavior(url: str) -> dict:
    """
    Eye 3 — static HTML behavioral analysis.
    Returns behavior_score (0.0-1.0) and flags list.
    """
    page_domain = get_domain(url)
    html, final_url = fetch_html(url)

    # if we can't fetch the page, return unknown
    if html is None:
        return {
            "behavior_score": 0.5,
            "fetch_success": False,
            "flags": ["PAGE_UNREACHABLE"],
            "features": {
                "form_action_external": None,
                "has_password_field": None,
                "num_external_scripts": None,
                "favicon_external": None,
                "has_hidden_iframe": None,
                "num_external_links": None,
                "redirect_domain_changed": None,
            }
        }

    # check if page redirected to a different domain
    final_domain = get_domain(final_url) if final_url else page_domain
    redirect_domain_changed = (
        final_domain != page_domain and bool(final_domain)
    )

    soup = BeautifulSoup(html, "lxml")

    # ── FEATURE 1: form action external ───────────────────────────────
    form_action_external = False
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if not action or action.startswith("#"):
            continue
        # resolve relative URLs
        absolute_action = urljoin(final_url or url, action)
        action_domain = get_domain(absolute_action)
        if action_domain and action_domain != final_domain:
            form_action_external = True
            break

    # ── FEATURE 2: password field present ─────────────────────────────
    has_password_field = bool(
        soup.find("input", {"type": "password"})
    )

    # ── FEATURE 3: external scripts ───────────────────────────────────
    external_scripts = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        if src.startswith("//"):
            src = "https:" + src
        if src.startswith("http"):
            script_domain = get_domain(src)
            if script_domain and script_domain != final_domain:
                external_scripts.append(script_domain)
    num_external_scripts = len(external_scripts)

    # ── FEATURE 4: favicon domain check ───────────────────────────────
    favicon_external = False
    favicon_tag = soup.find("link", rel=lambda r: r and "icon" in r)
    if favicon_tag:
        favicon_href = favicon_tag.get("href", "")
        if favicon_href:
            absolute_favicon = urljoin(final_url or url, favicon_href)
            favicon_domain = get_domain(absolute_favicon)
            if favicon_domain and favicon_domain != final_domain:
                favicon_external = True

    # ── FEATURE 5: hidden iframes ──────────────────────────────────────
    has_hidden_iframe = False
    for iframe in soup.find_all("iframe"):
        style  = iframe.get("style", "").lower().replace(" ", "")
        width  = iframe.get("width",  "1")
        height = iframe.get("height", "1")
        if (
            "display:none"   in style or
            "visibility:hidden" in style or
            width  in ("0", "1") or
            height in ("0", "1")
        ):
            has_hidden_iframe = True
            break

    # ── FEATURE 6: external links ratio ───────────────────────────────
    all_links = soup.find_all("a", href=True)
    external_links = []
    for a in all_links:
        href = a.get("href", "")
        if href.startswith("http"):
            link_domain = get_domain(href)
            if link_domain and link_domain != final_domain:
                external_links.append(link_domain)
    num_external_links = len(external_links)

    # ── SCORING ────────────────────────────────────────────────────────
    flags = []
    score = 0.0

    if redirect_domain_changed:
        score += 0.15
        flags.append("REDIRECT_DOMAIN_CHANGED")

    if form_action_external:
        score += 0.45
        flags.append("FORM_POSTS_EXTERNALLY")

    if has_password_field and form_action_external:
        score += 0.20
        flags.append("CREDENTIAL_HARVESTING_PATTERN")

    elif has_password_field:
        score += 0.05
        flags.append("HAS_PASSWORD_FIELD")

    if favicon_external:
        score += 0.15
        flags.append("FAVICON_FROM_EXTERNAL_DOMAIN")

    if has_hidden_iframe:
        score += 0.10
        flags.append("HIDDEN_IFRAME_DETECTED")

    if num_external_scripts > 15:
        score += 0.10
        flags.append("EXCESSIVE_EXTERNAL_SCRIPTS")
    elif num_external_scripts > 8:
        score += 0.05
        flags.append("HIGH_EXTERNAL_SCRIPTS")

    score = min(score, 1.0)

    return {
        "behavior_score": round(score, 4),
        "fetch_success": True,
        "flags": flags,
        "features": {
            "form_action_external": form_action_external,
            "has_password_field": has_password_field,
            "num_external_scripts": num_external_scripts,
            "favicon_external": favicon_external,
            "has_hidden_iframe": has_hidden_iframe,
            "num_external_links": num_external_links,
            "redirect_domain_changed": redirect_domain_changed,
        }
    }