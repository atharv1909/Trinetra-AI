import asyncio
import hashlib
from pathlib import Path
from urllib.parse import urlparse
import imagehash
from PIL import Image
import io

# ── paths ──────────────────────────────────────────────────────────────
BASE          = Path(__file__).parent / "data"
SCREENSHOTS   = BASE / "org_screenshots"
SCREENSHOTS.mkdir(exist_ok=True)

# ── helpers ────────────────────────────────────────────────────────────

def load_org_fingerprints() -> dict:
    """
    Load pHash fingerprints for all org screenshots.
    Returns {org_key: phash_object}
    """
    fingerprints = {}
    for png in SCREENSHOTS.glob("*.png"):
        org_key = png.stem  # filename without extension = org key
        try:
            fingerprints[org_key] = imagehash.phash(Image.open(png))
        except Exception as e:
            print(f"[Eye2] Could not load fingerprint for {org_key}: {e}")
    return fingerprints


async def take_screenshot(url: str) -> bytes | None:
    """
    Take a screenshot of a URL using Playwright.
    Returns PNG bytes or None on failure.
    """
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = await context.new_page()

            try:
                await page.goto(url, timeout=8000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)  # let page render
            except Exception:
                # try screenshot anyway even if page didn't fully load
                pass

            screenshot = await page.screenshot(full_page=False)
            await browser.close()
            return screenshot

    except Exception as e:
        print(f"[Eye2] Screenshot failed for {url}: {e}")
        return None


def compare_screenshots(
    target_bytes: bytes,
    org_key: str,
    fingerprints: dict
) -> dict:
    """
    Compare target screenshot against org fingerprint.
    Returns similarity score and details.
    """
    if org_key not in fingerprints:
        return {
            "similarity": 0.5,  # unknown
            "hamming_distance": -1,
            "org_fingerprint_found": False,
        }

    try:
        target_img  = Image.open(io.BytesIO(target_bytes))
        target_hash = imagehash.phash(target_img)
        org_hash    = fingerprints[org_key]

        hamming     = target_hash - org_hash
        similarity  = round(1 - (hamming / 64), 4)
        similarity  = max(0.0, min(1.0, similarity))

        return {
            "similarity":            similarity,
            "hamming_distance":      hamming,
            "org_fingerprint_found": True,
        }
    except Exception as e:
        print(f"[Eye2] Comparison error: {e}")
        return {
            "similarity":            0.5,
            "hamming_distance":      -1,
            "org_fingerprint_found": False,
        }


def analyze_visual(url: str, target_org: str = None) -> dict:
    """
    Eye 2 entry point — called from FastAPI background task.
    Synchronous wrapper around async screenshot logic.
    """
    # if this is the official domain, skip visual comparison
    # it will always match — that's expected, not suspicious
    if target_org:
        import json
        from pathlib import Path
        profiles_path = Path(__file__).parent / "data" / "brand_profiles" / "profiles.json"
        profiles = json.load(open(profiles_path))
        if target_org in profiles:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ""
            official = profiles[target_org]["official_domain"]
            official_subs = [
                s.replace("https://","").replace("http://","").split("/")[0]
                for s in profiles[target_org]["official_subdomains"]
            ]
            if hostname == official or hostname in official_subs:
                return {
                    "visual_score":     0.0,
                    "flags":            ["OFFICIAL_DOMAIN_SKIPPED_VISUAL"],
                    "similarity":       1.0,
                    "hamming_distance": 0,
                    "screenshot_taken": False,
                    "target_org":       target_org,
                }

    fingerprints = load_org_fingerprints()

    # take screenshot
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        screenshot_bytes = loop.run_until_complete(take_screenshot(url))
        loop.close()
    except Exception as e:
        print(f"[Eye2] Event loop error: {e}")
        screenshot_bytes = None

    # if screenshot failed
    if screenshot_bytes is None:
        return {
            "visual_score":      0.5,
            "flags":             ["SCREENSHOT_FAILED"],
            "similarity":        0.5,
            "hamming_distance":  -1,
            "screenshot_taken":  False,
        }

    # compare against target org if specified
    flags      = []
    similarity = 0.5

    if target_org and target_org in fingerprints:
        comparison = compare_screenshots(
            screenshot_bytes, target_org, fingerprints
        )
        similarity = comparison["similarity"]

        if similarity > 0.85:
            flags.append("VISUAL_CLONE_DETECTED")
        elif similarity > 0.70:
            flags.append("HIGH_VISUAL_SIMILARITY")
        elif similarity > 0.55:
            flags.append("MODERATE_VISUAL_SIMILARITY")

        visual_score = similarity

    elif target_org and target_org not in fingerprints:
        # org selected but no fingerprint stored yet
        flags.append("NO_ORG_FINGERPRINT")
        visual_score = 0.5

    else:
        # no target org — check against all orgs
        best_sim = 0.0
        best_org = None
        for org_key in fingerprints:
            comp = compare_screenshots(
                screenshot_bytes, org_key, fingerprints
            )
            if comp["similarity"] > best_sim:
                best_sim = comp["similarity"]
                best_org = org_key

        similarity   = best_sim
        visual_score = best_sim

        if best_sim > 0.85:
            flags.append(f"VISUAL_CLONE_OF_{best_org.upper()}")
        elif best_sim > 0.70:
            flags.append(f"SIMILAR_TO_{best_org.upper()}")

    return {
        "visual_score":     round(visual_score, 4),
        "flags":            flags,
        "similarity":       round(similarity, 4),
        "hamming_distance": -1,
        "screenshot_taken": True,
        "target_org":       target_org,
    }