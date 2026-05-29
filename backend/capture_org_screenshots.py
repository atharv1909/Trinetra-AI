"""
Run this once to capture official login page screenshots
for all target organizations.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright
import imagehash
from PIL import Image
import io

SCREENSHOTS_DIR = Path(__file__).parent / "data" / "org_screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

ORG_URLS = {
    "irctc": "https://www.irctc.co.in/nget/train-search",
}


async def capture(org_key: str, url: str):
    print(f"Capturing {org_key} — {url}")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        )
        page = await context.new_page()
        try:
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            await page.wait_for_timeout(4000)
        except Exception as e:
            print(f"  Warning: {e}")

        path = SCREENSHOTS_DIR / f"{org_key}.png"
        await page.screenshot(path=str(path), full_page=False)
        await browser.close()

        # verify and print hash
        img  = Image.open(path)
        hash = imagehash.phash(img)
        size = path.stat().st_size
        print(f"  Saved: {path.name} ({size/1024:.1f} KB) — pHash: {hash}")


async def main():
    for org_key, url in ORG_URLS.items():
        try:
            await capture(org_key, url)
        except Exception as e:
            print(f"  FAILED {org_key}: {e}")
    print("\nAll done. Screenshots saved to:", SCREENSHOTS_DIR)


asyncio.run(main())