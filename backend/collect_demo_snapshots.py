"""
Run this to collect and save real phishing page snapshots
for demo day. These are used when live phishing URLs go down.
"""
import asyncio
import json
import requests
from pathlib import Path
from playwright.async_api import async_playwright

SNAPSHOTS_DIR = Path(__file__).parent / "demo_snapshots"
SNAPSHOTS_DIR.mkdir(exist_ok=True)

DEMO_URLS = [
    {
        "id":         "microsoft_phish_1",
        "url":        "https://authentication.ms/E.rss8ZATzUT4lXg?/VGhlIG5leHQgZ2VuZXJhdGlvbiBvZiBzZWN1cml0eSBhd2FyZW5lc3MgaXMgZGVzaWduZWQgZm9yIGVtcGxveWVlcyBhbmQgYnVpbHQgZm9yIGVudGVycHJpc2VzLiBPdXIgaW5kdXN0cnktbGVhZGluZyByZXN1bHRzIGFyZSBwb3dlcmVkIGJ5IGNvZ25pdGl2ZSBhdXRvbWF0aW9uLg",
        "target_org": "microsoft",
        "note":       "Fake Microsoft authentication page"
    },
    {
        "id":         "paypal_phish_1",
        "url":        "https://yolo-shop.github.io/Paypal-",
        "target_org": "paypal",
        "note":       "PayPal phishing clone"
    },
    {
        "id":         "bank_phish_1",
        "url":        "https://chase.pcj-group.com/login",
        "target_org": "hdfc",
        "note":       "Bank login credential harvester"
    },
    {
        "id":         "sbi_phish_1",
        "url":        "http://sbi-secure-login.xyz",
        "target_org": "sbi",
        "note":       "SBI typosquat phishing domain"
    },
    {
        "id":         "microsoft_phish_2",
        "url":        "https://rnicrosoft.com",
        "target_org": "microsoft",
        "note":       "Microsoft typosquat — rn substitution attack"
    },
]


async def capture_snapshot(entry: dict):
    url = entry["url"]
    sid = entry["id"]
    out_dir = SNAPSHOTS_DIR / sid
    out_dir.mkdir(exist_ok=True)

    print(f"\nCapturing: {sid} — {url}")

    # save metadata
    with open(out_dir / "meta.json", "w") as f:
        json.dump(entry, f, indent=2)

    # try to fetch HTML
    try:
        resp = requests.get(
            url, timeout=8, verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with open(out_dir / "page.html", "w",
                  encoding="utf-8", errors="ignore") as f:
            f.write(resp.text)
        print(f"  HTML saved: {len(resp.text)} chars")
    except Exception as e:
        print(f"  HTML fetch failed: {e}")

    # take screenshot
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True
            )
            page = await context.new_page()
            try:
                await page.goto(url, timeout=8000,
                                wait_until="domcontentloaded")
                await page.wait_for_timeout(2000)
            except Exception as e:
                print(f"  Page load warning: {e}")
            await page.screenshot(
                path=str(out_dir / "screenshot.png"),
                full_page=False
            )
            await browser.close()
        print(f"  Screenshot saved")
    except Exception as e:
        print(f"  Screenshot failed: {e}")


async def main():
    for entry in DEMO_URLS:
        await capture_snapshot(entry)
    print(f"\nSnapshots saved to: {SNAPSHOTS_DIR}")
    print(f"Total: {len(DEMO_URLS)} snapshots")


asyncio.run(main())