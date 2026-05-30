import sys
import warnings
from pathlib import Path

# suppress urllib3 SSL warnings globally
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json

from eye1_url import analyze_url
from eye3_behavior import analyze_behavior
from scorer import compute_final_score, get_risk_level, check_local_blocklist
from database import init_db, save_scan, get_scan, get_history, update_visual

# ── app setup ──────────────────────────────────────────────────────────
app = FastAPI(
    title="Trinetra AI",
    description="Targeted Brand Impersonation & Phishing Detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # frontend can call from anywhere
    allow_methods=["*"],
    allow_headers=["*"],
)

# initialize DB on startup
@app.on_event("startup")
def startup():
    init_db()
    print("Trinetra AI backend started.")


# ── request/response models ────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    target_org: str | None = None   # optional, e.g. "sbi", "google"


class ScanResponse(BaseModel):
    scan_id: str
    url: str
    target_org: str | None
    final_score: float
    risk_level: str
    flags: list
    url_score: float
    behavior_score: float
    visual_score: float
    visual_pending: bool
    component_scores: dict
    eye1_result: dict
    eye3_result: dict


# ── background task: Eye 2 visual analysis ────────────────────────────
def run_visual_analysis(scan_id: str, url: str, target_org: str | None):
    """
    Visual analysis disabled on hosted version due to RAM constraints.
    Eye 2 (Playwright) requires ~400MB RAM — not available on free tier.
    Run locally for full visual detection.
    """
    visual_score = 0.5
    visual_flags = ["VISUAL_ANALYSIS_DISABLED_ON_HOST"]

    scan = get_scan(scan_id)
    if not scan:
        return

    updated = compute_final_score(
        url_score      = scan["url_score"] or 0.0,
        behavior_score = scan["behavior_score"] or 0.0,
        visual_score   = visual_score,
        blocklist_hit  = check_local_blocklist(url),
    )

    update_visual(
        scan_id      = scan_id,
        visual_score = visual_score,
        final_score  = updated["final_score"],
        risk_level   = updated["risk_level"],
        visual_flags = visual_flags,
    )
    print(f"[Eye2] Scan {scan_id} visual updated: {visual_score}")


# ── endpoints ──────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "Trinetra AI is running", "version": "1.0.0"}


@app.get("/orgs")
def list_orgs():
    """Return available target organizations."""
    profiles_path = Path(__file__).parent / "data" / "brand_profiles" / "profiles.json"
    with open(profiles_path) as f:
        profiles = json.load(f)
    return {
        key: {
            "display_name": val["display_name"],
            "official_domain": val["official_domain"],
        }
        for key, val in profiles.items()
    }


@app.post("/scan", response_model=ScanResponse)
def scan_url(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Main scan endpoint.
    Runs Eye 1 and Eye 3 synchronously, returns result immediately.
    Eye 2 (visual) runs in background and updates the scan record.
    """
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    target_org = request.target_org

   # ── Eye 1: URL intelligence ────────────────────────────────────────
    eye1 = analyze_url(url, target_org)

    # ── Eye 3: behavioral analysis ────────────────────────────────────
    eye3 = analyze_behavior(url)

    # ── ML model prediction ───────────────────────────────────────────
    from ml_model import predict as ml_predict
    html = eye3.get("html", "")
    ml_result = ml_predict(url, html)
    ml_score  = ml_result["ml_score"]

    # ── blocklist check ───────────────────────────────────────────────
    blocklist_hit = check_local_blocklist(url)

    # ── blend eye1 rule score with ML score ───────────────────────────
    blended_url_score = round(
        0.5 * eye1["url_score"] + 0.5 * ml_score, 4
    )

    # ── initial score (visual = 0.5 = unknown/pending) ────────────────
    scored = compute_final_score(
        url_score      = blended_url_score,
        behavior_score = eye3["behavior_score"],
        visual_score   = 0.5,
        blocklist_hit  = blocklist_hit,
    )

    # ── combine all flags ─────────────────────────────────────────────
    all_flags = eye1["flags"] + eye3["flags"]

    # ── save to DB ────────────────────────────────────────────────────
    scan_data = {
        "url":             url,
        "target_org":      target_org,
        "url_score":       blended_url_score,
        "behavior_score":  eye3["behavior_score"],
        "visual_score":    0.5,
        "final_score":     scored["final_score"],
        "risk_level":      scored["risk_level"],
        "flags":           all_flags,
        "eye1_result":     eye1,
        "eye3_result":     eye3,
        "ml_result":       ml_result,
    }
    scan_id = save_scan(scan_data)

    # ── kick off Eye 2 in background ──────────────────────────────────
    background_tasks.add_task(run_visual_analysis, scan_id, url, target_org)

    return ScanResponse(
        scan_id         = scan_id,
        url             = url,
        target_org      = target_org,
        final_score     = scored["final_score"],
        risk_level      = scored["risk_level"],
        flags           = all_flags,
        url_score       = eye1["url_score"],
        behavior_score  = eye3["behavior_score"],
        visual_score    = 0.5,
        visual_pending  = True,
        component_scores = scored["component_scores"],
        eye1_result     = eye1,
        eye3_result     = eye3,
    )


@app.get("/scan/{scan_id}")
def get_scan_result(scan_id: str):
    """
    Poll this endpoint to get the complete result including
    visual score once Eye 2 finishes.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/history")
def scan_history(limit: int = 50):
    """Return recent scan history."""
    return get_history(limit)


@app.delete("/history")
def clear_history():
    """Clear all scan history — useful during demo prep."""
    from database import get_connection
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return {"status": "history cleared"}
