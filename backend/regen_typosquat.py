import subprocess
import json
import sys
from pathlib import Path

domains = {
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
}

for org, domain in domains.items():
    print(f"Generating {org}...")
    result = subprocess.run(
        [sys.executable, "-m", "dnstwist", "--format", "json", domain],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )
    
    output = result.stdout if result.stdout.strip() else result.stderr
    
    json_start = output.find("[")
    if json_start == -1:
        print(f"  No JSON found. Output: {output[:200]}")
        continue
        
    json_str = output[json_start:]
    
    out_path = Path("data/typosquat_sets") / f"{org}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json_str)
    
    try:
        data = json.load(open(out_path, encoding="utf-8"))
        print(f"  OK: {len(data)} entries saved")
    except Exception as e:
        print(f"  FAILED: {e}")