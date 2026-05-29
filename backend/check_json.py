import json
from pathlib import Path

for f in Path('data/typosquat_sets').glob('*.json'):
    try:
        data = json.load(open(f, encoding='utf-8-sig'))
        print(f'OK: {f.name} — {len(data)} entries')
    except Exception as e:
        print(f'BAD: {f.name} — {e}')