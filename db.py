import json
from pathlib import Path

DB_FILE = Path('scan_results.json')

def load_results():
    if DB_FILE.exists():
        return json.loads(DB_FILE.read_text())
    return []

def save_result(result):
    data = load_results()
    data.append(result)
    DB_FILE.write_text(json.dumps(data, indent=2))
