# WebAppVulnScanner (GitHub-ready)

Minimal Web Application Vulnerability Scanner (XSS, SQLi, CSRF tests)
with a simple Flask UI. Use only against targets you own or have permission to test.

## Quick start (Windows)
1. Open a terminal in this folder.
2. Create virtualenv and activate:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Run the app:
   ```powershell
   python app.py
   ```
5. Open http://127.0.0.1:5000

## Quick start (Mac / Linux)
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Notes
- This is a learning/demo tool. Do **not** scan systems without permission.
- The scanner is intentionally simple. Improve it for production (politeness, rate-limits, robots.txt, authentication).
