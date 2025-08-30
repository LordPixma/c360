C360 Flask backend (local dev scaffolding)

- App factory in `app/__init__.py`
- Install with: `pip install -e .` (or `pip install -r requirements.txt` if you add one)
- Run with: `flask --app app run --debug`

Config:
- Set CORS origin via env var `C360_CORS_ORIGIN` (default `*`). Example: `C360_CORS_ORIGIN=https://yourapp.com flask --app app run`.
