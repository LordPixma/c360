C360 Flask backend (local dev scaffolding)

- App factory in `app/__init__.py`
- Install with: `pip install -e .` (or `pip install -r requirements.txt` if you add one)
- Run with: `flask --app app run --debug`

Config:
- Single CORS origin via `C360_CORS_ORIGIN` (default `*`). Example: `C360_CORS_ORIGIN=https://yourapp.com flask --app app run`.
- Multiple CORS origins via `C360_CORS_ORIGINS` (comma-separated). Example: `C360_CORS_ORIGINS=https://app.example.com,https://admin.example.com`.
	- If `C360_CORS_ORIGINS` is set, it takes precedence over `C360_CORS_ORIGIN`.
- Bearer auth token via `C360_API_TOKEN`. When set, all `/api/**` routes require `Authorization: Bearer <token>`.
