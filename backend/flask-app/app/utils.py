from typing import Tuple, Dict, Any


def error_response(code: str, message: str, status: int) -> Tuple[Dict[str, Any], int]:
    """Return a uniform error envelope used across the API.

    Example: error_response("bad_request", "name is required", 400)
    -> ({"error": {"code": "bad_request", "message": "name is required"}}, 400)
    """
    return {"error": {"code": code, "message": message}}, status
