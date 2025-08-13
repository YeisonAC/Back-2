import os
import json
from datetime import datetime
from typing import Any, Dict, Optional

from supabase import create_client, Client

_SUPABASE_CLIENT: Optional[Client] = None


def get_supabase() -> Optional[Client]:
    """
    Creates or returns a cached Supabase client using env vars.
    Requires SUPABASE_URL and SUPABASE_KEY in environment.
    Returns None if not configured to avoid breaking the app.
    """
    global _SUPABASE_CLIENT
    if _SUPABASE_CLIENT is not None:
        return _SUPABASE_CLIENT

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        return None

    try:
        _SUPABASE_CLIENT = create_client(url, key)
        return _SUPABASE_CLIENT
    except Exception:
        # Never propagate errors from telemetry setup
        return None


def log_interaction(
    provider: str,
    endpoint: str,
    request_payload: Dict[str, Any],
    response_payload: Dict[str, Any],
    status: str,
    user_ip: Optional[str] = None,
    table: str = "backend_logs",
) -> None:
    """
    Non-blocking best-effort logging of a backend interaction to Supabase.

    Table expected schema (create in Supabase):
      - id: uuid (default gen_random_uuid())
      - created_at: timestamptz (default now())
      - provider: text
      - endpoint: text
      - status: text
      - user_ip: text
      - request_payload: jsonb
      - response_payload: jsonb
    """
    sb = get_supabase()
    if sb is None:
        return

    try:
        sb.table(table).insert({
            "provider": provider,
            "endpoint": endpoint,
            "status": status,
            "user_ip": user_ip,
            "request_payload": request_payload,
            "response_payload": response_payload,
        }).execute()
    except Exception:
        # Swallow logging errors to avoid breaking request flow
        pass
