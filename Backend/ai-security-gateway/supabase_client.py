import os
from typing import Any, Dict, Optional

from supabase import create_client, Client

_SUPABASE_CLIENT: Optional[Client] = None
_DEBUG = os.getenv("SUPABASE_DEBUG", "").lower() in {"1", "true", "yes"}


def get_supabase() -> Optional[Client]:
    global _SUPABASE_CLIENT
    if _SUPABASE_CLIENT is not None:
        return _SUPABASE_CLIENT
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        if _DEBUG:
            print("[SUPABASE] get_supabase: missing SUPABASE_URL or SUPABASE_KEY")
        return None
    try:
        _SUPABASE_CLIENT = create_client(url, key)
        return _SUPABASE_CLIENT
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] get_supabase: failed to create client: {e}")
        return None


def log_interaction(
    endpoint: str,
    request_payload: Dict[str, Any],
    response_payload: Dict[str, Any],
    status: str,
    user_ip: Optional[str] = None,
    layer: Optional[str] = "gateway",
    table: str = "backend_logs",
    blocked_status: Optional[str] = None,
    reason: Optional[str] = None,
    # Nuevos campos para seguimiento por API key y uso
    api_key_id: Optional[str] = None,
    prompt_tokens: Optional[int] = None,
    completion_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
) -> None:
    sb = get_supabase()
    if sb is None:
        if _DEBUG:
            print("[SUPABASE] log_interaction: Supabase client unavailable; skipping insert")
        return
    try:
        payload = {
            "layer": layer,
            "endpoint": endpoint,
            "status": status,
            "user_ip": user_ip,
            "request_payload": request_payload,
            "response_payload": response_payload,
        }
        # Campos nuevos opcionales
        if blocked_status is not None:
            payload["blocked_status"] = blocked_status
        if reason is not None:
            payload["reason"] = reason
        if api_key_id is not None:
            payload["api_key_id"] = api_key_id
        # Token usage (si está disponible)
        if prompt_tokens is not None:
            payload["prompt_tokens"] = prompt_tokens
        if completion_tokens is not None:
            payload["completion_tokens"] = completion_tokens
        if total_tokens is not None:
            payload["total_tokens"] = total_tokens

        sb.table(table).insert(payload).execute()
        if _DEBUG:
            print("[SUPABASE] log_interaction: insert ok")
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] log_interaction: insert failed: {e}")
        pass
