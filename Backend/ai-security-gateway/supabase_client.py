import os
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from supabase import create_client, Client

_SUPABASE_CLIENT: Optional[Client] = None
_DEBUG = os.getenv("SUPABASE_DEBUG", "").lower() in {"1", "true", "yes"}
API_USAGE_TABLE = os.getenv("API_USAGE_TABLE", "api_usage")
API_KEYS_TABLE = os.getenv("API_KEYS_TABLE", "api_keys")


def get_supabase() -> Optional[Client]:
    global _SUPABASE_CLIENT
    if _SUPABASE_CLIENT is not None:
        return _SUPABASE_CLIENT
    # Permitir múltiples nombres de variables de entorno.
    # Priorizar SERVICE_ROLE para operaciones administrativas (crear/revocar claves),
    # luego SUPABASE_KEY genérica; como último recurso, aceptar la anon key pública.
    url = (
        os.getenv("SUPABASE_URL")
        or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    )
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    )

    if not url or not key:
        if _DEBUG:
            print(
                "[SUPABASE] get_supabase: missing URL or KEY. Tried SUPABASE_URL/NEXT_PUBLIC_SUPABASE_URL "
                "and SUPABASE_SERVICE_ROLE_KEY/SUPABASE_SERVICE_KEY/SUPABASE_KEY/NEXT_PUBLIC_SUPABASE_ANON_KEY"
            )
        return None

    if _DEBUG:
        key_type = (
            "service_role" if os.getenv("SUPABASE_SERVICE_ROLE_KEY") else
            ("service" if os.getenv("SUPABASE_SERVICE_KEY") else
             ("generic" if os.getenv("SUPABASE_KEY") else "anon"))
        )
        print(f"[SUPABASE] Creating client. URL from: {'SUPABASE_URL' if os.getenv('SUPABASE_URL') else 'NEXT_PUBLIC_SUPABASE_URL'}; KEY type: {key_type}")
        if key_type == "anon":
            print("[SUPABASE][WARN] Using ANON key. Admin operations may fail due to RLS permissions.")

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


def _current_period_key() -> str:
    """Periodo de consumo en formato YYYY-MM."""
    now = datetime.utcnow()
    return now.strftime("%Y-%m")


def increment_api_usage(key_id: str, period_key: Optional[str] = None) -> Optional[int]:
    """Incrementa el contador de uso para una API key en el período dado.
    Devuelve el conteo actual tras el incremento, o None si no hay Supabase.
    Estructura de tabla esperada: { key_id: text, period_key: text, count: int, updated_at: timestamp }
    Clave única sugerida: (key_id, period_key)
    """
    sb = get_supabase()
    if sb is None:
        if _DEBUG:
            print("[SUPABASE] increment_api_usage: client unavailable; skipping")
        return None
    period = period_key or _current_period_key()
    try:
        # Intentar upsert atómico: si existe, incrementar; si no, crear con count=1
        # Nota: La librería python de Supabase no soporta operadores nativos de incremento,
        # así que hacemos: leer -> upsert con count+1.
        res = sb.table(API_USAGE_TABLE).select("count").eq("key_id", key_id).eq("period_key", period).limit(1).execute()
        rows = getattr(res, 'data', None) or []
        if rows:
            current = int(rows[0].get("count") or 0) + 1
            sb.table(API_USAGE_TABLE).upsert({
                "key_id": key_id,
                "period_key": period,
                "count": current,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, on_conflict="key_id,period_key").execute()
            return current
        else:
            sb.table(API_USAGE_TABLE).upsert({
                "key_id": key_id,
                "period_key": period,
                "count": 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, on_conflict="key_id,period_key").execute()
            return 1
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] increment_api_usage failed: {e}")
        return None


def get_api_usage_count(key_id: str, period_key: Optional[str] = None) -> Optional[int]:
    """Obtiene el conteo de uso para una API key en el período dado."""
    sb = get_supabase()
    if sb is None:
        return None
    period = period_key or _current_period_key()
    try:
        res = sb.table(API_USAGE_TABLE).select("count").eq("key_id", key_id).eq("period_key", period).limit(1).execute()
        rows = getattr(res, 'data', None) or []
        if not rows:
            return 0
        return int(rows[0].get("count") or 0)
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] get_api_usage_count failed: {e}")
        return None


def touch_api_key_last_used(key_id: Optional[str]) -> None:
    """Actualiza last_used_at de la API key. Silencioso si no hay Supabase o key_id es None."""
    if not key_id:
        return
    sb = get_supabase()
    if sb is None:
        return
    try:
        sb.table(API_KEYS_TABLE).update({
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        }).eq("key_id", key_id).execute()
        if _DEBUG:
            print("[SUPABASE] touch_api_key_last_used: ok")
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] touch_api_key_last_used failed: {e}")
        return
