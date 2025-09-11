import os
import json
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
        
    # Debug: Print all environment variables that start with SUPABASE or NEXT_PUBLIC
    if _DEBUG:
        print("[SUPABASE] Available environment variables:")
        for k, v in os.environ.items():
            if 'SUPABASE' in k or 'NEXT_PUBLIC' in k:
                print(f"  {k} = {'[REDACTED]' if 'KEY' in k else v}")
    
    # Check URL sources - prioritize NEXT_PUBLIC_SUPABASE_URL
    url = os.getenv("NEXT_PUBLIC_SUPABASE_URL") or os.getenv("SUPABASE_URL")
    
    # Check key sources in order of preference
    key_sources = [
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_SERVICE_KEY",
        "SUPABASE_KEY",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY"
    ]
    
    key = None
    used_key_source = None
    for key_source in key_sources:
        key = os.getenv(key_source)
        if key:
            used_key_source = key_source
            break
    
    if not url or not key:
        error_msg = (
            "[SUPABASE] Missing required configuration. "
            f"URL: {'Found' if url else 'Missing'}, "
            f"Key: {'Found' if key else 'Missing'}"
        )
        if _DEBUG:
            print(error_msg)
            if not url:
                print("  - Tried: SUPABASE_URL, NEXT_PUBLIC_SUPABASE_URL")
            if not key:
                print("  - Tried: " + ", ".join(key_sources))
        return None
        
    if _DEBUG:
        print(f"[SUPABASE] Using URL from: {'SUPABASE_URL' if os.getenv('SUPABASE_URL') else 'NEXT_PUBLIC_SUPABASE_URL'}")
        print(f"[SUPABASE] Using key from: {used_key_source}")

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
    api_key_id: Optional[str] = None,
    api_key: Optional[str] = None,
    prompt_tokens: Optional[int] = None,
    completion_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
) -> None:
    """Registra una interacción en Supabase.

    Args:
        endpoint: Ruta del endpoint (ej: /v1/chat/completions)
        request_payload: Payload de la solicitud (puede ser un dict o string JSON)
        response_payload: Payload de la respuesta (puede ser un dict o string JSON)
        status: Estado de la solicitud (ej: "success", "blocked", "error")
        user_ip: IP del usuario (opcional)
        layer: Capa de seguridad (ej: "firewall", "gateway")
        table: Nombre de la tabla en Supabase (default: 'backend_logs')
        blocked_status: Estado de bloqueo (opcional)
        reason: Razón del bloqueo (opcional)
        api_key_id: ID de la API key utilizada (opcional)
        prompt_tokens: Tokens de prompt utilizados (opcional)
        completion_tokens: Tokens de completado utilizados (opcional)
        total_tokens: Total de tokens utilizados (opcional)
    """
    if _DEBUG:
        print(f"[SUPABASE] log_interaction: Attempting to log to {table}")
        print(f"[SUPABASE] Endpoint: {endpoint}, Status: {status}, Layer: {layer}")
        print(f"[SUPABASE] User IP: {user_ip}, API Key ID: {api_key_id}")
    
    sb = get_supabase()
    if not sb:
        error_msg = f"[ERROR] No Supabase client available to log interaction to {endpoint}"
        print(error_msg)
        # Also print environment info for debugging
        print("[DEBUG] Environment variables:")
        for k, v in os.environ.items():
            if 'SUPABASE' in k or 'NEXT_PUBLIC' in k:
                print(f"  {k} = {'[REDACTED]' if 'KEY' in k else v}")
        return

    try:
        if _DEBUG:
            print("[SUPABASE] Preparing to log interaction...")
            
        # Asegurarse de que los payloads sean serializables
        try:
            if not isinstance(request_payload, (str, bytes)):
                request_payload = json.dumps(request_payload, ensure_ascii=False)
        except Exception as e:
            print(f"[ERROR] Failed to serialize request_payload: {e}")
            request_payload = str(request_payload)

        try:
            if not isinstance(response_payload, (str, bytes)):
                response_payload = json.dumps(response_payload, ensure_ascii=False)
        except Exception as e:
            print(f"[ERROR] Failed to serialize response_payload: {e}")
            response_payload = str(response_payload)

        # Limitar el tamaño de los payloads para evitar errores de base de datos
        max_length = 5000
        if isinstance(request_payload, str) and len(request_payload) > max_length:
            request_payload = request_payload[:max_length] + "... [TRUNCATED]"
        if isinstance(response_payload, str) and len(response_payload) > max_length:
            response_payload = response_payload[:max_length] + "... [TRUNCATED]"

        log_data = {
            "endpoint": endpoint,
            "request_payload": request_payload,
            "response_payload": response_payload,
            "status": status,
            "user_ip": user_ip,
            "layer": layer,
            "blocked_status": blocked_status,
            "reason": reason,
            "api_key_id": api_key_id,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Filtrar valores None para evitar errores de inserción
        log_data = {k: v for k, v in log_data.items() if v is not None}
        
        if _DEBUG:
            print("[SUPABASE] Prepared log data:")
            for k, v in log_data.items():
                print(f"  {k}: {str(v)[:100]}{'...' if len(str(v)) > 100 else ''}")

        # Insertar en Supabase
        if _DEBUG:
            print("[SUPABASE] Attempting to insert into table:", table)
            
        result = sb.table(table).insert(log_data).execute()
        
        # Verificar si hay errores en la respuesta
        if hasattr(result, 'error') and result.error:
            error_msg = f"[ERROR] Failed to log interaction to Supabase: {result.error}"
            print(error_msg)
            # Intentar obtener más detalles del error
            if hasattr(result, 'data') and result.data:
                print(f"[ERROR] Response data: {result.data}")
            if hasattr(result, 'status_code'):
                print(f"[ERROR] Status code: {result.status_code}")
        else:
            if _DEBUG:
                print("[SUPABASE] Successfully logged interaction")
                if hasattr(result, 'data') and result.data:
                    print(f"[SUPABASE] Inserted data: {result.data}")
                
    except Exception as e:
        error_msg = f"[ERROR] Exception in log_interaction: {str(e)}"
        print(error_msg)
        import traceback
        print("Traceback:", traceback.format_exc())


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


def touch_api_key_last_used(key_id: Optional[str]):
    """Actualiza last_used_at de la API key. Silencioso si no hay Supabase o key_id es None."""
    if not key_id:
        return
    sb = get_supabase()
    if not sb:
        return
    try:
        sb.table(API_KEYS_TABLE).update({"last_used_at": datetime.now(timezone.utc).isoformat()})\
            .eq("key_id", key_id).execute()
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] Error updating last_used_at for key {key_id}: {e}")


def get_api_key_meta(key_id: str) -> Optional[dict]:
    """Obtiene los metadatos de una API key.
    
    Args:
        key_id: ID de la API key a consultar
        
    Returns:
        dict con los metadatos de la key o None si no se encuentra o hay error
    """
    sb = get_supabase()
    if not sb:
        return None
        
    try:
        res = sb.table(API_KEYS_TABLE).select("key_id, name, active, rate_limit, created_at, last_used_at, user_id").eq("key_id", key_id).limit(1).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None
    except Exception as e:
        if _DEBUG:
            print(f"[SUPABASE] Error getting API key meta for {key_id}: {e}")
        return None
