import os
import base64
import secrets
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    from .supabase_client import get_supabase
except ImportError:
    from supabase_client import get_supabase

# Tabla por defecto en Supabase
API_KEYS_TABLE = os.getenv("API_KEYS_TABLE", "api_keys")

PBKDF2_ITERATIONS = int(os.getenv("API_KEYS_PBKDF2_ITERS", "200000"))
SALT_BYTES = 16
KEY_ID_BYTES = 8  # 8 bytes -> 16 hex chars aprox
SECRET_BYTES = 32


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _derive(secret: str, salt_b64: str) -> str:
    salt = _b64d(salt_b64)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        secret.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return _b64e(dk)


def _gen_key_id() -> str:
    # 8 bytes aleatorios codificados base64 urlsafe recortado
    return _b64e(os.urandom(KEY_ID_BYTES))


def _gen_secret() -> str:
    return _b64e(os.urandom(SECRET_BYTES))


def parse_full_key(full_key: str) -> Tuple[Optional[str], Optional[str]]:
    """Devuelve (key_id, secret). Formatos soportados:
    - EONS_<keyid>.<secret>
    - <keyid>.<secret>
    - Si no tiene separador, se considera todo como secret sin key_id.
    """
    if not full_key:
        return None, None
    val = full_key.strip()
    if val.upper().startswith("EONS_"):
        val = val.split("_", 1)[1]
    if "." in val:
        key_id, secret = val.split(".", 1)
        return key_id.strip(), secret.strip()
    return None, val


def create_api_key(
    name: str,
    rate_limit: Optional[int] = None,
    created_by: Optional[str] = None,
    owner_user_id: Optional[str] = None,
) -> Optional[str]:
    """Crea una API key, guarda hash+salt en Supabase y devuelve la clave completa una sola vez."""
    sb = get_supabase()
    if sb is None:
        return None
    key_id = _gen_key_id()
    secret = _gen_secret()
    full_key = f"EONS_{key_id}.{secret}"
    salt = _b64e(os.urandom(SALT_BYTES))
    derived = _derive(secret, salt)
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "key_id": key_id,
        "hash": derived,
        "salt": salt,
        "active": True,
        "name": name,
        "rate_limit": rate_limit,
        "created_at": now,
        "created_by": created_by,
        # Guardar un prefijo seguro (no revela el secreto completo)
        "prefix": secret[:8],
        # Propietario de la clave para filtrado por usuario en UI
        # Usar user_id en lugar de owner_user_id para coincidir con el esquema
        "user_id": owner_user_id,
    }
    sb.table(API_KEYS_TABLE).insert(payload).execute()
    return full_key


def revoke_api_key(key_id: str) -> bool:
    sb = get_supabase()
    if sb is None:
        return False
    sb.table(API_KEYS_TABLE).update({"active": False}).eq("key_id", key_id).execute()
    return True


def verify_api_key(full_key: str) -> Tuple[bool, Optional[str]]:
    """Verifica la API key. Devuelve (ok, key_id)."""
    sb = get_supabase()
    if sb is None:
        return False, None
    key_id, secret = parse_full_key(full_key)
    if not secret:
        return False, None
    # Si hay key_id, buscamos por key_id, si no, estrategia fallback no soportada (requiere key_id)
    if not key_id:
        return False, None
    res = sb.table(API_KEYS_TABLE).select("key_id, hash, salt, active").eq("key_id", key_id).limit(1).execute()
    rows = getattr(res, 'data', None) or []
    if not rows:
        return False, None
    row = rows[0]
    if not row.get("active"):
        return False, key_id
    derived = _derive(secret, row["salt"])
    if hmac.compare_digest(derived, row["hash"]):
        return True, key_id
    return False, key_id


def get_api_key_meta(key_id: str) -> Optional[dict]:
    """Obtiene metadatos de la API key, incluyendo rate_limit y active."""
    sb = get_supabase()
    if sb is None:
        return None
    try:
        res = (
            sb.table(API_KEYS_TABLE)
            .select("key_id, name, active, rate_limit, created_at, last_used_at, user_id")
            .eq("key_id", key_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, 'data', None) or []
        if not rows:
            return None
        return rows[0]
    except Exception:
        return None


def update_api_key(key_id: str, name: Optional[str] = None, active: Optional[bool] = None) -> bool:
    sb = get_supabase()
    if sb is None:
        return False
    updates = {}
    if name is not None:
        updates["name"] = name
    if active is not None:
        updates["active"] = bool(active)
    if not updates:
        return True
    try:
        sb.table(API_KEYS_TABLE).update(updates).eq("key_id", key_id).execute()
        return True
    except Exception:
        return False


def list_api_keys(limit: int = 100, offset: int = 0, owner_user_id: Optional[str] = None) -> list[dict]:
    sb = get_supabase()
    if sb is None:
        return []
    try:
        q = (
            sb.table(API_KEYS_TABLE)
            .select("key_id, name, active, rate_limit, created_at, last_used_at, prefix, user_id")
            .order("created_at", desc=True)
        )
        if owner_user_id:
            q = q.eq("user_id", owner_user_id)
        res = q.range(offset, offset + max(0, limit - 1)).execute()
        return getattr(res, 'data', None) or []
    except Exception:
        return []


def delete_api_key(key_id: str) -> bool:
    sb = get_supabase()
    if sb is None:
        return False
    try:
        sb.table(API_KEYS_TABLE).delete().eq("key_id", key_id).execute()
        return True
    except Exception:
        return False


def get_api_key_rate_limit(key_id: str) -> Optional[int]:
    meta = get_api_key_meta(key_id)
    if not meta:
        return None
    rl = meta.get("rate_limit")
    try:
        return int(rl) if rl is not None else None
    except Exception:
        return None
