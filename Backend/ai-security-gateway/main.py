from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import json
import base64
import ast
import requests
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Union, Set
import http
from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path
from supabase import create_client, Client
from dataclasses import dataclass

# Importar funciones de API keys
try:
    from .api_keys import create_api_key, list_api_keys, revoke_api_key, update_api_key, delete_api_key, get_api_key_meta, parse_full_key
except ImportError:
    from api_keys import create_api_key, list_api_keys, revoke_api_key, update_api_key, delete_api_key, get_api_key_meta, parse_full_key

# Cargar variables de entorno
load_dotenv(dotenv_path=Path(__file__).with_name('.env'))

# Configuración de modelos Groq
COMPLETION_MODEL = os.getenv("GROQ_COMPLETION_MODEL", "openai/gpt-oss-20b")
CLASSIFIER_MODEL = os.getenv("GROQ_CLASSIFIER_MODEL", "openai/gpt-oss-20b")
ENABLE_INTENT_LAYER = os.getenv("ENABLE_INTENT_LAYER", "true").lower() == "true"

# Variables de entorno específicas por tier
L1_MINI_COMPLETION_MODEL = os.getenv("L1_MINI_COMPLETION_MODEL", "l1-mini")
L1_MINI_CLASSIFIER_MODEL = os.getenv("L1_MINI_CLASSIFIER_MODEL", "l1-mini")
L1_MEDIUM_COMPLETION_MODEL = os.getenv("L1_MEDIUM_COMPLETION_MODEL", "l1-medium")
L1_MEDIUM_CLASSIFIER_MODEL = os.getenv("L1_MEDIUM_CLASSIFIER_MODEL", "l1-mini")
L1_PRO_COMPLETION_MODEL = os.getenv("L1_PRO_COMPLETION_MODEL", "l1-pro")
L1_PRO_CLASSIFIER_MODEL = os.getenv("L1_PRO_CLASSIFIER_MODEL", "l1-mini")
ML1_COMPLETION_MODEL = os.getenv("ML1_COMPLETION_MODEL", "ml1")
ML1_CLASSIFIER_MODEL = os.getenv("ML1_CLASSIFIER_MODEL", "l1-mini")

@dataclass
class TierConfig:
    name: str
    max_context_tokens: int
    max_output_tokens: int
    completion_model: str
    completion_temperature: float
    completion_top_p: float
    classifier_model: str
    classifier_temperature: float
    classifier_max_tokens: int
    classifier_retries: int
    enable_intent_layer: bool


def _env_or(default: str, env_var: str) -> str:
    """Helper para obtener variable de entorno o usar default"""
    return os.getenv(env_var, default)


TIER_CONFIGS: dict[str, TierConfig] = {
    "L1-mini": TierConfig(
        name="L1-mini",
        max_context_tokens=4000,
        max_output_tokens=512,
        completion_model=_env_or(COMPLETION_MODEL, "L1_MINI_COMPLETION_MODEL"),
        completion_temperature=0.7,
        completion_top_p=1.0,
        classifier_model=_env_or(CLASSIFIER_MODEL, "L1_MINI_CLASSIFIER_MODEL"),
        classifier_temperature=0.0,
        classifier_max_tokens=256,
        classifier_retries=0,
        enable_intent_layer=ENABLE_INTENT_LAYER,
    ),
    "L1-medium": TierConfig(
        name="L1-medium",
        max_context_tokens=16000,
        max_output_tokens=1024,
        completion_model=_env_or(COMPLETION_MODEL, "L1_MEDIUM_COMPLETION_MODEL"),
        completion_temperature=0.6,
        completion_top_p=0.95,
        classifier_model=_env_or(CLASSIFIER_MODEL, "L1_MEDIUM_CLASSIFIER_MODEL"),
        classifier_temperature=0.0,
        classifier_max_tokens=384,
        classifier_retries=1,
        enable_intent_layer=True,
    ),
    "L1-pro": TierConfig(
        name="L1-pro",
        max_context_tokens=64000,
        max_output_tokens=2048,
        completion_model=_env_or(COMPLETION_MODEL, "L1_PRO_COMPLETION_MODEL"),
        completion_temperature=0.4,
        completion_top_p=0.9,
        classifier_model=_env_or(CLASSIFIER_MODEL, "L1_PRO_CLASSIFIER_MODEL"),
        classifier_temperature=0.0,
        classifier_max_tokens=512,
        classifier_retries=2,
        enable_intent_layer=True,
    ),
    "ML1": TierConfig(
        name="ML1",
        max_context_tokens=16000,
        max_output_tokens=1024,
        completion_model=_env_or(COMPLETION_MODEL, "ML1_COMPLETION_MODEL"),
        completion_temperature=0.2,
        completion_top_p=0.9,
        classifier_model=_env_or(CLASSIFIER_MODEL, "ML1_CLASSIFIER_MODEL"),
        classifier_temperature=0.0,
        classifier_max_tokens=256,
        classifier_retries=0,
        enable_intent_layer=False,
    ),
}


def _normalize_tier_name(raw: Optional[str]) -> str:
    if not raw:
        return "L1-mini"
    v = raw.strip().lower()
    if v in {"mini", "l1", "l1-mini", "l1_mini"}:
        return "L1-mini"
    if v in {"medium", "mid", "l1-medium", "l1_medium"}:
        return "L1-medium"
    if v in {"pro", "l1-pro", "l1_pro"}:
        return "L1-pro"
    if v in {"ml1", "multi-layer", "multi_layer"}:
        return "ML1"
    return "L1-mini"


def _select_tier(request: Request) -> TierConfig:
    # Prioridad: Header > query param > default
    raw = request.headers.get("X-Layer") or request.query_params.get("layer")
    name = _normalize_tier_name(raw)
    return TIER_CONFIGS.get(name, TIER_CONFIGS["L1-mini"])


def _estimate_tokens(text: str) -> int:
    # Aproximación 1 token ~ 4 chars
    return max(1, len(text) // 4)


def _cap_messages_to_context(messages: list[dict], max_context_tokens: int) -> list[dict]:
    # Conserva desde el final (más recientes) y trunca si excede
    kept: list[dict] = []
    total = 0
    for msg in reversed(messages):
        content = str(msg.get("content", ""))
        t = _estimate_tokens(content)
        if total + t <= max_context_tokens:
            kept.append(msg)
            total += t
        else:
            # Intentar truncar este mensaje si nada se ha agregado aún
            if t > 0 and not kept and max_context_tokens > 0:
                # Mantener solo la cola del contenido que quepa
                approx_chars = max_context_tokens * 4
                msg_copy = dict(msg)
                msg_copy["content"] = content[-approx_chars:]
                kept.append(msg_copy)
            break
    kept.reverse()
    return kept

# Configuración de Supabase
supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
supabase_anon_key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
supabase_service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase_available = False

print(f"DEBUG: Supabase URL: {'***' + supabase_url[-20:] if supabase_url else 'NOT SET'}")
print(f"DEBUG: Supabase Anon Key: {'***' + supabase_anon_key[-10:] if supabase_anon_key else 'NOT SET'}")
print(f"DEBUG: Supabase Service Key: {'***' + supabase_service_key[-10:] if supabase_service_key else 'NOT SET'}")

# Verificar si Supabase está disponible
if supabase_url and supabase_anon_key:
    try:
        from supabase import create_client, Client
        # Inicializar cliente de Supabase (anon key para operaciones normales)
        supabase: Client = create_client(supabase_url, supabase_anon_key)

        # Inicializar cliente de Supabase con service role key para backend_logs
        supabase_service: Client = create_client(supabase_url, supabase_service_key) if supabase_service_key else supabase

        supabase_available = True
        print("DEBUG: Supabase clients initialized successfully")
    except Exception as e:
        print(f"DEBUG: Supabase connection failed: {str(e)}")
        supabase_available = False
else:
    print("DEBUG: Supabase credentials not found")
    supabase_available = False

# Configuración básica
app = FastAPI(title="EONS API - Minimal Version", version="1.0.0")

# Función para obtener cliente de Supabase (usando la función de supabase_client.py)
def get_supabase():
    try:
        from supabase_client import get_supabase as get_supabase_client
        client = get_supabase_client()
        return client
    except ImportError:
        # Fallback si no se puede importar supabase_client
        if not supabase_available:
            return None
        try:
            from supabase import create_client, Client
            return create_client(supabase_url, supabase_anon_key)
        except Exception:
            return None
    except Exception:
        return None

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de respuesta
class LogItem(BaseModel):
    id: str
    api_key_id: str
    endpoint: str
    status: str
    created_at: str
    request_payload: Optional[dict] = None
    response_payload: Optional[dict] = None

class LogsResponse(BaseModel):
    data: List[LogItem]
    total: int
    page: int
    page_size: int
    debug_info: Optional[dict] = None

# Modelos para API Keys
class CreateKeyRequest(BaseModel):
    name: str
    rate_limit: Optional[int] = None
    user_id: Optional[str] = None

class UpdateKeyRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None

class MgmtCreateKeyRequest(BaseModel):
    name: str
    rate_limit: Optional[int] = None

class MgmtUpdateKeyRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_id: str
    full_key: str
    rate_limit: Optional[int] = None
    created_at: str
    is_active: bool = True
    owner_user_id: Optional[str] = None

class APIKeyMetaResponse(BaseModel):
    id: str
    name: str
    key_id: str
    rate_limit: Optional[int] = None
    created_at: str
    is_active: bool
    owner_user_id: Optional[str] = None

# Modelos para Chat Completions
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False

# Constantes para el servicio
SERVICE_NAME = "EONS API"
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

# Seguridad básica
security = HTTPBearer()

def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Extrae user_id del JWT token"""
    try:
        token = credentials.credentials
        # Decodificar manualmente el payload (base64)
        token_parts = token.split('.')
        if len(token_parts) != 3:
            raise HTTPException(status_code=401, detail="Token inválido")
        
        payload_b64 = token_parts[1]
        padding_needed = len(payload_b64) % 4
        if padding_needed:
            payload_b64 += '=' * (4 - padding_needed)
        
        payload_bytes = base64.b64decode(payload_b64)
        payload_str = payload_bytes.decode('utf-8')
        payload = json.loads(payload_str)
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID no encontrado en token")
        
        return user_id
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")

# Funciones de utilidad para chat completions
def get_client_ip(request: Request) -> str:
    """Obtener IP del cliente"""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _build_forwarded_ip_headers(request: Request, client_ip: str) -> Dict[str, str]:
    """Construir headers con IP forward"""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.getenv('GROQ_API_KEY', '')}",
        "X-Forwarded-For": client_ip,
    }
    return headers



def classify_intent(request: Request, content: str, client_ip: str, tier) -> Optional[Dict]:
    """Clasificar intención del usuario"""
    # Implementación simple - siempre retornar None por ahora
    return None

def derive_labels_from_intent(intent: Dict) -> Set[str]:
    """Derivar etiquetas de seguridad desde intención"""
    return set()

def derive_labels_from_flags(flags: List[str]) -> Set[str]:
    """Derivar etiquetas de seguridad desde flags"""
    return set(flags)

def pick_primary_label(labels: Set[str]) -> Optional[str]:
    """Seleccionar etiqueta primaria"""
    return next(iter(labels)) if labels else None

def _normalize_tier_name(tier_name: str) -> str:
    """Normalizar nombre de tier"""
    return tier_name.lower()

# Importar la clase AIFirewall real
try:
    from .ai_firewall import AIFirewall
except ImportError:
    from ai_firewall import AIFirewall

# Instancia global del firewall real
firewall = AIFirewall()

# Endpoints básicos
@app.get("/")
async def root():
    return {"message": "EONS API - Minimal Version", "status": "ok"}

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/api/test/keys")
async def test_api_keys():
    """Endpoint de prueba para verificar la funcionalidad de API keys"""
    try:
        # Probar la conectividad a Supabase
        sb = get_supabase()
        if sb is None:
            return {"error": "Supabase not available", "status": "error"}
        
        # Probar crear una API key de prueba
        test_key = create_api_key(
            name="test-key",
            rate_limit=1000,
            owner_user_id="test-user"
        )
        
        if test_key is None:
            return {"error": "Failed to create test API key", "status": "error"}
        
        # Parsear la clave para obtener el key_id
        key_id, _ = parse_full_key(test_key)
        
        # Obtener metadatos
        key_meta = get_api_key_meta(key_id)
        
        return {
            "status": "success",
            "message": "API key creation test successful",
            "test_key_id": key_id,
            "key_meta_available": key_meta is not None,
            "key_meta": key_meta,
            "supabase_connected": True
        }
        
    except Exception as e:
        import traceback
        return {
            "error": f"Test failed: {str(e)}",
            "status": "error",
            "exception_type": type(e).__name__,
            "traceback": traceback.format_exc()
        }

@app.get("/api/debug/supabase")
async def debug_supabase():
    """Endpoint de diagnóstico para verificar la configuración de Supabase"""
    try:
        # Verificar variables de entorno
        env_vars = {
            "NEXT_PUBLIC_SUPABASE_URL": os.getenv("NEXT_PUBLIC_SUPABASE_URL"),
            "NEXT_PUBLIC_SUPABASE_ANON_KEY": "***" + os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", "")[-10:] if os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY") else None,
            "SUPABASE_SERVICE_ROLE_KEY": "***" + os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")[-10:] if os.getenv("SUPABASE_SERVICE_ROLE_KEY") else None,
        }
        
        # Probar conexión a Supabase
        sb = get_supabase()
        if sb is None:
            return {
                "status": "error",
                "message": "Supabase client is None",
                "env_vars": env_vars
            }
        
        # Probar consulta simple
        try:
            result = sb.table("api_keys").select("count").limit(1).execute()
            table_accessible = True
            table_error = None
        except Exception as e:
            table_accessible = False
            table_error = str(e)
        
        return {
            "status": "success",
            "message": "Supabase configuration check",
            "env_vars": env_vars,
            "supabase_client": "available",
            "table_accessible": table_accessible,
            "table_error": table_error
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "error",
            "message": f"Debug failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

@app.get("/api/debug/groq")
async def debug_groq():
    """Endpoint de diagnóstico para verificar la configuración de Groq"""
    try:
        # Verificar variables de entorno
        groq_api_key = os.getenv('GROQ_API_KEY')
        groq_url = GROQ_CHAT_URL
        
        env_vars = {
            "GROQ_API_KEY": "***" + groq_api_key[-10:] if groq_api_key else None,
            "GROQ_CHAT_URL": groq_url,
        }
        
        if not groq_api_key:
            return {
                "status": "error",
                "message": "GROQ_API_KEY not found",
                "env_vars": env_vars
            }
        
        # Probar conexión a Groq con una petición simple
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {groq_api_key}",
        }
        
        test_payload = {
            "model": "openai-oss-8b",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }
        
        try:
            response = requests.post(groq_url, headers=headers, json=test_payload, timeout=10)
            groq_accessible = True
            groq_status = response.status_code
            groq_error = None
            
            if response.status_code == 200:
                groq_response = response.json()
                groq_success = True
            else:
                groq_success = False
                groq_error = response.text
                
        except Exception as e:
            groq_accessible = False
            groq_status = None
            groq_error = str(e)
            groq_success = False
        
        return {
            "status": "success",
            "message": "Groq configuration check",
            "env_vars": env_vars,
            "groq_accessible": groq_accessible,
            "groq_status": groq_status,
            "groq_success": groq_success,
            "groq_error": groq_error
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "error",
            "message": f"Debug failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

@app.post("/api/test/chat")
async def test_chat_completions(request: Request):
    """Endpoint de prueba para verificar el chat completions"""
    try:
        print("DEBUG: Starting test chat completions")
        
        # Verificar variables de entorno
        groq_api_key = os.getenv('GROQ_API_KEY')
        if not groq_api_key:
            return JSONResponse(
                status_code=500,
                content={"error": "GROQ_API_KEY not found"}
            )
        
        # Obtener IP del cliente
        client_ip = get_client_ip(request)
        print(f"DEBUG: Client IP: {client_ip}")
        
        # Headers para Groq
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {groq_api_key}",
            "X-Forwarded-For": client_ip,
        }
        
        # Payload de prueba simple
        test_payload = {
            "model": "openai-oss-8b",
            "messages": [{"role": "user", "content": "Hello, how are you?"}],
            "max_tokens": 50,
            "temperature": 0.7
        }
        
        print(f"DEBUG: Sending request to Groq: {test_payload}")
        
        # Hacer la petición a Groq
        response = requests.post(GROQ_CHAT_URL, headers=headers, json=test_payload, timeout=30)
        
        print(f"DEBUG: Groq response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"DEBUG: Groq response data: {data}")
            
            return JSONResponse(content={
                "status": "success",
                "message": "Chat completions test successful",
                "groq_response": data,
                "client_ip": client_ip
            })
        else:
            print(f"ERROR: Groq API error: {response.status_code} - {response.text}")
            return JSONResponse(
                status_code=response.status_code,
                content={
                    "error": f"Groq API error: {response.text}",
                    "status_code": response.status_code
                }
            )
            
    except Exception as e:
        print(f"ERROR: Test chat completions failed: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Test failed: {str(e)}",
                "traceback": traceback.format_exc()
            }
        )

@app.get("/api/logs", response_model=LogsResponse)
async def get_logs(
    request: Request,
    page: int = 1,
    page_size: int = 20,
    current_user_id: str = Depends(get_current_user_id)
):
    """
    Get logs for the authenticated user from Supabase database
    """
    try:
        print(f"DEBUG: Iniciando get_logs para user_id: {current_user_id}")
        
        if not supabase_available:
            raise HTTPException(status_code=503, detail="Supabase database not available")
        
        # Obtener cliente de Supabase
        supabase = get_supabase()
        
        # Preparar información de depuración básica
        debug_info = {
            "user_id": current_user_id,
            "api_key_ids": [],
            "table_used": "backend_logs",
            "message": "Processing logs request"
        }
        
        # Primero obtener las API keys del usuario
        print(f"DEBUG: Buscando API keys para user_id: {current_user_id}")
        
        # Intentar con api_keys_public primero
        api_keys_response = supabase.table("api_keys_public").select("*").eq("owner_user_id", current_user_id).execute()
        print(f"DEBUG: Respuesta api_keys_public: {api_keys_response}")
        
        if not api_keys_response.data:
            # Si no hay datos en api_keys_public, intentar con api_keys
            api_keys_response = supabase.table("api_keys").select("*").eq("owner_user_id", current_user_id).execute()
            print(f"DEBUG: Respuesta api_keys: {api_keys_response}")
        
        api_keys = api_keys_response.data if api_keys_response.data else []
        
        print(f"DEBUG: API keys encontradas: {len(api_keys)}")
        
        # Extraer key_id de las API keys (filtrando nulos)
        api_key_ids = []
        null_count = 0
        if api_keys:
            for i, key in enumerate(api_keys):
                key_id = key.get("key_id")
                if key_id and key_id.strip():  # Filtrar nulos y vacíos
                    api_key_ids.append(str(key_id))
                else:
                    null_count += 1
                    if i < 5:  # Mostrar solo los primeros 5 nulos para depuración
                        print(f"DEBUG: API key {i} con key_id nulo/vacío: {key}")
            
            print(f"DEBUG: Total de API key IDs válidos: {len(api_key_ids)} de {len(api_keys)}")
            print(f"DEBUG: API keys con key_id nulo/vacío: {null_count}")
            print(f"DEBUG: Primeros 5 API key IDs válidos: {api_key_ids[:5]}")
        else:
            print(f"DEBUG: No se encontraron API keys")
        
        debug_info["api_key_ids"] = api_key_ids
        
        if not api_key_ids:
            print(f"DEBUG: No se encontraron API keys para el usuario {current_user_id}")
            return LogsResponse(data=[], total=0, page=page, page_size=page_size)
        
        # Buscar logs relacionados con las API keys del usuario
        print(f"DEBUG: Buscando logs para API key IDs: {api_key_ids}")
        
        # Intentar diferentes tablas de logs
        logs_data = []
        
        # Usar específicamente la tabla backend_logs que existe y contiene los campos necesarios
        print(f"DEBUG: Usando tabla backend_logs que contiene los campos request_payload y response_payload")
        
        # Verificar conexión y mostrar información de Supabase
        try:
            print(f"DEBUG: Verificando conexión a Supabase...")
            print(f"DEBUG: Supabase URL: {supabase.supabase_url if hasattr(supabase, 'supabase_url') else 'No disponible'}")
            
            # Intentar obtener información de la conexión
            health_response = supabase.table("api_keys_public").select("count").limit(1).execute()
            print(f"DEBUG: Conexión a Supabase OK - puede consultar api_keys_public")
            
            # Verificar que la tabla backend_logs existe y obtener estructura (usando service role key)
            sample_response = supabase_service.table("backend_logs").select("*").limit(1).execute()
            if sample_response.data:
                print(f"DEBUG: Tabla backend_logs existe y tiene datos")
                print(f"DEBUG: Estructura del primer registro: {sample_response.data[0]}")
                # Mostrar campos disponibles
                first_record = sample_response.data[0]
                available_fields = list(first_record.keys())
                print(f"DEBUG: Campos disponibles en backend_logs: {available_fields}")
                
                # Verificar campos específicos que necesitamos
                required_fields = ["api_key_id", "endpoint", "status", "created_at", "request_payload", "response_payload"]
                missing_fields = [field for field in required_fields if field not in available_fields]
                if missing_fields:
                    print(f"DEBUG: Campos faltantes: {missing_fields}")
                else:
                    print(f"DEBUG: Todos los campos requeridos están disponibles")
                    
                # Verificar total de registros en backend_logs (usando service role key)
                count_response = supabase_service.table("backend_logs").select("*", count="exact").execute()
                if hasattr(count_response, 'count'):
                    print(f"DEBUG: Total de registros en backend_logs: {count_response.count}")
                else:
                    print(f"DEBUG: No se pudo obtener el conteo total")
            else:
                print(f"DEBUG: Tabla backend_logs existe pero no tiene datos")
                
                # Listar tablas disponibles para diagnóstico
                try:
                    print(f"DEBUG: Intentando listar tablas disponibles...")
                    # Esto es un intento de diagnóstico, puede fallar dependiendo de los permisos
                    tables_response = supabase.table("api_keys_public").select("*").limit(1).execute()
                    print(f"DEBUG: Puede acceder a api_keys_public")
                except Exception as table_e:
                    print(f"DEBUG: Error al verificar tablas: {str(table_e)}")
                    
        except Exception as e:
            print(f"DEBUG: Error consultando tabla backend_logs: {str(e)}")
            print(f"DEBUG: Tipo de error: {type(e)}")
            print(f"DEBUG: Esto sugiere que la tabla backend_logs no existe o no hay permisos")
            raise HTTPException(status_code=500, detail=f"Error accessing backend_logs table: {str(e)}")
        
        # Buscar logs en la tabla backend_logs para las API keys del usuario
        try:
            print(f"DEBUG: Ejecutando consulta con {len(api_key_ids)} API key IDs")
            print(f"DEBUG: API key IDs para consulta: {api_key_ids[:3]}...")  # Mostrar solo primeros 3
            
            # Primero, verificar si hay logs en general (usando service role key)
            all_logs_response = supabase_service.table("backend_logs").select("*").limit(1).execute()
            print(f"DEBUG: Hay logs en backend_logs: {len(all_logs_response.data) > 0}")
            
            if all_logs_response.data:
                print(f"DEBUG: Estructura de un log existente: {all_logs_response.data[0]}")
                # Verificar el valor de api_key_id en un log existente
                existing_api_key_id = all_logs_response.data[0].get("api_key_id")
                print(f"DEBUG: api_key_id en log existente: {existing_api_key_id}, tipo: {type(existing_api_key_id)}")
                
                # Verificar si alguno de nuestros API key IDs coincide
                if existing_api_key_id in api_key_ids:
                    print(f"DEBUG: ¡Coincidencia encontrada! El api_key_id {existing_api_key_id} está en nuestra lista")
                else:
                    print(f"DEBUG: No hay coincidencia. Nuestros IDs: {api_key_ids[:3]}...")
            
            # Ahora hacer la consulta filtrada - excluir nulos en api_key_id (usando service role key)
            print(f"DEBUG: Ejecutando consulta .in_() con {len(api_key_ids)} API key IDs")
            print(f"DEBUG: Primeros 5 API key IDs: {api_key_ids[:5]}")
            
            # Primero, intentar sin el filtro .not_.is_() para ver si hay logs
            logs_response_simple = supabase_service.table("backend_logs").select("*").in_("api_key_id", api_key_ids).execute()
            print(f"DEBUG: Respuesta de consulta simple (sin excluir nulos): {len(logs_response_simple.data)} logs")
            
            # Luego con el filtro completo
            logs_response = supabase_service.table("backend_logs").select("*").in_("api_key_id", api_key_ids).not_.is_("api_key_id", "null").execute()
            print(f"DEBUG: Respuesta de consulta filtrada (excluyendo nulos): {len(logs_response.data)} logs")
            print(f"DEBUG: Respuesta completa: {logs_response}")
            
            if logs_response.data:
                # Los datos ya vienen filtrados por la consulta, no necesitamos filtrar adicionalmente
                logs_data.extend(logs_response.data)
                print(f"DEBUG: Encontrados {len(logs_response.data)} logs en backend_logs")
                print(f"DEBUG: API key IDs encontrados: {set(log.get('api_key_id') for log in logs_response.data)}")
                if logs_response.data:
                    print(f"DEBUG: Estructura del primer log: {logs_response.data[0]}")
            else:
                print(f"DEBUG: No se encontraron logs en backend_logs para los API key IDs: {api_key_ids}")
                
                # Intentar con un solo API key ID para probar
                if api_key_ids:
                    test_response = supabase_service.table("backend_logs").select("*").eq("api_key_id", api_key_ids[0]).not_.is_("api_key_id", "null").execute()
                    print(f"DEBUG: Prueba con primer API key ID ({api_key_ids[0]}): {len(test_response.data)} logs")
                    
                    # Probar específicamente con V3HkXnORegU que sabemos que funciona manualmente
                    if "V3HkXnORegU" in api_key_ids:
                        manual_test_response = supabase_service.table("backend_logs").select("*").eq("api_key_id", "V3HkXnORegU").execute()
                        print(f"DEBUG: Prueba manual con V3HkXnORegU: {len(manual_test_response.data)} logs")
                        if manual_test_response.data:
                            print(f"DEBUG: Logs encontrados manualmente: {manual_test_response.data}")
                            # Si encontramos logs manualmente, agregarlos a la respuesta
                            logs_data.extend(manual_test_response.data)
                            print(f"DEBUG: Agregados {len(manual_test_response.data)} logs manualmente")
                        else:
                            print(f"DEBUG: ¡Inesperado! No se encontraron logs para V3HkXnORegU")
                    else:
                        print(f"DEBUG: V3HkXnORegU no está en la lista de API key IDs")
                    
                    # Si aún no hay resultados, mostrar logs con api_key_id nulo para comparar
                    null_logs_response = supabase_service.table("backend_logs").select("*").is_("api_key_id", "null").limit(3).execute()
                    if null_logs_response.data:
                        print(f"DEBUG: Muestra de logs con api_key_id nulo: {len(null_logs_response.data)} registros")
                        print(f"DEBUG: Estructura de log con api_key_id nulo: {null_logs_response.data[0]}")
        except Exception as e:
            print(f"DEBUG: Error consultando backend_logs: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error querying backend_logs: {str(e)}")
        
        # Actualizar información de depuración
        debug_info["message"] = "No logs found - check debug info"
        
        # Si no se encontraron logs, retornar información de depuración
        if not logs_data:
            print(f"DEBUG: No se encontraron logs para el usuario {current_user_id}")
            # Crear una respuesta temporal con información de depuración
            class DebugResponse(BaseModel):
                data: List = []
                total: int = 0
                page: int = 1
                page_size: int = 20
                debug_info: dict = {}
            
            response = DebugResponse()
            response.debug_info = debug_info
            return response
        
        # Convertir logs a formato LogItem
        log_items = []
        for log in logs_data:
            try:
                # Convertir request_payload y response_payload de string a dict si es necesario
                request_payload = log.get("request_payload", {})
                response_payload = log.get("response_payload", {})
                
                # Si son strings, intentar convertirlos a diccionarios
                if isinstance(request_payload, str):
                    print(f"DEBUG: request_payload es string: {request_payload[:100]}...")
                    try:
                        # Primero intentar con JSON estándar (comillas dobles)
                        request_payload = json.loads(request_payload)
                        print(f"DEBUG: request_payload convertido exitosamente con JSON")
                    except json.JSONDecodeError:
                        try:
                            # Si falla, intentar con ast.literal_eval (comillas simples)
                            request_payload = ast.literal_eval(request_payload)
                            print(f"DEBUG: request_payload convertido exitosamente con ast.literal_eval")
                        except (ValueError, SyntaxError) as e:
                            print(f"DEBUG: Error convirtiendo request_payload con ambos métodos: {e}")
                            request_payload = {}
                else:
                    print(f"DEBUG: request_payload no es string, tipo: {type(request_payload)}")
                        
                if isinstance(response_payload, str):
                    print(f"DEBUG: response_payload es string: {response_payload[:100]}...")
                    try:
                        # Primero intentar con JSON estándar (comillas dobles)
                        response_payload = json.loads(response_payload)
                        print(f"DEBUG: response_payload convertido exitosamente con JSON")
                    except json.JSONDecodeError:
                        try:
                            # Si falla, intentar con ast.literal_eval (comillas simples)
                            response_payload = ast.literal_eval(response_payload)
                            print(f"DEBUG: response_payload convertido exitosamente con ast.literal_eval")
                        except (ValueError, SyntaxError) as e:
                            print(f"DEBUG: Error convirtiendo response_payload con ambos métodos: {e}")
                            response_payload = {}
                else:
                    print(f"DEBUG: response_payload no es string, tipo: {type(response_payload)}")
                
                log_item = LogItem(
                    id=str(log.get("id", f"log-{current_user_id[:8]}-{len(log_items)}")),
                    api_key_id=str(log.get("api_key_id", "")),
                    endpoint=log.get("endpoint", "/api/unknown"),
                    status=log.get("status", "unknown"),
                    created_at=log.get("created_at", "2025-01-01T00:00:00Z"),
                    request_payload=request_payload,
                    response_payload=response_payload
                )
                log_items.append(log_item)
            except Exception as e:
                print(f"DEBUG: Error procesando log {log}: {str(e)}")
                continue
        
        # Ordenar por created_at descendente
        log_items.sort(key=lambda x: x.created_at, reverse=True)
        
        # Aplicar paginación
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_logs = log_items[start_idx:end_idx]
        
        print(f"DEBUG: Retornando {len(paginated_logs)} logs reales para user_id: {current_user_id}")
        print(f"DEBUG: Total logs: {len(log_items)}, Page: {page}, Page size: {page_size}")
        
        # Crear respuesta con información de depuración
        response = LogsResponse(
            data=paginated_logs,
            total=len(log_items),
            page=page,
            page_size=page_size
        )
        
        # Agregar información de depuración como atributo adicional
        response.debug_info = {
            "user_id": current_user_id,
            "api_key_ids": api_key_ids,
            "table_used": "backend_logs",
            "message": f"Found {len(log_items)} total logs, returning {len(paginated_logs)}"
        }
        
        return response
        
    except Exception as e:
        print(f"DEBUG: Error consultando Supabase: {str(e)}")
        print(f"DEBUG: Tipo de error: {type(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting logs: {str(e)}")


# -------- Endpoint Proxy: Chat Completions --------
@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    request_body = await request.json()
    
    try:
        chat_request = ChatCompletionRequest(**request_body)
    except Exception as e:
        try:
            log_interaction(
                endpoint="/v1/chat/completions",
                request_payload=request_body if isinstance(request_body, dict) else {"raw": str(request_body)},
                response_payload={"error": f"Error de validación: {str(e)}"},
                status="error",
                user_ip=get_client_ip(request),
                layer=_normalize_tier_name(request.headers.get("X-Layer") or request.query_params.get("layer")),
                blocked_status="no blocked",
                reason=f"validation_error: {str(e)}",
                api_key_id=getattr(request.state, "api_key_id", None),
                api_key=getattr(request.state, "api_key", None),
            )
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f"Error de validación: {str(e)}")
    
    # Selección de nivel
    tier = _select_tier(request)

    # Obtener IP del cliente
    client_ip = get_client_ip(request)

    print(f"INFO: Incoming prompt ip={client_ip} tier={tier.name} enforced_model={tier.completion_model}")

    # Metadatos opcionales de seguridad
    user_id = request.headers.get("X-User-Id", "anonymous")
    system_purpose = request.headers.get("X-System-Purpose", "general")

    # Detección y acumulación de etiquetas
    security_labels: Set[str] = set()

    # Primera capa: clasificación de intención por LLM + firewall tradicional
    detected_intents: list[dict] = []
    for msg in chat_request.messages:
        if msg.role != 'user':
            continue
        intent = classify_intent(request, msg.content, client_ip, tier)
        if intent:
            detected_intents.append(intent)
            security_labels |= derive_labels_from_intent(intent)
            print(f"INFO: Intent classifier -> {intent} ip={client_ip} tier={tier.name}")
            if intent.get("is_malicious") is True:
                primary = pick_primary_label(security_labels)
                try:
                    log_interaction(
                        endpoint="/v1/chat/completions",
                        request_payload=request_body if isinstance(request_body, dict) else {"raw": str(request_body)},
                        response_payload={
                            "error": "Blocked by intent classifier",
                            "intent": intent,
                            "tier": tier.name,
                            "security_labels": sorted(list(security_labels)),
                            "primary_security_label": primary,
                        },
                        status="blocked",
                        user_ip=client_ip,
                        layer=tier.name,
                        blocked_status="blocked",
                        reason=intent.get("reason") or "intent_classifier_malicious",
                        api_key_id=getattr(request.state, "api_key_id", None),
                        api_key=getattr(request.state, "api_key", None),
                    )
                except Exception:
                    pass
                return JSONResponse(status_code=403, content={
                    "error": "Blocked by intent classifier",
                    "intent": intent,
                    "tier": tier.name,
                    "security_labels": sorted(list(security_labels)),
                    "primary_security_label": primary,
                })
        insp = firewall.inspect_request(user_id=user_id, prompt=msg.content, system_purpose=system_purpose)
        if insp.flags:
            security_labels |= derive_labels_from_flags(insp.flags)
        if insp.decision == "BLOCK":
            print(f"ALERTA: Firewall bloqueó la solicitud. ip={client_ip} score={insp.threat_score} flags={insp.flags}")
            primary = pick_primary_label(security_labels)
            try:
                log_interaction(
                    endpoint="/v1/chat/completions",
                    request_payload=request_body if isinstance(request_body, dict) else {"raw": str(request_body)},
                    response_payload={
                        "error": "Security policy violation detected by firewall",
                        "threat_score": insp.threat_score,
                        "flags": insp.flags,
                        "tier": tier.name,
                        "security_labels": sorted(list(security_labels)),
                        "primary_security_label": primary,
                    },
                    status="blocked",
                    user_ip=client_ip,
                    layer=tier.name,
                    blocked_status="blocked",
                    reason=f"firewall_flags: {', '.join(insp.flags) if insp.flags else 'BLOCK'}",
                    api_key_id=getattr(request.state, "api_key_id", None),
                    api_key=getattr(request.state, "api_key", None),
                )
            except Exception:
                pass
            return JSONResponse(status_code=403, content={
                "error": "Security policy violation detected by firewall",
                "threat_score": insp.threat_score,
                "flags": insp.flags,
                "tier": tier.name,
                "security_labels": sorted(list(security_labels)),
                "primary_security_label": primary,
            })

    # Preparar la petición para Groq
    headers = _build_forwarded_ip_headers(request, client_ip)
    
    # Inyectar un mensaje de sistema con el label de intención (último) si existe
    forward_body = request_body.copy()

    # Selección de modelo por nivel
    forward_body["model"] = tier.completion_model

    # Respetar límites de salida del nivel
    try:
        user_max_tokens = int(forward_body.get("max_tokens")) if forward_body.get("max_tokens") is not None else None
    except Exception:
        user_max_tokens = None
    forward_body["max_tokens"] = min(user_max_tokens, tier.max_output_tokens) if user_max_tokens else tier.max_output_tokens

    # Aplicar temperatura/top_p del nivel salvo override explícito
    if "temperature" not in forward_body:
        forward_body["temperature"] = tier.completion_temperature
    if "top_p" not in forward_body:
        forward_body["top_p"] = tier.completion_top_p

    try:
        # Copiar mensajes de forma segura
        orig_messages = forward_body.get("messages", [])
        capped_messages = _cap_messages_to_context(orig_messages, tier.max_context_tokens)
        if detected_intents:
            last_intent = detected_intents[-1]
            system_intent_note = {
                "role": "system",
                "content": (
                    "Security Note: intent_label="
                    + str(last_intent.get("intent_label", "unknown"))
                ),
            }
            forward_body["messages"] = [system_intent_note] + capped_messages
        else:
            forward_body["messages"] = capped_messages
    except Exception:
        forward_body["messages"] = request_body.get("messages", [])

    try:
        response = requests.post(GROQ_CHAT_URL, headers=headers, json=forward_body, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            # Inspección y posible redacción de la respuesta del modelo
            try:
                content_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            except Exception:
                content_text = ""
            resp_insp = firewall.inspect_response(content_text)
            if resp_insp.flags:
                print(f"ALERTA: Firewall detectó problemas en la respuesta. ip={client_ip} flags={resp_insp.flags}")
                if isinstance(data.get("choices"), list) and data["choices"]:
                    if "message" in data["choices"][0]:
                        data["choices"][0]["message"]["content"] = resp_insp.redacted_text
                data["firewall"] = {"flags": resp_insp.flags, "redacted": resp_insp.redacted_text != content_text}
                security_labels |= derive_labels_from_flags(resp_insp.flags)
            else:
                data.setdefault("firewall", {"flags": [], "redacted": False})

            # Adjuntar metadata de intención y nivel
            if detected_intents:
                data["intent_layer"] = {
                    "enabled": True,
                    "last_intent": detected_intents[-1],
                }
                security_labels |= derive_labels_from_intent(detected_intents[-1])
            else:
                data.setdefault("intent_layer", {"enabled": tier.enable_intent_layer, "last_intent": None})

            data["tier"] = tier.name
            # Añadir etiquetas de seguridad
            primary = pick_primary_label(security_labels)
            data["security_labels"] = sorted(list(security_labels))
            data["primary_security_label"] = primary

            try:
                log_interaction(
                    endpoint="/v1/chat/completions",
                    request_payload=forward_body,
                    response_payload=data,
                    status="success",
                    user_ip=client_ip,
                    layer=tier.name,
                    blocked_status="no blocked",
                    reason=None,
                    api_key_id=getattr(request.state, "api_key_id", None),
                    api_key=getattr(request.state, "api_key", None),
                    prompt_tokens=(data.get("usage", {}) or {}).get("prompt_tokens"),
                    completion_tokens=(data.get("usage", {}) or {}).get("completion_tokens"),
                    total_tokens=(data.get("usage", {}) or {}).get("total_tokens"),
                )
            except Exception:
                pass

            return JSONResponse(content=data, status_code=response.status_code)
        else:
            print(f"ERROR: Error de Groq API: {response.status_code} - {response.text} ip={client_ip}")
            primary = pick_primary_label(security_labels)
            try:
                log_interaction(
                    endpoint="/v1/chat/completions",
                    request_payload=forward_body,
                    response_payload={
                        "error": f"Groq API error: {response.text}",
                        "tier": tier.name,
                        "security_labels": sorted(list(security_labels)),
                        "primary_security_label": primary,
                    },
                    status="error",
                    user_ip=client_ip,
                    layer=tier.name,
                    blocked_status="no blocked",
                    reason=f"groq_api_error: {response.status_code}",
                    api_key_id=getattr(request.state, "api_key_id", None),
                    api_key=getattr(request.state, "api_key", None),
                )
            except Exception:
                pass
            return JSONResponse(
                content={
                    "error": f"Groq API error: {response.text}",
                    "tier": tier.name,
                    "security_labels": sorted(list(security_labels)),
                    "primary_security_label": primary,
                }, 
                status_code=response.status_code
            )
            
    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout en la petición a Groq ip={client_ip}")
        try:
            log_interaction(
                endpoint="/v1/chat/completions",
                request_payload=forward_body if isinstance(locals().get("forward_body"), dict) else {},
                response_payload={"error": "Request timeout to Groq API"},
                status="error",
                user_ip=client_ip,
                layer=tier.name,
                blocked_status="no blocked",
                reason="timeout",
                api_key_id=getattr(request.state, "api_key_id", None),
                api_key=getattr(request.state, "api_key", None),
            )
        except Exception:
            pass
        raise HTTPException(status_code=504, detail="Request timeout to Groq API")
    
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Error en la petición a Groq: {str(e)} ip={client_ip}")
        try:
            log_interaction(
                endpoint="/v1/chat/completions",
                request_payload=forward_body if isinstance(locals().get("forward_body"), dict) else {},
                response_payload={"error": f"Error connecting to Groq API: {str(e)}"},
                status="error",
                user_ip=client_ip,
                layer=tier.name,
                blocked_status="no blocked",
                reason=f"request_exception: {str(e)}",
                api_key_id=getattr(request.state, "api_key_id", None),
                api_key=getattr(request.state, "api_key", None),
            )
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=f"Error connecting to Groq API: {str(e)}")


# -------- Admin: Gestión de API Keys --------
def _is_admin(request: Request) -> bool:
    """Verifica si la request es de un admin (por ahora, siempre true para desarrollo)"""
    # En producción, aquí deberías verificar si el usuario tiene rol de admin
    # Por ahora, permitimos todas las operaciones para desarrollo
    return True

@app.post("/api/admin/keys")
async def admin_create_api_key(request: Request, body: CreateKeyRequest):
    """Crea una nueva API key (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Verificar conectividad a Supabase primero
        sb = get_supabase()
        if sb is None:
            print("ERROR: Supabase client is None")
            return JSONResponse(
                status_code=503,
                content={"error": "Database service unavailable. Please check your Supabase configuration."}
            )
        
        full_key = create_api_key(
            name=body.name,
            rate_limit=body.rate_limit,
            owner_user_id=body.user_id
        )
        
        if not full_key:
            print("ERROR: create_api_key returned None")
            return JSONResponse(
                status_code=500,
                content={"error": "Failed to create API key. Please try again or contact support."}
            )
        
        # Parsear la clave para obtener el key_id
        key_id, _ = parse_full_key(full_key)
        
        if not key_id:
            print("ERROR: Failed to parse key_id from full_key")
            return JSONResponse(
                status_code=500,
                content={"error": "Invalid API key format generated. Please try again."}
            )
        
        # Obtener metadatos de la clave recién creada
        key_meta = get_api_key_meta(key_id)
        
        if not key_meta:
            # Fallback si no se pueden obtener metadatos
            return APIKeyResponse(
                id=key_id,
                name=body.name,
                key_id=key_id,
                full_key=full_key,
                rate_limit=body.rate_limit,
                created_at=datetime.now(timezone.utc).isoformat(),
                is_active=True,
                owner_user_id=body.user_id
            )
        
        return APIKeyResponse(
            id=key_meta.get("key_id", key_id),
            name=key_meta.get("name", body.name),
            key_id=key_meta.get("key_id", key_id),
            full_key=full_key,
            rate_limit=key_meta.get("rate_limit"),
            created_at=key_meta.get("created_at", datetime.now(timezone.utc).isoformat()),
            is_active=key_meta.get("active", True),
            owner_user_id=key_meta.get("user_id")
        )
    except Exception as e:
        # Log del error para debugging
        print(f"ERROR: Unexpected error in admin_create_api_key: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal server error: {str(e)}"}
        )

@app.get("/api/admin/keys")
async def admin_list_api_keys(request: Request, limit: int = 100, offset: int = 0, user_id: Optional[str] = None):
    """Lista todas las API keys (solo admin)"""
    print(f"DEBUG: Starting admin_list_api_keys with limit: {limit}, offset: {offset}, user_id: {user_id}")
    
    if not _is_admin(request):
        return JSONResponse(
            status_code=403,
            content={"error": "Admin access required"}
        )
    
    try:
        # Verificar conectividad a Supabase primero
        sb = get_supabase()
        print(f"DEBUG: Supabase client: {sb is not None}")
        
        if sb is None:
            print("ERROR: Supabase client is None")
            return JSONResponse(
                status_code=503,
                content={"error": "Database service unavailable. Please check your Supabase configuration."}
            )
        
        print(f"DEBUG: Getting API keys for user: {user_id}")
        keys = list_api_keys(limit=limit, offset=offset, owner_user_id=user_id)
        print(f"DEBUG: Found {len(keys)} keys")
        
        response_data = []
        for key in keys:
            print(f"DEBUG: Processing key: {key}")
            key_data = {
                "id": key.get("key_id", ""),
                "name": key.get("name", ""),
                "key_id": key.get("key_id", ""),
                "rate_limit": key.get("rate_limit"),
                "created_at": key.get("created_at", ""),
                "is_active": key.get("active", True),
                "owner_user_id": key.get("user_id")
            }
            response_data.append(key_data)
        
        print(f"DEBUG: Final response: {response_data}")
        return JSONResponse(content=response_data)
        
    except Exception as e:
        print(f"ERROR: Unexpected error in admin_list_api_keys: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Error listing API keys: {str(e)}"}
        )

@app.delete("/api/admin/keys/{key_id}")
async def admin_delete_api_key(request: Request, key_id: str):
    """Elimina una API key (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        delete_api_key(key_id)
        return {"message": f"API key {key_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting API key: {str(e)}")

@app.put("/api/admin/keys/{key_id}", response_model=APIKeyMetaResponse)
async def admin_update_api_key(request: Request, key_id: str, body: UpdateKeyRequest):
    """Actualiza una API key (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        update_api_key(key_id, name=body.name, active=body.is_active)
        
        # Obtener la key actualizada
        key_meta = get_api_key_meta(key_id)
        
        return APIKeyMetaResponse(
            id=key_meta.get("id", ""),
            name=key_meta.get("name", ""),
            key_id=key_meta.get("key_id", ""),
            rate_limit=key_meta.get("rate_limit"),
            created_at=key_meta.get("created_at", ""),
            is_active=key_meta.get("active", True),
            owner_user_id=key_meta.get("user_id")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating API key: {str(e)}")

@app.post("/api/admin/keys/{key_id}/revoke")
async def admin_revoke_api_key(request: Request, key_id: str):
    """Revoca una API key (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        revoke_api_key(key_id)
        return {"message": f"API key {key_id} revoked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error revoking API key: {str(e)}")


# -------- User-scoped management: cada usuario gestiona sus propias keys --------
def _require_user_id(request: Request) -> str:
    """Obtiene el user_id del request (similar a get_current_user_id pero sin JWT)"""
    # Por ahora, para desarrollo, usamos un header o retornamos un valor por defecto
    user_id = request.headers.get("X-User-ID")
    if not user_id:
        # En producción, esto debería venir del JWT
        user_id = "dev-user-id"
    return user_id

@app.post("/api/keys")
async def mgmt_create_key(request: Request, body: MgmtCreateKeyRequest):
    """Crea una nueva API key para el usuario autenticado"""
    print(f"DEBUG: Starting mgmt_create_key with body: {body}")
    
    try:
        user_id = _require_user_id(request)
        print(f"DEBUG: User ID: {user_id}")
        
        # Verificar conectividad a Supabase primero
        sb = get_supabase()
        print(f"DEBUG: Supabase client: {sb is not None}")
        
        if sb is None:
            print("ERROR: Supabase client is None")
            return JSONResponse(
                status_code=503,
                content={"error": "Database service unavailable. Please check your Supabase configuration."}
            )
        
        print(f"DEBUG: Creating API key with name: {body.name}, rate_limit: {body.rate_limit}")
        full_key = create_api_key(
            name=body.name,
            rate_limit=body.rate_limit,
            owner_user_id=user_id
        )
        print(f"DEBUG: Created API key: {full_key is not None}")
        
        if not full_key:
            print("ERROR: create_api_key returned None")
            return JSONResponse(
                status_code=500,
                content={"error": "Failed to create API key. Please try again or contact support."}
            )
        
        # Parsear la clave para obtener el key_id
        key_id, _ = parse_full_key(full_key)
        print(f"DEBUG: Parsed key_id: {key_id}")
        
        if not key_id:
            print("ERROR: Failed to parse key_id from full_key")
            return JSONResponse(
                status_code=500,
                content={"error": "Invalid API key format generated. Please try again."}
            )
        
        # Obtener metadatos de la clave recién creada
        print(f"DEBUG: Getting metadata for key_id: {key_id}")
        key_meta = get_api_key_meta(key_id)
        print(f"DEBUG: Key metadata: {key_meta}")
        
        if not key_meta:
            # Fallback si no se pueden obtener metadatos
            print("DEBUG: Using fallback response without metadata")
            response_data = {
                "id": key_id,
                "name": body.name,
                "key_id": key_id,
                "full_key": full_key,
                "rate_limit": body.rate_limit,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True,
                "owner_user_id": user_id
            }
            print(f"DEBUG: Fallback response: {response_data}")
            return JSONResponse(content=response_data)
        
        response_data = {
            "id": key_meta.get("key_id", key_id),
            "name": key_meta.get("name", body.name),
            "key_id": key_meta.get("key_id", key_id),
            "full_key": full_key,
            "rate_limit": key_meta.get("rate_limit"),
            "created_at": key_meta.get("created_at", datetime.now(timezone.utc).isoformat()),
            "is_active": key_meta.get("active", True),
            "owner_user_id": key_meta.get("user_id")
        }
        print(f"DEBUG: Full response: {response_data}")
        return JSONResponse(content=response_data)
        
    except Exception as e:
        # Log del error para debugging
        print(f"ERROR: Unexpected error in mgmt_create_key: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal server error: {str(e)}"}
        )

@app.get("/api/keys")
async def mgmt_list_keys(request: Request, limit: int = 100, offset: int = 0):
    """Lista las API keys del usuario autenticado"""
    print(f"DEBUG: Starting mgmt_list_keys with limit: {limit}, offset: {offset}")
    
    try:
        user_id = _require_user_id(request)
        print(f"DEBUG: User ID: {user_id}")
        
        # Verificar conectividad a Supabase primero
        sb = get_supabase()
        print(f"DEBUG: Supabase client: {sb is not None}")
        
        if sb is None:
            print("ERROR: Supabase client is None")
            return JSONResponse(
                status_code=503,
                content={"error": "Database service unavailable. Please check your Supabase configuration."}
            )
        
        print(f"DEBUG: Getting API keys for user: {user_id}")
        keys = list_api_keys(limit=limit, offset=offset, owner_user_id=user_id)
        print(f"DEBUG: Found {len(keys)} keys")
        
        response_data = []
        for key in keys:
            print(f"DEBUG: Processing key: {key}")
            key_data = {
                "id": key.get("key_id", ""),
                "name": key.get("name", ""),
                "key_id": key.get("key_id", ""),
                "rate_limit": key.get("rate_limit"),
                "created_at": key.get("created_at", ""),
                "is_active": key.get("active", True),
                "owner_user_id": key.get("user_id")
            }
            response_data.append(key_data)
        
        print(f"DEBUG: Final response: {response_data}")
        return JSONResponse(content=response_data)
        
    except Exception as e:
        print(f"ERROR: Unexpected error in mgmt_list_keys: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Error listing API keys: {str(e)}"}
        )

@app.put("/api/keys/{key_id}", response_model=APIKeyMetaResponse)
async def mgmt_update_key(request: Request, key_id: str, body: MgmtUpdateKeyRequest):
    """Actualiza una API key del usuario autenticado"""
    try:
        user_id = _require_user_id(request)
        
        # Verificar que la key pertenece al usuario
        key_meta = get_api_key_meta(key_id)
        if key_meta.get("owner_user_id") != user_id:
            raise HTTPException(status_code=403, detail="API key does not belong to user")
        
        update_api_key(key_id, name=body.name, active=body.is_active)
        
        # Obtener la key actualizada
        key_meta = get_api_key_meta(key_id)
        
        return APIKeyMetaResponse(
            id=key_meta.get("id", ""),
            name=key_meta.get("name", ""),
            key_id=key_meta.get("key_id", ""),
            rate_limit=key_meta.get("rate_limit"),
            created_at=key_meta.get("created_at", ""),
            is_active=key_meta.get("active", True),
            owner_user_id=key_meta.get("user_id")
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating API key: {str(e)}")

@app.delete("/api/keys/{key_id}")
async def mgmt_delete_key(request: Request, key_id: str):
    """Elimina una API key del usuario autenticado"""
    try:
        user_id = _require_user_id(request)
        
        # Verificar que la key pertenece al usuario
        key_meta = get_api_key_meta(key_id)
        if key_meta.get("owner_user_id") != user_id:
            raise HTTPException(status_code=403, detail="API key does not belong to user")
        
        delete_api_key(key_id)
        return {"message": f"API key {key_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting API key: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
