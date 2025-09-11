from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import base64
import ast
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Union
import http
from dotenv import load_dotenv
from pathlib import Path
from supabase import create_client, Client

# Importar funciones de API keys
try:
    from .api_keys import create_api_key, list_api_keys, revoke_api_key, update_api_key, delete_api_key, get_api_key_meta
except ImportError:
    from api_keys import create_api_key, list_api_keys, revoke_api_key, update_api_key, delete_api_key, get_api_key_meta

# Cargar variables de entorno
load_dotenv(dotenv_path=Path(__file__).with_name('.env'))

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

# Función para obtener cliente de Supabase
def get_supabase() -> Client:
    if not supabase_available:
        raise Exception("Supabase not available")
    from supabase import create_client, Client
    return create_client(supabase_url, supabase_anon_key)

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

# Endpoints básicos
@app.get("/")
async def root():
    return {"message": "EONS API - Minimal Version", "status": "ok"}

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "1.0.0"}

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


# -------- Admin: Gestión de API Keys --------
def _is_admin(request: Request) -> bool:
    """Verifica si la request es de un admin (por ahora, siempre true para desarrollo)"""
    # En producción, aquí deberías verificar si el usuario tiene rol de admin
    # Por ahora, permitimos todas las operaciones para desarrollo
    return True

@app.post("/api/admin/keys", response_model=APIKeyResponse)
async def admin_create_api_key(request: Request, body: CreateKeyRequest):
    """Crea una nueva API key (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        result = create_api_key(
            name=body.name,
            rate_limit=body.rate_limit,
            owner_user_id=body.user_id
        )
        
        return APIKeyResponse(
            id=result.get("id", ""),
            name=result.get("name", ""),
            key_id=result.get("key_id", ""),
            full_key=result.get("full_key", ""),
            rate_limit=result.get("rate_limit"),
            created_at=result.get("created_at", ""),
            is_active=result.get("is_active", True),
            owner_user_id=result.get("owner_user_id")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating API key: {str(e)}")

@app.get("/api/admin/keys", response_model=List[APIKeyMetaResponse])
async def admin_list_api_keys(request: Request, limit: int = 100, offset: int = 0, user_id: Optional[str] = None):
    """Lista todas las API keys (solo admin)"""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        keys = list_api_keys(limit=limit, offset=offset, owner_user_id=user_id)
        
        return [
            APIKeyMetaResponse(
                id=key.get("id", ""),
                name=key.get("name", ""),
                key_id=key.get("key_id", ""),
                rate_limit=key.get("rate_limit"),
                created_at=key.get("created_at", ""),
                is_active=key.get("is_active", True),
                owner_user_id=key.get("owner_user_id")
            ) for key in keys
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing API keys: {str(e)}")

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
            is_active=key_meta.get("is_active", True),
            owner_user_id=key_meta.get("owner_user_id")
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

@app.post("/api/keys", response_model=APIKeyResponse)
async def mgmt_create_key(request: Request, body: MgmtCreateKeyRequest):
    """Crea una nueva API key para el usuario autenticado"""
    try:
        user_id = _require_user_id(request)
        
        result = create_api_key(
            name=body.name,
            rate_limit=body.rate_limit,
            owner_user_id=user_id
        )
        
        return APIKeyResponse(
            id=result.get("id", ""),
            name=result.get("name", ""),
            key_id=result.get("key_id", ""),
            full_key=result.get("full_key", ""),
            rate_limit=result.get("rate_limit"),
            created_at=result.get("created_at", ""),
            is_active=result.get("is_active", True),
            owner_user_id=result.get("owner_user_id")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating API key: {str(e)}")

@app.get("/api/keys", response_model=List[APIKeyMetaResponse])
async def mgmt_list_keys(request: Request, limit: int = 100, offset: int = 0):
    """Lista las API keys del usuario autenticado"""
    try:
        user_id = _require_user_id(request)
        
        keys = list_api_keys(limit=limit, offset=offset, owner_user_id=user_id)
        
        return [
            APIKeyMetaResponse(
                id=key.get("id", ""),
                name=key.get("name", ""),
                key_id=key.get("key_id", ""),
                rate_limit=key.get("rate_limit"),
                created_at=key.get("created_at", ""),
                is_active=key.get("is_active", True),
                owner_user_id=key.get("owner_user_id")
            ) for key in keys
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing API keys: {str(e)}")

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
            is_active=key_meta.get("is_active", True),
            owner_user_id=key_meta.get("owner_user_id")
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
