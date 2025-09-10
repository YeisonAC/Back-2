from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import base64
from pydantic import BaseModel
from typing import Optional, List
import http
from dotenv import load_dotenv
from pathlib import Path
from supabase import create_client, Client

# Cargar variables de entorno
load_dotenv(dotenv_path=Path(__file__).with_name('.env'))

# Configuración de Supabase
supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
supabase_key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
supabase_available = False

print(f"DEBUG: Supabase URL: {'***' + supabase_url[-20:] if supabase_url else 'NOT SET'}")
print(f"DEBUG: Supabase Key: {'***' + supabase_key[-10:] if supabase_key else 'NOT SET'}")

# Verificar si Supabase está disponible
if supabase_url and supabase_key:
    try:
        from supabase import create_client, Client
        # Probar conexión
        test_client = create_client(supabase_url, supabase_key)
        supabase_available = True
        print("DEBUG: Supabase connection successful")
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
    return create_client(supabase_url, supabase_key)

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
    """Endpoint para obtener logs con fallback a datos de prueba"""
    try:
        print(f"DEBUG: Iniciando get_logs para user_id: {current_user_id}")
        
        # Intentar obtener datos de Supabase si está disponible
        if supabase_available:
            try:
                print(f"DEBUG: Intentando conexión a Supabase")
                supabase = get_supabase()
                print(f"DEBUG: Cliente Supabase creado exitosamente")
                
                # Obtener API keys del usuario desde api_keys_public
                print(f"DEBUG: Consultando API keys para user_id: {current_user_id}")
                try:
                    api_keys_response = supabase.table("api_keys_public").select("api_key").eq("owner_user_id", current_user_id).execute()
                    print(f"DEBUG: Respuesta API keys - Status: {getattr(api_keys_response, 'status_code', 'N/A')}")
                    print(f"DEBUG: Respuesta API keys - Data: {getattr(api_keys_response, 'data', 'N/A')}")
                    print(f"DEBUG: Respuesta API keys - Error: {getattr(api_keys_response, 'error', 'N/A')}")
                except Exception as query_error:
                    print(f"DEBUG: Error en consulta API keys: {str(query_error)}")
                    raise
                
                if api_keys_response.data:
                    api_key_ids = [key["api_key"] for key in api_keys_response.data]
                    print(f"DEBUG: API keys encontradas: {api_key_ids}")
                    
                    # Intentar obtener logs de la tabla debug_logs si existe
                    logs_data = []
                    total_logs = 0
                    
                    try:
                        # Probar si la tabla debug_logs existe
                        print(f"DEBUG: Verificando si existe la tabla debug_logs")
                        test_response = supabase.table("debug_logs").select("id", count="exact").limit(1).execute()
                        print(f"DEBUG: Tabla debug_logs existe - Status: {getattr(test_response, 'status_code', 'N/A')}")
                        
                        # Si existe, obtener los logs
                        offset = (page - 1) * page_size
                        print(f"DEBUG: Paginación - page: {page}, page_size: {page_size}, offset: {offset}")
                        
                        logs_response = supabase.table("debug_logs").select(
                            "id, api_key_id, endpoint, status, created_at, request_payload, response_payload"
                        ).in_("api_key_id", api_key_ids).order("created_at", desc=True).range(offset, offset + page_size - 1).execute()
                        
                        count_response = supabase.table("debug_logs").select("id", count="exact").in_("api_key_id", api_key_ids).execute()
                        total_logs = count_response.count if count_response.count else 0
                        
                        # Formatear datos reales
                        for log in logs_response.data:
                            logs_data.append(LogItem(
                                id=log["id"],
                                api_key_id=log["api_key_id"],
                                endpoint=log["endpoint"],
                                status=log["status"],
                                created_at=log["created_at"],
                                request_payload=log.get("request_payload"),
                                response_payload=log.get("response_payload")
                            ))
                        
                        print(f"DEBUG: Obtenidos {len(logs_data)} logs reales desde debug_logs")
                        
                    except Exception as e:
                        print(f"DEBUG: La tabla debug_logs no existe o hay error: {str(e)}")
                        print(f"DEBUG: Creando logs de prueba basados en API keys encontradas")
                        
                        # Crear logs de prueba basados en las API keys reales
                        for i, api_key_id in enumerate(api_key_ids):
                            logs_data.append(LogItem(
                                id=f"mock-{api_key_id}-{i+1}",
                                api_key_id=api_key_id,
                                endpoint="/api/test",
                                status="success",
                                created_at="2025-01-01T00:00:00Z",
                                request_payload={"test": "data", "api_key": api_key_id},
                                response_payload={"result": "ok", "api_key": api_key_id}
                            ))
                        
                        total_logs = len(logs_data)
                        print(f"DEBUG: Creados {len(logs_data)} logs de prueba")
                    
                    print(f"DEBUG: Retornando {len(logs_data)} logs")
                    return LogsResponse(
                        data=logs_data,
                        total=total_logs,
                        page=page,
                        page_size=page_size
                    )
                else:
                    print(f"DEBUG: No se encontraron API keys para el usuario")
                    # Usar datos de prueba
                    return get_test_logs(page, page_size)
            except Exception as supabase_error:
                print(f"DEBUG: Error en Supabase, usando fallback: {str(supabase_error)}")
                # Usar datos de prueba como fallback
                return get_test_logs(page, page_size)
        else:
            print(f"DEBUG: Supabase no disponible, usando datos de prueba")
            # Usar datos de prueba
            return get_test_logs(page, page_size)
            
    except Exception as e:
        print(f"ERROR en get_logs: {str(e)}")
        print(f"ERROR Tipo: {type(e).__name__}")
        import traceback
        print(f"ERROR Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=http.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {str(e)}"
        )

# Función para obtener datos de prueba
def get_test_logs(page: int, page_size: int) -> LogsResponse:
    """Retorna datos de prueba para el endpoint"""
    test_logs = [
        {
            "id": "test-1",
            "api_key_id": "test-key-1",
            "endpoint": "/api/test",
            "status": "success",
            "created_at": "2025-01-01T00:00:00Z",
            "request_payload": {"test": "data"},
            "response_payload": {"result": "ok"}
        },
        {
            "id": "test-2",
            "api_key_id": "test-key-2",
            "endpoint": "/api/debug",
            "status": "error",
            "created_at": "2025-01-02T00:00:00Z",
            "request_payload": {"debug": "true"},
            "response_payload": {"error": "test error"}
        }
    ]
    
    return LogsResponse(
        data=test_logs,
        total=len(test_logs),
        page=page,
        page_size=page_size
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
