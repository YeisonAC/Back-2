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
    """
    Get logs for the authenticated user from Supabase database
    """
    try:
        print(f"DEBUG: Iniciando get_logs para user_id: {current_user_id}")
        
        if not supabase_available:
            raise HTTPException(status_code=503, detail="Supabase database not available")
        
        # Obtener cliente de Supabase
        supabase = get_supabase()
        
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
        api_key_ids = [key["key_id"] for key in api_keys] if api_keys else []
        
        print(f"DEBUG: API keys encontradas: {len(api_keys)}, IDs: {api_key_ids}")
        
        if not api_key_ids:
            print(f"DEBUG: No se encontraron API keys para el usuario {current_user_id}")
            return LogsResponse(data=[], total=0, page=page, page_size=page_size)
        
        # Buscar logs relacionados con las API keys del usuario
        print(f"DEBUG: Buscando logs para API key IDs: {api_key_ids}")
        
        # Intentar diferentes tablas de logs
        logs_data = []
        
        # Usar específicamente la tabla backend_logs que existe y contiene los campos necesarios
        print(f"DEBUG: Usando tabla backend_logs que contiene los campos request_payload y response_payload")
        
        # Verificar que la tabla backend_logs existe y obtener estructura
        try:
            sample_response = supabase.table("backend_logs").select("*").limit(1).execute()
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
            else:
                print(f"DEBUG: Tabla backend_logs existe pero no tiene datos")
        except Exception as e:
            print(f"DEBUG: Error consultando tabla backend_logs: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error accessing backend_logs table: {str(e)}")
        
        # Buscar logs en la tabla backend_logs para las API keys del usuario
        try:
            logs_response = supabase.table("backend_logs").select("*").in_("api_key_id", api_key_ids).execute()
            if logs_response.data:
                logs_data.extend(logs_response.data)
                print(f"DEBUG: Encontrados {len(logs_response.data)} logs en backend_logs para el usuario")
                print(f"DEBUG: Estructura del primer log: {logs_response.data[0] if logs_response.data else 'No logs'}")
            else:
                print(f"DEBUG: No se encontraron logs en backend_logs para los API key IDs: {api_key_ids}")
                # Intentar ver logs sin filtro para verificar si hay datos en general
                try:
                    all_logs_response = supabase.table("backend_logs").select("*").limit(3).execute()
                    if all_logs_response.data:
                        print(f"DEBUG: Muestra de logs en backend_logs (sin filtrar): {all_logs_response.data}")
                        print(f"DEBUG: Hay datos en backend_logs pero no para este usuario")
                    else:
                        print(f"DEBUG: No hay datos en backend_logs")
                except Exception as e:
                    print(f"DEBUG: Error consultando muestra de backend_logs: {str(e)}")
        except Exception as e:
            print(f"DEBUG: Error consultando backend_logs: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error querying backend_logs: {str(e)}")
        
        # Preparar información de depuración
        debug_info = {
            "user_id": current_user_id,
            "api_key_ids": api_key_ids,
            "table_used": "backend_logs",
            "message": "No logs found - check debug info"
        }
        
        # Si no se encontraron logs, retornar información de depuración
        if not logs_data:
            print(f"DEBUG: No se encontraron logs para el usuario {current_user_id}")
            # Crear una respuesta temporal con información de depuración
            class DebugResponse(BaseModel):
                data: List = []
                total: int = 0
                page: int = 1
                page_size: int = 20
                debug_info: dict = debug_info
            
            return DebugResponse()
        
        # Convertir logs a formato LogItem
        log_items = []
        for log in logs_data:
            try:
                log_item = LogItem(
                    id=str(log.get("id", f"log-{current_user_id[:8]}-{len(log_items)}")),
                    api_key_id=str(log.get("api_key_id", "")),
                    endpoint=log.get("endpoint", "/api/unknown"),
                    status=log.get("status", "unknown"),
                    created_at=log.get("created_at", "2025-01-01T00:00:00Z"),
                    request_payload=log.get("request_payload", {}),
                    response_payload=log.get("response_payload", {})
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
        
        return LogsResponse(
            data=paginated_logs,
            total=len(log_items),
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        print(f"DEBUG: Error consultando Supabase: {str(e)}")
        print(f"DEBUG: Tipo de error: {type(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting logs: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
