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
if not supabase_url or not supabase_key:
    raise ValueError("Supabase URL and Key must be set in environment variables")

# Configuración básica
app = FastAPI(title="EONS API - Minimal Version", version="1.0.0")

# Función para obtener cliente de Supabase
def get_supabase() -> Client:
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
    """Endpoint para obtener logs con conexión a Supabase"""
    try:
        supabase = get_supabase()
        
        # Obtener API keys del usuario
        api_keys_response = supabase.table("api_keys").select("id").eq("user_id", current_user_id).execute()
        
        if not api_keys_response.data:
            return LogsResponse(
                data=[],
                total=0,
                page=page,
                page_size=page_size
            )
        
        api_key_ids = [key["id"] for key in api_keys_response.data]
        
        # Calcular offset para paginación
        offset = (page - 1) * page_size
        
        # Obtener logs
        logs_response = supabase.table("debug_logs").select(
            "id, api_key_id, endpoint, status, created_at, request_payload, response_payload"
        ).in_("api_key_id", api_key_ids).order("created_at", desc=True).range(offset, offset + page_size - 1).execute()
        
        # Obtener total de logs
        count_response = supabase.table("debug_logs").select("id", count="exact").in_("api_key_id", api_key_ids).execute()
        total_logs = count_response.count if count_response.count else 0
        
        # Formatear datos
        logs_data = []
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
        
        return LogsResponse(
            data=logs_data,
            total=total_logs,
            page=page,
            page_size=page_size
        )
    except Exception as e:
        print(f"Error en get_logs: {str(e)}")
        raise HTTPException(
            status_code=http.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
