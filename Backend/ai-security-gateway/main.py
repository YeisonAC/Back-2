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
    def get_logs(current_user_id: str, page: int = 1, page_size: int = 20) -> LogsResponse:
        """
        Get logs for the authenticated user - returns structured test data
        """
        try:
            print(f"DEBUG: Iniciando get_logs para user_id: {current_user_id}")
            
            # Crear datos de prueba estructurados basados en el user_id
            logs_data = [
                LogItem(
                    id=f"log-{current_user_id[:8]}-1",
                    api_key_id=f"api-key-{current_user_id[:8]}-1",
                    endpoint="/api/security/scan",
                    status="success",
                    created_at="2025-01-01T10:00:00Z",
                    request_payload={
                        "url": "https://example.com",
                        "scan_type": "xss",
                        "user_id": current_user_id
                    },
                    response_payload={
                        "result": "clean",
                        "vulnerabilities_found": 0,
                        "scan_duration": 1.2,
                        "user_id": current_user_id
                    }
                ),
                LogItem(
                    id=f"log-{current_user_id[:8]}-2",
                    api_key_id=f"api-key-{current_user_id[:8]}-2",
                    endpoint="/api/security/validate",
                    status="warning",
                    created_at="2025-01-01T11:30:00Z",
                    request_payload={
                        "input": "test<script>alert(1)</script>",
                        "validation_type": "xss",
                        "user_id": current_user_id
                    },
                    response_payload={
                        "result": "potentially_malicious",
                        "risk_level": "medium",
                        "suggestions": ["Sanitize input", "Use parameterized queries"],
                        "user_id": current_user_id
                    }
                ),
                LogItem(
                    id=f"log-{current_user_id[:8]}-3",
                    api_key_id=f"api-key-{current_user_id[:8]}-1",
                    endpoint="/api/security/firewall",
                    status="success",
                    created_at="2025-01-01T14:15:00Z",
                    request_payload={
                        "ip": "192.168.1.100",
                        "action": "allow",
                        "user_id": current_user_id
                    },
                    response_payload={
                        "action_taken": "allowed",
                        "reason": "trusted_ip",
                        "user_id": current_user_id
                    }
                ),
                LogItem(
                    id=f"log-{current_user_id[:8]}-4",
                    api_key_id=f"api-key-{current_user_id[:8]}-3",
                    endpoint="/api/security/monitor",
                    status="error",
                    created_at="2025-01-01T16:45:00Z",
                    request_payload={
                        "endpoint": "/admin",
                        "method": "GET",
                        "user_agent": "Mozilla/5.0",
                        "user_id": current_user_id
                    },
                    response_payload={
                        "error": "access_denied",
                        "reason": "insufficient_permissions",
                        "user_id": current_user_id
                    }
                )
            ]
            
            # Aplicar paginación
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            paginated_logs = logs_data[start_idx:end_idx]
            
            print(f"DEBUG: Retornando {len(paginated_logs)} logs para user_id: {current_user_id}")
            print(f"DEBUG: Total logs: {len(logs_data)}, Page: {page}, Page size: {page_size}")
            
            return LogsResponse(
                data=paginated_logs,
                total=len(logs_data),
                page=page,
                page_size=page_size
            )
        
        except Exception as e:
            print(f"DEBUG: Error inesperado en get_logs: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error getting logs: {str(e)}")
    
    return get_logs(current_user_id, page, page_size)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
