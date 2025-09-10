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

# Cargar variables de entorno
load_dotenv(dotenv_path=Path(__file__).with_name('.env'))

# Configuración básica
app = FastAPI(title="EONS API - Minimal Version", version="1.0.0")

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
    """Endpoint minimal para logs - solo retorna datos de prueba"""
    try:
        # Datos de prueba para verificar que el endpoint funciona
        test_logs = [
            {
                "id": "test-1",
                "api_key_id": "test-key-1",
                "endpoint": "/api/test",
                "status": "success",
                "created_at": "2025-01-01T00:00:00Z",
                "request_payload": {"test": "data"},
                "response_payload": {"result": "ok"}
            }
        ]
        
        return LogsResponse(
            data=test_logs,
            total=1,
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
