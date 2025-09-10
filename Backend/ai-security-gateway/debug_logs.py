"""
Endpoint de diagnóstico para verificar la relación JWT -> user_id -> API keys -> backend_logs
"""
import os
import json
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
from supabase_client import get_supabase

security = HTTPBearer()

async def get_current_user_id_debug(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Versión de diagnóstico de get_current_user_id
    """
    try:
        # En producción, validar el token JWT aquí
        # Por ahora, asumimos que el token es el user_id (solo para desarrollo)
        user_id = credentials.credentials
        print(f"[DEBUG] JWT recibido: {user_id}")
        return user_id
    except Exception as e:
        print(f"[DEBUG] Error extrayendo user_id: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def debug_auth_chain(request: Request, current_user_id: str) -> Dict[str, Any]:
    """
    Diagnostica la cadena completa de autenticación
    """
    debug_info = {
        "timestamp": datetime.now().isoformat(),
        "step1_jwt_extraction": {
            "jwt_from_header": request.headers.get("authorization", "No encontrado"),
            "extracted_user_id": current_user_id,
            "user_id_length": len(current_user_id) if current_user_id else 0
        },
        "step2_api_keys_lookup": {},
        "step3_backend_logs_lookup": {},
        "errors": []
    }
    
    try:
        sb = get_supabase()
        if not sb:
            debug_info["errors"].append("No se pudo conectar a Supabase")
            return debug_info
        
        # Paso 2: Buscar API keys del usuario
        print(f"[DEBUG] Buscando API keys para user_id: {current_user_id}")
        keys_response = sb.table('api_keys') \
            .select('key_id, name, active, created_at, owner_user_id') \
            .eq('owner_user_id', current_user_id) \
            .execute()
        
        debug_info["step2_api_keys_lookup"] = {
            "query": f"SELECT key_id, name, active, created_at, owner_user_id FROM api_keys WHERE owner_user_id = '{current_user_id}'",
            "found_keys": keys_response.data if keys_response.data else [],
            "key_count": len(keys_response.data) if keys_response.data else 0,
            "raw_response": str(keys_response)
        }
        
        if not keys_response.data:
            debug_info["errors"].append(f"No se encontraron API keys para el user_id: {current_user_id}")
            return debug_info
        
        key_ids = [key['key_id'] for key in keys_response.data]
        debug_info["step2_api_keys_lookup"]["extracted_key_ids"] = key_ids
        
        # Paso 3: Buscar backend logs para esas API keys
        print(f"[DEBUG] Buscando backend logs para key_ids: {key_ids}")
        logs_response = sb.table('backend_logs') \
            .select('*') \
            .in_('api_key_id', key_ids) \
            .order('created_at', desc=True) \
            .limit(5) \
            .execute()
        
        debug_info["step3_backend_logs_lookup"] = {
            "query": f"SELECT * FROM backend_logs WHERE api_key_id IN ({key_ids}) ORDER BY created_at DESC LIMIT 5",
            "found_logs": logs_response.data if logs_response.data else [],
            "log_count": len(logs_response.data) if logs_response.data else 0,
            "raw_response": str(logs_response)
        }
        
        # Verificación adicional: Buscar todos los logs para ver si existen datos
        all_logs_response = sb.table('backend_logs') \
            .select('api_key_id, endpoint, status, created_at') \
            .limit(5) \
            .execute()
        
        debug_info["additional_checks"] = {
            "total_logs_sample": {
                "query": "SELECT api_key_id, endpoint, status, created_at FROM backend_logs LIMIT 5",
                "sample_logs": all_logs_response.data if all_logs_response.data else [],
                "total_sample_count": len(all_logs_response.data) if all_logs_response.data else 0
            }
        }
        
        # Verificar si los key_ids existen en los logs
        if logs_response.data:
            found_api_key_ids = set(log['api_key_id'] for log in logs_response.data if log.get('api_key_id'))
            debug_info["step3_backend_logs_lookup"]["found_api_key_ids_in_logs"] = list(found_api_key_ids)
            debug_info["step3_backend_logs_lookup"]["key_ids_match"] = set(key_ids) == found_api_key_ids
        else:
            debug_info["step3_backend_logs_lookup"]["found_api_key_ids_in_logs"] = []
            debug_info["step3_backend_logs_lookup"]["key_ids_match"] = False
        
    except Exception as e:
        error_msg = f"Error en diagnóstico: {str(e)}"
        debug_info["errors"].append(error_msg)
        print(f"[DEBUG] {error_msg}")
    
    return debug_info

# Función para añadir el endpoint de diagnóstico a la app FastAPI
def add_debug_endpoint(app: FastAPI):
    @app.get("/api/debug/logs-auth")
    async def debug_logs_auth(
        request: Request,
        current_user_id: str = Depends(get_current_user_id_debug)
    ):
        """
        Endpoint de diagnóstico para verificar la cadena de autenticación de logs
        """
        try:
            debug_info = debug_auth_chain(request, current_user_id)
            return JSONResponse(content=debug_info)
        except Exception as e:
            print(f"[DEBUG] Error en endpoint de diagnóstico: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"error": f"Error en diagnóstico: {str(e)}"}
            )
    
    @app.get("/api/debug/check-tables")
    async def check_tables():
        """
        Verifica la existencia y contenido de las tablas relacionadas
        """
        try:
            sb = get_supabase()
            if not sb:
                return {"error": "No se pudo conectar a Supabase"}
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "tables": {}
            }
            
            # Verificar tabla api_keys
            try:
                keys_sample = sb.table('api_keys') \
                    .select('key_id, owner_user_id, name, active') \
                    .limit(3) \
                    .execute()
                result["tables"]["api_keys"] = {
                    "exists": True,
                    "sample_count": len(keys_sample.data) if keys_sample.data else 0,
                    "sample_data": keys_sample.data if keys_sample.data else []
                }
            except Exception as e:
                result["tables"]["api_keys"] = {"exists": False, "error": str(e)}
            
            # Verificar tabla backend_logs
            try:
                logs_sample = sb.table('backend_logs') \
                    .select('id, api_key_id, endpoint, status, created_at') \
                    .limit(3) \
                    .execute()
                result["tables"]["backend_logs"] = {
                    "exists": True,
                    "sample_count": len(logs_sample.data) if logs_sample.data else 0,
                    "sample_data": logs_sample.data if logs_sample.data else []
                }
            except Exception as e:
                result["tables"]["backend_logs"] = {"exists": False, "error": str(e)}
            
            return result
            
        except Exception as e:
            return {"error": f"Error verificando tablas: {str(e)}"}
    
    @app.get("/api/debug/public-check-tables")
    async def public_check_tables():
        """
        Endpoint público para verificar tablas sin autenticación
        """
        try:
            sb = get_supabase()
            if not sb:
                return {"error": "No se pudo conectar a Supabase"}
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "tables": {}
            }
            
            # Verificar tabla api_keys
            try:
                keys_sample = sb.table('api_keys') \
                    .select('key_id, owner_user_id, name, active') \
                    .limit(3) \
                    .execute()
                result["tables"]["api_keys"] = {
                    "exists": True,
                    "sample_count": len(keys_sample.data) if keys_sample.data else 0,
                    "sample_data": keys_sample.data if keys_sample.data else []
                }
            except Exception as e:
                result["tables"]["api_keys"] = {"exists": False, "error": str(e)}
            
            # Verificar tabla backend_logs
            try:
                logs_sample = sb.table('backend_logs') \
                    .select('id, api_key_id, endpoint, status, created_at') \
                    .limit(3) \
                    .execute()
                result["tables"]["backend_logs"] = {
                    "exists": True,
                    "sample_count": len(logs_sample.data) if logs_sample.data else 0,
                    "sample_data": logs_sample.data if logs_sample.data else []
                }
            except Exception as e:
                result["tables"]["backend_logs"] = {"exists": False, "error": str(e)}
            
            # Contar total de registros
            try:
                total_keys = sb.table('api_keys').select('*', count='exact').execute()
                total_logs = sb.table('backend_logs').select('*', count='exact').execute()
                
                result["totals"] = {
                    "api_keys": total_keys.count if hasattr(total_keys, 'count') else 0,
                    "backend_logs": total_logs.count if hasattr(total_logs, 'count') else 0
                }
            except Exception as e:
                result["totals"] = {"error": str(e)}
            
            return result
            
        except Exception as e:
            return {"error": f"Error verificando tablas: {str(e)}"}
    
    @app.get("/api/debug/public-check-user")
    async def public_check_user(request: Request):
        """
        Endpoint público para verificar la extracción del user_id del JWT
        """
        try:
            auth_header = request.headers.get("authorization")
            if not auth_header:
                return {
                    "error": "No authorization header found",
                    "headers": dict(request.headers)
                }
            
            # Extraer el token
            if " " in auth_header:
                scheme, token = auth_header.split(" ", 1)
                if scheme.lower() != "bearer":
                    return {"error": f"Invalid scheme: {scheme}"}
            else:
                token = auth_header
            
            # Simular la extracción del user_id (como lo hace get_current_user_id)
            user_id = token  # En desarrollo, el token es el user_id
            
            return {
                "timestamp": datetime.now().isoformat(),
                "auth_header": auth_header[:50] + "..." if len(auth_header) > 50 else auth_header,
                "extracted_user_id": user_id,
                "user_id_length": len(user_id) if user_id else 0,
                "user_id_preview": user_id[:20] + "..." if user_id and len(user_id) > 20 else user_id
            }
            
        except Exception as e:
            return {"error": f"Error verificando user: {str(e)}"}
    
    # Importar la función get_current_user_id del main.py
    from main import get_current_user_id
    
    @app.get("/api/debug/diagnose-logs")
    async def diagnose_logs(
        request: Request,
        current_user_id: str = Depends(get_current_user_id)
    ):
        """
        Endpoint de diagnóstico que usa la misma autenticación que /api/logs
        """
        try:
            debug_info = debug_auth_chain(request, current_user_id)
            return JSONResponse(content=debug_info)
        except Exception as e:
            print(f"[DEBUG] Error en endpoint de diagnóstico: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"error": f"Error en diagnóstico: {str(e)}"}
            )
    
    print("[DEBUG] Endpoints de diagnóstico añadidos:")
    print("  - GET /api/debug/logs-auth - Diagnóstico de cadena de autenticación (requiere JWT)")
    print("  - GET /api/debug/check-tables - Verificación de tablas (requiere API key)")
    print("  - GET /api/debug/public-check-tables - Verificación pública de tablas (sin autenticación)")
    print("  - GET /api/debug/public-check-user - Verificación pública de extracción de user_id (requiere JWT)")
    print("  - GET /api/debug/diagnose-logs - Diagnóstico completo con misma autenticación que /api/logs")
