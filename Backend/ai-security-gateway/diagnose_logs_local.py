#!/usr/bin/env python3
"""
Script de diagnóstico local para verificar la relación JWT -> user_id -> API keys -> backend_logs
"""
import os
import json
from datetime import datetime
from dotenv import load_dotenv
import jwt
from supabase_client import get_supabase

# Cargar variables de entorno
load_dotenv()

def decode_jwt_user_id(jwt_token):
    """
    Extrae el user_id del JWT correctamente
    """
    try:
        print(f"[DEBUG] JWT recibido: {jwt_token[:50]}...")
        print(f"[DEBUG] Longitud del JWT: {len(jwt_token)}")
        
        # Decodificar el JWT para obtener el payload
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        print(f"[DEBUG] JWT decodificado: {decoded}")
        
        # Extraer el user_id del payload
        user_id = decoded.get("sub")
        if not user_id:
            # Intentar con otros campos comunes
            user_id = decoded.get("user_id") or decoded.get("user_metadata", {}).get("sub")
        
        if user_id:
            print(f"[DEBUG] User ID extraído: {user_id}")
            print(f"[DEBUG] Longitud del user_id: {len(user_id)}")
            return user_id
        else:
            print(f"[DEBUG] No se encontró user_id en el JWT")
            return None
            
    except Exception as e:
        print(f"[DEBUG] Error decodificando JWT: {str(e)}")
        return None

def diagnose_auth_chain(jwt_token):
    """
    Diagnostica la cadena completa de autenticación
    """
    debug_info = {
        "timestamp": datetime.now().isoformat(),
        "step1_jwt_extraction": {},
        "step2_api_keys_lookup": {},
        "step3_backend_logs_lookup": {},
        "errors": []
    }
    
    # Paso 1: Extraer user_id del JWT
    try:
        user_id = decode_jwt_user_id(jwt_token)
        if not user_id:
            debug_info["errors"].append("No se pudo extraer user_id del JWT")
            return debug_info
        
        debug_info["step1_jwt_extraction"] = {
            "jwt_length": len(jwt_token),
            "extracted_user_id": user_id,
            "user_id_length": len(user_id),
            "user_id_preview": user_id[:20] + "..." if len(user_id) > 20 else user_id
        }
        
        print(f"[DEBUG] User ID extraído: {user_id}")
        
    except Exception as e:
        error_msg = f"Error en extracción de JWT: {str(e)}"
        debug_info["errors"].append(error_msg)
        print(f"[DEBUG] {error_msg}")
        return debug_info
    
    try:
        sb = get_supabase()
        if not sb:
            debug_info["errors"].append("No se pudo conectar a Supabase")
            return debug_info
        
        # Paso 2: Buscar API keys del usuario
        print(f"[DEBUG] Buscando API keys para user_id: {user_id}")
        keys_response = sb.table('api_keys') \
            .select('key_id, name, active, created_at, owner_user_id') \
            .eq('owner_user_id', user_id) \
            .execute()
        
        debug_info["step2_api_keys_lookup"] = {
            "query": f"SELECT key_id, name, active, created_at, owner_user_id FROM api_keys WHERE owner_user_id = '{user_id}'",
            "found_keys": keys_response.data if keys_response.data else [],
            "key_count": len(keys_response.data) if keys_response.data else 0,
            "raw_response": str(keys_response)
        }
        
        if not keys_response.data:
            debug_info["errors"].append(f"No se encontraron API keys para el user_id: {user_id}")
            print(f"[DEBUG] No se encontraron API keys para el user_id: {user_id}")
            return debug_info
        
        key_ids = [key['key_id'] for key in keys_response.data]
        debug_info["step2_api_keys_lookup"]["extracted_key_ids"] = key_ids
        
        print(f"[DEBUG] API keys encontradas: {key_ids}")
        
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
            print(f"[DEBUG] API key IDs encontrados en logs: {found_api_key_ids}")
            print(f"[DEBUG] ¿Coinciden los key_ids? {set(key_ids) == found_api_key_ids}")
        else:
            debug_info["step3_backend_logs_lookup"]["found_api_key_ids_in_logs"] = []
            debug_info["step3_backend_logs_lookup"]["key_ids_match"] = False
            print(f"[DEBUG] No se encontraron logs para los key_ids: {key_ids}")
        
        # Contar total de registros en cada tabla
        try:
            total_keys = sb.table('api_keys').select('*', count='exact').execute()
            total_logs = sb.table('backend_logs').select('*', count='exact').execute()
            
            debug_info["totals"] = {
                "api_keys": total_keys.count if hasattr(total_keys, 'count') else 0,
                "backend_logs": total_logs.count if hasattr(total_logs, 'count') else 0
            }
            print(f"[DEBUG] Total API keys: {debug_info['totals']['api_keys']}")
            print(f"[DEBUG] Total backend logs: {debug_info['totals']['backend_logs']}")
        except Exception as e:
            debug_info["totals"] = {"error": str(e)}
        
    except Exception as e:
        error_msg = f"Error en diagnóstico: {str(e)}"
        debug_info["errors"].append(error_msg)
        print(f"[DEBUG] {error_msg}")
    
    return debug_info

def main():
    """
    Función principal para ejecutar el diagnóstico
    """
    print("=== DIAGNÓSTICO DE CADENA DE AUTENTICACIÓN ===")
    print()
    
    # JWT del usuario (pegar aquí el JWT completo)
    jwt_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InpmR2w5b3l2U3I3dVJXUVYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2NiaHB3bnh1aG5rZ3Nid3RqaWt4LnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI0ZGM1YzY1Yy1mNGYxLTQyZGItYmRiMy0yODliMjVjYTJhNWUiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzU2OTM2NDc4LCJpYXQiOjE3NTY5MzI4NzgsImVtYWlsIjoieWVpc29uYXJyb3lhdmUuY2FAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJlbWFpbCIsInByb3ZpZGVycyI6WyJlbWFpbCJdfSwidXNlcl9tZXRhZGF0YSI6eyJlbWFpbCI6InllaXNvbmFycm95YXZlLmNhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmdWxsX25hbWUiOiJZZWlzb24iLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjRkYzVjNjVjLWY0ZjEtNDJkYi1iZGIzLTI4OWIyNWNhMmE1ZSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzU2OTMyODc4fV0sInNlc3Npb25faWQiOiIzNWUwYTcyZC1kZWMzLTRhNzktOGNlNy01NjYxODlmYWJiMzEiLCJpc19hbm9ub3ltb3VzIjpmYWxzZX0.57reLFTPDDzeMMa1FTAD32HUp2FSERR9ipLq7nSDVsk"
    
    print("JWT Token (primeros 50 caracteres):")
    print(f"{jwt_token[:50]}...")
    print()
    
    # Ejecutar diagnóstico
    debug_info = diagnose_auth_chain(jwt_token)
    
    # Mostrar resultados
    print("\n=== RESULTADOS DEL DIAGNÓSTICO ===")
    print(json.dumps(debug_info, indent=2, default=str))
    
    # Análisis final
    print("\n=== ANÁLISIS FINAL ===")
    
    if debug_info["errors"]:
        print("❌ ERRORES ENCONTRADOS:")
        for error in debug_info["errors"]:
            print(f"  - {error}")
    
    # Paso 1: JWT
    step1 = debug_info["step1_jwt_extraction"]
    if step1:
        print(f"✅ Paso 1 (JWT): User ID extraído correctamente")
        print(f"   - User ID: {step1.get('user_id_preview', 'N/A')}")
        print(f"   - Longitud: {step1.get('user_id_length', 0)}")
    
    # Paso 2: API Keys
    step2 = debug_info["step2_api_keys_lookup"]
    if step2:
        key_count = step2.get("key_count", 0)
        if key_count > 0:
            print(f"✅ Paso 2 (API Keys): Se encontraron {key_count} API keys")
            print(f"   - Key IDs: {step2.get('extracted_key_ids', [])}")
        else:
            print(f"❌ Paso 2 (API Keys): No se encontraron API keys para este usuario")
    
    # Paso 3: Backend Logs
    step3 = debug_info["step3_backend_logs_lookup"]
    if step3:
        log_count = step3.get("log_count", 0)
        if log_count > 0:
            print(f"✅ Paso 3 (Backend Logs): Se encontraron {log_count} logs")
            print(f"   - Key IDs en logs: {step3.get('found_api_key_ids_in_logs', [])}")
            print(f"   - ¿Coinciden? {step3.get('key_ids_match', False)}")
        else:
            print(f"❌ Paso 3 (Backend Logs): No se encontraron logs para las API keys del usuario")
    
    # Totales
    totals = debug_info.get("totals", {})
    if totals:
        print(f"\n📊 TOTALES:")
        print(f"   - Total API keys en la base de datos: {totals.get('api_keys', 0)}")
        print(f"   - Total backend logs en la base de datos: {totals.get('backend_logs', 0)}")
    
    # Verificación adicional
    additional = debug_info.get("additional_checks", {})
    if additional:
        total_sample = additional.get("total_logs_sample", {})
        sample_count = total_sample.get("total_sample_count", 0)
        if sample_count > 0:
            print(f"\n📋 MUESTRA DE TODOS LOS LOGS:")
            print(f"   - Se encontraron {sample_count} logs en total")
            for i, log in enumerate(total_sample.get("sample_logs", [])[:3]):
                print(f"   - Log {i+1}: API Key ID: {log.get('api_key_id', 'N/A')}, Endpoint: {log.get('endpoint', 'N/A')}")

if __name__ == "__main__":
    main()
