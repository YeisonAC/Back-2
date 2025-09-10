#!/usr/bin/env python3
"""
Script para simular exactamente la lógica del servidor y verificar el flujo completo
"""
import os
import json
from dotenv import load_dotenv
import jwt
from supabase_client import get_supabase

# Cargar variables de entorno
load_dotenv()

def simulate_get_logs_endpoint():
    """
    Simula exactamente la lógica del endpoint /api/logs
    """
    print("=== SIMULACIÓN DEL ENDPOINT /api/logs ===")
    
    # JWT del usuario
    jwt_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InpmR2w5b3l2U3I3dVJXUVYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2NiaHB3bnh1aG5rZ3Nid3RqaWt4LnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI0ZGM1YzY1Yy1mNGYxLTQyZGItYmRiMy0yODliMjVjYTJhNWUiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzU2OTM2NDc4LCJpYXQiOjE3NTY5MzI4NzgsImVtYWlsIjoieWVpc29uYXJyb3lhdmUuY2FAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJlbWFpbCIsInByb3ZpZGVycyI6WyJlbWFpbCJdfSwidXNlcl9tZXRhZGF0YSI6eyJlbWFpbCI6InllaXNvbmFycm95YXZlLmNhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmdWxsX25hbWUiOiJZZWlzb24iLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjRkYzVjNjVjLWY0ZjEtNDJkYi1iZGIzLTI4OWIyNWNhMmE1ZSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzU2OTMyODc4fV0sInNlc3Npb25faWQiOiIzNWUwYTcyZC1kZWMzLTRhNzktOGNlNy01NjYxODlmYWJiMzEiLCJpc19hbm9ub3ltb3VzIjpmYWxzZX0.57reLFTPDDzeMMa1FTAD32HUp2FSERR9ipLq7nSDVsk"
    
    try:
        # Paso 1: Simular get_current_user_id (versión corregida)
        print("Paso 1: Extrayendo user_id del JWT...")
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
        current_user_id = decoded_token.get("sub")
        
        if not current_user_id:
            current_user_id = decoded_token.get("user_id") or decoded_token.get("user_metadata", {}).get("sub")
        
        if not current_user_id:
            raise Exception("Invalid JWT: missing user_id")
        
        print(f"✅ User ID extraído: {current_user_id}")
        
        # Paso 2: Conectar a Supabase
        print("\nPaso 2: Conectando a Supabase...")
        sb = get_supabase()
        if not sb:
            raise Exception("No se pudo conectar a Supabase")
        
        print("✅ Conexión a Supabase establecida")
        
        # Paso 3: Obtener API keys del usuario
        print(f"\nPaso 3: Buscando API keys para user_id: {current_user_id}")
        keys_response = sb.table('api_keys') \
            .select('key_id') \
            .eq('owner_user_id', current_user_id) \
            .execute()
        
        if not keys_response.data:
            print(f"❌ No se encontraron API keys para el user_id: {current_user_id}")
            return {"data": [], "total": 0, "page": 1, "page_size": 20}
        
        key_ids = [key['key_id'] for key in keys_response.data]
        print(f"✅ Se encontraron {len(key_ids)} API keys")
        print(f"   Key IDs: {key_ids[:5]}...")  # Mostrar solo los primeros 5
        
        # Paso 4: Obtener logs filtrados por API keys
        print(f"\nPaso 4: Buscando logs para {len(key_ids)} API keys...")
        page = 1
        page_size = 20
        offset = (page - 1) * page_size
        
        query = sb.table('backend_logs') \
            .select('*', count='exact') \
            .in_('api_key_id', key_ids) \
            .order('created_at', desc=True) \
            .limit(page_size) \
            .range(offset, offset + page_size - 1)
        
        result = query.execute()
        
        print(f"✅ Query ejecutada")
        print(f"   - Datos encontrados: {len(result.data) if result.data else 0}")
        print(f"   - Total count: {result.count if hasattr(result, 'count') else 'N/A'}")
        
        # Paso 5: Procesar resultados
        if result.data:
            processed_data = []
            for log in result.data:
                processed_log = dict(log)
                # Convertir JSON strings a dicts si es necesario
                if isinstance(processed_log.get('request_payload'), str):
                    try:
                        processed_log['request_payload'] = json.loads(processed_log['request_payload'])
                    except:
                        pass
                if isinstance(processed_log.get('response_payload'), str):
                    try:
                        processed_log['response_payload'] = json.loads(processed_log['response_payload'])
                    except:
                        pass
                processed_data.append(processed_log)
            
            print(f"✅ Datos procesados: {len(processed_data)} logs")
            
            # Mostrar resumen de los logs encontrados
            for i, log in enumerate(processed_data[:3]):  # Mostrar solo los primeros 3
                print(f"   - Log {i+1}:")
                print(f"     ID: {log.get('id', 'N/A')}")
                print(f"     Endpoint: {log.get('endpoint', 'N/A')}")
                print(f"     Status: {log.get('status', 'N/A')}")
                print(f"     API Key ID: {log.get('api_key_id', 'N/A')}")
                print(f"     Created: {log.get('created_at', 'N/A')}")
                print()
            
            return {
                "data": processed_data,
                "total": result.count if hasattr(result, 'count') else len(processed_data),
                "page": page,
                "page_size": page_size
            }
        else:
            print("❌ No se encontraron logs para las API keys del usuario")
            return {"data": [], "total": 0, "page": 1, "page_size": 20}
            
    except Exception as e:
        print(f"❌ Error en la simulación: {str(e)}")
        return {"error": str(e)}

def test_with_old_logic():
    """
    Prueba con la lógica antigua (tratando JWT como user_id directamente)
    """
    print("\n=== PRUEBA CON LÓGICA ANTIGUA (JWT como user_id) ===")
    
    # JWT del usuario (tratado como user_id directamente)
    jwt_as_user_id = "eyJhbGciOiJIUzI1NiIsImtpZCI6InpmR2w5b3l2U3I3dVJXUVYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2NiaHB3bnh1aG5rZ3Nid3RqaWt4LnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI0ZGM1YzY1Yy1mNGYxLTQyZGItYmRiMy0yODliMjVjYTJhNWUiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzU2OTM2NDc4LCJpYXQiOjE3NTY5MzI4NzgsImVtYWlsIjoieWVpc29uYXJyb3lhdmUuY2FAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJlbWFpbCIsInByb3ZpZGVycyI6WyJlbWFpbCJdfSwidXNlcl9tZXRhZGF0YSI6eyJlbWFpbCI6InllaXNvbmFycm95YXZlLmNhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmdWxsX25hbWUiOiJZZWlzb24iLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjRkYzVjNjVjLWY0ZjEtNDJkYi1iZGIzLTI4OWIyNWNhMmE1ZSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzU2OTMyODc4fV0sInNlc3Npb25faWQiOiIzNWUwYTcyZC1kZWMzLTRhNzktOGNlNy01NjYxODlmYWJiMzEiLCJpc19hbm9ub3ltb3VzIjpmYWxzZX0.57reLFTPDDzeMMa1FTAD32HUp2FSERR9ipLq7nSDVsk"
    
    try:
        sb = get_supabase()
        if not sb:
            raise Exception("No se pudo conectar a Supabase")
        
        print(f"Buscando API keys con user_id (JWT completo): {jwt_as_user_id[:50]}...")
        
        keys_response = sb.table('api_keys') \
            .select('key_id') \
            .eq('owner_user_id', jwt_as_user_id) \
            .execute()
        
        print(f"API keys encontradas con lógica antigua: {len(keys_response.data) if keys_response.data else 0}")
        
        if keys_response.data:
            key_ids = [key['key_id'] for key in keys_response.data]
            print(f"Key IDs: {key_ids}")
        else:
            print("❌ Esta es la razón por la que el endpoint retorna vacío en producción")
            
    except Exception as e:
        print(f"Error con lógica antigua: {str(e)}")

if __name__ == "__main__":
    # Probar con la lógica corregida
    result = simulate_get_logs_endpoint()
    
    print("\n=== RESULTADO FINAL ===")
    print(json.dumps(result, indent=2, default=str))
    
    # Probar con la lógica antigua para comparar
    test_with_old_logic()
