#!/usr/bin/env python3
"""
Script para probar la corrección de extracción de user_id del JWT
"""
import os
import json
from dotenv import load_dotenv
import jwt

# Cargar variables de entorno
load_dotenv()

def test_jwt_decoding():
    """
    Prueba la decodificación del JWT para extraer el user_id
    """
    # JWT del usuario
    jwt_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InpmR2w5b3l2U3I3dVJXUVYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2NiaHB3bnh1aG5rZ3Nid3RqaWt4LnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI0ZGM1YzY1Yy1mNGYxLTQyZGItYmRiMy0yODliMjVjYTJhNWUiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzU2OTM2NDc4LCJpYXQiOjE3NTY5MzI4NzgsImVtYWlsIjoieWVpc29uYXJyb3lhdmUuY2FAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJlbWFpbCIsInByb3ZpZGVycyI6WyJlbWFpbCJdfSwidXNlcl9tZXRhZGF0YSI6eyJlbWFpbCI6InllaXNvbmFycm95YXZlLmNhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmdWxsX25hbWUiOiJZZWlzb24iLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjRkYzVjNjVjLWY0ZjEtNDJkYi1iZGIzLTI4OWIyNWNhMmE1ZSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzU2OTMyODc4fV0sInNlc3Npb25faWQiOiIzNWUwYTcyZC1kZWMzLTRhNzktOGNlNy01NjYxODlmYWJiMzEiLCJpc19hbm9ueW1vdXMiOmZhbHNlfQ.57reLFTPDDzeMMa1FTAD32HUp2FSERR9ipLq7nSDVsk"
    
    print("=== PRUEBA DE DECODIFICACIÓN JWT ===")
    print(f"JWT Token (primeros 50 caracteres): {jwt_token[:50]}...")
    print()
    
    try:
        # Decodificar el JWT sin verificar firma
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
        
        print("✅ JWT decodificado correctamente:")
        print(json.dumps(decoded_token, indent=2, default=str))
        print()
        
        # Extraer el user_id del campo 'sub'
        user_id = decoded_token.get("sub")
        
        if not user_id:
            # Intentar con otros campos comunes
            user_id = decoded_token.get("user_id") or decoded_token.get("user_metadata", {}).get("sub")
        
        if user_id:
            print(f"✅ User ID extraído: {user_id}")
            print(f"✅ Longitud del user_id: {len(user_id)}")
            print(f"✅ Formato UUID válido: {'-' in user_id and len(user_id) == 36}")
            
            # Verificar que es un UUID válido
            import uuid
            try:
                uuid.UUID(user_id)
                print("✅ User ID es un UUID válido")
            except ValueError:
                print("❌ User ID no es un UUID válido")
                
        else:
            print("❌ No se encontró user_id en el JWT")
            
    except jwt.DecodeError as e:
        print(f"❌ Error de decodificación JWT: {str(e)}")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")

def simulate_get_current_user_id():
    """
    Simula la función get_current_user_id actualizada
    """
    print("\n=== SIMULACIÓN DE get_current_user_id ===")
    
    # JWT del usuario
    jwt_token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InpmR2w5b3l2U3I3dVJXUVYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2NiaHB3bnh1aG5rZ3Nid3RqaWt4LnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI0ZGM1YzY1Yy1mNGYxLTQyZGItYmRiMy0yODliMjVjYTJhNWUiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzU2OTM2NDc4LCJpYXQiOjE3NTY5MzI4NzgsImVtYWlsIjoieWVpc29uYXJyb3lhdmUuY2FAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJlbWFpbCIsInByb3ZpZGVycyI6WyJlbWFpbCJdfSwidXNlcl9tZXRhZGF0YSI6eyJlbWFpbCI6InllaXNvbmFycm95YXZlLmNhQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmdWxsX25hbWUiOiJZZWlzb24iLCJwaG9uZV92ZXJpZmllZCI6ZmFsc2UsInN1YiI6IjRkYzVjNjVjLWY0ZjEtNDJkYi1iZGIzLTI4OWIyNWNhMmE1ZSJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6InBhc3N3b3JkIiwidGltZXN0YW1wIjoxNzU2OTMyODc4fV0sInNlc3Npb25faWQiOiIzNWUwYTcyZC1kZWMzLTRhNzktOGNlNy01NjYxODlmYWJiMzEiLCJpc19hbm9ub3ltb3VzIjpmYWxzZX0.57reLFTPDDzeMMa1FTAD32HUp2FSERR9ipLq7nSDVsk"
    
    # Simular el objeto credentials
    class MockCredentials:
        def __init__(self, token):
            self.credentials = token
    
    credentials = MockCredentials(jwt_token)
    
    try:
        # Decodificar el JWT sin verificar firma
        decoded_token = jwt.decode(credentials.credentials, options={"verify_signature": False})
        
        # Extraer el user_id del campo 'sub'
        user_id = decoded_token.get("sub")
        
        if not user_id:
            # Intentar con otros campos comunes
            user_id = decoded_token.get("user_id") or decoded_token.get("user_metadata", {}).get("sub")
        
        if not user_id:
            raise Exception("Invalid JWT: missing user_id")
        
        print(f"✅ get_current_user_id retornaría: {user_id}")
        print(f"✅ Este user_id debería encontrar las 34 API keys del usuario")
        print(f"✅ Y luego debería encontrar los 4 logs asociados a esas API keys")
        
    except jwt.DecodeError:
        print("❌ get_current_user_id retornaría error: Invalid JWT format")
    except Exception as e:
        print(f"❌ get_current_user_id retornaría error: {str(e)}")

if __name__ == "__main__":
    test_jwt_decoding()
    simulate_get_current_user_id()
