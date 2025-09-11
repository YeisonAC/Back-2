#!/usr/bin/env python3
"""
Script de prueba para insertar directamente en Supabase
y diagnosticar problemas con la creación de API keys
"""

import os
import sys
from datetime import datetime, timezone
from supabase import create_client, Client

# Cargar variables de entorno
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).with_name('.env'))

def test_supabase_connection():
    """Probar conexión a Supabase"""
    print("=== Probando conexión a Supabase ===")
    
    # Obtener configuración
    url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    anon_key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    
    print(f"URL: {'***' + url[-20:] if url else 'NOT SET'}")
    print(f"Service Key: {'***' + service_key[-10:] if service_key else 'NOT SET'}")
    print(f"Anon Key: {'***' + anon_key[-10:] if anon_key else 'NOT SET'}")
    
    if not url or not service_key:
        print("ERROR: Faltan credenciales de Supabase")
        return None
    
    try:
        # Probar con service role key
        client = create_client(url, service_key)
        print("✓ Cliente de Supabase creado con service role key")
        return client
    except Exception as e:
        print(f"ERROR: No se pudo crear cliente de Supabase: {e}")
        return None

def test_table_structure(client):
    """Probar estructura de la tabla api_keys"""
    print("\n=== Probando estructura de tabla api_keys ===")
    
    try:
        # Intentar obtener la estructura de la tabla
        result = client.table("api_keys").select("*").limit(1).execute()
        print(f"✓ Tabla api_keys accesible")
        print(f"  - Resultado: {result}")
        
        # Verificar si hay datos
        if hasattr(result, 'data') and result.data:
            print(f"  - Hay {len(result.data)} registros en la tabla")
            print(f"  - Primer registro: {result.data[0]}")
        else:
            print("  - No hay registros en la tabla")
            
        return True
    except Exception as e:
        print(f"ERROR: No se pudo acceder a la tabla api_keys: {e}")
        return False

def test_direct_insert(client):
    """Probar inserción directa en la tabla api_keys"""
    print("\n=== Probando inserción directa ===")
    
    try:
        # Datos de prueba
        test_data = {
            "key_id": "test_key_123",
            "hash": "test_hash_123",
            "salt": "test_salt_123",
            "active": True,
            "name": "Test Key Direct Insert",
            "rate_limit": 1000,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": "test_script",
            "prefix": "test1234",
            "user_id": "test_user_123"
        }
        
        print(f"Insertando datos de prueba: {test_data}")
        
        # Insertar directamente
        result = client.table("api_keys").insert(test_data).execute()
        print(f"✓ Inserción ejecutada")
        print(f"  - Resultado: {result}")
        
        # Verificar si la inserción fue exitosa
        if hasattr(result, 'data') and result.data:
            print(f"  - Datos insertados: {result.data}")
            
            # Verificar que se puede leer el registro
            verify_result = client.table("api_keys").select("*").eq("key_id", "test_key_123").execute()
            print(f"  - Verificación: {verify_result}")
            
            if hasattr(verify_result, 'data') and verify_result.data:
                print("✓ Registro verificado correctamente")
                return True
            else:
                print("✗ Registro no encontrado después de inserción")
                return False
        else:
            print("✗ No se recibieron datos en la respuesta de inserción")
            return False
            
    except Exception as e:
        print(f"ERROR: Falló la inserción directa: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def test_rls_permissions(client):
    """Probar permisos RLS"""
    print("\n=== Probando permisos RLS ===")
    
    try:
        # Intentar leer con diferentes tipos de cliente
        anon_key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
        url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
        
        if anon_key:
            anon_client = create_client(url, anon_key)
            print("Probando con cliente anónimo...")
            
            try:
                result = anon_client.table("api_keys").select("*").limit(1).execute()
                print(f"✓ Lectura con cliente anónimo exitosa: {len(result.data) if result.data else 0} registros")
            except Exception as e:
                print(f"✗ Lectura con cliente anónimo fallida: {e}")
        
        # Probar inserción con cliente anónimo
        if anon_key:
            try:
                test_data = {
                    "key_id": "test_anon_key",
                    "hash": "test_anon_hash",
                    "salt": "test_anon_salt",
                    "active": True,
                    "name": "Test Anon Key",
                    "rate_limit": 500,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "created_by": "anon_test",
                    "prefix": "anon1234",
                    "user_id": "anon_user"
                }
                
                result = anon_client.table("api_keys").insert(test_data).execute()
                print(f"✓ Inserción con cliente anónimo exitosa: {result}")
            except Exception as e:
                print(f"✗ Inserción con cliente anónimo fallida: {e}")
        
    except Exception as e:
        print(f"ERROR: Falló la prueba de RLS: {e}")

def cleanup_test_data(client):
    """Limpiar datos de prueba"""
    print("\n=== Limpiando datos de prueba ===")
    
    try:
        # Eliminar registros de prueba
        client.table("api_keys").delete().eq("key_id", "test_key_123").execute()
        client.table("api_keys").delete().eq("key_id", "test_anon_key").execute()
        print("✓ Datos de prueba eliminados")
    except Exception as e:
        print(f"ERROR: No se pudieron eliminar datos de prueba: {e}")

def main():
    """Función principal"""
    print("Iniciando pruebas de Supabase...")
    
    # Probar conexión
    client = test_supabase_connection()
    if not client:
        print("No se pudo establecer conexión a Supabase")
        sys.exit(1)
    
    # Probar estructura de tabla
    if not test_table_structure(client):
        print("Problemas con la estructura de la tabla")
        sys.exit(1)
    
    # Probar inserción directa
    if not test_direct_insert(client):
        print("La inserción directa falló")
        sys.exit(1)
    
    # Probar permisos RLS
    test_rls_permissions(client)
    
    # Limpiar datos de prueba
    cleanup_test_data(client)
    
    print("\n=== Pruebas completadas ===")
    print("Si todo salió bien, la inserción debería funcionar correctamente")

if __name__ == "__main__":
    main()
