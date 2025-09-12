#!/usr/bin/env python3
"""
Script para verificar si una API key existe en la base de datos
"""

import sys
import os
from dotenv import load_dotenv

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Cargar variables de entorno
load_dotenv()

def check_api_key(api_key):
    """Verifica si una API key existe en la base de datos"""
    
    try:
        from supabase import create_client
        
        # Obtener credenciales de Supabase
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        if not supabase_url or not supabase_service_key:
            print("❌ Error: No se encontraron las credenciales de Supabase en el archivo .env")
            return False
        
        # Crear cliente de Supabase
        supabase = create_client(supabase_url, supabase_service_key)
        
        print(f"🔍 Buscando API key: {api_key}")
        
        # Buscar en la tabla api_keys_public
        response = supabase.table("api_keys_public").select("*").eq("key", api_key).execute()
        
        if response.data:
            print("✅ API key encontrada en api_keys_public:")
            key_data = response.data[0]
            print(f"   ID: {key_data.get('id')}")
            print(f"   Owner: {key_data.get('owner_user_id')}")
            print(f"   Status: {key_data.get('status', 'active')}")
            print(f"   Created: {key_data.get('created_at')}")
            return True
        else:
            print("❌ API key no encontrada en api_keys_public")
            
            # Buscar en la tabla api_keys
            response = supabase.table("api_keys").select("*").eq("key", api_key).execute()
            
            if response.data:
                print("✅ API key encontrada en api_keys:")
                key_data = response.data[0]
                print(f"   ID: {key_data.get('id')}")
                print(f"   Owner: {key_data.get('owner_user_id')}")
                print(f"   Status: {key_data.get('status', 'active')}")
                print(f"   Created: {key_data.get('created_at')}")
                return True
            else:
                print("❌ API key no encontrada en ninguna tabla")
                return False
                
    except Exception as e:
        print(f"❌ Error verificando API key: {str(e)}")
        return False

def list_all_api_keys():
    """Lista todas las API keys en la base de datos (para debugging)"""
    
    try:
        from supabase import create_client
        
        # Obtener credenciales de Supabase
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        if not supabase_url or not supabase_service_key:
            print("❌ Error: No se encontraron las credenciales de Supabase")
            return
        
        # Crear cliente de Supabase
        supabase = create_client(supabase_url, supabase_service_key)
        
        print("\n📋 API keys en api_keys_public:")
        response = supabase.table("api_keys_public").select("*").limit(10).execute()
        
        if response.data:
            for key_data in response.data:
                print(f"   - ID: {key_data.get('id')}")
                print(f"     Key: {key_data.get('key', 'N/A')[:20]}...")
                print(f"     Owner: {key_data.get('owner_user_id')}")
                print(f"     Status: {key_data.get('status', 'active')}")
                print()
        else:
            print("   No hay API keys en api_keys_public")
        
        print("📋 API keys en api_keys:")
        response = supabase.table("api_keys").select("*").limit(10).execute()
        
        if response.data:
            for key_data in response.data:
                print(f"   - ID: {key_data.get('id')}")
                print(f"     Key: {key_data.get('key', 'N/A')[:20]}...")
                print(f"     Owner: {key_data.get('owner_user_id')}")
                print(f"     Status: {key_data.get('status', 'active')}")
                print()
        else:
            print("   No hay API keys en api_keys")
            
    except Exception as e:
        print(f"❌ Error listando API keys: {str(e)}")

if __name__ == "__main__":
    api_key = "EONS_J-90Vtunvds.dAbaQtYdC_fmi8J-j1Pw8F0fbRDACyJ1hyAtKBiQWHY"
    
    print("=== Verificación de API Key ===\n")
    
    # Verificar API key específica
    check_api_key(api_key)
    
    # Listar todas las API keys para debugging
    print("\n=== Listado de API Keys ===")
    list_all_api_keys()
