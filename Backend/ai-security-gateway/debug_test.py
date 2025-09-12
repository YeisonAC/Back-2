#!/usr/bin/env python3
"""
Script de depuración para obtener más información del error 500
"""
import requests
import json
import traceback

# Configuración
URL = "https://back-2-testing.vercel.app/v1/chat/completions"
API_KEY = "EONS_wHQkajuh3fM.JWzz_wgPrvVqbsU-uJUEg6E8B5UXE0ZXg7waKhvxNaU"

def test_with_debug():
    """Probar con más información de depuración"""
    print("=== Test con depuración detallada ===")
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'Debug-Test/1.0'
    }
    
    data = {
        'model': 'L1-mini',
        'messages': [
            {'role': 'user', 'content': 'Hola'}
        ]
    }
    
    print(f"URL: {URL}")
    print(f"Headers: {json.dumps(headers, indent=2)}")
    print(f"Data: {json.dumps(data, indent=2)}")
    print()
    
    try:
        response = requests.post(URL, headers=headers, json=data, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code != 200:
            print(f"Error Response: {response.text}")
            print(f"Response Content (raw): {response.content}")
            
            # Intentar parsear como JSON si es posible
            try:
                error_json = response.json()
                print(f"Error JSON: {json.dumps(error_json, indent=2)}")
            except:
                print("Response is not JSON")
        
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"General Exception: {e}")
        traceback.print_exc()
    
    print()

def test_debug_endpoint():
    """Probar el endpoint de debug para ver si funciona"""
    print("=== Test endpoint de debug ===")
    
    debug_url = "https://back-2-testing.vercel.app/debug/groq"
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_KEY}'
    }
    
    try:
        response = requests.get(debug_url, headers=headers, timeout=30)
        print(f"Debug URL: {debug_url}")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Debug Response: {json.dumps(result, indent=2)}")
        else:
            print(f"Debug Error: {response.text}")
            
    except Exception as e:
        print(f"Debug Exception: {e}")
        traceback.print_exc()
    
    print()

def test_with_different_tier():
    """Probar especificando el tier en header"""
    print("=== Test con tier especificado en header ===")
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_KEY}',
        'X-Layer': 'L1-mini'
    }
    
    data = {
        'model': 'L1-mini',
        'messages': [
            {'role': 'user', 'content': 'Hola'}
        ]
    }
    
    try:
        response = requests.post(URL, headers=headers, json=data, timeout=30)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Success: {json.dumps(result, indent=2)}")
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Exception: {e}")
        traceback.print_exc()
    
    print()

if __name__ == "__main__":
    print("Iniciando pruebas de depuración...")
    print(f"URL: {URL}")
    print(f"API Key: {API_KEY[:20]}...")
    print()
    
    test_debug_endpoint()
    test_with_debug()
    test_with_different_tier()
    
    print("=== Pruebas de depuración completadas ===")
