#!/usr/bin/env python3
"""
Script de prueba para la funcionalidad de geolocalización
"""

import sys
import os

# Agregar el directorio actual al path para importar los módulos
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from geolocation import geolocation_service

def test_geolocation():
    """Prueba el servicio de geolocalización con diferentes IPs"""
    
    print("=== Prueba de Geolocalización ===\n")
    
    # Lista de IPs de prueba
    test_ips = [
        "8.8.8.8",        # Google DNS (US)
        "1.1.1.1",        # Cloudflare DNS (US)
        "208.67.222.222", # OpenDNS (US)
        "127.0.0.1",      # Localhost
        "192.168.1.1",    # IP privada
        "200.3.193.100",  # ETB (Colombia)
        "181.118.144.1",  # Claro (Colombia)
    ]
    
    for ip in test_ips:
        print(f"Probando IP: {ip}")
        print("-" * 40)
        
        try:
            result = geolocation_service.get_country_from_ip(ip)
            
            print(f"Código de país: {result['country_code']}")
            print(f"Nombre del país: {result['country_name']}")
            print(f"Ciudad: {result['city']}")
            print(f"Región: {result['region']}")
            print(f"Éxito: {result['success']}")
            if result['error']:
                print(f"Error: {result['error']}")
            
        except Exception as e:
            print(f"Error inesperado: {str(e)}")
        
        print()

def test_private_ip_detection():
    """Prueba la detección de IPs privadas"""
    
    print("=== Prueba de Detección de IPs Privadas ===\n")
    
    private_ips = [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.1.1",
        "::1",
    ]
    
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "200.3.193.100",
    ]
    
    print("IPs Privadas:")
    for ip in private_ips:
        result = geolocation_service.get_country_from_ip(ip)
        expected_country = "LOCAL"
        actual_country = result['country_code']
        status = "✓" if actual_country == expected_country else "✗"
        print(f"  {status} {ip} -> {actual_country} (esperado: {expected_country})")
    
    print("\nIPs Públicas:")
    for ip in public_ips:
        result = geolocation_service.get_country_from_ip(ip)
        status = "✓" if result['success'] and result['country_code'] != "LOCAL" else "✗"
        print(f"  {status} {ip} -> {result['country_code']} ({result['country_name']})")

if __name__ == "__main__":
    print("Iniciando pruebas de geolocalización...\n")
    
    # Probar geolocalización básica
    test_geolocation()
    
    # Probar detección de IPs privadas
    test_private_ip_detection()
    
    print("\n=== Pruebas completadas ===")
