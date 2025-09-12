#!/usr/bin/env python3
"""
Debug para la función _select_tier
"""

def _normalize_tier_name(raw):
    """Función normalizar nombre de tier"""
    if not raw:
        return "L1-mini"
    v = raw.strip().lower()
    if v in {"l1-mini", "mini", "l1_mini", "l1 mini"}:
        return "L1-mini"
    if v in {"medium", "mid", "l1-medium", "l1_medium"}:
        return "L1-medium"
    if v in {"pro", "l1-pro", "l1_pro"}:
        return "L1-pro"
    if v in {"ml1", "multi-layer", "multi_layer"}:
        return "ML1"
    return "L1-mini"

# Simular TIER_CONFIGS
TIER_CONFIGS = {
    "L1-mini": type('TierConfig', (), {'name': 'L1-mini', 'completion_model': 'l1-mini'})(),
    "L1-medium": type('TierConfig', (), {'name': 'L1-medium', 'completion_model': 'l1-medium'})(),
    "L1-pro": type('TierConfig', (), {'name': 'L1-pro', 'completion_model': 'l1-pro'})(),
}

def _select_tier(request_body=None):
    """Simulación de la función _select_tier"""
    # Prioridad: Request body model > Header > query param > default
    if request_body and "model" in request_body:
        raw = request_body["model"]
        print(f"Usando model del request body: {raw}")
    else:
        print("No hay model en request body, usando default")
        raw = None
    name = _normalize_tier_name(raw)
    print(f"Nombre normalizado: {name}")
    tier = TIER_CONFIGS.get(name, TIER_CONFIGS["L1-mini"])
    print(f"Tier seleccionado: {tier.name}")
    return tier

# Test cases
print("=== Test 1: Request body con model L1-mini ===")
request_body = {"model": "L1-mini", "messages": [{"role": "user", "content": "Hola"}]}
tier = _select_tier(request_body)
print(f"Resultado: {tier.name}")
print()

print("=== Test 2: Request body sin model ===")
request_body = {"messages": [{"role": "user", "content": "Hola"}]}
tier = _select_tier(request_body)
print(f"Resultado: {tier.name}")
print()

print("=== Test 3: Request body None ===")
tier = _select_tier(None)
print(f"Resultado: {tier.name}")
print()

print("=== Test 4: Request body con model diferente ===")
request_body = {"model": "L1-medium", "messages": [{"role": "user", "content": "Hola"}]}
tier = _select_tier(request_body)
print(f"Resultado: {tier.name}")
print()
