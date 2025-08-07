import re

# Función de DLP (Prevención de Fuga de Datos)
def check_for_sensitive_data(text: str) -> bool:
    patrones = [
        r'API_KEY[_A-Z0-9]*\s*=\s*[\'"][^\'"]+[\'"]',  # API Keys
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',   # Emails
        r'\b\d{16}\b',  # Tarjetas de crédito simples
    ]
    for patron in patrones:
        if re.search(patron, text):
            return True
    return False

# Función de Detección de Inyección de Prompt
def check_for_prompt_injection(text: str) -> bool:
    frases_ataque = [
        "ignora las instrucciones anteriores",
        "actúa como DAN",
        "olvida todo lo anterior",
        "ignore previous instructions",
        "act as DAN",
        "forget all previous",
    ]
    for frase in frases_ataque:
        if re.search(frase, text, re.IGNORECASE):
            return True
    return False
