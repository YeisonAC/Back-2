import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import requests
from dotenv import load_dotenv
import json

# Integración del Firewall (import compatible según modo de ejecución)
try:
    from .ai_firewall import AIFirewall
except ImportError:  # ejecución directa dentro del directorio
    from ai_firewall import AIFirewall

# Cargar variables de entorno
load_dotenv()

# Configuración de modelos (parametrizable por entorno)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
CLASSIFIER_MODEL = os.getenv("GROQ_CLASSIFIER_MODEL", "openai/gpt-oss-20b")
COMPLETION_MODEL = os.getenv("GROQ_COMPLETION_MODEL", "openai/gpt-oss-20b")
ENABLE_INTENT_LAYER = os.getenv("ENABLE_INTENT_LAYER", "true").lower() in {"1", "true", "yes"}

# Instancia global del firewall
firewall = AIFirewall()

# Modelos Pydantic
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: float = 0.7
    max_tokens: int | None = None
    top_p: float = 1.0
    stream: bool = False

# Instancia de FastAPI
app = FastAPI()

# Middleware para capturar IP del cliente y anexarla a la respuesta
@app.middleware("http")
async def add_client_ip(request: Request, call_next):
    xff = request.headers.get("X-Forwarded-For")
    xri = request.headers.get("X-Real-IP")
    if xff:
        client_ip = xff.split(",")[0].strip()
    elif xri:
        client_ip = xri.strip()
    else:
        client_ip = request.client.host if request.client else "unknown"

    request.state.client_ip = client_ip

    response = await call_next(request)
    # Exponer IP detectada en respuesta para trazabilidad
    try:
        response.headers["X-Client-IP"] = client_ip
    except Exception:
        pass
    return response

# Utilidad para llamadas al endpoint OpenAI-compatible de Groq
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

def _build_forwarded_ip_headers(request: Request, client_ip: str) -> dict:
    headers: dict = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    incoming_xff = request.headers.get("X-Forwarded-For")
    if incoming_xff:
        if client_ip and client_ip not in incoming_xff:
            headers["X-Forwarded-For"] = f"{incoming_xff}, {client_ip}"
        else:
            headers["X-Forwarded-For"] = incoming_xff
    else:
        headers["X-Forwarded-For"] = client_ip
    headers["X-Real-IP"] = client_ip
    return headers

# Prompt de sistema para clasificar intención y sentimiento, devolver JSON estricto
INTENT_SYSTEM_PROMPT = (
    "Eres un clasificador de intención y seguridad. Analiza el mensaje del usuario y responde SOLO en JSON, "
    "sin texto adicional, con el siguiente esquema: {\n"
    "  \"intent_label\": string en snake_case descriptivo (p.ej. 'benign_information', 'malicious_hacking', 'self_harm'),\n"
    "  \"is_malicious\": boolean,\n"
    "  \"sentiment\": one_of ['negative','neutral','positive'],\n"
    "  \"categories\": array de strings con etiquetas adicionales,\n"
    "  \"confidence\": number entre 0 y 1,\n"
    "  \"reason\": string breve explicando la decisión\n"
    "}. Si la petición busca daño, ilegalidad, autolesión, fraude, malware o violar políticas, marca is_malicious=true."
)


def classify_intent(request: Request, prompt_text: str, client_ip: str) -> dict | None:
    if not ENABLE_INTENT_LAYER:
        return None
    messages = [
        {"role": "system", "content": INTENT_SYSTEM_PROMPT},
        {"role": "user", "content": prompt_text},
    ]
    payload = {
        "model": CLASSIFIER_MODEL,
        "messages": messages,
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 256,
        "stream": False,
    }
    headers = _build_forwarded_ip_headers(request, client_ip)
    try:
        resp = requests.post(GROQ_CHAT_URL, headers=headers, json=payload, timeout=30)
        if resp.status_code != 200:
            print(f"ERROR: Intent classifier error: {resp.status_code} - {resp.text} ip={client_ip}")
            return None
        data = resp.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        # Asegurar parseo JSON robusto
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
        return json.loads(text)
    except Exception as e:
        print(f"ERROR: Exception in intent classification: {e} ip={client_ip}")
        return None

# Endpoint Proxy
@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    request_body = await request.json()
    
    try:
        chat_request = ChatCompletionRequest(**request_body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error de validación: {str(e)}")
    
    # Obtener IP del cliente desde el middleware o calcular de forma defensiva
    try:
        client_ip = getattr(request.state, "client_ip")
    except Exception:
        client_ip = None
    if not client_ip:
        xff = request.headers.get("X-Forwarded-For")
        xri = request.headers.get("X-Real-IP")
        if xff:
            client_ip = xff.split(",")[0].strip()
        elif xri:
            client_ip = xri.strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

    print(f"INFO: Incoming prompt for model {chat_request.model} ip={client_ip}")

    # Metadatos opcionales de seguridad
    user_id = request.headers.get("X-User-Id", "anonymous")
    system_purpose = request.headers.get("X-System-Purpose", "general")

    # Primera capa: clasificación de intención por LLM + firewall tradicional
    detected_intents: list[dict] = []
    for msg in chat_request.messages:
        if msg.role != 'user':
            continue
        # Clasificación por LLM (si está habilitada)
        intent = classify_intent(request, msg.content, client_ip)
        if intent:
            detected_intents.append(intent)
            print(f"INFO: Intent classifier -> {intent} ip={client_ip}")
            if intent.get("is_malicious") is True:
                return JSONResponse(status_code=403, content={
                    "error": "Blocked by intent classifier",
                    "intent": intent,
                })
        # Firewall heurístico
        insp = firewall.inspect_request(user_id=user_id, prompt=msg.content, system_purpose=system_purpose)
        if insp.decision == "BLOCK":
            print(f"ALERTA: Firewall bloqueó la solicitud. ip={client_ip} score={insp.threat_score} flags={insp.flags}")
            return JSONResponse(status_code=403, content={
                "error": "Security policy violation detected by firewall",
                "threat_score": insp.threat_score,
                "flags": insp.flags,
            })

    # Preparar la petición para Groq
    headers = _build_forwarded_ip_headers(request, client_ip)
    
    # Inyectar un mensaje de sistema con el label de intención (último) si existe
    forward_body = request_body.copy()
    forward_body["model"] = COMPLETION_MODEL
    try:
        # Copiar mensajes de forma segura
        orig_messages = forward_body.get("messages", [])
        if detected_intents:
            last_intent = detected_intents[-1]
            system_intent_note = {
                "role": "system",
                "content": (
                    "Security Note: intent_label="
                    + str(last_intent.get("intent_label", "unknown"))
                ),
            }
            # Prepend al inicio para no alterar el último turno del usuario
            forward_body["messages"] = [system_intent_note] + orig_messages
        else:
            forward_body["messages"] = orig_messages
    except Exception:
        # Fallback sin cambios en mensajes
        forward_body["messages"] = request_body.get("messages", [])

    try:
        response = requests.post(GROQ_CHAT_URL, headers=headers, json=forward_body, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            # Inspección y posible redacción de la respuesta del modelo
            try:
                content_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            except Exception:
                content_text = ""
            resp_insp = firewall.inspect_response(content_text)
            if resp_insp.flags:
                print(f"ALERTA: Firewall detectó problemas en la respuesta. ip={client_ip} flags={resp_insp.flags}")
                # Redactar contenido en la estructura OpenAI-like si aplica
                if isinstance(data.get("choices"), list) and data["choices"]:
                    if "message" in data["choices"][0]:
                        data["choices"][0]["message"]["content"] = resp_insp.redacted_text
                # Inyectar metadatos de firewall
                data["firewall"] = {"flags": resp_insp.flags, "redacted": resp_insp.redacted_text != content_text}
            else:
                data.setdefault("firewall", {"flags": [], "redacted": False})

            # Adjuntar metadata de intención detectada (si la hubo)
            if detected_intents:
                data["intent_layer"] = {
                    "enabled": True,
                    "last_intent": detected_intents[-1],
                }
            else:
                data.setdefault("intent_layer", {"enabled": ENABLE_INTENT_LAYER, "last_intent": None})

            return JSONResponse(content=data, status_code=response.status_code)
        else:
            print(f"ERROR: Error de Groq API: {response.status_code} - {response.text} ip={client_ip}")
            return JSONResponse(
                content={"error": f"Groq API error: {response.text}"}, 
                status_code=response.status_code
            )
            
    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout en la petición a Groq ip={client_ip}")
        raise HTTPException(status_code=504, detail="Request timeout to Groq API")
    
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Error en la petición a Groq: {str(e)} ip={client_ip}")
        raise HTTPException(status_code=502, detail=f"Error connecting to Groq API: {str(e)}")

# Endpoint de salud
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "groq-proxy"}

# Nuevo: endpoint raíz para evitar 404 en "/"
@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "groq-proxy",
        "endpoints": ["/health", "/v1/chat/completions"],
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)