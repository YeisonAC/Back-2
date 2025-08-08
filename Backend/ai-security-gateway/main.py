import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import requests
from dotenv import load_dotenv

# Integración del Firewall (import compatible según modo de ejecución)
try:
    from .ai_firewall import AIFirewall
except ImportError:  # ejecución directa dentro del directorio
    from ai_firewall import AIFirewall

# Cargar variables de entorno
load_dotenv()

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

    # Firewall avanzado: inspeccionar todos los mensajes del usuario
    for msg in chat_request.messages:
        if msg.role == 'user':
            insp = firewall.inspect_request(user_id=user_id, prompt=msg.content, system_purpose=system_purpose)
            if insp.decision == "BLOCK":
                print(f"ALERTA: Firewall bloqueó la solicitud. ip={client_ip} score={insp.threat_score} flags={insp.flags}")
                return JSONResponse(status_code=403, content={
                    "error": "Security policy violation detected by firewall",
                    "threat_score": insp.threat_score,
                    "flags": insp.flags,
                })

    # Preparar la petición para Groq
    groq_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",
        "Content-Type": "application/json",
    }

    # Reenviar y encadenar X-Forwarded-For / X-Real-IP hacia Groq
    incoming_xff = request.headers.get("X-Forwarded-For")
    if incoming_xff:
        if client_ip and client_ip not in incoming_xff:
            headers["X-Forwarded-For"] = f"{incoming_xff}, {client_ip}"
        else:
            headers["X-Forwarded-For"] = incoming_xff
    else:
        headers["X-Forwarded-For"] = client_ip
    headers["X-Real-IP"] = client_ip
    
    # Modificar el modelo en la petición para usar el modelo de Groq
    groq_request_body = request_body.copy()
    groq_request_body["model"] = "openai/gpt-oss-20b"
    
    try:
        response = requests.post(groq_url, headers=headers, json=groq_request_body, timeout=60)
        
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)