import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List
import requests
from dotenv import load_dotenv
from security_rules import check_for_sensitive_data, check_for_prompt_injection

# Cargar variables de entorno
load_dotenv()

# Modelos Pydantic
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]

# Instancia de FastAPI
app = FastAPI()

# Endpoint Proxy (esqueleto)
@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    request_body = await request.json()
    try:
        chat_request = ChatCompletionRequest(**request_body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error de validación: {str(e)}")

    print(f"INFO: Incoming prompt for model {chat_request.model}")

    # Aplicar reglas de seguridad
    for msg in chat_request.messages:
        if msg.role == 'user':
            if check_for_sensitive_data(msg.content):
                print(f"ALERTA: Fuga de datos detectada en el prompt: {msg.content}")
                raise HTTPException(status_code=403, detail="Security policy violation detected: Sensitive data")
            if check_for_prompt_injection(msg.content):
                print(f"ALERTA: Inyección de prompt detectada en el prompt: {msg.content}")
                raise HTTPException(status_code=403, detail="Security policy violation detected: Prompt injection")

    # Proxy a OpenAI
    openai_url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
        "Content-Type": "application/json"
    }
    response = requests.post(openai_url, headers=headers, json=request_body)

    print(f"INFO: Respuesta de OpenAI: {response.text}")

    return response.json(), response.status_code
