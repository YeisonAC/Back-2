1- Enable an API connection 

# Guía de Consumo del API (Gateway EONS)

Esta guía explica cómo cualquier usuario puede consumir el gateway de EONS paso a paso.

## 1) Requisitos

- EONS_API Key (proporcionada por tu administrador)
- Base URL del gateway: reemplaza `<BASE_URL>` (ej. `https://api.eons.ai`)
- Layer (nivel de capacidad) mediante header `X-Layer` o query `?layer=`:
  - Valores: `L1-mini` (default), `L1-medium`, `L1-pro`, `ML1`
- Importante: el campo `model` del body es opcional e ignorado. El backend impone el modelo según el Layer.

## 2) Endpoint

- Método: POST
- Ruta: `<BASE_URL>/v1/chat/completions`
- Headers:
  - `EONS_API: <TU_API_KEY>`
  - `Content-Type: application/json`
  - `X-Layer: L1-mini | L1-medium | L1-pro | ML1` (opcional; default `L1-mini`)

## 3) Cuerpo (request)

```json
{
  "messages": [{ "role": "user", "content": "Hola, ¿qué puedes hacer?" }],
  "temperature": 0.7,
  "top_p": 1.0,
  "max_tokens": 512,
  "stream": false
}


Examples
curl -X POST "<BASE_URL>/v1/chat/completions" \
  -H "EONS_API: <TU_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "X-Layer: L1-mini" \
  -d '{
    "messages":[{"role":"user","content":"Explícame JSON en 3 puntos."}],
    "max_tokens": 300
  }'



JavaScript
const res = await fetch("<BASE_URL>/v1/chat/completions?layer=L1-pro", {
  method: "POST",
  headers: {
    "EONS_API": "<TU_API_KEY>",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    messages: [{ role: "user", content: "Resume este texto:" }],
    temperature: 0.5
  })
});
const data = await res.json();
console.log(data.choices?.[0]?.message?.content);



Python(requests)
import requests

url = "<BASE_URL>/v1/chat/completions"
headers = {
    "EONS_API": "<TU_API_KEY>",
    "Content-Type": "application/json",
    "X-Layer": "ML1"
}
payload = {
    "messages": [{"role": "user", "content": "Genera 3 ideas de nombres de app."}],
    "max_tokens": 256
}
r = requests.post(url, headers=headers, json=payload, timeout=60)
print(r.json())
)

Answer (OPENAI-compatible)
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1720000000,
  "model": "enforced-by-layer",
  "choices": [
    { "index": 0, "message": { "role": "assistant", "content": "..." }, "finish_reason": "stop" }
  ],
  "usage": { "prompt_tokens": 42, "completion_tokens": 80, "total_tokens": 122 },
  "tier": "L1-mini",
  "intent_layer": { "enabled": true, "last_intent": { "...": "..." } },
  "firewall": { "flags": [], "redacted": false },
  "security_labels": ["..."],
  "primary_security_label": "..."
}