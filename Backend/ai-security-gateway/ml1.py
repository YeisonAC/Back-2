import os
import json
from typing import List, Dict, Any
import requests

# Minimal DSPy usage for structuring a multi-layer program
try:
    import dspy  # type: ignore
except Exception:  # dspy is optional at runtime but required for ML1
    dspy = None  # allows module import without immediate error

HF_MODEL_ID = os.getenv("HF_MODEL_ID", "Qwen/Qwen2.5-Coder-7B-Instruct")
HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL_ID}"

HEADERS = {
    "Authorization": f"Bearer {HF_API_TOKEN}" if HF_API_TOKEN else "",
    "Content-Type": "application/json",
}


def _chat_to_task(messages: List[Dict[str, Any]]) -> str:
    """Convert OpenAI-style chat messages to a single coding task prompt.
    Keeps system instruction (if any), then summarizes user content.
    """
    system_parts: List[str] = []
    user_parts: List[str] = []
    for m in messages:
        role = (m.get("role") or "").lower()
        content = str(m.get("content", "")).strip()
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
        elif role == "user":
            user_parts.append(content)
        else:
            user_parts.append(f"[{role}] {content}")
    sys_block = ("\n\n".join(system_parts)).strip()
    usr_block = ("\n\n".join(user_parts)).strip()
    if sys_block:
        return f"System instructions:\n{sys_block}\n\nUser request:\n{usr_block}\n\nProvide helpful, safe, and high-quality code.".strip()
    return f"User request:\n{usr_block}\n\nProvide helpful, safe, and high-quality code.".strip()


def _generate_with_hf(prompt: str, max_new_tokens: int = 512, temperature: float = 0.2, top_p: float = 0.9) -> str:
    if not HF_API_TOKEN:
        raise RuntimeError("HF_API_TOKEN is required for ML1 remote inference")
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "return_full_text": False,
        },
        "options": {"use_cache": True},
    }
    resp = requests.post(HF_API_URL, headers=HEADERS, data=json.dumps(payload), timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"HF inference error {resp.status_code}: {resp.text}")
    data = resp.json()
    # HF Inference API returns a list of dicts with 'generated_text'
    if isinstance(data, list) and data:
        text = data[0].get("generated_text")
        if isinstance(text, str):
            return text.strip()
    # Fallback
    return str(data)


def _refine_output(raw: str) -> str:
    """Simple self-check/refine: ensure fenced code if code-like content appears."""
    text = raw.strip()
    needs_fence = ("def " in text or "class " in text or "function " in text or text.count("\n") > 6)
    if needs_fence and "```" not in text:
        return f"```\n{text}\n```"
    return text


def run_ml1_pipeline(request_body: Dict[str, Any]) -> Dict[str, Any]:
    """Runs the ML1 (Multi Layer) pipeline and returns an OpenAI-compatible response dict."""
    messages = request_body.get("messages") or []
    user_prompt = _chat_to_task(messages)

    # Layer 1: intent/goal shaping (if dspy available, we could add a Signature)
    shaped = user_prompt  # keep simple; can add DSPy modules later

    # Layer 2: code generation with Qwen3-Coder via HF Inference API
    try:
        generated = _generate_with_hf(shaped, max_new_tokens=min(int(request_body.get("max_tokens") or 512), 1024))
    except Exception as e:
        raise RuntimeError(f"ML1 generation failed: {e}")

    # Layer 3: self-check/refine
    final_text = _refine_output(generated)

    # OpenAI Chat Completions compatible shape
    return {
        "id": "ml1-gen-1",
        "object": "chat.completion",
        "created": int(os.getenv("REQUEST_TIME", "0") or 0),
        "model": HF_MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": final_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None},
    }
