import sys
import os
from pathlib import Path

# Asegurar que el paquete del gateway esté en PYTHONPATH
REPO_ROOT = Path(__file__).resolve().parents[1]
GATEWAY_DIR = REPO_ROOT / "Backend" / "ai-security-gateway"
sys.path.insert(0, str(GATEWAY_DIR))

# Importar la app FastAPI existente
from main import app  # type: ignore

# Handler para Vercel (vercel-python detecta "app")
# No se requiere más código; FastAPI maneja las rutas: /, /health, /v1/chat/completions 