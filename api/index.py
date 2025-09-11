import sys
import os
import logging
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    # Asegurar que el paquete del gateway esté en PYTHONPATH
    REPO_ROOT = Path(__file__).resolve().parents[1]
    GATEWAY_DIR = REPO_ROOT / "Backend" / "ai-security-gateway"
    
    # Agregar el directorio del gateway al path
    sys.path.insert(0, str(GATEWAY_DIR))
    logger.info(f"Added to sys.path: {GATEWAY_DIR}")
    
    # Verificar que el directorio existe
    if not GATEWAY_DIR.exists():
        raise ImportError(f"Directory not found: {GATEWAY_DIR}")
    
    # Importar la app FastAPI específicamente desde main.py
    logger.info("Attempting to import app from main.py...")
    import importlib.util
    spec = importlib.util.spec_from_file_location("main_module", str(GATEWAY_DIR / "main.py"))
    main_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main_module)
    app = main_module.app
    logger.info("Successfully imported app from main.py")
    
    # Verificar que la app se importó correctamente
    if app is None:
        raise ImportError("Failed to import FastAPI app from main.py")
    
    # Verificar variables de entorno requeridas
    required_env_vars = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        logger.warning(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    logger.info("Vercel handler initialized successfully")
    
except Exception as e:
    logger.error(f"Error initializing Vercel handler: {str(e)}", exc_info=True)
    raise

# Handler para Vercel (vercel-python detecta "app")
# FastAPI maneja las rutas: /, /health, /v1/chat/completions