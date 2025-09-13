import sys
import os
import logging
from pathlib import Path

# Configurar logging con más detalle
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Variables globales
app = None
initialization_error = None

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
    required_env_vars = ["NEXT_PUBLIC_SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
        logger.error(error_msg)
        raise EnvironmentError(error_msg)
    
    # Verificar variables opcionales
    optional_vars = ["GROQ_API_KEY", "NEXT_PUBLIC_SUPABASE_ANON_KEY"]
    missing_optional = [var for var in optional_vars if not os.getenv(var)]
    if missing_optional:
        logger.warning(f"Missing optional environment variables: {', '.join(missing_optional)}")
    
    logger.info("Vercel handler initialized successfully")
    logger.info(f"Environment check - NEXT_PUBLIC_SUPABASE_URL: {'Set' if os.getenv('NEXT_PUBLIC_SUPABASE_URL') else 'Missing'}")
    logger.info(f"Environment check - SUPABASE_SERVICE_ROLE_KEY: {'Set' if os.getenv('SUPABASE_SERVICE_ROLE_KEY') else 'Missing'}")
    
except Exception as e:
    initialization_error = str(e)
    logger.error(f"Error initializing Vercel handler: {initialization_error}", exc_info=True)
    # No hacemos raise aquí para permitir que la función se despliegue pero falle graciosamente

# Handler para Vercel (vercel-python detecta "app")
# FastAPI maneja las rutas: /, /health, /v1/chat/completions

# Si hay un error de inicialización, crear una app mínima que devuelva el error
if initialization_error:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    
    app = FastAPI(title="EONS API - Error", description="API failed to initialize")
    
    @app.get("/")
    async def root():
        return JSONResponse(
            status_code=500,
            content={
                "error": "Initialization Error",
                "message": initialization_error,
                "details": "The API failed to initialize. Please check environment variables and logs."
            }
        )
    
    @app.get("/health")
    async def health():
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": initialization_error,
                "required_env_vars": ["NEXT_PUBLIC_SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]
            }
        )
    
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def catch_all(path: str):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Service Unavailable",
                "message": "API failed to initialize",
                "initialization_error": initialization_error
            }
        )