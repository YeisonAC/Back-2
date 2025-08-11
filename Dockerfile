# syntax=docker/dockerfile:1

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Dependencias básicas para construir ruedas si hiciera falta
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias
COPY Backend/ai-security-gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copiar el código del gateway
COPY Backend/ai-security-gateway/ /app/

# Puerto por defecto
EXPOSE 8080

# Ejecutar uvicorn respetando $PORT si la plataforma lo define
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"] 