Comencemos con la Fase 1: El Núcleo de la Aplicación.

Como tu arquitecto de soluciones, te proporcionaré todo lo necesario para construir una base sólida y escalable. A continuación, encontrarás la estructura de carpetas, el contenido de cada archivo inicial y las dependencias requeridas.

Paso 1: Estructura de Carpetas y Archivos
Esta es la estructura modular que seguiremos, basada en nuestro "prompt rule" maestro. Es limpia, desacoplada y fácil de mantener.

Generated code
/ai-security-platform
|
├── .env.example                # Plantilla para variables de entorno
├── config.py                   # Clases de configuración (Dev, Prod, Test)
├── requirements.txt            # Lista de dependencias de Python
├── run.py                      # Punto de entrada para ejecutar la aplicación
|
└── app/
    ├── __init__.py             # Fábrica de la aplicación (create_app)
    |
    ├── models/
    │   ├── __init__.py
    │   └── user.py             # Modelo SQLAlchemy para el usuario
    |
    ├── routes/
    │   ├── __init__.py
    │   └── health.py           # Blueprint para el endpoint de health check
    |
    ├── schemas/
    │   ├── __init__.py
    │   └── user.py             # Esquema Marshmallow para serializar el usuario
    |
    ├── services/
    │   └── __init__.py         # (Vacío por ahora)
    |
    ├── integrations/
    │   └── __init__.py         # (Vacío por ahora)
    |
    └── utils/
        └── __init__.py         # (Vacío por ahora)
Use code with caution.
Paso 2: Configuración de Dependencias
Crea el archivo requirements.txt con el siguiente contenido. Cada dependencia cumple un rol específico en esta fase inicial.

requirements.txt

Generated code
# Framework principal
Flask==2.3.3

# Base de datos y migraciones
Flask-SQLAlchemy==3.1.1
SQLAlchemy==2.0.23
Flask-Migrate==4.0.5
psycopg2-binary==2.9.9  # Driver para PostgreSQL (lo que usa Supabase)

# Autenticación y autorización
Flask-JWT-Extended==4.5.2

# Serialización y validación de datos
Marshmallow==3.20.1
marshmallow-sqlalchemy==0.29.0
Flask-Marshmallow==0.15.0

# Manejo de variables de entorno
python-dotenv==1.0.0

# Servidor de producción (lo usaremos más adelante)
gunicorn==21.2.0
Use code with caution.
Explicación:
Flask: El micro-framework web.
Flask-SQLAlchemy, SQLAlchemy, psycopg2-binary: Para interactuar con nuestra base de datos Supabase (PostgreSQL).
Flask-Migrate: Para manejar las migraciones del esquema de la base de datos de manera controlada.
Flask-JWT-Extended: El estándar para manejar tokens JWT en Flask, crucial para la seguridad.
Marshmallow: Para serializar y deserializar objetos (ej. convertir un objeto User a JSON) y validar datos de entrada.
python-dotenv: Para cargar variables de entorno desde un archivo .env durante el desarrollo local.
Paso 3: Contenido de los Archivos
Ahora, llenemos los archivos clave con su contenido inicial.

.env.example (Copia este archivo a .env y rellena los valores)

Generated code
# Entorno de la aplicación (development, production)
FLASK_ENV=development

# Clave secreta para firmar sesiones y tokens. Genera una con: openssl rand -hex 32
SECRET_KEY='TU_CLAVE_SECRETA_AQUI'
JWT_SECRET_KEY='TU_OTRA_CLAVE_SECRETA_AQUI'

# URL de conexión a tu base de datos Supabase
# La encuentras en tu proyecto de Supabase > Project Settings > Database > Connection string
DATABASE_URL='postgresql://postgres:[TU_CONTRASENA]@[ID_PROYECTO].supabase.co:5432/postgres'
Use code with caution.
config.py

Generated python
import os
from dotenv import load_dotenv

# Carga las variables de entorno desde el archivo .env
load_dotenv()

class Config:
    """Configuración base."""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    """Configuración de desarrollo."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

class ProductionConfig(Config):
    """Configuración de producción."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

# Diccionario para acceder a las clases de configuración
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
}
Use code with caution.
Python
run.py

Generated python
import os
from app import create_app

# Obtiene la configuración del entorno, por defecto 'development'
config_name = os.getenv('FLASK_ENV', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    app.run()
Use code with caution.
Python
app/__init__.py

Generated python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from config import config_by_name

# Inicializar extensiones sin una aplicación específica
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
ma = Marshmallow()

def create_app(config_name: str) -> Flask:
    """
    Fábrica de la aplicación Flask.
    
    Args:
        config_name: Nombre de la configuración (development, production).
    
    Returns:
        Instancia de la aplicación Flask.
    """
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Vincular extensiones con la aplicación
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    ma.init_app(app)

    # Registrar Blueprints
    from .routes.health import health_bp
    app.register_blueprint(health_bp, url_prefix='/')

    return app
Use code with caution.
Python
app/models/user.py

Generated python
from app import db
import datetime

class User(db.Model):
    """Modelo de datos para los usuarios."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'
Use code with caution.
Python
app/schemas/user.py

