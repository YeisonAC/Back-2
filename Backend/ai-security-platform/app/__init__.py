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
    from .routes.huggingface import huggingface_bp
    app.register_blueprint(huggingface_bp, url_prefix='/')
    from .routes.openai_anthropic import llm_bp
    app.register_blueprint(llm_bp, url_prefix='/')
    from .routes.kubernetes import kube_bp
    app.register_blueprint(kube_bp, url_prefix='/')
    from .routes.github import github_bp
    app.register_blueprint(github_bp, url_prefix='/')

    return app 