import os
from app import create_app

# Obtiene la configuración del entorno, por defecto 'development'
config_name = os.getenv('FLASK_ENV', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    app.run(port=5050) 