from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from pydantic import BaseModel, ValidationError, constr
from app import db
from app.models.user import User
from functools import wraps
import datetime

auth_bp = Blueprint('auth', __name__)

# Modelos Pydantic para validación
class RegisterRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=80)
    email: constr(strip_whitespace=True, min_length=5, max_length=120)
    password: constr(strip_whitespace=True, min_length=6, max_length=100)

class LoginRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=80)
    password: constr(strip_whitespace=True, min_length=1, max_length=100)

# Decorador para verificar API key
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key requerida'}), 401
        
        user = User.find_by_api_key(api_key)
        if not user:
            return jsonify({'error': 'API key inválida'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/auth/register', methods=['POST'])
def register():
    """Registra un nuevo usuario."""
    try:
        data = request.get_json()
        validated = RegisterRequest(**data)
    except (ValidationError, TypeError) as e:
        return jsonify({'error': 'Datos inválidos', 'details': str(e)}), 400
    
    # Verificar si el usuario ya existe
    if User.query.filter_by(username=validated.username).first():
        return jsonify({'error': 'El nombre de usuario ya existe'}), 409
    
    if User.query.filter_by(email=validated.email).first():
        return jsonify({'error': 'El email ya está registrado'}), 409
    
    # Crear nuevo usuario
    user = User(
        username=validated.username,
        email=validated.email
    )
    user.set_password(validated.password)
    user.generate_api_key()
    
    try:
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'Usuario registrado exitosamente',
            'user_id': user.id,
            'username': user.username,
            'api_key': user.api_key
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error al crear usuario', 'details': str(e)}), 500

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    """Inicia sesión y devuelve un token JWT."""
    try:
        data = request.get_json()
        validated = LoginRequest(**data)
    except (ValidationError, TypeError) as e:
        return jsonify({'error': 'Datos inválidos', 'details': str(e)}), 400
    
    user = User.query.filter_by(username=validated.username).first()
    if not user or not user.verify_password(validated.password):
        return jsonify({'error': 'Credenciales inválidas'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Usuario desactivado'}), 403
    
    # Actualizar último login
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()
    
    # Generar token JWT
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'Login exitoso',
        'access_token': access_token,
        'user_id': user.id,
        'username': user.username,
        'api_key': user.api_key
    }), 200

@auth_bp.route('/auth/api-key', methods=['POST'])
@jwt_required()
def generate_api_key():
    """Genera una nueva API key para el usuario autenticado."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    new_api_key = user.generate_api_key()
    db.session.commit()
    
    return jsonify({
        'message': 'Nueva API key generada',
        'api_key': new_api_key
    }), 200

@auth_bp.route('/auth/profile', methods=['GET'])
@require_api_key
def get_profile():
    """Obtiene el perfil del usuario usando API key."""
    user = request.current_user
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None
    }), 200

@auth_bp.route('/auth/profile', methods=['GET'])
@jwt_required()
def get_profile_jwt():
    """Obtiene el perfil del usuario usando JWT."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None
    }), 200 