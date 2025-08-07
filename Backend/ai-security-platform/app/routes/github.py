from flask import Blueprint, request, jsonify, abort
from github import Github
import os
import hmac
import hashlib
from pydantic import BaseModel, ValidationError, constr

github_bp = Blueprint('github', __name__)

# Endpoint para listar repos públicos de un usuario
@github_bp.route('/github/user-repos/<username>', methods=['GET'])
def user_repos(username):
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        return jsonify({'error': 'Token de GitHub no configurado'}), 500
    g = Github(token)
    try:
        user = g.get_user(username)
        repos = [{'name': repo.name, 'url': repo.html_url} for repo in user.get_repos(type='public')]
        return jsonify({'repos': repos})
    except Exception as e:
        return jsonify({'error': 'Error al obtener repos', 'details': str(e)}), 500

# Modelo Pydantic para validar el payload del webhook
class WebhookPayload(BaseModel):
    action: constr(strip_whitespace=True, min_length=1, max_length=64)
    repository: dict

# Endpoint seguro para recibir webhooks
@github_bp.route('/github/secure-webhook', methods=['POST'])
def secure_webhook():
    secret = os.getenv('GITHUB_WEBHOOK_SECRET')
    if not secret:
        return jsonify({'error': 'Secreto de webhook no configurado'}), 500
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        abort(400, 'Falta la firma del webhook')
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        abort(400, 'Algoritmo de firma no soportado')
    mac = hmac.new(secret.encode(), msg=request.data, digestmod=hashlib.sha256)
    if not hmac.compare_digest(mac.hexdigest(), signature):
        abort(403, 'Firma inválida')
    try:
        data = request.get_json()
        validated = WebhookPayload(**data)
    except (ValidationError, TypeError) as e:
        return jsonify({'error': 'Payload inválido', 'details': str(e)}), 400
    # Procesamiento seguro del payload
    return jsonify({'status': 'ok', 'action': validated.action, 'repo': validated.repository.get('full_name', '')}) 