from flask import Blueprint, request, jsonify
from pydantic import BaseModel, ValidationError, constr
from markupsafe import escape
from transformers import pipeline
import os

huggingface_bp = Blueprint('huggingface', __name__)

# Modelo Pydantic para validar la entrada
class InferenceInput(BaseModel):
    text: constr(strip_whitespace=True, min_length=1, max_length=512)

# Cargar pipeline seguro (solo modelos confiables)
MODEL_NAME = os.getenv('HUGGINGFACE_MODEL', 'distilbert-base-uncased-finetuned-sst-2-english')
hf_pipeline = pipeline('sentiment-analysis', model=MODEL_NAME)

@huggingface_bp.route('/huggingface/secure-inference', methods=['POST'])
def secure_inference():
    try:
        data = request.get_json()
        validated = InferenceInput(**data)
    except (ValidationError, TypeError) as e:
        return jsonify({'error': 'Entrada inválida', 'details': str(e)}), 400
    # Sanitizar entrada
    clean_text = escape(validated.text)
    # Inferencia segura
    result = hf_pipeline(clean_text)
    # Validar salida (ejemplo simple)
    if not isinstance(result, list) or 'label' not in result[0]:
        return jsonify({'error': 'Respuesta inesperada del modelo'}), 500
    return jsonify({'result': result}) 