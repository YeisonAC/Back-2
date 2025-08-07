from flask import Blueprint, jsonify
from kubernetes import client, config
import os

kube_bp = Blueprint('kube', __name__)

@kube_bp.route('/kubernetes/secure-list-pods', methods=['GET'])
def secure_list_pods():
    try:
        # Cargar configuración segura (dentro del clúster o local)
        if os.getenv('KUBERNETES_SERVICE_HOST'):
            config.load_incluster_config()
        else:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        namespace = os.getenv('KUBE_NAMESPACE', 'default')
        pods = v1.list_namespaced_pod(namespace=namespace)
        # Solo exponer información mínima
        result = [
            {'name': pod.metadata.name, 'phase': pod.status.phase}
            for pod in pods.items
        ]
        return jsonify({'pods': result})
    except Exception as e:
        return jsonify({'error': 'Error al listar pods', 'details': str(e)}), 500 