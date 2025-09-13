¡Entendido! Si el proyecto ya existe y solo necesitamos crear los rules, entonces el context prompt debe enfocarse directamente en la definición, gestión e integración de esas reglas. Eliminaremos la parte de la estructura del proyecto y nos centraremos en los módulos relevantes para las reglas.

Aquí tienes una versión ajustada, centrada exclusivamente en la creación y gestión de las reglas:

code
Code

download

content_copy

expand_less
# Context Prompt para Editor de Código: Firewall de IA - Implementación de Reglas de Bloqueo

## Objetivo:
Implementar y/o actualizar el conjunto de reglas de un firewall de IA existente, diseñado para bloquear mensajes y conexiones maliciosas. Las reglas deben basarse en IP, país de origen, heurísticas de IA y otras consideraciones dinámicas. El enfoque es puramente en la **creación y gestión de las reglas** dentro de la estructura de código existente.

---

## Módulos de Reglas Existentes (Asumidos):

Asumimos que ya existen módulos o archivos donde se gestionan los diferentes tipos de reglas. Si no existen, este prompt servirá como guía para crearlos.

*   `firewall/rules.py` (o similar): Archivo principal para definir y orquestar la evaluación de reglas.
*   `firewall/ip_blacklist.py` (o similar): Lógica específica para IPs.
*   `firewall/country_block.py` (o similar): Lógica específica para bloqueo por país.
*   `firewall/ai_heuristics.py` (o similar): Lógica para la detección de anomalías por IA.
*   `config.py` (o similar): Archivo de configuración global.
*   `logging.py` (o similar): Módulo de registro de eventos.

---

## Pasos de Implementación Detallados para las Reglas:

### Paso 1: Configuración de Reglas (Modificar `config.py`)
1.  **Asegurar o Añadir Variables de Configuración Clave:**
    *   `WHITELISTED_IPS`: Lista de IPs permitidas que siempre deben pasar.
    *   `BLOCKED_IPS_INITIAL`: Lista inicial (puede ser estática) de IPs a bloquear.
    *   `BLOCKED_COUNTRIES_INITIAL`: Lista inicial de códigos de país a bloquear (ej. `['CN', 'RU', 'KP']`).
    *   `ANOMALY_THRESHOLD`: Umbral para que la IA clasifique una solicitud como maliciosa.
    *   `GEOIP_DB_PATH`: Ruta a la base de datos GeoIP (ej. `GeoLite2-Country.mmdb`) para resolución de países.
    *   `RATE_LIMIT_THRESHOLD`: Número máximo de solicitudes por IP en un `RATE_LIMIT_WINDOW_SECONDS`.
    *   `RATE_LIMIT_WINDOW_SECONDS`: Ventana de tiempo para el límite de tasa.
    *   `USER_AGENT_BLACKLIST_PATTERNS`: Patrones Regex para User-Agents maliciosos conocidos.
    *   `SUSPICIOUS_URL_PATTERNS`: Patrones Regex para URLs que indican intentos de ataque (ej. `../`, `%20`).

### Paso 2: Actualización del Gestor de IPs (Modificar `firewall/ip_blacklist.py`)
1.  **Refinar `IPBlacklistManager`:**
    *   Asegurar que `add_ip(ip_address)` y `remove_ip(ip_address)` actualicen una estructura de datos eficiente en memoria (ej. `set`) y persistan los cambios en un archivo (`ip_blacklist.txt`).
    *   Añadir una función `get_dynamically_blocked_ips()` para recuperar IPs bloqueadas temporalmente por otros mecanismos (ej. límite de tasa o IA).
    *   Implementar una lógica para envejecer o expirar IPs bloqueadas temporalmente.

### Paso 3: Actualización del Gestor de Países (Modificar `firewall/country_block.py`)
1.  **Refinar `CountryBlockManager`:**
    *   Verificar que `get_country_from_ip(ip_address)` utilice correctamente la base de datos GeoIP (ej. `maxminddb`).
    *   Asegurar que `is_country_blocked(ip_address)` realice una verificación rápida contra la lista de países bloqueados.

### Paso 4: Definición y Orquestación de Reglas (Modificar `firewall/rules.py`)

Este es el módulo central para las reglas. Se asume que existe una función principal (ej. `process_request(request_data)`) o una clase `FirewallRulesEngine` que orquesta la evaluación.

1.  **Priorización y Flujo de Evaluación de Reglas:**
    Asegurar que la función `process_request(request_data)` (o método equivalente) siga una clara prioridad:

    *   **Regla 1: Whitelist (Permitir siempre):**
        *   Si `source_ip` está en `config.WHITELISTED_IPS`, `log_event("WHITELISTED", source_ip, "IP en lista blanca.")` y `return "ALLOW"`.

    *   **Regla 2: Bloqueo por IP Estática/Persistente:**
        *   Si `ip_manager.is_blocked(source_ip)` (incluyendo IPs del archivo `ip_blacklist.txt`), `log_event("BLOCKED_IP", source_ip, "IP en lista negra.")` y `return "DENY"`.

    *   **Regla 3: Bloqueo por País:**
        *   Si `country_manager.is_country_blocked(source_ip)`, `log_event("BLOCKED_COUNTRY", source_ip, f"País {country_code} bloqueado.")` y `return "DENY"`.

    *   **Regla 4: Límite de Tasa (Rate Limiting):**
        *   Implementar un contador de solicitudes por `source_ip` dentro de `config.RATE_LIMIT_WINDOW_SECONDS`.
        *   Si el contador excede `config.RATE_LIMIT_THRESHOLD`, añadir `source_ip` a una lista negra *temporal* y `log_event("BLOCKED_RATE_LIMIT", source_ip, "Exceso de solicitudes.")` y `return "DENY"`.
        *   Considerar el uso de una caché (ej. Redis, LRU cache) para almacenar los contadores.

    *   **Regla 5: Detección de Patrones de User-Agent Maliciosos:**
        *   Extraer `User-Agent` de `request_data`.
        *   Iterar sobre `config.USER_AGENT_BLACKLIST_PATTERNS`. Si hay una coincidencia, `log_event("BLOCKED_USER_AGENT", source_ip, f"User-Agent sospechoso: {user_agent}.")` y `return "DENY"`.

    *   **Regla 6: Detección de Patrones de URL Sospechosos:**
        *   Extraer la URL o path de `request_data`.
        *   Iterar sobre `config.SUSPICIOUS_URL_PATTERNS`. Si hay una coincidencia (ej. `../`, `eval(`), `log_event("BLOCKED_URL_PATTERN", source_ip, f"URL sospechosa: {request_url}.")` y `return "DENY"`.

    *   **Regla 7: Heurísticas de IA:**
        *   Llamar a `ai_heuristics_manager.analyze_request(request_data)`.
        *   Si la IA clasifica la solicitud como maliciosa (`True` o `anomaly_score > config.ANOMALY_THRESHOLD`), `log_event("BLOCKED_AI_HEURISTICS", source_ip, "Detectado por IA como malicioso.")` y `return "DENY"`.
        *   Considerar que la IA pueda, además de bloquear, añadir la IP a la lista negra *dinámica/temporal* si su confianza es alta.

    *   **Regla Final: Permitir por Defecto:**
        *   Si ninguna de las reglas anteriores bloqueó la solicitud, `log_event("ALLOWED", source_ip, "Solicitud permitida.")` y `return "ALLOW"`.

2.  **Funciones de Gestión de Reglas Dinámicas:**
    *   Asegurar o crear funciones como `block_ip_temporarily(ip_address, duration)` y `unblock_ip(ip_address)` dentro de `rules.py` o en un módulo auxiliar para gestionar los bloqueos temporales impuestos por el límite de tasa o la IA.

### Paso 5: Integración y Mejora de Heurísticas de IA (Modificar `firewall/ai_heuristics.py`)
1.  **Asegurar que `AIHeuristicsManager` sea flexible:**
    *   `extract_features(request_data)`: Revisar y expandir las características extraídas. Considerar:
        *   Longitud del cuerpo del mensaje.
        *   Frecuencia de caracteres especiales.
        *   Presencia de palabras clave de ataque (ej. `SELECT`, `UNION`, `<script>`).
        *   Entropía del contenido.
        *   Validez de cabeceras HTTP.
    *   La salida de `analyze_request` debe ser clara (booleano o puntaje de confianza) para la `FirewallRulesEngine`.
    *   Si es necesario, añadir un mecanismo para cargar diferentes modelos de IA o actualizar el modelo en caliente si el proyecto lo permite.

### Paso 6: Logging y Alertas (Modificar `logging.py`)
1.  **Detalle de los Registros:**
    *   Asegurar que `log_event` capture todos los detalles necesarios para cada tipo de bloqueo (`event_type`, `source_ip`, `details`, `timestamp`, `rule_triggered`).
    *   La función `alert_admin` debe activarse para eventos de bloqueo de alta confianza o ataques persistentes.

---

## Consideraciones Adicionales para un Proyecto Existente:

*   **Impacto en Rendimiento:** Al añadir nuevas reglas, especialmente las de IA, monitorear el impacto en la latencia del procesamiento de solicitudes.
*   **Manejo de Errores:** Asegurarse de que las fallas en la evaluación de reglas (ej. GeoIP no disponible) no detengan el firewall, sino que se registren y la solicitud se maneje con una política de seguridad (ej. "permitir por defecto con advertencia" o "denegar por seguridad").
*   **Observabilidad:** Implementar métricas (ej. Prometeus, Grafana) para visualizar cuántas solicitudes son bloqueadas por cada tipo de regla.
*   **Testeo:** Escribir pruebas unitarias y de integración para cada nueva regla para asegurar que funcionan como se espera y no introducen falsos positivos/negativos.

---

Este prompt se enfoca en guiar al editor de código a través de la implementación o mejora de las reglas específicas, asumiendo que el marco general del firewall ya está establecido.
Aquí tienes una ilustración de un firewall que ya está en funcionamiento y al que se le están añadiendo nuevas reglas para mejorar su capacidad de defensa.
