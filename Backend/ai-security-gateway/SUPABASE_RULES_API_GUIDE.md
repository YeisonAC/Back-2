# Guía de API de Reglas de Firewall con Supabase

## 📋 Resumen

Todos los endpoints de reglas de firewall ahora están completamente integrados con Supabase y utilizan la tabla `firewall_rules` con las siguientes columnas:

- `id` (uuid) - Identificador único de la regla
- `user_id` (uuid) - ID del usuario propietario
- `api_key_id` (uuid) - ID de la API key asociada
- `name` (text) - Nombre de la regla
- `description` (text) - Descripción de la regla
- `rule_type` (text) - Tipo de regla
- `action` (text) - Acción a realizar
- `status` (text) - Estado de la regla
- `conditions` (jsonb) - Condiciones específicas de la regla
- `value` (jsonb) - Valor extraído de las condiciones
- `priority` (int4) - Prioridad de la regla
- `created_at` (timestamptz) - Fecha de creación
- `updated_at` (timestamptz) - Fecha de última actualización
- `expires_at` (timestamptz) - Fecha de expiración (opcional)

## 🔐 Autenticación

Todos los endpoints requieren autenticación con tu API key:

```bash
Authorization: Bearer tu-api-key
```

## 📡 Endpoints Disponibles

### 1. **Obtener Tipos de Reglas Disponibles**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules/types" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

**Respuesta:**
```json
{
  "rule_types": [
    {
      "type": "ip_whitelist",
      "name": "IP Whitelist",
      "description": "Allow requests only from specific IP addresses",
      "conditions_schema": {
        "ips": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of allowed IP addresses"
        }
      }
    }
    // ... más tipos de reglas
  ],
  "actions": ["allow", "block", "log_only"],
  "statuses": ["active", "inactive", "pending", "expired"]
}
```

### 2. **Crear una Nueva Regla**

```bash
curl -X POST "https://tu-dominio.com/v1/firewall/rules" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Bloquear IPs Maliciosas",
    "description": "Bloquear solicitudes de IPs maliciosas conocidas",
    "rule_type": "ip_blacklist",
    "action": "block",
    "conditions": {
      "ips": ["192.168.1.100", "10.0.0.50"]
    },
    "priority": 10,
    "expires_at": "2024-12-31T23:59:59Z"
  }'
```

### 3. **Obtener Todas las Reglas (con paginación)**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules?page=1&page_size=20&rule_type=ip_blacklist&status=active" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

**Parámetros de consulta:**
- `page` (opcional, default: 1): Número de página
- `page_size` (opcional, default: 20): Número de elementos por página
- `rule_type` (opcional): Filtrar por tipo de regla
- `status` (opcional): Filtrar por estado

### 4. **Obtener una Regla Específica**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules/uuid-de-la-regla" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

### 5. **Actualizar una Regla**

```bash
curl -X PUT "https://tu-dominio.com/v1/firewall/rules/uuid-de-la-regla" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Nombre Actualizado",
    "description": "Descripción actualizada",
    "action": "block",
    "status": "active",
    "conditions": {
      "ips": ["192.168.1.100", "10.0.0.50", "203.0.113.1"]
    },
    "priority": 15
  }'
```

### 6. **Eliminar una Regla**

```bash
curl -X DELETE "https://tu-dominio.com/v1/firewall/rules/uuid-de-la-regla" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

### 7. **Obtener Estadísticas de Reglas**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules/stats" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

**Respuesta:**
```json
{
  "total_rules": 5,
  "active_rules": 3,
  "inactive_rules": 1,
  "expired_rules": 1,
  "rule_type_distribution": {
    "ip_blacklist": 2,
    "country_block": 1,
    "pattern_block": 1,
    "time_block": 1
  },
  "action_distribution": {
    "block": 4,
    "allow": 1
  }
}
```

### 8. **Buscar Reglas**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules/search?q=malicious&rule_type=ip_blacklist" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

**Parámetros de consulta:**
- `q` (requerido): Término de búsqueda
- `rule_type` (opcional): Filtrar por tipo de regla

### 9. **Obtener Reglas por Tipo**

```bash
curl -X GET "https://tu-dominio.com/v1/firewall/rules/by-type/ip_blacklist" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json"
```

## 🎯 Tipos de Reglas Disponibles

### **IP Whitelist**
```json
{
  "name": "Permitir IPs de Oficina",
  "description": "Solo permitir solicitudes de IPs de oficina",
  "rule_type": "ip_whitelist",
  "action": "allow",
  "conditions": {
    "ips": ["192.168.1.0/24", "10.0.0.100"]
  }
}
```

### **IP Blacklist**
```json
{
  "name": "Bloquear IPs Maliciosas",
  "description": "Bloquear solicitudes de IPs maliciosas conocidas",
  "rule_type": "ip_blacklist",
  "action": "block",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50"]
  }
}
```

### **Country Block**
```json
{
  "name": "Bloquear Países de Alto Riesgo",
  "description": "Bloquear solicitudes de países específicos de alto riesgo",
  "rule_type": "country_block",
  "action": "block",
  "conditions": {
    "countries": ["CN", "RU", "KP"]
  }
}
```

### **Rate Limit**
```json
{
  "name": "Límite de Velocidad",
  "description": "Limitar solicitudes a 100 por minuto",
  "rule_type": "rate_limit",
  "action": "block",
  "conditions": {
    "requests_per_minute": 100
  }
}
```

### **Pattern Block**
```json
{
  "name": "Bloquear Inyección SQL",
  "description": "Bloquear solicitudes que contengan patrones de inyección SQL",
  "rule_type": "pattern_block",
  "action": "block",
  "conditions": {
    "patterns": [
      "UNION SELECT",
      "DROP TABLE",
      "OR 1=1",
      "'; DROP"
    ]
  }
}
```

### **Time Block**
```json
{
  "name": "Solo Horario Laboral",
  "description": "Solo permitir solicitudes durante horario laboral",
  "rule_type": "time_block",
  "action": "block",
  "conditions": {
    "start_time": "18:00",
    "end_time": "08:00"
  }
}
```

### **User Agent Block**
```json
{
  "name": "Bloquear Bots",
  "description": "Bloquear user agents de bots conocidos",
  "rule_type": "user_agent_block",
  "action": "block",
  "conditions": {
    "user_agents": [
      "BadBot/1.0",
      "SpamBot/2.0"
    ]
  }
}
```

### **Custom AI Rule**
```json
{
  "name": "Bloquear Intentos de Jailbreak",
  "description": "Bloquear intentos de jailbreak de la IA",
  "rule_type": "custom_ai_rule",
  "action": "block",
  "conditions": {
    "prompt_patterns": [
      "act as a dan",
      "do anything now",
      "jailbreak",
      "ignore previous instructions"
    ]
  }
}
```

## ⚠️ Códigos de Error

### 400 Bad Request
```json
{
  "detail": "Invalid rule type: invalid_type"
}
```

### 403 Forbidden
```json
{
  "detail": "Access denied"
}
```

### 404 Not Found
```json
{
  "detail": "Rule not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Failed to create firewall rule: [error details]"
}
```

## 🔧 Características Técnicas

### **Integración con Supabase**
- Todos los endpoints utilizan la tabla `firewall_rules` en Supabase
- Operaciones CRUD completas con validación de permisos
- Búsqueda y filtrado optimizados
- Paginación eficiente

### **Validación de Datos**
- Validación de tipos de regla
- Validación de acciones permitidas
- Validación de estados
- Validación de formato de fechas ISO

### **Seguridad**
- Verificación de propiedad de reglas
- Autenticación requerida en todos los endpoints
- Validación de permisos por API key

### **Rendimiento**
- Consultas optimizadas con índices
- Paginación para grandes conjuntos de datos
- Búsqueda eficiente por texto

## 📊 Límites de Velocidad

- **Creación de reglas**: 100 solicitudes por minuto
- **Lectura de reglas**: 1000 solicitudes por minuto
- **Actualización/Eliminación**: 50 solicitudes por minuto

## 🚀 Ejemplos de Uso Completo

### Crear y Gestionar Reglas de Firewall

```bash
# 1. Obtener tipos de reglas disponibles
curl -X GET "https://tu-dominio.com/v1/firewall/rules/types" \
  -H "Authorization: Bearer tu-api-key"

# 2. Crear una regla de bloqueo de IP
curl -X POST "https://tu-dominio.com/v1/firewall/rules" \
  -H "Authorization: Bearer tu-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Bloquear IPs Maliciosas",
    "description": "Bloquear IPs conocidas por actividad maliciosa",
    "rule_type": "ip_blacklist",
    "action": "block",
    "conditions": {
      "ips": ["192.168.1.100", "10.0.0.50"]
    },
    "priority": 10
  }'

# 3. Obtener todas las reglas
curl -X GET "https://tu-dominio.com/v1/firewall/rules" \
  -H "Authorization: Bearer tu-api-key"

# 4. Buscar reglas específicas
curl -X GET "https://tu-dominio.com/v1/firewall/rules/search?q=malicious" \
  -H "Authorization: Bearer tu-api-key"

# 5. Obtener estadísticas
curl -X GET "https://tu-dominio.com/v1/firewall/rules/stats" \
  -H "Authorization: Bearer tu-api-key"
```

## 📝 Notas Importantes

1. **Prioridades**: Los números más altos tienen mayor prioridad
2. **Fechas**: Usar formato ISO 8601 para fechas de expiración
3. **Estados**: Las reglas pueden estar en `active`, `inactive`, `pending`, o `expired`
4. **Acciones**: `allow`, `block`, o `log_only`
5. **Validación**: Todas las condiciones se validan según el tipo de regla
6. **Permisos**: Solo puedes gestionar reglas de tus propias API keys

¡Todos los endpoints están ahora completamente integrados con Supabase y listos para usar! 🎉
