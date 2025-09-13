# Firewall Rules API Documentation

## Overview

This API allows users to create and manage custom firewall rules for their API keys. Users can define rules to block or allow requests based on various criteria such as IP addresses, countries, patterns, time ranges, and more.

## Base URL

```
https://your-api-domain.com/v1/firewall
```

## Authentication

All endpoints require authentication using an API key in the `Authorization` header:

```
Authorization: Bearer your-api-key
```

## Endpoints

### 1. Get Available Rule Types

**GET** `/rules/types`

Get information about all available firewall rule types and their configuration options.

**Response:**
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
    },
    {
      "type": "ip_blacklist",
      "name": "IP Blacklist",
      "description": "Block requests from specific IP addresses",
      "conditions_schema": {
        "ips": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of blocked IP addresses"
        }
      }
    },
    {
      "type": "country_block",
      "name": "Country Block",
      "description": "Block requests from specific countries",
      "conditions_schema": {
        "countries": {
          "type": "array",
          "items": {"type": "string", "maxLength": 2},
          "description": "List of 2-letter country codes to block"
        }
      }
    },
    {
      "type": "rate_limit",
      "name": "Rate Limit",
      "description": "Limit number of requests per time period",
      "conditions_schema": {
        "requests_per_minute": {
          "type": "integer",
          "minimum": 1,
          "description": "Maximum requests per minute"
        }
      }
    },
    {
      "type": "pattern_block",
      "name": "Pattern Block",
      "description": "Block requests containing specific patterns",
      "conditions_schema": {
        "patterns": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of patterns to block in request content"
        }
      }
    },
    {
      "type": "time_block",
      "name": "Time Block",
      "description": "Block requests during specific time ranges",
      "conditions_schema": {
        "start_time": {
          "type": "string",
          "pattern": "^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
          "description": "Start time in HH:MM format"
        },
        "end_time": {
          "type": "string",
          "pattern": "^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
          "description": "End time in HH:MM format"
        }
      }
    },
    {
      "type": "user_agent_block",
      "name": "User Agent Block",
      "description": "Block requests from specific user agents",
      "conditions_schema": {
        "user_agents": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of user agent patterns to block"
        }
      }
    },
    {
      "type": "custom_ai_rule",
      "name": "Custom AI Rule",
      "description": "Custom rules using AI pattern detection",
      "conditions_schema": {
        "prompt_patterns": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of prompt patterns to detect"
        }
      }
    }
  ],
  "actions": ["allow", "block", "log_only"],
  "statuses": ["active", "inactive", "pending", "expired"]
}
```

### 2. Create Firewall Rule

**POST** `/rules`

Create a new firewall rule for your API key.

**Request Body:**
```json
{
  "name": "Block Malicious IPs",
  "description": "Block requests from known malicious IP addresses",
  "rule_type": "ip_blacklist",
  "action": "block",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50"]
  },
  "priority": 10,
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "user_id": "user-id",
  "api_key_id": "api-key-id",
  "name": "Block Malicious IPs",
  "description": "Block requests from known malicious IP addresses",
  "rule_type": "ip_blacklist",
  "action": "block",
  "status": "active",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50"]
  },
  "priority": 10,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### 3. Get Firewall Rules

**GET** `/rules?page=1&page_size=20`

Get all firewall rules for your API key with pagination.

**Query Parameters:**
- `page` (optional, default: 1): Page number
- `page_size` (optional, default: 20): Number of items per page

**Response:**
```json
{
  "rules": [
    {
      "id": "uuid-string",
      "user_id": "user-id",
      "api_key_id": "api-key-id",
      "name": "Block Malicious IPs",
      "description": "Block requests from known malicious IP addresses",
      "rule_type": "ip_blacklist",
      "action": "block",
      "status": "active",
      "conditions": {
        "ips": ["192.168.1.100", "10.0.0.50"]
      },
      "priority": 10,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-12-31T23:59:59Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

### 4. Get Specific Rule

**GET** `/rules/{rule_id}`

Get a specific firewall rule by ID.

**Response:**
```json
{
  "id": "uuid-string",
  "user_id": "user-id",
  "api_key_id": "api-key-id",
  "name": "Block Malicious IPs",
  "description": "Block requests from known malicious IP addresses",
  "rule_type": "ip_blacklist",
  "action": "block",
  "status": "active",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50"]
  },
  "priority": 10,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### 5. Update Firewall Rule

**PUT** `/rules/{rule_id}`

Update an existing firewall rule.

**Request Body:**
```json
{
  "name": "Updated Rule Name",
  "description": "Updated description",
  "action": "block",
  "status": "active",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50", "203.0.113.1"]
  },
  "priority": 15
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "user_id": "user-id",
  "api_key_id": "api-key-id",
  "name": "Updated Rule Name",
  "description": "Updated description",
  "rule_type": "ip_blacklist",
  "action": "block",
  "status": "active",
  "conditions": {
    "ips": ["192.168.1.100", "10.0.0.50", "203.0.113.1"]
  },
  "priority": 15,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T11:45:00Z",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### 6. Delete Firewall Rule

**DELETE** `/rules/{rule_id}`

Delete a firewall rule.

**Response:**
```json
{
  "message": "Rule deleted successfully"
}
```

### 7. Get Firewall Rules Statistics

**GET** `/rules/stats`

Get statistics for your firewall rules.

**Response:**
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

## Rule Examples

### IP Whitelist Rule

```json
{
  "name": "Allow Office IPs",
  "description": "Only allow requests from office IP addresses",
  "rule_type": "ip_whitelist",
  "action": "allow",
  "conditions": {
    "ips": ["192.168.1.0/24", "10.0.0.100"]
  }
}
```

### Country Block Rule

```json
{
  "name": "Block High-Risk Countries",
  "description": "Block requests from specific high-risk countries",
  "rule_type": "country_block",
  "action": "block",
  "conditions": {
    "countries": ["CN", "RU", "KP"]
  }
}
```

### Pattern Block Rule

```json
{
  "name": "Block SQL Injection",
  "description": "Block requests containing SQL injection patterns",
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

### Time Block Rule

```json
{
  "name": "Business Hours Only",
  "description": "Only allow requests during business hours",
  "rule_type": "time_block",
  "action": "block",
  "conditions": {
    "start_time": "18:00",
    "end_time": "08:00"
  }
}
```

### Custom AI Rule

```json
{
  "name": "Block Jailbreak Attempts",
  "description": "Block attempts to jailbreak the AI",
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

## Error Responses

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
  "detail": "Failed to create rule"
}
```

## Integration Guide

### Frontend Implementation

Here's a basic React component example for managing firewall rules:

```jsx
import React, { useState, useEffect } from 'react';

const FirewallRulesManager = ({ apiKey }) => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch rules
  const fetchRules = async () => {
    setLoading(true);
    try {
      const response = await fetch('/v1/firewall/rules', {
        headers: {
          'Authorization': `Bearer ${apiKey}`
        }
      });
      const data = await response.json();
      setRules(data.rules);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Create rule
  const createRule = async (ruleData) => {
    try {
      const response = await fetch('/v1/firewall/rules', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(ruleData)
      });
      const data = await response.json();
      await fetchRules(); // Refresh rules list
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  // Update rule
  const updateRule = async (ruleId, ruleData) => {
    try {
      const response = await fetch(`/v1/firewall/rules/${ruleId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(ruleData)
      });
      const data = await response.json();
      await fetchRules(); // Refresh rules list
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  // Delete rule
  const deleteRule = async (ruleId) => {
    try {
      const response = await fetch(`/v1/firewall/rules/${ruleId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${apiKey}`
        }
      });
      await fetchRules(); // Refresh rules list
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  useEffect(() => {
    fetchRules();
  }, [apiKey]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <h2>Firewall Rules</h2>
      {/* Render rules and management UI */}
    </div>
  );
};

export default FirewallRulesManager;
```

### Best Practices

1. **Rule Priority**: Higher priority numbers are evaluated first. Use this to ensure critical rules are processed first.

2. **Rule Testing**: Test new rules with `action: "log_only"` before setting them to `block` to avoid accidentally blocking legitimate traffic.

3. **Expiration Dates**: Set expiration dates for temporary rules to ensure they don't remain active indefinitely.

4. **Monitoring**: Regularly check the `/rules/stats` endpoint to monitor rule effectiveness.

5. **Error Handling**: Implement proper error handling in your frontend to provide feedback to users when rule operations fail.

## Rate Limits

The firewall rules API has the following rate limits:
- 100 requests per minute for rule creation
- 1000 requests per minute for rule reading
- 50 requests per minute for rule updates/deletion

## Support

For support or questions about the firewall rules API, please contact our support team or refer to the main API documentation.
