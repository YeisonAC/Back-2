"""
Supabase-based firewall rules management system
Maneja las operaciones CRUD para reglas de firewall en Supabase
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import os

from supabase_client import get_supabase

class RuleType(Enum):
    """Types of firewall rules users can create"""
    IP_WHITELIST = "ip_whitelist"
    IP_BLACKLIST = "ip_blacklist"
    COUNTRY_BLOCK = "country_block"
    RATE_LIMIT = "rate_limit"
    PATTERN_BLOCK = "pattern_block"
    TIME_BLOCK = "time_block"
    USER_AGENT_BLOCK = "user_agent_block"
    CUSTOM_AI_RULE = "custom_ai_rule"

class RuleAction(Enum):
    """Actions for firewall rules"""
    ALLOW = "allow"
    BLOCK = "block"
    LOG_ONLY = "log_only"

class RuleStatus(Enum):
    """Status of user rules"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    EXPIRED = "expired"

@dataclass
class FirewallRule:
    """Firewall rule data structure matching Supabase schema"""
    id: str
    user_id: str
    api_key_id: str
    name: str
    description: str
    rule_type: str
    action: str
    status: str
    conditions: Dict[str, Any]
    value: Dict[str, Any]
    priority: int
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert rule to dictionary for JSON serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FirewallRule':
        """Create rule from dictionary"""
        data = data.copy()
        
        # Parse datetime fields
        if data.get('created_at'):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        if data.get('updated_at'):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00'))
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        
        return cls(**data)

class SupabaseFirewallRulesManager:
    """Manages firewall rules in Supabase database"""
    
    def __init__(self):
        self.table_name = "firewall_rules"
        self.supabase = get_supabase()
        
    def _ensure_supabase(self):
        """Ensure Supabase client is available"""
        if not self.supabase:
            raise Exception("Supabase client not available")
    
    def create_rule(self, rule_data: Dict[str, Any]) -> FirewallRule:
        """Create a new firewall rule in Supabase"""
        self._ensure_supabase()
        
        # Generate ID if not provided
        if 'id' not in rule_data or not rule_data['id']:
            rule_data['id'] = str(uuid.uuid4())
        
        # Set timestamps
        now = datetime.now(timezone.utc)
        rule_data['created_at'] = now.isoformat()
        rule_data['updated_at'] = now.isoformat()
        
        # Ensure conditions and value are JSON serializable
        if 'conditions' in rule_data:
            rule_data['conditions'] = json.dumps(rule_data['conditions']) if isinstance(rule_data['conditions'], dict) else rule_data['conditions']
        if 'value' in rule_data:
            rule_data['value'] = json.dumps(rule_data['value']) if isinstance(rule_data['value'], dict) else rule_data['value']
        
        try:
            result = self.supabase.table(self.table_name).insert(rule_data).execute()
            
            if result.data and len(result.data) > 0:
                return FirewallRule.from_dict(result.data[0])
            else:
                raise Exception("Failed to create rule - no data returned")
                
        except Exception as e:
            print(f"[ERROR] Failed to create firewall rule: {e}")
            raise Exception(f"Failed to create firewall rule: {str(e)}")
    
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Get a specific rule by ID"""
        self._ensure_supabase()
        
        try:
            result = self.supabase.table(self.table_name).select("*").eq("id", rule_id).execute()
            
            if result.data and len(result.data) > 0:
                return FirewallRule.from_dict(result.data[0])
            return None
            
        except Exception as e:
            print(f"[ERROR] Failed to get firewall rule {rule_id}: {e}")
            return None
    
    def get_rules(self, user_id: str, api_key_id: Optional[str] = None, 
                  page: int = 1, page_size: int = 20, 
                  rule_type: Optional[str] = None,
                  status: Optional[str] = None) -> Tuple[List[FirewallRule], int]:
        """Get rules with pagination and filtering"""
        self._ensure_supabase()
        
        try:
            # Build query
            query = self.supabase.table(self.table_name).select("*", count="exact")
            
            # Apply filters
            query = query.eq("user_id", user_id)
            
            if api_key_id:
                query = query.eq("api_key_id", api_key_id)
            if rule_type:
                query = query.eq("rule_type", rule_type)
            if status:
                query = query.eq("status", status)
            
            # Apply pagination
            offset = (page - 1) * page_size
            query = query.range(offset, offset + page_size - 1)
            
            # Order by priority (descending) and created_at (descending)
            query = query.order("priority", desc=True).order("created_at", desc=True)
            
            result = query.execute()
            
            rules = []
            if result.data:
                for rule_data in result.data:
                    rules.append(FirewallRule.from_dict(rule_data))
            
            total_count = result.count if hasattr(result, 'count') else len(rules)
            
            return rules, total_count
            
        except Exception as e:
            print(f"[ERROR] Failed to get firewall rules: {e}")
            return [], 0
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[FirewallRule]:
        """Update an existing rule"""
        self._ensure_supabase()
        
        # Set updated timestamp
        updates['updated_at'] = datetime.now(timezone.utc).isoformat()
        
        # Ensure conditions and value are JSON serializable
        if 'conditions' in updates and isinstance(updates['conditions'], dict):
            updates['conditions'] = json.dumps(updates['conditions'])
        if 'value' in updates and isinstance(updates['value'], dict):
            updates['value'] = json.dumps(updates['value'])
        
        try:
            result = self.supabase.table(self.table_name).update(updates).eq("id", rule_id).execute()
            
            if result.data and len(result.data) > 0:
                return FirewallRule.from_dict(result.data[0])
            return None
            
        except Exception as e:
            print(f"[ERROR] Failed to update firewall rule {rule_id}: {e}")
            return None
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        self._ensure_supabase()
        
        try:
            result = self.supabase.table(self.table_name).delete().eq("id", rule_id).execute()
            
            # Check if any rows were affected
            return result.data is not None and len(result.data) > 0
            
        except Exception as e:
            print(f"[ERROR] Failed to delete firewall rule {rule_id}: {e}")
            return False
    
    def get_rule_statistics(self, user_id: str, api_key_id: Optional[str] = None) -> Dict[str, Any]:
        """Get statistics for user's firewall rules"""
        self._ensure_supabase()
        
        try:
            # Build base query
            query = self.supabase.table(self.table_name).select("*")
            query = query.eq("user_id", user_id)
            
            if api_key_id:
                query = query.eq("api_key_id", api_key_id)
            
            result = query.execute()
            
            if not result.data:
                return {
                    "total_rules": 0,
                    "active_rules": 0,
                    "inactive_rules": 0,
                    "expired_rules": 0,
                    "rule_type_distribution": {},
                    "action_distribution": {}
                }
            
            # Process statistics
            total_rules = len(result.data)
            active_rules = 0
            inactive_rules = 0
            expired_rules = 0
            rule_type_distribution = {}
            action_distribution = {}
            
            current_time = datetime.now(timezone.utc)
            
            for rule_data in result.data:
                # Count by status
                status = rule_data.get('status', 'inactive')
                if status == 'active':
                    active_rules += 1
                elif status == 'inactive':
                    inactive_rules += 1
                elif status == 'expired':
                    expired_rules += 1
                
                # Check if rule is expired by date
                expires_at = rule_data.get('expires_at')
                if expires_at and status == 'active':
                    try:
                        expires_datetime = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                        if expires_datetime <= current_time:
                            expired_rules += 1
                            active_rules -= 1
                    except:
                        pass
                
                # Count by rule type
                rule_type = rule_data.get('rule_type', 'unknown')
                rule_type_distribution[rule_type] = rule_type_distribution.get(rule_type, 0) + 1
                
                # Count by action
                action = rule_data.get('action', 'unknown')
                action_distribution[action] = action_distribution.get(action, 0) + 1
            
            return {
                "total_rules": total_rules,
                "active_rules": active_rules,
                "inactive_rules": inactive_rules,
                "expired_rules": expired_rules,
                "rule_type_distribution": rule_type_distribution,
                "action_distribution": action_distribution
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get firewall rule statistics: {e}")
            return {
                "total_rules": 0,
                "active_rules": 0,
                "inactive_rules": 0,
                "expired_rules": 0,
                "rule_type_distribution": {},
                "action_distribution": {}
            }
    
    def search_rules(self, user_id: str, query: str, 
                    api_key_id: Optional[str] = None,
                    rule_type: Optional[str] = None) -> List[FirewallRule]:
        """Search rules by name or description"""
        self._ensure_supabase()
        
        try:
            # Build base query
            search_query = self.supabase.table(self.table_name).select("*")
            search_query = search_query.eq("user_id", user_id)
            
            if api_key_id:
                search_query = search_query.eq("api_key_id", api_key_id)
            if rule_type:
                search_query = search_query.eq("rule_type", rule_type)
            
            # Search in name and description (case insensitive)
            search_query = search_query.or_(f"name.ilike.%{query}%,description.ilike.%{query}%")
            
            # Order by priority and created_at
            search_query = search_query.order("priority", desc=True).order("created_at", desc=True)
            
            result = search_query.execute()
            
            rules = []
            if result.data:
                for rule_data in result.data:
                    rules.append(FirewallRule.from_dict(rule_data))
            
            return rules
            
        except Exception as e:
            print(f"[ERROR] Failed to search firewall rules: {e}")
            return []
    
    def get_rules_by_type(self, user_id: str, rule_type: str,
                         api_key_id: Optional[str] = None) -> List[FirewallRule]:
        """Get all rules of a specific type for a user"""
        self._ensure_supabase()
        
        try:
            query = self.supabase.table(self.table_name).select("*")
            query = query.eq("user_id", user_id).eq("rule_type", rule_type)
            
            if api_key_id:
                query = query.eq("api_key_id", api_key_id)
            
            query = query.order("priority", desc=True).order("created_at", desc=True)
            
            result = query.execute()
            
            rules = []
            if result.data:
                for rule_data in result.data:
                    rules.append(FirewallRule.from_dict(rule_data))
            
            return rules
            
        except Exception as e:
            print(f"[ERROR] Failed to get rules by type {rule_type}: {e}")
            return []

# Global instance
supabase_rules_manager = SupabaseFirewallRulesManager()
