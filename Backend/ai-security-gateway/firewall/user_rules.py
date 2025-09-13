"""
User-defined firewall rules management system
Allows users to create custom firewall rules for their API keys
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from dataclasses import dataclass, asdict
import threading
import os

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
class UserFirewallRule:
    """User-defined firewall rule"""
    id: str
    user_id: str
    api_key_id: str
    name: str
    description: str
    rule_type: RuleType
    action: RuleAction
    status: RuleStatus
    conditions: Dict[str, Any]  # Rule-specific conditions
    priority: int = 0  # Higher priority = executed first
    created_at: datetime = None
    updated_at: datetime = None
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict:
        """Convert rule to dictionary for JSON serialization"""
        data = asdict(self)
        data['rule_type'] = self.rule_type.value
        data['action'] = self.action.value
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UserFirewallRule':
        """Create rule from dictionary"""
        data = data.copy()
        data['rule_type'] = RuleType(data['rule_type'])
        data['action'] = RuleAction(data['action'])
        data['status'] = RuleStatus(data['status'])
        
        # Parse datetime fields
        if data.get('created_at'):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        if data.get('updated_at'):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00'))
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        
        return cls(**data)

class UserRulesManager:
    """Manages user-defined firewall rules"""
    
    def __init__(self, storage_path: str = "user_firewall_rules.json"):
        self.storage_path = storage_path
        self.rules: Dict[str, UserFirewallRule] = {}  # rule_id -> rule
        self.user_rules: Dict[str, List[str]] = {}  # user_id -> [rule_ids]
        self.api_key_rules: Dict[str, List[str]] = {}  # api_key_id -> [rule_ids]
        self._lock = threading.Lock()
        self._load_rules()
    
    def _load_rules(self):
        """Load rules from storage file"""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Load rules
                for rule_data in data.get('rules', []):
                    rule = UserFirewallRule.from_dict(rule_data)
                    self.rules[rule.id] = rule
                    
                    # Update indexes
                    if rule.user_id not in self.user_rules:
                        self.user_rules[rule.user_id] = []
                    self.user_rules[rule.user_id].append(rule.id)
                    
                    if rule.api_key_id not in self.api_key_rules:
                        self.api_key_rules[rule.api_key_id] = []
                    self.api_key_rules[rule.api_key_id].append(rule.id)
                
                print(f"Loaded {len(self.rules)} user firewall rules")
        except Exception as e:
            print(f"Error loading user firewall rules: {e}")
    
    def _save_rules(self):
        """Save rules to storage file"""
        try:
            data = {
                'rules': [rule.to_dict() for rule in self.rules.values()],
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving user firewall rules: {e}")
    
    def create_rule(self, rule: UserFirewallRule) -> str:
        """Create a new user firewall rule"""
        with self._lock:
            # Generate ID if not provided
            if not rule.id:
                rule.id = str(uuid.uuid4())
            
            # Store rule
            self.rules[rule.id] = rule
            
            # Update indexes
            if rule.user_id not in self.user_rules:
                self.user_rules[rule.user_id] = []
            self.user_rules[rule.user_id].append(rule.id)
            
            if rule.api_key_id not in self.api_key_rules:
                self.api_key_rules[rule.api_key_id] = []
            self.api_key_rules[rule.api_key_id].append(rule.id)
            
            self._save_rules()
            return rule.id
    
    def get_rule(self, rule_id: str) -> Optional[UserFirewallRule]:
        """Get a specific rule by ID"""
        return self.rules.get(rule_id)
    
    def get_user_rules(self, user_id: str, api_key_id: Optional[str] = None) -> List[UserFirewallRule]:
        """Get all rules for a user, optionally filtered by API key"""
        rule_ids = self.user_rules.get(user_id, [])
        
        rules = []
        for rule_id in rule_ids:
            rule = self.rules.get(rule_id)
            if rule and (api_key_id is None or rule.api_key_id == api_key_id):
                rules.append(rule)
        
        # Sort by priority (descending)
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules
    
    def get_api_key_rules(self, api_key_id: str) -> List[UserFirewallRule]:
        """Get all rules for a specific API key"""
        rule_ids = self.api_key_rules.get(api_key_id, [])
        
        rules = []
        for rule_id in rule_ids:
            rule = self.rules.get(rule_id)
            if rule:
                rules.append(rule)
        
        # Sort by priority (descending)
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[UserFirewallRule]:
        """Update an existing rule"""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return None
            
            # Update fields
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            
            rule.updated_at = datetime.now(timezone.utc)
            self._save_rules()
            return rule
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return False
            
            # Remove from main storage
            del self.rules[rule_id]
            
            # Remove from user index
            if rule.user_id in self.user_rules:
                self.user_rules[rule.user_id].remove(rule_id)
                if not self.user_rules[rule.user_id]:
                    del self.user_rules[rule.user_id]
            
            # Remove from API key index
            if rule.api_key_id in self.api_key_rules:
                self.api_key_rules[rule.api_key_id].remove(rule_id)
                if not self.api_key_rules[rule.api_key_id]:
                    del self.api_key_rules[rule.api_key_id]
            
            self._save_rules()
            return True
    
    def get_active_rules_for_api_key(self, api_key_id: str) -> List[UserFirewallRule]:
        """Get all active rules for an API key"""
        rules = self.get_api_key_rules(api_key_id)
        active_rules = []
        
        current_time = datetime.now(timezone.utc)
        for rule in rules:
            if (rule.status == RuleStatus.ACTIVE and 
                (rule.expires_at is None or rule.expires_at > current_time)):
                active_rules.append(rule)
        
        return active_rules
    
    def validate_rule_conditions(self, rule_type: RuleType, conditions: Dict[str, Any]) -> List[str]:
        """Validate rule conditions based on rule type"""
        errors = []
        
        if rule_type == RuleType.IP_WHITELIST:
            if 'ips' not in conditions or not isinstance(conditions['ips'], list):
                errors.append("IP whitelist requires 'ips' list")
            else:
                for ip in conditions['ips']:
                    if not isinstance(ip, str) or not ip.strip():
                        errors.append(f"Invalid IP address: {ip}")
        
        elif rule_type == RuleType.IP_BLACKLIST:
            if 'ips' not in conditions or not isinstance(conditions['ips'], list):
                errors.append("IP blacklist requires 'ips' list")
            else:
                for ip in conditions['ips']:
                    if not isinstance(ip, str) or not ip.strip():
                        errors.append(f"Invalid IP address: {ip}")
        
        elif rule_type == RuleType.COUNTRY_BLOCK:
            if 'countries' not in conditions or not isinstance(conditions['countries'], list):
                errors.append("Country block requires 'countries' list")
            else:
                for country in conditions['countries']:
                    if not isinstance(country, str) or len(country) != 2:
                        errors.append(f"Invalid country code: {country} (must be 2 letters)")
        
        elif rule_type == RuleType.RATE_LIMIT:
            if 'requests_per_minute' not in conditions or not isinstance(conditions['requests_per_minute'], int):
                errors.append("Rate limit requires 'requests_per_minute' integer")
            elif conditions['requests_per_minute'] <= 0:
                errors.append("Rate limit must be positive")
        
        elif rule_type == RuleType.PATTERN_BLOCK:
            if 'patterns' not in conditions or not isinstance(conditions['patterns'], list):
                errors.append("Pattern block requires 'patterns' list")
            else:
                for pattern in conditions['patterns']:
                    if not isinstance(pattern, str) or not pattern.strip():
                        errors.append(f"Invalid pattern: {pattern}")
        
        elif rule_type == RuleType.TIME_BLOCK:
            if 'start_time' not in conditions or 'end_time' not in conditions:
                errors.append("Time block requires 'start_time' and 'end_time'")
            else:
                try:
                    # Validate time format (HH:MM)
                    for time_field in ['start_time', 'end_time']:
                        time_str = conditions[time_field]
                        if not isinstance(time_str, str):
                            errors.append(f"{time_field} must be string")
                        else:
                            hours, minutes = time_str.split(':')
                            if not (0 <= int(hours) <= 23 and 0 <= int(minutes) <= 59):
                                errors.append(f"Invalid time format for {time_field}: {time_str}")
                except ValueError:
                    errors.append("Invalid time format, use HH:MM")
        
        elif rule_type == RuleType.USER_AGENT_BLOCK:
            if 'user_agents' not in conditions or not isinstance(conditions['user_agents'], list):
                errors.append("User agent block requires 'user_agents' list")
            else:
                for ua in conditions['user_agents']:
                    if not isinstance(ua, str) or not ua.strip():
                        errors.append(f"Invalid user agent pattern: {ua}")
        
        elif rule_type == RuleType.CUSTOM_AI_RULE:
            if 'prompt_patterns' not in conditions or not isinstance(conditions['prompt_patterns'], list):
                errors.append("Custom AI rule requires 'prompt_patterns' list")
            else:
                for pattern in conditions['prompt_patterns']:
                    if not isinstance(pattern, str) or not pattern.strip():
                        errors.append(f"Invalid prompt pattern: {pattern}")
        
        return errors
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about user rules"""
        total_rules = len(self.rules)
        total_users = len(self.user_rules)
        total_api_keys = len(self.api_key_rules)
        
        # Count by rule type
        rule_type_counts = {}
        for rule in self.rules.values():
            rule_type = rule.rule_type.value
            rule_type_counts[rule_type] = rule_type_counts.get(rule_type, 0) + 1
        
        # Count by status
        status_counts = {}
        for rule in self.rules.values():
            status = rule.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_rules': total_rules,
            'total_users': total_users,
            'total_api_keys': total_api_keys,
            'rule_type_distribution': rule_type_counts,
            'status_distribution': status_counts
        }

# Global instance
user_rules_manager = UserRulesManager()
