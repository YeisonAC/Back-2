"""
Firewall Rules Engine
Main orchestration module for all firewall rules and threat detection
"""

import time
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import defaultdict, deque

from .config import (
    WHITELISTED_IPS,
    RATE_LIMIT_THRESHOLD,
    RATE_LIMIT_WINDOW_SECONDS,
    USER_AGENT_BLACKLIST_PATTERNS,
    SUSPICIOUS_URL_PATTERNS,
    TEMPORARY_BLOCK_DURATION,
    DEBUG_MODE
)
from .ip_blacklist import ip_blacklist_manager
from .country_block import country_block_manager
from .ai_heuristics import ai_heuristics_manager, ThreatAnalysis
from .logging import log_event, alert_admin
from .user_rules import user_rules_manager, RuleType, RuleAction, RuleStatus


@dataclass
class FirewallResult:
    """Result of firewall rule evaluation"""
    decision: str  # "ALLOW", "DENY"
    reason: str
    rule_triggered: str
    confidence_score: float = 0.0
    threat_analysis: Optional[ThreatAnalysis] = None
    additional_info: Optional[Dict[str, Any]] = None


class FirewallRulesEngine:
    """
    Main firewall rules engine that orchestrates all security rules
    """
    
    def __init__(self):
        self._rate_limits: Dict[str, deque] = defaultdict(deque)
        self._rate_limit_lock = threading.RLock()
        self._request_count = 0
        self._start_time = time.time()
        
        if DEBUG_MODE:
            print("Firewall Rules Engine initialized")
    
    def _evaluate_user_rules(self, request_data: Dict[str, Any]) -> Optional[FirewallResult]:
        """
        Evaluate user-defined firewall rules
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            FirewallResult if a user rule triggers, None otherwise
        """
        api_key_id = request_data.get('api_key_id')
        if not api_key_id:
            return None
        
        # Get active user rules for this API key
        user_rules = user_rules_manager.get_active_rules_for_api_key(api_key_id)
        
        client_ip = request_data.get('client_ip', '')
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        url = request_data.get('url', '')
        method = request_data.get('method', 'GET')
        message_content = request_data.get('message_content', '')
        
        # Evaluate user rules in priority order
        for rule in user_rules:
            try:
                result = self._evaluate_single_user_rule(rule, request_data)
                if result:
                    return result
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Error evaluating user rule {rule.id}: {e}")
                continue
        
        return None
    
    def _evaluate_single_user_rule(self, rule, request_data: Dict[str, Any]) -> Optional[FirewallResult]:
        """
        Evaluate a single user-defined rule
        
        Args:
            rule: UserFirewallRule instance
            request_data: Dictionary containing request information
            
        Returns:
            FirewallResult if rule triggers, None otherwise
        """
        client_ip = request_data.get('client_ip', '')
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        url = request_data.get('url', '')
        message_content = request_data.get('message_content', '')
        
        # Check if rule conditions are met
        conditions_met = False
        
        if rule.rule_type == RuleType.IP_WHITELIST:
            allowed_ips = rule.conditions.get('ips', [])
            conditions_met = client_ip in allowed_ips
            
        elif rule.rule_type == RuleType.IP_BLACKLIST:
            blocked_ips = rule.conditions.get('ips', [])
            conditions_met = client_ip in blocked_ips
            
        elif rule.rule_type == RuleType.COUNTRY_BLOCK:
            blocked_countries = rule.conditions.get('countries', [])
            country_code = country_block_manager.get_country_from_ip(client_ip)
            conditions_met = country_code in blocked_countries
            
        elif rule.rule_type == RuleType.RATE_LIMIT:
            # This is a simplified rate limit check
            # For production, you'd want to implement proper rate limiting per API key
            requests_per_minute = rule.conditions.get('requests_per_minute', 60)
            # Note: This is a basic implementation. In production, you'd want to track
            # request counts per API key with proper time windows
            conditions_met = False  # Placeholder - implement proper rate limiting
            
        elif rule.rule_type == RuleType.PATTERN_BLOCK:
            blocked_patterns = rule.conditions.get('patterns', [])
            # Check patterns in message content, URL, and headers
            text_to_check = f"{message_content} {url} {user_agent}".lower()
            conditions_met = any(pattern.lower() in text_to_check for pattern in blocked_patterns)
            
        elif rule.rule_type == RuleType.TIME_BLOCK:
            import datetime
            now = datetime.datetime.now()
            current_time = now.strftime("%H:%M")
            start_time = rule.conditions.get('start_time', '00:00')
            end_time = rule.conditions.get('end_time', '23:59')
            conditions_met = start_time <= current_time <= end_time
            
        elif rule.rule_type == RuleType.USER_AGENT_BLOCK:
            blocked_user_agents = rule.conditions.get('user_agents', [])
            conditions_met = any(ua.lower() in user_agent.lower() for ua in blocked_user_agents)
            
        elif rule.rule_type == RuleType.CUSTOM_AI_RULE:
            prompt_patterns = rule.conditions.get('prompt_patterns', [])
            # Check if message content contains any of the prompt patterns
            conditions_met = any(pattern.lower() in message_content.lower() for pattern in prompt_patterns)
        
        # If conditions are met, return result based on rule action
        if conditions_met:
            if rule.action == RuleAction.BLOCK:
                log_event(
                    "USER_RULE_BLOCK",
                    client_ip,
                    f"Blocked by user rule '{rule.name}': {rule.description}",
                    request_data,
                    additional_info={"rule_id": rule.id, "rule_type": rule.rule_type.value}
                )
                return FirewallResult(
                    decision="DENY",
                    reason=f"User rule: {rule.name}",
                    rule_triggered="USER_RULE",
                    additional_info={
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "rule_type": rule.rule_type.value
                    }
                )
            elif rule.action == RuleAction.ALLOW:
                log_event(
                    "USER_RULE_ALLOW",
                    client_ip,
                    f"Allowed by user rule '{rule.name}': {rule.description}",
                    request_data,
                    additional_info={"rule_id": rule.id, "rule_type": rule.rule_type.value}
                )
                return FirewallResult(
                    decision="ALLOW",
                    reason=f"User rule: {rule.name}",
                    rule_triggered="USER_RULE",
                    additional_info={
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "rule_type": rule.rule_type.value
                    }
                )
            elif rule.action == RuleAction.LOG_ONLY:
                log_event(
                    "USER_RULE_LOG",
                    client_ip,
                    f"Logged by user rule '{rule.name}': {rule.description}",
                    request_data,
                    additional_info={"rule_id": rule.id, "rule_type": rule.rule_type.value}
                )
                # Don't return a result, just log and continue
        
        return None
    
    def process_request(self, request_data: Dict[str, Any]) -> FirewallResult:
        """
        Process a request through all firewall rules
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            FirewallResult: Decision and reasoning
        """
        self._request_count += 1
        
        # Extract essential information
        client_ip = request_data.get('client_ip', '')
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        url = request_data.get('url', '')
        method = request_data.get('method', 'GET')
        
        # Rule 1: Whitelist (Permitir siempre)
        if self._is_whitelisted(client_ip):
            log_event("WHITELISTED", client_ip, "IP en lista blanca.", request_data)
            return FirewallResult(
                decision="ALLOW",
                reason="IP whitelisted",
                rule_triggered="WHITELIST"
            )
        
        # Rule 1.5: User-defined rules (evaluated after whitelist but before other security rules)
        user_rule_result = self._evaluate_user_rules(request_data)
        if user_rule_result:
            return user_rule_result
        
        # Rule 2: Bloqueo por IP Estática/Persistente
        if ip_blacklist_manager.is_blocked(client_ip):
            block_info = ip_blacklist_manager.get_block_info(client_ip)
            log_event("BLOCKED_IP", client_ip, f"IP en lista negra: {block_info}", request_data)
            return FirewallResult(
                decision="DENY",
                reason="IP blacklisted",
                rule_triggered="IP_BLACKLIST",
                additional_info=block_info
            )
        
        # Rule 3: Bloqueo por País
        if country_block_manager.is_country_blocked(client_ip):
            country_code = country_block_manager.get_country_from_ip(client_ip)
            log_event("BLOCKED_COUNTRY", client_ip, f"País {country_code} bloqueado.", request_data)
            return FirewallResult(
                decision="DENY",
                reason=f"Country blocked: {country_code}",
                rule_triggered="COUNTRY_BLOCK",
                additional_info={"country_code": country_code}
            )
        
        # Rule 4: Límite de Tasa (Rate Limiting)
        if self._is_rate_limited(client_ip):
            # Add IP to temporary blacklist
            ip_blacklist_manager.block_ip_temporarily(client_ip, TEMPORARY_BLOCK_DURATION)
            log_event("BLOCKED_RATE_LIMIT", client_ip, "Exceso de solicitudes.", request_data)
            return FirewallResult(
                decision="DENY",
                reason="Rate limit exceeded",
                rule_triggered="RATE_LIMIT",
                additional_info={"temporary_block_duration": TEMPORARY_BLOCK_DURATION}
            )
        
        # Rule 5: Detección de Patrones de User-Agent Maliciosos
        if self._is_malicious_user_agent(user_agent):
            log_event("BLOCKED_USER_AGENT", client_ip, f"User-Agent sospechoso: {user_agent}", request_data)
            return FirewallResult(
                decision="DENY",
                reason="Malicious User-Agent detected",
                rule_triggered="USER_AGENT_BLACKLIST"
            )
        
        # Rule 6: Detección de Patrones de URL Sospechosos
        if self._is_suspicious_url(url):
            log_event("BLOCKED_URL_PATTERN", client_ip, f"URL sospechosa: {url}", request_data)
            return FirewallResult(
                decision="DENY",
                reason="Suspicious URL pattern detected",
                rule_triggered="URL_PATTERN_BLACKLIST"
            )
        
        # Rule 7: Heurísticas de IA
        threat_analysis = ai_heuristics_manager.analyze_request(request_data)
        if threat_analysis.is_malicious:
            # Add IP to temporary blacklist if confidence is high
            if threat_analysis.confidence_score > 0.8:
                ip_blacklist_manager.block_ip_temporarily(client_ip, TEMPORARY_BLOCK_DURATION)
            
            log_event(
                "BLOCKED_AI_HEURISTICS",
                client_ip,
                f"Detectado por IA como malicioso: {threat_analysis.threat_type}",
                request_data
            )
            
            # Alert admin for high-confidence threats
            if threat_analysis.confidence_score > 0.9:
                alert_admin(
                    f"High-confidence threat detected from {client_ip}: {threat_analysis.threat_type}",
                    request_data,
                    threat_analysis
                )
            
            return FirewallResult(
                decision="DENY",
                reason=f"AI detected malicious content: {threat_analysis.threat_type}",
                rule_triggered="AI_HEURISTICS",
                confidence_score=threat_analysis.confidence_score,
                threat_analysis=threat_analysis,
                additional_info={
                    "threat_type": threat_analysis.threat_type,
                    "flags": threat_analysis.flags,
                    "anomaly_score": threat_analysis.anomaly_score
                }
            )
        
        # Rule Final: Permitir por Defecto
        log_event("ALLOWED", client_ip, "Solicitud permitida.", request_data)
        return FirewallResult(
            decision="ALLOW",
            reason="Request allowed by default",
            rule_triggered="DEFAULT_ALLOW"
        )
    
    def _is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is in whitelist"""
        return ip_address in WHITELISTED_IPS
    
    def _is_rate_limited(self, ip_address: str) -> bool:
        """Check if IP has exceeded rate limit"""
        with self._rate_limit_lock:
            current_time = time.time()
            request_times = self._rate_limits[ip_address]
            
            # Remove old requests outside the time window
            while request_times and current_time - request_times[0] > RATE_LIMIT_WINDOW_SECONDS:
                request_times.popleft()
            
            # Check if rate limit is exceeded
            if len(request_times) >= RATE_LIMIT_THRESHOLD:
                return True
            
            # Add current request time
            request_times.append(current_time)
            return False
    
    def _is_malicious_user_agent(self, user_agent: str) -> bool:
        """Check if User-Agent matches malicious patterns"""
        if not user_agent:
            return False
        
        for pattern in USER_AGENT_BLACKLIST_PATTERNS:
            if pattern.search(user_agent):
                return True
        
        return False
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL matches suspicious patterns"""
        if not url:
            return False
        
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if pattern.search(url):
                return True
        
        return False
    
    def block_ip_temporarily(self, ip_address: str, duration: int = None) -> bool:
        """
        Block an IP temporarily
        
        Args:
            ip_address: IP to block
            duration: Block duration in seconds
            
        Returns:
            bool: True if blocked successfully
        """
        return ip_blacklist_manager.block_ip_temporarily(ip_address, duration)
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            bool: True if unblocked successfully
        """
        return ip_blacklist_manager.remove_ip(ip_address)
    
    def add_blocked_country(self, country_code: str) -> bool:
        """
        Add a country to the blocked list
        
        Args:
            country_code: Two-letter country code
            
        Returns:
            bool: True if added successfully
        """
        return country_block_manager.add_blocked_country(country_code)
    
    def remove_blocked_country(self, country_code: str) -> bool:
        """
        Remove a country from the blocked list
        
        Args:
            country_code: Two-letter country code
            
        Returns:
            bool: True if removed successfully
        """
        return country_block_manager.remove_blocked_country(country_code)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive firewall statistics
        
        Returns:
            Dict: Firewall statistics
        """
        current_time = time.time()
        uptime = current_time - self._start_time
        
        # Get rate limit statistics
        with self._rate_limit_lock:
            active_rate_limits = len(self._rate_limits)
            total_rate_limited_requests = sum(len(times) for times in self._rate_limits.values())
        
        return {
            "uptime_seconds": uptime,
            "total_requests_processed": self._request_count,
            "requests_per_second": self._request_count / uptime if uptime > 0 else 0,
            "active_rate_limits": active_rate_limits,
            "total_rate_limited_requests": total_rate_limited_requests,
            "ip_blacklist_stats": ip_blacklist_manager.get_statistics(),
            "country_block_stats": country_block_manager.get_statistics(),
            "ai_heuristics_stats": ai_heuristics_manager.get_statistics()
        }
    
    def cleanup_expired_blocks(self) -> int:
        """
        Clean up expired blocks
        
        Returns:
            int: Number of expired blocks removed
        """
        return ip_blacklist_manager.cleanup_expired_blocks()
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of all blocked IPs
        
        Returns:
            List[str]: List of blocked IPs
        """
        return ip_blacklist_manager.get_all_blocked_ips()
    
    def get_blocked_countries(self) -> List[str]:
        """
        Get list of blocked countries
        
        Returns:
            List[str]: List of blocked country codes
        """
        return country_block_manager.get_blocked_countries()
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP is blocked
        
        Args:
            ip_address: IP to check
            
        Returns:
            bool: True if blocked
        """
        return ip_blacklist_manager.is_blocked(ip_address)
    
    def is_country_blocked(self, country_code: str) -> bool:
        """
        Check if a country is blocked
        
        Args:
            country_code: Country code to check
            
        Returns:
            bool: True if blocked
        """
        return country_block_manager.is_country_code_blocked(country_code)


# Global instance
firewall_rules_engine = FirewallRulesEngine()
