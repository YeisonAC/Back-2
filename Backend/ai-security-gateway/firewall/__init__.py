"""
Firewall Package
Comprehensive AI-powered firewall system for threat detection and prevention
"""

from .config import *
from .ip_blacklist import ip_blacklist_manager, IPBlacklistManager
from .country_block import country_block_manager, CountryBlockManager
from .ai_heuristics import ai_heuristics_manager, AIHeuristicsManager, ThreatAnalysis
from .rules import firewall_rules_engine, FirewallRulesEngine, FirewallResult
from .logging import firewall_logger, FirewallLogger, SecurityEvent, log_event, alert_admin

__version__ = "1.0.0"
__author__ = "EONS Security Team"
__description__ = "AI-powered firewall with comprehensive threat detection"

# Main exports for easy usage
__all__ = [
    # Configuration
    'WHITELISTED_IPS',
    'BLOCKED_IPS_INITIAL',
    'BLOCKED_COUNTRIES_INITIAL',
    'ANOMALY_THRESHOLD',
    'RATE_LIMIT_THRESHOLD',
    'RATE_LIMIT_WINDOW_SECONDS',
    
    # Managers
    'ip_blacklist_manager',
    'IPBlacklistManager',
    'country_block_manager',
    'CountryBlockManager',
    'ai_heuristics_manager',
    'AIHeuristicsManager',
    'firewall_rules_engine',
    'FirewallRulesEngine',
    'firewall_logger',
    'FirewallLogger',
    'user_rules_manager',
    'UserFirewallRule',
    'RuleType',
    'RuleAction',
    'RuleStatus',
    
    # Data structures
    'ThreatAnalysis',
    'FirewallResult',
    'SecurityEvent',
    
    # Convenience functions
    'log_event',
    'alert_admin',
    'firewall_rules_engine as firewall',
    'user_rules_manager as user_firewall_rules',
]

# Package initialization
def initialize_firewall():
    """
    Initialize the firewall system
    This function should be called when the application starts
    """
    try:
        # Test that all components are properly initialized
        ip_blacklist_manager.get_statistics()
        country_block_manager.get_statistics()
        ai_heuristics_manager.get_statistics()
        firewall_rules_engine.get_statistics()
        firewall_logger.get_event_statistics()
        
        print("Firewall system initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing firewall system: {e}")
        return False

def get_firewall_status():
    """
    Get the current status of the firewall system
    
    Returns:
        dict: Firewall status information
    """
    return {
        "ip_blacklist": ip_blacklist_manager.get_statistics(),
        "country_block": country_block_manager.get_statistics(),
        "ai_heuristics": ai_heuristics_manager.get_statistics(),
        "rules_engine": firewall_rules_engine.get_statistics(),
        "logging": firewall_logger.get_event_statistics()
    }
