"""
Firewall Configuration Module
Contains all configuration variables for the AI firewall system
"""

import os
from typing import List, Pattern
import re

# IP-based configuration
WHITELISTED_IPS: List[str] = [
    "127.0.0.1",      # Localhost
    "::1",            # IPv6 localhost
    # Add more whitelisted IPs as needed
]

BLOCKED_IPS_INITIAL: List[str] = [
    # Add known malicious IPs here
    # Example: "192.168.1.100"
]

# Country-based blocking configuration
BLOCKED_COUNTRIES_INITIAL: List[str] = [
    "CN",  # China
    "RU",  # Russia
    "KP",  # North Korea
    # Add more country codes as needed
]

# GeoIP database path
GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "GeoLite2-Country.mmdb")

# AI heuristics configuration
ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "0.7"))
AI_CONFIDENCE_THRESHOLD: float = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.8"))

# Rate limiting configuration
RATE_LIMIT_THRESHOLD: int = int(os.getenv("RATE_LIMIT_THRESHOLD", "100"))
RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# User-Agent blacklist patterns
USER_AGENT_BLACKLIST_PATTERNS: List[Pattern] = [
    re.compile(r"bot", re.IGNORECASE),
    re.compile(r"crawler", re.IGNORECASE),
    re.compile(r"spider", re.IGNORECASE),
    re.compile(r"scanner", re.IGNORECASE),
    re.compile(r"curl", re.IGNORECASE),
    re.compile(r"wget", re.IGNORECASE),
    # Add more patterns as needed
]

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS: List[Pattern] = [
    re.compile(r"\.\./", re.IGNORECASE),  # Directory traversal
    re.compile(r"%20", re.IGNORECASE),    # URL encoding
    re.compile(r"<script", re.IGNORECASE),  # XSS attempts
    re.compile(r"eval\(", re.IGNORECASE),    # Code execution
    re.compile(r"union.*select", re.IGNORECASE),  # SQL injection
    re.compile(r"drop.*table", re.IGNORECASE),    # SQL injection
    re.compile(r"exec\(", re.IGNORECASE),         # Command execution
    re.compile(r"system\(", re.IGNORECASE),       # Command execution
    # Add more patterns as needed
]

# File paths for persistent storage
IP_BLACKLIST_FILE: str = os.getenv("IP_BLACKLIST_FILE", "ip_blacklist.txt")
TEMPORARY_BLOCKS_FILE: str = os.getenv("TEMPORARY_BLOCKS_FILE", "temporary_blocks.txt")

# Security thresholds
MAX_REQUEST_SIZE: int = int(os.getenv("MAX_REQUEST_SIZE", "1048576"))  # 1MB
MAX_HEADER_SIZE: int = int(os.getenv("MAX_HEADER_SIZE", "8192"))       # 8KB

# Logging configuration
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str = os.getenv("LOG_FILE", "firewall.log")
ENABLE_ADMIN_ALERTS: bool = os.getenv("ENABLE_ADMIN_ALERTS", "true").lower() == "true"

# Performance configuration
ENABLE_CACHING: bool = os.getenv("ENABLE_CACHING", "true").lower() == "true"
CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "300"))  # 5 minutes

# Debug mode
DEBUG_MODE: bool = os.getenv("DEBUG_MODE", "false").lower() == "true"

# Block duration for temporary blocks (in seconds)
TEMPORARY_BLOCK_DURATION: int = int(os.getenv("TEMPORARY_BLOCK_DURATION", "3600"))  # 1 hour

# AI model configuration
AI_MODEL_PATH: str = os.getenv("AI_MODEL_PATH", "models/threat_detection_model.pkl")
AI_FEATURE_EXTRACTION_ENABLED: bool = os.getenv("AI_FEATURE_EXTRACTION_ENABLED", "true").lower() == "true"

# Advanced threat detection
ENABLE_BEHAVIORAL_ANALYSIS: bool = os.getenv("ENABLE_BEHAVIORAL_ANALYSIS", "true").lower() == "true"
BEHAVIORAL_ANALYSIS_WINDOW: int = int(os.getenv("BEHAVIORAL_ANALYSIS_WINDOW", "300"))  # 5 minutes

# DLP (Data Loss Prevention) patterns
DLP_PATTERNS: List[Pattern] = [
    re.compile(r"API_KEY[_A-Z0-9]*\s*=\s*['\"][^'\"]+['\"]"),
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),  # Email
    re.compile(r"\b\d{16}\b"),  # Credit card (basic)
    re.compile(r"sk_(live|test)?_[A-Za-z0-9]{16,}"),  # OpenAI API key
    # Add more DLP patterns as needed
]

# Request validation
REQUIRED_HEADERS: List[str] = [
    "User-Agent",
    "Accept",
    # Add more required headers as needed
]

# Response security headers
SECURITY_HEADERS: dict = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
}

# Session management
SESSION_TIMEOUT_SECONDS: int = int(os.getenv("SESSION_TIMEOUT_SECONDS", "1800"))  # 30 minutes
MAX_CONCURRENT_SESSIONS: int = int(os.getenv("MAX_CONCURRENT_SESSIONS", "10"))

# Admin configuration
ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@example.com")
ALERT_COOLDOWN_SECONDS: int = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))  # 5 minutes
