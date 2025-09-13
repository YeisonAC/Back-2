"""
AI Heuristics Module
Implements AI-based threat detection and anomaly analysis
"""

import re
import math
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import Counter
import hashlib

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from .config import (
    ANOMALY_THRESHOLD,
    AI_CONFIDENCE_THRESHOLD,
    AI_MODEL_PATH,
    AI_FEATURE_EXTRACTION_ENABLED,
    DEBUG_MODE,
    DLP_PATTERNS
)


@dataclass
class ThreatAnalysis:
    """Result of AI threat analysis"""
    is_malicious: bool
    confidence_score: float
    threat_type: str
    features: Dict[str, Any]
    anomaly_score: float
    flags: List[str]


class AIHeuristicsManager:
    """
    Manages AI-based threat detection and anomaly analysis
    """
    
    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._lock = threading.RLock()
        self._feature_cache: Dict[str, Dict] = {}
        self._request_history: List[Dict] = []
        self._history_lock = threading.RLock()
        self._initialize_ai_components()
        
        # Attack patterns and keywords
        self._attack_keywords = [
            "union", "select", "insert", "update", "delete", "drop", "alter",
            "exec", "eval", "system", "shell", "cmd", "bash", "powershell",
            "script", "javascript", "vbscript", "iframe", "onload", "onerror",
            "prompt", "alert", "document.cookie", "window.location",
            "file://", "ftp://", "smb://", "ldap://", "gopher://",
            "<script", "</script", "javascript:", "data:text/html",
            "xss", "csrf", "ssrf", "rce", "lfi", "rfi", "sqli"
        ]
        
        self._suspicious_patterns = [
            r"\.\./",  # Directory traversal
            r"%[0-9a-fA-F]{2}",  # URL encoding
            r"<[^>]*script",  # Script tags
            r"javascript\s*:",  # JavaScript protocol
            r"on\w+\s*=",  # Event handlers
            r"eval\s*\(",  # eval() function
            r"document\.",  # Document object access
            r"window\.",  # Window object access
            r"exec\s*\(",  # exec() function
            r"system\s*\(",  # system() function
            r"shell_exec\s*\(",  # shell_exec() function
            r"passthru\s*\(",  # passthru() function
            r"base64_decode\s*\(",  # base64_decode() function
        ]
        
        # Compile regex patterns
        self._compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self._suspicious_patterns]
    
    def _initialize_ai_components(self) -> None:
        """Initialize AI model and vectorizer"""
        if not ML_AVAILABLE:
            if DEBUG_MODE:
                print("Machine learning libraries not available. Using rule-based detection only.")
            return
        
        try:
            # Try to load existing model
            if os.path.exists(AI_MODEL_PATH):
                self._model = joblib.load(AI_MODEL_PATH)
                if DEBUG_MODE:
                    print(f"Loaded AI model from: {AI_MODEL_PATH}")
            else:
                # Create new model if none exists
                self._model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                if DEBUG_MODE:
                    print("Created new Isolation Forest model")
            
            # Initialize vectorizer for text analysis
            self._vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 3)
            )
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Error initializing AI components: {e}")
            self._model = None
            self._vectorizer = None
    
    def extract_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from request data for AI analysis
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Dict: Extracted features
        """
        if not AI_FEATURE_EXTRACTION_ENABLED:
            return {}
        
        features = {}
        
        # Extract text content
        text_content = self._extract_text_content(request_data)
        features['text_content'] = text_content
        
        # Basic text features
        features['text_length'] = len(text_content)
        features['word_count'] = len(text_content.split())
        features['sentence_count'] = len(re.split(r'[.!?]+', text_content))
        features['avg_word_length'] = sum(len(word) for word in text_content.split()) / max(len(text_content.split()), 1)
        
        # Character frequency features
        features['special_char_count'] = sum(1 for c in text_content if not c.isalnum() and not c.isspace())
        features['digit_count'] = sum(1 for c in text_content if c.isdigit())
        features['uppercase_count'] = sum(1 for c in text_content if c.isupper())
        features['lowercase_count'] = sum(1 for c in text_content if c.islower())
        
        # Entropy calculation
        features['entropy'] = self._calculate_entropy(text_content)
        
        # Attack keyword detection
        features['attack_keyword_count'] = sum(1 for keyword in self._attack_keywords if keyword.lower() in text_content.lower())
        features['attack_keyword_density'] = features['attack_keyword_count'] / max(len(text_content.split()), 1)
        
        # Pattern matching
        features['suspicious_pattern_count'] = sum(1 for pattern in self._compiled_patterns if pattern.search(text_content))
        
        # DLP pattern detection
        features['dlp_pattern_count'] = sum(1 for pattern in DLP_PATTERNS if pattern.search(text_content))
        
        # HTTP header analysis
        headers = request_data.get('headers', {})
        features['header_count'] = len(headers)
        features['user_agent_length'] = len(headers.get('User-Agent', ''))
        features['has_referer'] = 1 if 'Referer' in headers else 0
        features['has_cookie'] = 1 if 'Cookie' in headers else 0
        
        # URL analysis
        url = request_data.get('url', '')
        features['url_length'] = len(url)
        features['url_param_count'] = url.count('?') + url.count('&')
        features['url_depth'] = url.count('/')
        
        # Request method
        features['is_post_request'] = 1 if request_data.get('method', '').upper() == 'POST' else 0
        features['is_get_request'] = 1 if request_data.get('method', '').upper() == 'GET' else 0
        
        # Content type analysis
        content_type = headers.get('Content-Type', '')
        features['is_json_content'] = 1 if 'application/json' in content_type.lower() else 0
        features['is_form_content'] = 1 if 'application/x-www-form-urlencoded' in content_type.lower() else 0
        
        return features
    
    def _extract_text_content(self, request_data: Dict[str, Any]) -> str:
        """Extract all text content from request data"""
        text_parts = []
        
        # Add URL
        if 'url' in request_data:
            text_parts.append(request_data['url'])
        
        # Add headers
        headers = request_data.get('headers', {})
        for key, value in headers.items():
            text_parts.append(f"{key}: {value}")
        
        # Add body/content
        if 'body' in request_data:
            if isinstance(request_data['body'], dict):
                # Handle JSON body
                text_parts.append(str(request_data['body']))
            else:
                text_parts.append(str(request_data['body']))
        
        # Add query parameters
        if 'query_params' in request_data:
            for key, value in request_data['query_params'].items():
                text_parts.append(f"{key}={value}")
        
        return ' '.join(text_parts)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        total_chars = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_request(self, request_data: Dict[str, Any]) -> ThreatAnalysis:
        """
        Analyze request for threats using AI heuristics
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            ThreatAnalysis: Analysis result
        """
        # Extract features
        features = self.extract_features(request_data)
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(features)
        
        # Detect threat type
        threat_type, flags = self._detect_threat_type(features, request_data)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(features, anomaly_score, flags)
        
        # Determine if malicious
        is_malicious = confidence_score > AI_CONFIDENCE_THRESHOLD or anomaly_score > ANOMALY_THRESHOLD
        
        # Create analysis result
        analysis = ThreatAnalysis(
            is_malicious=is_malicious,
            confidence_score=confidence_score,
            threat_type=threat_type,
            features=features,
            anomaly_score=anomaly_score,
            flags=flags
        )
        
        # Store in history for behavioral analysis
        self._add_to_history(request_data, analysis)
        
        if DEBUG_MODE and is_malicious:
            print(f"AI detected malicious request: {threat_type} (confidence: {confidence_score:.2f})")
        
        return analysis
    
    def _calculate_anomaly_score(self, features: Dict[str, Any]) -> float:
        """Calculate anomaly score using ML model or rule-based approach"""
        if not ML_AVAILABLE or self._model is None:
            # Rule-based anomaly scoring
            score = 0.0
            
            # High entropy indicates potential obfuscation
            if features.get('entropy', 0) > 4.0:
                score += 0.3
            
            # Many special characters
            if features.get('special_char_count', 0) > 20:
                score += 0.2
            
            # Many attack keywords
            if features.get('attack_keyword_count', 0) > 3:
                score += 0.4
            
            # Many suspicious patterns
            if features.get('suspicious_pattern_count', 0) > 2:
                score += 0.3
            
            # DLP patterns
            if features.get('dlp_pattern_count', 0) > 0:
                score += 0.5
            
            return min(score, 1.0)
        
        try:
            # Convert features to vector
            feature_vector = self._features_to_vector(features)
            
            # Use ML model for anomaly detection
            if feature_vector is not None:
                anomaly_score = -self._model.decision_function([feature_vector])[0]
                return max(0.0, min(1.0, anomaly_score))
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Error in ML anomaly detection: {e}")
        
        return 0.0
    
    def _features_to_vector(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Convert features to vector for ML model"""
        if not ML_AVAILABLE or self._vectorizer is None:
            return None
        
        try:
            # Create a simple feature vector
            numeric_features = [
                features.get('text_length', 0),
                features.get('word_count', 0),
                features.get('sentence_count', 0),
                features.get('avg_word_length', 0),
                features.get('special_char_count', 0),
                features.get('digit_count', 0),
                features.get('uppercase_count', 0),
                features.get('lowercase_count', 0),
                features.get('entropy', 0),
                features.get('attack_keyword_count', 0),
                features.get('attack_keyword_density', 0),
                features.get('suspicious_pattern_count', 0),
                features.get('dlp_pattern_count', 0),
                features.get('header_count', 0),
                features.get('user_agent_length', 0),
                features.get('has_referer', 0),
                features.get('has_cookie', 0),
                features.get('url_length', 0),
                features.get('url_param_count', 0),
                features.get('url_depth', 0),
                features.get('is_post_request', 0),
                features.get('is_get_request', 0),
                features.get('is_json_content', 0),
                features.get('is_form_content', 0),
            ]
            
            return np.array(numeric_features)
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Error converting features to vector: {e}")
            return None
    
    def _detect_threat_type(self, features: Dict[str, Any], request_data: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Detect threat type based on features"""
        flags = []
        threat_type = "benign"
        
        text_content = features.get('text_content', '').lower()
        
        # SQL Injection detection
        sql_indicators = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'alter']
        if any(indicator in text_content for indicator in sql_indicators):
            flags.append("SQL_INJECTION")
            threat_type = "sql_injection"
        
        # XSS detection
        xss_indicators = ['<script', 'javascript:', 'onload=', 'onerror=', 'alert(', 'document.cookie']
        if any(indicator in text_content for indicator in xss_indicators):
            flags.append("XSS")
            threat_type = "xss"
        
        # Command injection detection
        cmd_indicators = ['exec(', 'system(', 'shell_exec(', 'cmd', 'bash', 'powershell']
        if any(indicator in text_content for indicator in cmd_indicators):
            flags.append("COMMAND_INJECTION")
            threat_type = "command_injection"
        
        # Directory traversal detection
        if '../' in text_content or '..\\' in text_content:
            flags.append("DIRECTORY_TRAVERSAL")
            threat_type = "directory_traversal"
        
        # DLP detection
        if features.get('dlp_pattern_count', 0) > 0:
            flags.append("DLP_VIOLATION")
            threat_type = "dlp_violation"
        
        # High entropy detection (potential obfuscation)
        if features.get('entropy', 0) > 4.5:
            flags.append("HIGH_ENTROPY")
            if threat_type == "benign":
                threat_type = "obfuscation"
        
        # Rate limiting detection (based on history)
        if self._is_rate_limited(request_data):
            flags.append("RATE_LIMITED")
            threat_type = "rate_limiting"
        
        return threat_type, flags
    
    def _calculate_confidence_score(self, features: Dict[str, Any], anomaly_score: float, flags: List[str]) -> float:
        """Calculate confidence score for threat detection"""
        confidence = 0.0
        
        # Base confidence from anomaly score
        confidence += anomaly_score * 0.4
        
        # Confidence from flags
        flag_weights = {
            "SQL_INJECTION": 0.3,
            "XSS": 0.3,
            "COMMAND_INJECTION": 0.3,
            "DIRECTORY_TRAVERSAL": 0.25,
            "DLP_VIOLATION": 0.2,
            "HIGH_ENTROPY": 0.15,
            "RATE_LIMITED": 0.1
        }
        
        for flag in flags:
            confidence += flag_weights.get(flag, 0.1)
        
        # Confidence from attack keyword density
        keyword_density = features.get('attack_keyword_density', 0)
        confidence += min(keyword_density * 2, 0.3)
        
        # Confidence from suspicious patterns
        pattern_count = features.get('suspicious_pattern_count', 0)
        confidence += min(pattern_count * 0.1, 0.2)
        
        return min(confidence, 1.0)
    
    def _add_to_history(self, request_data: Dict[str, Any], analysis: ThreatAnalysis) -> None:
        """Add request to history for behavioral analysis"""
        with self._history_lock:
            history_entry = {
                'timestamp': time.time(),
                'ip': request_data.get('client_ip', ''),
                'analysis': analysis,
                'request_data': {
                    'method': request_data.get('method', ''),
                    'url': request_data.get('url', ''),
                    'user_agent': request_data.get('headers', {}).get('User-Agent', '')
                }
            }
            
            self._request_history.append(history_entry)
            
            # Keep only last 1000 entries
            if len(self._request_history) > 1000:
                self._request_history = self._request_history[-1000:]
    
    def _is_rate_limited(self, request_data: Dict[str, Any]) -> bool:
        """Check if request should be rate limited based on history"""
        with self._history_lock:
            current_time = time.time()
            ip = request_data.get('client_ip', '')
            
            # Count requests from this IP in the last minute
            recent_requests = [
                entry for entry in self._request_history
                if entry['ip'] == ip and current_time - entry['timestamp'] < 60
            ]
            
            return len(recent_requests) > 100  # More than 100 requests per minute
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get AI heuristics statistics"""
        with self._history_lock:
            total_requests = len(self._request_history)
            
            if total_requests == 0:
                return {
                    "total_requests_analyzed": 0,
                    "malicious_requests": 0,
                    "benign_requests": 0,
                    "ml_available": ML_AVAILABLE,
                    "model_loaded": self._model is not None
                }
            
            malicious_count = sum(1 for entry in self._request_history if entry['analysis'].is_malicious)
            
            # Threat type distribution
            threat_types = Counter(entry['analysis'].threat_type for entry in self._request_history)
            
            # Flag distribution
            all_flags = []
            for entry in self._request_history:
                all_flags.extend(entry['analysis'].flags)
            flag_distribution = Counter(all_flags)
            
            return {
                "total_requests_analyzed": total_requests,
                "malicious_requests": malicious_count,
                "benign_requests": total_requests - malicious_count,
                "malicious_rate": malicious_count / total_requests,
                "threat_type_distribution": dict(threat_types),
                "flag_distribution": dict(flag_distribution),
                "ml_available": ML_AVAILABLE,
                "model_loaded": self._model is not None
            }


# Global instance
ai_heuristics_manager = AIHeuristicsManager()
