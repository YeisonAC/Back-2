"""
Firewall Logging Module
Handles security event logging and admin alerts
"""

import os
import json
import time
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, asdict
import logging
from logging.handlers import RotatingFileHandler

from .config import (
    LOG_LEVEL,
    LOG_FILE,
    ENABLE_ADMIN_ALERTS,
    ADMIN_EMAIL,
    ALERT_COOLDOWN_SECONDS,
    DEBUG_MODE
)


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    source_ip: str
    details: str
    timestamp: float
    rule_triggered: str
    request_data: Optional[Dict[str, Any]] = None
    threat_analysis: Optional[Dict[str, Any]] = None
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL


class FirewallLogger:
    """
    Handles security event logging and admin notifications
    """
    
    def __init__(self):
        self._events: List[SecurityEvent] = []
        self._events_lock = threading.RLock()
        self._last_alert_time: Dict[str, float] = {}
        self._alert_lock = threading.RLock()
        
        # Setup Python logging
        self._setup_logging()
        
        if DEBUG_MODE:
            print("Firewall Logger initialized")
    
    def _setup_logging(self) -> None:
        """Setup Python logging configuration"""
        # Detectar si estamos en Vercel
        is_vercel = os.environ.get('VERCEL', '').lower() == '1' or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') is not None
        
        if is_vercel:
            # En Vercel/serverless, no usar archivo de log, solo console
            logging.basicConfig(
                level=getattr(logging, LOG_LEVEL.upper()),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.StreamHandler()  # Solo log a console
                ]
            )
            if DEBUG_MODE:
                print("Firewall Logger initialized for Vercel (console only)")
        else:
            # En entorno local, usar archivo de log
            # Create logs directory if it doesn't exist
            log_dir = os.path.dirname(LOG_FILE)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Configure logging
            logging.basicConfig(
                level=getattr(logging, LOG_LEVEL.upper()),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    RotatingFileHandler(
                        LOG_FILE,
                        maxBytes=10*1024*1024,  # 10MB
                        backupCount=5
                    ),
                    logging.StreamHandler()  # Also log to console
                ]
            )
            if DEBUG_MODE:
                print("Firewall Logger initialized for local environment")
        
        self.logger = logging.getLogger('Firewall')
    
    def log_event(self, event_type: str, source_ip: str, details: str, 
                  request_data: Optional[Dict[str, Any]] = None,
                  rule_triggered: str = "UNKNOWN",
                  threat_analysis: Optional[Dict[str, Any]] = None,
                  severity: str = "INFO") -> None:
        """
        Log a security event
        
        Args:
            event_type: Type of event (e.g., "BLOCKED_IP", "ALLOWED")
            source_ip: Source IP address
            details: Event details
            request_data: Original request data
            rule_triggered: Which rule triggered this event
            threat_analysis: AI threat analysis if applicable
            severity: Event severity level
        """
        event = SecurityEvent(
            event_type=event_type,
            source_ip=source_ip,
            details=details,
            timestamp=time.time(),
            rule_triggered=rule_triggered,
            request_data=request_data,
            threat_analysis=threat_analysis,
            severity=severity
        )
        
        # Add to in-memory events list
        with self._events_lock:
            self._events.append(event)
            
            # Keep only last 10000 events in memory
            if len(self._events) > 10000:
                self._events = self._events[-10000:]
        
        # Log to Python logger
        log_message = f"[{event_type}] IP: {source_ip} | Rule: {rule_triggered} | Details: {details}"
        
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "ERROR":
            self.logger.error(log_message)
        elif severity == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log detailed information if debug mode is enabled
        if DEBUG_MODE and request_data:
            self.logger.debug(f"Request data: {json.dumps(request_data, indent=2)}")
        
        if DEBUG_MODE and threat_analysis:
            self.logger.debug(f"Threat analysis: {json.dumps(threat_analysis, indent=2)}")
    
    def alert_admin(self, message: str, request_data: Optional[Dict[str, Any]] = None,
                   threat_analysis: Optional[Dict[str, Any]] = None,
                   alert_type: str = "THREAT_DETECTED") -> None:
        """
        Send alert to administrator
        
        Args:
            message: Alert message
            request_data: Related request data
            threat_analysis: Related threat analysis
            alert_type: Type of alert
        """
        if not ENABLE_ADMIN_ALERTS:
            return
        
        # Check alert cooldown
        with self._alert_lock:
            current_time = time.time()
            last_alert = self._last_alert_time.get(alert_type, 0)
            
            if current_time - last_alert < ALERT_COOLDOWN_SECONDS:
                if DEBUG_MODE:
                    print(f"Alert cooldown active for {alert_type}. Skipping alert.")
                return
            
            self._last_alert_time[alert_type] = current_time
        
        # Log the alert as a critical event
        self.log_event(
            event_type="ADMIN_ALERT",
            source_ip=request_data.get('client_ip', 'unknown') if request_data else 'unknown',
            details=f"Admin Alert: {message}",
            request_data=request_data,
            rule_triggered="ADMIN_ALERT",
            threat_analysis=threat_analysis,
            severity="CRITICAL"
        )
        
        # Send email alert (in a real implementation, you would use email service)
        self._send_email_alert(message, request_data, threat_analysis)
        
        if DEBUG_MODE:
            print(f"Admin alert sent: {message}")
    
    def _send_email_alert(self, message: str, request_data: Optional[Dict[str, Any]] = None,
                         threat_analysis: Optional[Dict[str, Any]] = None) -> None:
        """
        Send email alert to administrator
        
        Args:
            message: Alert message
            request_data: Related request data
            threat_analysis: Related threat analysis
        """
        # In a real implementation, you would use an email service like SMTP
        # For now, we'll just log the email content
        
        email_subject = f"Firewall Security Alert: {message}"
        email_body = f"""
Security Alert from Firewall

Alert Message: {message}
Timestamp: {datetime.now().isoformat()}

Request Details:
{json.dumps(request_data, indent=2) if request_data else 'No request data available'}

Threat Analysis:
{json.dumps(threat_analysis, indent=2) if threat_analysis else 'No threat analysis available'}

Please investigate this alert immediately.

---
Firewall Security System
        """
        
        # Log email content (in production, you would actually send the email)
        self.logger.info(f"EMAIL ALERT - To: {ADMIN_EMAIL}")
        self.logger.info(f"EMAIL ALERT - Subject: {email_subject}")
        self.logger.info(f"EMAIL ALERT - Body: {email_body}")
    
    def get_events(self, limit: int = 100, offset: int = 0, 
                   event_type: Optional[str] = None,
                   source_ip: Optional[str] = None,
                   severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get security events with filtering
        
        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            event_type: Filter by event type
            source_ip: Filter by source IP
            severity: Filter by severity
            
        Returns:
            List[Dict]: List of security events
        """
        with self._events_lock:
            filtered_events = []
            
            for event in self._events:
                # Apply filters
                if event_type and event.event_type != event_type:
                    continue
                if source_ip and event.source_ip != source_ip:
                    continue
                if severity and event.severity != severity:
                    continue
                
                filtered_events.append(event)
            
            # Apply pagination
            start_idx = min(offset, len(filtered_events))
            end_idx = min(start_idx + limit, len(filtered_events))
            paginated_events = filtered_events[start_idx:end_idx]
            
            # Convert to dictionaries
            return [asdict(event) for event in paginated_events]
    
    def get_event_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about security events
        
        Returns:
            Dict: Event statistics
        """
        with self._events_lock:
            if not self._events:
                return {
                    "total_events": 0,
                    "event_types": {},
                    "severity_distribution": {},
                    "top_blocked_ips": [],
                    "top_triggered_rules": {}
                }
            
            # Count by event type
            event_types = {}
            for event in self._events:
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            # Count by severity
            severity_distribution = {}
            for event in self._events:
                severity_distribution[event.severity] = severity_distribution.get(event.severity, 0) + 1
            
            # Top blocked IPs
            ip_counts = {}
            for event in self._events:
                if event.event_type.startswith("BLOCKED"):
                    ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1
            
            top_blocked_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Top triggered rules
            rule_counts = {}
            for event in self._events:
                rule_counts[event.rule_triggered] = rule_counts.get(event.rule_triggered, 0) + 1
            
            return {
                "total_events": len(self._events),
                "event_types": event_types,
                "severity_distribution": severity_distribution,
                "top_blocked_ips": top_blocked_ips,
                "top_triggered_rules": rule_counts
            }
    
    def get_recent_events(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Get events from the last N minutes
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List[Dict]: Recent events
        """
        current_time = time.time()
        cutoff_time = current_time - (minutes * 60)
        
        with self._events_lock:
            recent_events = [
                event for event in self._events
                if event.timestamp >= cutoff_time
            ]
            
            return [asdict(event) for event in recent_events]
    
    def clear_events(self) -> None:
        """Clear all events from memory"""
        with self._events_lock:
            self._events.clear()
        self.logger.info("All security events cleared from memory")
    
    def export_events(self, filename: str, format_type: str = "json") -> bool:
        """
        Export events to file
        
        Args:
            filename: Output filename
            format_type: Export format ('json' or 'csv')
            
        Returns:
            bool: True if export successful
        """
        # Detectar si estamos en Vercel
        is_vercel = os.environ.get('VERCEL', '').lower() == '1' or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') is not None
        
        if is_vercel:
            self.logger.warning("Export events not available in Vercel environment (read-only filesystem)")
            return False
        
        try:
            with self._events_lock:
                events_data = [asdict(event) for event in self._events]
            
            if format_type.lower() == "json":
                with open(filename, 'w') as f:
                    json.dump(events_data, f, indent=2)
            elif format_type.lower() == "csv":
                import csv
                if events_data:
                    with open(filename, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=events_data[0].keys())
                        writer.writeheader()
                        writer.writerows(events_data)
            else:
                self.logger.error(f"Unsupported export format: {format_type}")
                return False
            
            self.logger.info(f"Exported {len(events_data)} events to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting events: {e}")
            return False
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get history of admin alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List[Dict]: Alert history
        """
        return self.get_events(
            limit=limit,
            event_type="ADMIN_ALERT",
            severity="CRITICAL"
        )


# Global instance
firewall_logger = FirewallLogger()

# Convenience functions for backward compatibility
def log_event(event_type: str, source_ip: str, details: str, 
              request_data: Optional[Dict[str, Any]] = None,
              rule_triggered: str = "UNKNOWN",
              threat_analysis: Optional[Dict[str, Any]] = None,
              severity: str = "INFO") -> None:
    """Convenience function for logging events"""
    firewall_logger.log_event(
        event_type, source_ip, details, request_data, 
        rule_triggered, threat_analysis, severity
    )

def alert_admin(message: str, request_data: Optional[Dict[str, Any]] = None,
               threat_analysis: Optional[Dict[str, Any]] = None,
               alert_type: str = "THREAT_DETECTED") -> None:
    """Convenience function for sending admin alerts"""
    firewall_logger.alert_admin(message, request_data, threat_analysis, alert_type)
