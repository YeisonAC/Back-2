"""
IP Blacklist Management Module
Handles static and dynamic IP blacklisting with persistence
"""

import os
import time
import threading
from typing import Set, Dict, List, Optional
from datetime import datetime, timedelta
import ipaddress

from .config import (
    BLOCKED_IPS_INITIAL,
    IP_BLACKLIST_FILE,
    TEMPORARY_BLOCK_DURATION,
    DEBUG_MODE
)


class IPBlacklistManager:
    """
    Manages IP blacklist operations including static and dynamic blocking
    """
    
    def __init__(self):
        self._static_blacklist: Set[str] = set()
        self._dynamic_blacklist: Dict[str, float] = {}  # IP -> expiration timestamp
        self._lock = threading.RLock()
        self._load_initial_blacklist()
        
    def _load_initial_blacklist(self) -> None:
        """Load initial blacklist from configuration and file"""
        with self._lock:
            # Load from configuration
            self._static_blacklist.update(BLOCKED_IPS_INITIAL)
            
            # Load from file if it exists
            if os.path.exists(IP_BLACKLIST_FILE):
                try:
                    with open(IP_BLACKLIST_FILE, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                self._static_blacklist.add(line)
                    if DEBUG_MODE:
                        print(f"Loaded {len(self._static_blacklist)} IPs from blacklist file")
                except Exception as e:
                    print(f"Error loading blacklist file: {e}")
    
    def _save_blacklist_to_file(self) -> None:
        """Save static blacklist to file"""
        try:
            with open(IP_BLACKLIST_FILE, 'w') as f:
                for ip in sorted(self._static_blacklist):
                    f.write(f"{ip}\n")
        except Exception as e:
            print(f"Error saving blacklist to file: {e}")
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def add_ip(self, ip_address: str, permanent: bool = True) -> bool:
        """
        Add an IP to the blacklist
        
        Args:
            ip_address: IP address to block
            permanent: If True, add to static blacklist; if False, add to dynamic
            
        Returns:
            bool: True if IP was added successfully
        """
        if not self._is_valid_ip(ip_address):
            if DEBUG_MODE:
                print(f"Invalid IP address: {ip_address}")
            return False
        
        with self._lock:
            if permanent:
                if ip_address not in self._static_blacklist:
                    self._static_blacklist.add(ip_address)
                    self._save_blacklist_to_file()
                    if DEBUG_MODE:
                        print(f"Added IP to static blacklist: {ip_address}")
                    return True
            else:
                # Add to dynamic blacklist with expiration
                expiration_time = time.time() + TEMPORARY_BLOCK_DURATION
                self._dynamic_blacklist[ip_address] = expiration_time
                if DEBUG_MODE:
                    print(f"Added IP to dynamic blacklist: {ip_address} (expires in {TEMPORARY_BLOCK_DURATION}s)")
                return True
        
        return False
    
    def remove_ip(self, ip_address: str) -> bool:
        """
        Remove an IP from both static and dynamic blacklists
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            bool: True if IP was removed successfully
        """
        with self._lock:
            removed = False
            
            # Remove from static blacklist
            if ip_address in self._static_blacklist:
                self._static_blacklist.remove(ip_address)
                self._save_blacklist_to_file()
                removed = True
                if DEBUG_MODE:
                    print(f"Removed IP from static blacklist: {ip_address}")
            
            # Remove from dynamic blacklist
            if ip_address in self._dynamic_blacklist:
                del self._dynamic_blacklist[ip_address]
                removed = True
                if DEBUG_MODE:
                    print(f"Removed IP from dynamic blacklist: {ip_address}")
            
            return removed
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if IP is blocked
        """
        if not self._is_valid_ip(ip_address):
            return False
        
        with self._lock:
            # Check static blacklist first
            if ip_address in self._static_blacklist:
                return True
            
            # Check dynamic blacklist and clean up expired entries
            current_time = time.time()
            expired_ips = []
            
            for ip, expiration in self._dynamic_blacklist.items():
                if current_time > expiration:
                    expired_ips.append(ip)
                elif ip == ip_address:
                    return True
            
            # Clean up expired entries
            for ip in expired_ips:
                del self._dynamic_blacklist[ip]
                if DEBUG_MODE:
                    print(f"Removed expired dynamic block: {ip}")
            
            return False
    
    def block_ip_temporarily(self, ip_address: str, duration: int = None) -> bool:
        """
        Block an IP temporarily for a specified duration
        
        Args:
            ip_address: IP address to block
            duration: Block duration in seconds (uses default if None)
            
        Returns:
            bool: True if IP was blocked successfully
        """
        if duration is None:
            duration = TEMPORARY_BLOCK_DURATION
        
        if not self._is_valid_ip(ip_address):
            return False
        
        with self._lock:
            expiration_time = time.time() + duration
            self._dynamic_blacklist[ip_address] = expiration_time
            if DEBUG_MODE:
                print(f"Temporarily blocked IP: {ip_address} for {duration}s")
            return True
    
    def get_dynamically_blocked_ips(self) -> List[str]:
        """
        Get list of currently dynamically blocked IPs
        
        Returns:
            List[str]: List of dynamically blocked IPs
        """
        with self._lock:
            current_time = time.time()
            active_ips = []
            
            for ip, expiration in self._dynamic_blacklist.items():
                if current_time <= expiration:
                    active_ips.append(ip)
            
            return active_ips
    
    def get_statically_blocked_ips(self) -> List[str]:
        """
        Get list of statically blocked IPs
        
        Returns:
            List[str]: List of statically blocked IPs
        """
        with self._lock:
            return list(self._static_blacklist)
    
    def get_all_blocked_ips(self) -> List[str]:
        """
        Get list of all blocked IPs (static + dynamic)
        
        Returns:
            List[str]: List of all blocked IPs
        """
        static_ips = self.get_statically_blocked_ips()
        dynamic_ips = self.get_dynamically_blocked_ips()
        return static_ips + dynamic_ips
    
    def get_block_info(self, ip_address: str) -> Optional[Dict]:
        """
        Get information about why an IP is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dict: Block information or None if not blocked
        """
        if not self.is_blocked(ip_address):
            return None
        
        with self._lock:
            if ip_address in self._static_blacklist:
                return {
                    "ip": ip_address,
                    "type": "static",
                    "reason": "Manually blacklisted"
                }
            elif ip_address in self._dynamic_blacklist:
                expiration = self._dynamic_blacklist[ip_address]
                remaining_time = max(0, expiration - time.time())
                return {
                    "ip": ip_address,
                    "type": "dynamic",
                    "reason": "Temporary block",
                    "expires_in": remaining_time,
                    "expires_at": datetime.fromtimestamp(expiration).isoformat()
                }
        
        return None
    
    def cleanup_expired_blocks(self) -> int:
        """
        Clean up expired dynamic blocks
        
        Returns:
            int: Number of expired blocks removed
        """
        with self._lock:
            current_time = time.time()
            expired_ips = []
            
            for ip, expiration in self._dynamic_blacklist.items():
                if current_time > expiration:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del self._dynamic_blacklist[ip]
            
            if DEBUG_MODE and expired_ips:
                print(f"Cleaned up {len(expired_ips)} expired dynamic blocks")
            
            return len(expired_ips)
    
    def get_statistics(self) -> Dict:
        """
        Get blacklist statistics
        
        Returns:
            Dict: Statistics about the blacklist
        """
        with self._lock:
            current_time = time.time()
            active_dynamic = sum(1 for exp in self._dynamic_blacklist.values() if exp > current_time)
            expired_dynamic = len(self._dynamic_blacklist) - active_dynamic
            
            return {
                "static_blocked_count": len(self._static_blacklist),
                "dynamic_blocked_count": active_dynamic,
                "expired_dynamic_count": expired_dynamic,
                "total_blocked_count": len(self._static_blacklist) + active_dynamic
            }


# Global instance
ip_blacklist_manager = IPBlacklistManager()
