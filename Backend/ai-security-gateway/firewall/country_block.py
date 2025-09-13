"""
Country-based Blocking Module
Handles blocking requests based on country of origin using GeoIP database
"""

import os
import ipaddress
from typing import Optional, Dict, List
import threading

try:
    import maxminddb
    MAXMIND_AVAILABLE = True
except ImportError:
    MAXMIND_AVAILABLE = False

from .config import (
    BLOCKED_COUNTRIES_INITIAL,
    GEOIP_DB_PATH,
    DEBUG_MODE
)


class CountryBlockManager:
    """
    Manages country-based IP blocking using GeoIP database
    """
    
    def __init__(self):
        self._blocked_countries: set = set(BLOCKED_COUNTRIES_INITIAL)
        self._geoip_reader = None
        self._lock = threading.RLock()
        self._cache: Dict[str, Optional[str]] = {}  # IP -> country code cache
        self._cache_lock = threading.RLock()
        self._initialize_geoip()
    
    def _initialize_geoip(self) -> None:
        """Initialize GeoIP database reader"""
        if not MAXMIND_AVAILABLE:
            if DEBUG_MODE:
                print("MaxMindDB not available. Country blocking disabled.")
            return
        
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self._geoip_reader = maxminddb.open_database(GEOIP_DB_PATH)
                if DEBUG_MODE:
                    print(f"Loaded GeoIP database from: {GEOIP_DB_PATH}")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Error loading GeoIP database: {e}")
        else:
            if DEBUG_MODE:
                print(f"GeoIP database not found at: {GEOIP_DB_PATH}")
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def get_country_from_ip(self, ip_address: str) -> Optional[str]:
        """
        Get country code from IP address using GeoIP database
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            str: Two-letter country code or None if not found
        """
        if not self._is_valid_ip(ip_address):
            return None
        
        # Check cache first
        with self._cache_lock:
            if ip_address in self._cache:
                return self._cache[ip_address]
        
        if not self._geoip_reader:
            return None
        
        try:
            response = self._geoip_reader.get(ip_address)
            if response and 'country' in response and 'iso_code' in response['country']:
                country_code = response['country']['iso_code']
                
                # Cache the result
                with self._cache_lock:
                    self._cache[ip_address] = country_code
                
                if DEBUG_MODE:
                    print(f"IP {ip_address} -> Country: {country_code}")
                
                return country_code
        except Exception as e:
            if DEBUG_MODE:
                print(f"Error looking up country for IP {ip_address}: {e}")
        
        # Cache negative result
        with self._cache_lock:
            self._cache[ip_address] = None
        
        return None
    
    def get_country_info(self, ip_address: str) -> Optional[Dict]:
        """
        Get detailed country information from IP address
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dict: Country information or None if not found
        """
        if not self._is_valid_ip(ip_address) or not self._geoip_reader:
            return None
        
        try:
            response = self._geoip_reader.get(ip_address)
            if response:
                country_info = {}
                
                if 'country' in response:
                    country_info['country_code'] = response['country'].get('iso_code')
                    country_info['country_name'] = response['country'].get('names', {}).get('en')
                
                if 'continent' in response:
                    country_info['continent_code'] = response['continent'].get('code')
                    country_info['continent_name'] = response['continent'].get('names', {}).get('en')
                
                if 'registered_country' in response:
                    country_info['registered_country_code'] = response['registered_country'].get('iso_code')
                    country_info['registered_country_name'] = response['registered_country'].get('names', {}).get('en')
                
                return country_info if country_info else None
        except Exception as e:
            if DEBUG_MODE:
                print(f"Error getting country info for IP {ip_address}: {e}")
        
        return None
    
    def is_country_blocked(self, ip_address: str) -> bool:
        """
        Check if the country of the given IP is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if the country is blocked
        """
        country_code = self.get_country_from_ip(ip_address)
        
        if country_code is None:
            # If we can't determine the country, don't block
            return False
        
        with self._lock:
            is_blocked = country_code in self._blocked_countries
        
        if DEBUG_MODE and is_blocked:
            print(f"Blocked request from {ip_address} (Country: {country_code})")
        
        return is_blocked
    
    def add_blocked_country(self, country_code: str) -> bool:
        """
        Add a country to the blocked list
        
        Args:
            country_code: Two-letter country code to block
            
        Returns:
            bool: True if country was added successfully
        """
        if not isinstance(country_code, str) or len(country_code) != 2:
            if DEBUG_MODE:
                print(f"Invalid country code: {country_code}")
            return False
        
        country_code = country_code.upper()
        
        with self._lock:
            if country_code not in self._blocked_countries:
                self._blocked_countries.add(country_code)
                if DEBUG_MODE:
                    print(f"Added country to block list: {country_code}")
                return True
        
        return False
    
    def remove_blocked_country(self, country_code: str) -> bool:
        """
        Remove a country from the blocked list
        
        Args:
            country_code: Two-letter country code to unblock
            
        Returns:
            bool: True if country was removed successfully
        """
        if not isinstance(country_code, str) or len(country_code) != 2:
            return False
        
        country_code = country_code.upper()
        
        with self._lock:
            if country_code in self._blocked_countries:
                self._blocked_countries.remove(country_code)
                if DEBUG_MODE:
                    print(f"Removed country from block list: {country_code}")
                return True
        
        return False
    
    def get_blocked_countries(self) -> List[str]:
        """
        Get list of blocked country codes
        
        Returns:
            List[str]: List of blocked country codes
        """
        with self._lock:
            return sorted(list(self._blocked_countries))
    
    def is_country_code_blocked(self, country_code: str) -> bool:
        """
        Check if a specific country code is blocked
        
        Args:
            country_code: Two-letter country code to check
            
        Returns:
            bool: True if the country is blocked
        """
        if not isinstance(country_code, str) or len(country_code) != 2:
            return False
        
        country_code = country_code.upper()
        
        with self._lock:
            return country_code in self._blocked_countries
    
    def clear_cache(self) -> None:
        """Clear the IP-to-country cache"""
        with self._cache_lock:
            self._cache.clear()
        if DEBUG_MODE:
            print("Country lookup cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """
        Get cache statistics
        
        Returns:
            Dict: Cache statistics
        """
        with self._cache_lock:
            total_entries = len(self._cache)
            positive_lookups = sum(1 for country in self._cache.values() if country is not None)
            negative_lookups = total_entries - positive_lookups
            
            return {
                "total_cache_entries": total_entries,
                "positive_lookups": positive_lookups,
                "negative_lookups": negative_lookups,
                "cache_hit_rate": positive_lookups / total_entries if total_entries > 0 else 0
            }
    
    def get_statistics(self) -> Dict:
        """
        Get country blocking statistics
        
        Returns:
            Dict: Statistics about country blocking
        """
        with self._lock:
            return {
                "blocked_countries_count": len(self._blocked_countries),
                "blocked_countries": sorted(list(self._blocked_countries)),
                "geoip_available": self._geoip_reader is not None,
                "cache_stats": self.get_cache_stats()
            }
    
    def close(self) -> None:
        """Close GeoIP database reader"""
        if self._geoip_reader:
            try:
                self._geoip_reader.close()
                if DEBUG_MODE:
                    print("GeoIP database reader closed")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Error closing GeoIP database: {e}")
            finally:
                self._geoip_reader = None
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        self.close()


# Global instance
country_block_manager = CountryBlockManager()
