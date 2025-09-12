"""
Módulo de geolocalización para obtener información de país desde dirección IP
"""

import logging
from typing import Optional, Dict, Any
from ip2geotools.databases.noncommercial import DbIpCity
from ip2geotools.errors import LocationDatabaseError, InvalidRequestError, IPAddressNotFoundError

logger = logging.getLogger(__name__)

class GeolocationService:
    """Servicio para obtener información de geolocalización desde IP"""
    
    def __init__(self):
        self.cache = {}  # Cache simple para evitar llamadas repetidas
        
    def get_country_from_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Obtiene información de país desde una dirección IP
        
        Args:
            ip_address: Dirección IP a geolocalizar
            
        Returns:
            Diccionario con información de geolocalización:
            {
                'country_code': str,  # Código de país (ej: 'US', 'CO')
                'country_name': str,  # Nombre del país (ej: 'United States', 'Colombia')
                'city': str,          # Ciudad si está disponible
                'region': str,        # Región/estado si está disponible
                'latitude': float,    # Latitud si está disponible
                'longitude': float,   # Longitud si está disponible
                'success': bool,      # Si la consulta fue exitosa
                'error': str          # Mensaje de error si hubo algún problema
            }
        """
        # Verificar cache primero
        if ip_address in self.cache:
            return self.cache[ip_address]
            
        result = {
            'country_code': None,
            'country_name': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'success': False,
            'error': None
        }
        
        try:
            # IPs locales o privadas - no se pueden geolocalizar
            if self._is_private_ip(ip_address):
                result['error'] = 'Private IP address cannot be geolocated'
                result['country_code'] = 'LOCAL'
                result['country_name'] = 'Local Network'
                result['success'] = True
                self.cache[ip_address] = result
                return result
            
            # Obtener geolocalización desde la base de datos gratuita
            response = DbIpCity.get(ip_address, api_key='free')
            
            # Mapear la respuesta a nuestro formato
            result.update({
                'country_code': response.country,
                'country_name': self._get_country_name(response.country),
                'city': response.city,
                'region': response.region,
                'latitude': response.latitude,
                'longitude': response.longitude,
                'success': True,
                'error': None
            })
            
            logger.info(f"Geolocalización exitosa para IP {ip_address}: {result['country_name']}")
            
        except IPAddressNotFoundError:
            result['error'] = f'IP address not found in database: {ip_address}'
            logger.warning(f"IP no encontrada en base de datos: {ip_address}")
            
        except InvalidRequestError as e:
            result['error'] = f'Invalid request: {str(e)}'
            logger.error(f"Petición inválida para IP {ip_address}: {str(e)}")
            
        except LocationDatabaseError as e:
            result['error'] = f'Database error: {str(e)}'
            logger.error(f"Error de base de datos para IP {ip_address}: {str(e)}")
            
        except Exception as e:
            result['error'] = f'Unexpected error: {str(e)}'
            logger.error(f"Error inesperado geolocalizando IP {ip_address}: {str(e)}")
        
        # Guardar en cache
        self.cache[ip_address] = result
        return result
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Verifica si una IP es privada/local"""
        private_ranges = [
            '10.',           # 10.0.0.0/8
            '172.16.',       # 172.16.0.0/12
            '192.168.',      # 192.168.0.0/16
            '127.',          # 127.0.0.0/8 (localhost)
            '169.254.',      # 169.254.0.0/16 (link-local)
            '::1',           # IPv6 localhost
            'fc00::',        # IPv6 unique local addresses
            'fe80::'         # IPv6 link-local
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
    def _get_country_name(self, country_code: str) -> str:
        """Obtiene el nombre del país desde el código ISO"""
        country_names = {
            'US': 'United States',
            'CO': 'Colombia', 
            'MX': 'Mexico',
            'ES': 'Spain',
            'AR': 'Argentina',
            'BR': 'Brazil',
            'CL': 'Chile',
            'PE': 'Peru',
            'VE': 'Venezuela',
            'EC': 'Ecuador',
            'BO': 'Bolivia',
            'PY': 'Paraguay',
            'UY': 'Uruguay',
            'GY': 'Guyana',
            'SR': 'Suriname',
            'GF': 'French Guiana',
            'CA': 'Canada',
            'GB': 'United Kingdom',
            'DE': 'Germany',
            'FR': 'France',
            'IT': 'Italy',
            'PT': 'Portugal',
            'NL': 'Netherlands',
            'BE': 'Belgium',
            'CH': 'Switzerland',
            'AT': 'Austria',
            'SE': 'Sweden',
            'NO': 'Norway',
            'DK': 'Denmark',
            'FI': 'Finland',
            'IE': 'Ireland',
            'PL': 'Poland',
            'CZ': 'Czech Republic',
            'HU': 'Hungary',
            'GR': 'Greece',
            'TR': 'Turkey',
            'RU': 'Russia',
            'CN': 'China',
            'JP': 'Japan',
            'KR': 'South Korea',
            'IN': 'India',
            'AU': 'Australia',
            'NZ': 'New Zealand',
            'ZA': 'South Africa',
            'EG': 'Egypt',
            'NG': 'Nigeria',
            'KE': 'Kenya',
            'MA': 'Morocco',
            'DZ': 'Algeria',
            'TN': 'Tunisia',
            'SA': 'Saudi Arabia',
            'AE': 'United Arab Emirates',
            'IL': 'Israel',
            'TH': 'Thailand',
            'VN': 'Vietnam',
            'PH': 'Philippines',
            'MY': 'Malaysia',
            'SG': 'Singapore',
            'ID': 'Indonesia',
            'PK': 'Pakistan',
            'BD': 'Bangladesh',
            'LK': 'Sri Lanka',
            'MM': 'Myanmar',
            'KH': 'Cambodia',
            'LA': 'Laos',
            'NP': 'Nepal',
            'BT': 'Bhutan',
            'MV': 'Maldives',
            'AF': 'Afghanistan',
            'IR': 'Iran',
            'IQ': 'Iraq',
            'SY': 'Syria',
            'LB': 'Lebanon',
            'JO': 'Jordan',
            'PS': 'Palestine',
            'YE': 'Yemen',
            'OM': 'Oman',
            'QA': 'Qatar',
            'KW': 'Kuwait',
            'BH': 'Bahrain',
            'CY': 'Cyprus',
            'MT': 'Malta',
            'IS': 'Iceland',
            'LU': 'Luxembourg',
            'MC': 'Monaco',
            'AD': 'Andorra',
            'LI': 'Liechtenstein',
            'SM': 'San Marino',
            'VA': 'Vatican City',
            'MD': 'Moldova',
            'RO': 'Romania',
            'BG': 'Bulgaria',
            'HR': 'Croatia',
            'SI': 'Slovenia',
            'BA': 'Bosnia and Herzegovina',
            'ME': 'Montenegro',
            'RS': 'Serbia',
            'MK': 'North Macedonia',
            'AL': 'Albania',
            'XK': 'Kosovo',
            'LV': 'Latvia',
            'LT': 'Lithuania',
            'EE': 'Estonia',
            'SK': 'Slovakia',
            'UA': 'Ukraine',
            'BY': 'Belarus',
            'GE': 'Georgia',
            'AM': 'Armenia',
            'AZ': 'Azerbaijan',
            'KZ': 'Kazakhstan',
            'UZ': 'Uzbekistan',
            'KG': 'Kyrgyzstan',
            'TJ': 'Tajikistan',
            'TM': 'Turkmenistan',
            'MN': 'Mongolia',
            'KP': 'North Korea',
            'TW': 'Taiwan',
            'HK': 'Hong Kong',
            'MO': 'Macau',
            'BD': 'Bangladesh',
            'LK': 'Sri Lanka',
            'MM': 'Myanmar',
            'KH': 'Cambodia',
            'LA': 'Laos',
            'NP': 'Nepal',
            'BT': 'Bhutan',
            'MV': 'Maldives',
        }
        
        return country_names.get(country_code.upper(), country_code.upper())

# Instancia global del servicio
geolocation_service = GeolocationService()
