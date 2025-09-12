#!/usr/bin/env python3
"""
Servicio de geolocalización simplificado usando API externa
Compatible con entornos serverless como Vercel
"""

import requests
import json
from typing import Dict, Any, Optional
from functools import lru_cache

class SimpleGeolocationService:
    """Servicio de geolocalización usando ip-api.com (gratis y sin API key)"""
    
    def __init__(self):
        self.cache = {}
        # Mapeo de códigos de país a nombres
        self.country_names = {
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
            'UY': 'Uruguay',
            'PY': 'Paraguay',
            'BO': 'Bolivia',
            'CR': 'Costa Rica',
            'PA': 'Panama',
            'GT': 'Guatemala',
            'SV': 'El Salvador',
            'HN': 'Honduras',
            'NI': 'Nicaragua',
            'DO': 'Dominican Republic',
            'PR': 'Puerto Rico',
            'CU': 'Cuba',
            'HT': 'Haiti',
            'JM': 'Jamaica',
            'TT': 'Trinidad and Tobago',
            'BB': 'Barbados',
            'BS': 'Bahamas',
            'GD': 'Grenada',
            'LC': 'Saint Lucia',
            'VC': 'Saint Vincent and the Grenadines',
            'AG': 'Antigua and Barbuda',
            'DM': 'Dominica',
            'KN': 'Saint Kitts and Nevis',
            'CA': 'Canada',
            'GB': 'United Kingdom',
            'FR': 'France',
            'DE': 'Germany',
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
            'UA': 'Ukraine',
            'RO': 'Romania',
            'BG': 'Bulgaria',
            'HR': 'Croatia',
            'SI': 'Slovenia',
            'SK': 'Slovakia',
            'EE': 'Estonia',
            'LV': 'Latvia',
            'LT': 'Lithuania',
            'MT': 'Malta',
            'CY': 'Cyprus',
            'LU': 'Luxembourg',
            'IS': 'Iceland',
            'LI': 'Liechtenstein',
            'MC': 'Monaco',
            'AD': 'Andorra',
            'SM': 'San Marino',
            'VA': 'Vatican City',
            'MD': 'Moldova',
            'AL': 'Albania',
            'MK': 'North Macedonia',
            'RS': 'Serbia',
            'BA': 'Bosnia and Herzegovina',
            'ME': 'Montenegro',
            'XK': 'Kosovo',
            'BY': 'Belarus',
            'AM': 'Armenia',
            'GE': 'Georgia',
            'AZ': 'Azerbaijan',
            'KZ': 'Kazakhstan',
            'UZ': 'Uzbekistan',
            'KG': 'Kyrgyzstan',
            'TJ': 'Tajikistan',
            'TM': 'Turkmenistan',
            'AF': 'Afghanistan',
            'PK': 'Pakistan',
            'BD': 'Bangladesh',
            'IN': 'India',
            'NP': 'Nepal',
            'LK': 'Sri Lanka',
            'MV': 'Maldives',
            'BT': 'Bhutan',
            'MM': 'Myanmar',
            'TH': 'Thailand',
            'VN': 'Vietnam',
            'KH': 'Cambodia',
            'LA': 'Laos',
            'PH': 'Philippines',
            'MY': 'Malaysia',
            'SG': 'Singapore',
            'ID': 'Indonesia',
            'BN': 'Brunei',
            'TL': 'East Timor',
            'CN': 'China',
            'JP': 'Japan',
            'KR': 'South Korea',
            'KP': 'North Korea',
            'TW': 'Taiwan',
            'MN': 'Mongolia',
            'HK': 'Hong Kong',
            'MO': 'Macau',
            'AU': 'Australia',
            'NZ': 'New Zealand',
            'FJ': 'Fiji',
            'PG': 'Papua New Guinea',
            'SB': 'Solomon Islands',
            'VU': 'Vanuatu',
            'NC': 'New Caledonia',
            'PF': 'French Polynesia',
            'WS': 'Samoa',
            'TO': 'Tonga',
            'KI': 'Kiribati',
            'TV': 'Tuvalu',
            'NR': 'Nauru',
            'FM': 'Federated States of Micronesia',
            'MH': 'Marshall Islands',
            'PW': 'Palau',
            'MP': 'Northern Mariana Islands',
            'GU': 'Guam',
            'AS': 'American Samoa',
            'UM': 'United States Minor Outlying Islands',
            'ZA': 'South Africa',
            'EG': 'Egypt',
            'NG': 'Nigeria',
            'KE': 'Kenya',
            'GH': 'Ghana',
            'MA': 'Morocco',
            'TN': 'Tunisia',
            'DZ': 'Algeria',
            'LY': 'Libya',
            'SD': 'Sudan',
            'SS': 'South Sudan',
            'ET': 'Ethiopia',
            'SO': 'Somalia',
            'DJ': 'Djibouti',
            'ER': 'Eritrea',
            'UG': 'Uganda',
            'RW': 'Rwanda',
            'BI': 'Burundi',
            'TZ': 'Tanzania',
            'MZ': 'Mozambique',
            'ZM': 'Zambia',
            'ZW': 'Zimbabwe',
            'BW': 'Botswana',
            'NA': 'Namibia',
            'LS': 'Lesotho',
            'SZ': 'Eswatini',
            'MG': 'Madagascar',
            'MU': 'Mauritius',
            'SC': 'Seychelles',
            'KM': 'Comoros',
            'YT': 'Mayotte',
            'RE': 'Reunion',
            'AO': 'Angola',
            'CM': 'Cameroon',
            'CF': 'Central African Republic',
            'TD': 'Chad',
            'GQ': 'Equatorial Guinea',
            'GA': 'Gabon',
            'CG': 'Republic of the Congo',
            'CD': 'Democratic Republic of the Congo',
            'BJ': 'Benin',
            'TG': 'Togo',
            'BF': 'Burkina Faso',
            'ML': 'Mali',
            'MR': 'Mauritania',
            'SN': 'Senegal',
            'GM': 'Gambia',
            'GW': 'Guinea-Bissau',
            'GN': 'Guinea',
            'SL': 'Sierra Leone',
            'LR': 'Liberia',
            'CI': "Cote d'Ivoire",
            'GH': 'Ghana',
            'NE': 'Niger',
            'BJ': 'Benin',
            'NG': 'Nigeria',
            'CM': 'Cameroon',
            'TD': 'Chad',
            'CF': 'Central African Republic',
            'GQ': 'Equatorial Guinea',
            'GA': 'Gabon',
            'CG': 'Republic of the Congo',
            'CD': 'Democratic Republic of the Congo',
            'AO': 'Angola',
            'ZM': 'Zambia',
            'ZW': 'Zimbabwe',
            'MW': 'Malawi',
            'MZ': 'Mozambique',
            'LS': 'Lesotho',
            'BW': 'Botswana',
            'NA': 'Namibia',
            'SZ': 'Eswatini',
            'MG': 'Madagascar',
            'MU': 'Mauritius',
            'SC': 'Seychelles',
            'KM': 'Comoros',
            'ST': 'Sao Tome and Principe',
            'GW': 'Guinea-Bissau',
            'CV': 'Cape Verde',
            'GQ': 'Equatorial Guinea',
            'SH': 'Saint Helena',
            'AC': 'Ascension Island',
            'TA': 'Tristan da Cunha',
        }
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Verifica si una IP es privada o local"""
        if not ip_address or ip_address == "unknown":
            return True
            
        # IPs privadas IPv4
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),  # localhost
            ('169.254.0.0', '169.254.255.255'),  # link-local
        ]
        
        # Convertir IP a números para comparación
        try:
            ip_parts = [int(x) for x in ip_address.split('.')]
            ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            
            for start_ip, end_ip in private_ranges:
                start_parts = [int(x) for x in start_ip.split('.')]
                end_parts = [int(x) for x in end_ip.split('.')]
                start_num = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
                end_num = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
                
                if start_num <= ip_num <= end_num:
                    return True
        except (ValueError, IndexError):
            pass
            
        # IPs locales IPv6
        if ip_address.startswith('::1') or ip_address.startswith('fc00:') or ip_address.startswith('fd00:'):
            return True
            
        return False
    
    def _get_country_name(self, country_code: str) -> str:
        """Obtiene el nombre del país desde el código"""
        return self.country_names.get(country_code.upper(), country_code or 'Unknown')
    
    @lru_cache(maxsize=1000)
    def get_country_from_ip(self, ip_address: str) -> Dict[str, Any]:
        """Obtiene información de geolocalización desde una IP usando ip-api.com"""
        
        # Verificar si es una IP privada
        if self._is_private_ip(ip_address):
            return {
                'country_code': 'LOCAL',
                'country_name': 'Local Network',
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'success': True,
                'error': None
            }
        
        # Verificar caché
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            # Usar ip-api.com (gratis, sin API key, límite de 45 peticiones por minuto)
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result = {
                        'country_code': data.get('countryCode'),
                        'country_name': self._get_country_name(data.get('countryCode')),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'success': True,
                        'error': None
                    }
                else:
                    result = {
                        'country_code': None,
                        'country_name': None,
                        'city': None,
                        'region': None,
                        'latitude': None,
                        'longitude': None,
                        'success': False,
                        'error': data.get('message', 'Unknown error')
                    }
            else:
                result = {
                    'country_code': None,
                    'country_name': None,
                    'city': None,
                    'region': None,
                    'latitude': None,
                    'longitude': None,
                    'success': False,
                    'error': f'HTTP {response.status_code}'
                }
                
        except requests.exceptions.Timeout:
            result = {
                'country_code': None,
                'country_name': None,
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'success': False,
                'error': 'Timeout'
            }
        except requests.exceptions.RequestException as e:
            result = {
                'country_code': None,
                'country_name': None,
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            result = {
                'country_code': None,
                'country_name': None,
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
        
        # Guardar en caché
        self.cache[ip_address] = result
        return result

# Instancia global del servicio
simple_geolocation_service = SimpleGeolocationService()
