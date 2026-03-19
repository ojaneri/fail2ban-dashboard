"""
GeoIP lookup module for Fail2Ban SOC Dashboard.
Supports both offline database and online API fallback.
"""
import asyncio
import ipaddress
from typing import Optional, Tuple
from functools import lru_cache
import aiohttp
from cachetools import TTLCache

# Cache for GeoIP results (TTL: 24 hours, max 10000 entries)
_geoip_cache: TTLCache = TTLCache(maxsize=10000, ttl=86400)

# Online GeoIP service (free tier)
_GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,countryCode,country"


class GeoIPError(Exception):
    """Custom exception for GeoIP lookup errors."""
    pass


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/reserved.
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is private or reserved, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_reserved
    except ValueError:
        return True


def validate_ip(ip: str) -> bool:
    """
    Validate IP address format and ensure it's not private.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid and not private, False otherwise
    """
    if not ip:
        return False
    
    # Check for valid IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    
    # Reject private IPs
    if is_private_ip(ip):
        return False
    
    return True


async def get_country_code_async(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Get country code and name for an IP address.
    Uses cache first, then falls back to online API.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Tuple of (country_code, country_name) or (None, None) if not found
    """
    # Validate IP
    if not validate_ip(ip):
        return None, None
    
    # Check cache first
    if ip in _geoip_cache:
        cached = _geoip_cache[ip]
        return cached["country_code"], cached["country_name"]
    
    try:
        # Try online API
        country_code, country_name = await _fetch_geoip_online(ip)
        
        # Cache the result
        _geoip_cache[ip] = {
            "country_code": country_code,
            "country_name": country_name
        }
        
        return country_code, country_name
        
    except Exception as e:
        # Log error and return unknown
        return None, None


async def _fetch_geoip_online(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetch GeoIP data from online API.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Tuple of (country_code, country_name)
    """
    # Skip private IPs
    if is_private_ip(ip):
        return None, None
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(_GEOIP_API_URL.format(ip=ip), timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        country_code = data.get("countryCode")
                        country_name = data.get("country")
                        return country_code, country_name
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    
    return None, None


def get_country_code(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Synchronous wrapper for GeoIP lookup.
    Note: Prefer using async version for better performance.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Tuple of (country_code, country_name) or (None, None) if not found
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, create a new task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, get_country_code_async(ip))
                return future.result()
        else:
            return asyncio.run(get_country_code_async(ip))
    except RuntimeError:
        # If no event loop exists, create one
        return asyncio.run(get_country_code_async(ip))


def clear_cache() -> None:
    """Clear the GeoIP cache."""
    _geoip_cache.clear()


def get_cache_size() -> int:
    """Get current cache size."""
    return len(_geoip_cache)


# Country code to name mapping for fallback
_COUNTRY_NAMES = {
    "US": "United States",
    "CN": "China",
    "RU": "Russia",
    "BR": "Brazil",
    "IN": "India",
    "DE": "Germany",
    "FR": "France",
    "UK": "United Kingdom",
    "JP": "Japan",
    "KR": "South Korea",
    "NL": "Netherlands",
    "CA": "Canada",
    "AU": "Australia",
    "IT": "Italy",
    "ES": "Spain",
    "MX": "Mexico",
    "ID": "Indonesia",
    "TR": "Turkey",
    "PL": "Poland",
    "UA": "Ukraine",
    "RO": "Romania",
    "VN": "Vietnam",
    "TH": "Thailand",
    "AR": "Argentina",
    "CO": "Colombia",
    "CL": "Chile",
    "PE": "Peru",
    "VE": "Venezuela",
    "PH": "Philippines",
    "MY": "Malaysia",
    "SG": "Singapore",
    "PK": "Pakistan",
    "EG": "Egypt",
    "NG": "Nigeria",
    "ZA": "South Africa",
    "IR": "Iran",
    "IQ": "Iraq",
    "SA": "Saudi Arabia",
    "AE": "United Arab Emirates",
    "IL": "Israel",
}


def get_country_name(country_code: str) -> Optional[str]:
    """
    Get country name from country code.
    
    Args:
        country_code: Two-letter country code
        
    Returns:
        Country name or None if not found
    """
    return _COUNTRY_NAMES.get(country_code.upper())
