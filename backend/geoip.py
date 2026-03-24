"""
GeoIP lookup module for Fail2Ban SOC Dashboard.
Supports both offline database and online API fallback.
"""
import asyncio
import ipaddress
from typing import Dict, List, Optional, Tuple
from functools import lru_cache
import aiohttp
from cachetools import TTLCache

# Cache for GeoIP results (TTL: 24 hours, max 10000 entries)
_geoip_cache: TTLCache = TTLCache(maxsize=10000, ttl=86400)

# Online GeoIP service (free tier)
_GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,countryCode,country"
_GEOIP_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,country,query"


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


async def get_country_codes_batch(ips: List[str]) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """
    Batch GeoIP lookup for up to 100 IPs per call (ip-api.com batch endpoint).
    Returns dict of ip -> (country_code, country_name).
    """
    results: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    valid_ips = [ip for ip in ips if validate_ip(ip) and ip not in _geoip_cache]

    # Process in batches of 100 (ip-api.com limit)
    for i in range(0, len(valid_ips), 100):
        batch = valid_ips[i:i + 100]
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _GEOIP_BATCH_URL,
                    json=[{"query": ip} for ip in batch],
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            ip = entry.get("query", "")
                            if entry.get("status") == "success":
                                cc = entry.get("countryCode")
                                cn = entry.get("country")
                                _geoip_cache[ip] = {"country_code": cc, "country_name": cn}
                                results[ip] = (cc, cn)
                            else:
                                results[ip] = (None, None)
        except Exception:
            # On failure, mark all in this batch as unknown
            for ip in batch:
                results[ip] = (None, None)

    # Also return cached results for IPs already in cache
    for ip in ips:
        if ip in _geoip_cache and ip not in results:
            cached = _geoip_cache[ip]
            results[ip] = (cached["country_code"], cached["country_name"])

    return results


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
