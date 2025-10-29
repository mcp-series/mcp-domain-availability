import asyncio
import socket
import time
import re
import os
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Domain Availability Checker", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

POPULAR_TLDS = [
    "com", "net", "org", "io", "ai", "app", "dev", "co", "xyz", "me", "info", "biz"
]

COUNTRY_TLDS = [
    "us", "uk", "ca", "au", "de", "fr", "it", "es", "nl", "jp", "kr", "cn", "in", 
    "br", "mx", "ar", "cl", "co", "pe", "ru", "pl", "cz", "ch", "at", "se", "no", 
    "dk", "fi", "be", "pt", "gr", "tr", "za", "eg", "ma", "ng", "ke"
]

NEW_TLDS = [
    "tech", "online", "site", "website", "store", "shop", "cloud", "digital", 
    "blog", "news", "agency", "studio", "design", "media", "photo", "video", 
    "music", "art", "gallery", "education", "university", "academy", "training", 
    "business", "company", "solutions", "services", "consulting", "finance", 
    "legal", "health", "medical", "travel", "hotel", "restaurant", "food", 
    "coffee", "bar", "club", "sport", "fitness", "games", "fun", "live", 
    "world", "global", "international", "network", "email", "mobile", "app"
]

ALL_TLDS = list(set(POPULAR_TLDS + COUNTRY_TLDS + NEW_TLDS))

TLD_MIN_LENGTH = {
    "com": 2, "net": 2, "org": 2, "info": 2, "biz": 3,

    "io": 2, "ai": 2, "co": 3, "me": 3,
    
    "de": 2, "fr": 2, "it": 2, "es": 2, "nl": 3,
    "ch": 3, "at": 3, "be": 3, "dk": 3, "se": 3,
    "no": 3, "fi": 3, "pl": 3, "cz": 3, "pt": 3,
    "gr": 3, "tr": 3, "ru": 3, "uk": 3, "au": 3,
    "ca": 3, "us": 3, "jp": 3, "kr": 3, "cn": 3,
    "in": 3, "br": 3, "mx": 3, "ar": 3, "cl": 3,
    "pe": 3, "za": 3, "eg": 3, "ma": 3, "ng": 3,
    "ke": 3,
    
    "app": 3, "dev": 3, "xyz": 3, "tech": 3,
    "online": 3, "site": 3, "website": 3, "store": 3,
    "shop": 3, "cloud": 3, "digital": 3, "blog": 3,
    "news": 3
}

def get_min_length_for_tld(tld: str) -> int:
    """Obtiene la longitud mínima requerida para un TLD"""
    return TLD_MIN_LENGTH.get(tld, 3)

def is_valid_domain_name(base_name: str, tld: str) -> bool:
    """Valida si un nombre de dominio cumple con las reglas del TLD"""
    min_length = get_min_length_for_tld(tld)
    if len(base_name) < min_length:
        return False
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', base_name):
        return False
    if base_name.startswith('-') or base_name.endswith('-'):
        return False
    if '--' in base_name:
        return False
    if len(base_name) > 63:
        return False
    return True

def clean_domain_name(domain: str) -> str:
    domain = domain.lower().strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        domain = domain.split('//')[-1]
    if '/' in domain:
        domain = domain.split('/')[0]
    return domain

def extract_domain_parts(domain: str) -> Tuple[str, str]:
    domain = clean_domain_name(domain)
    if '.' in domain:
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[:-1]), parts[-1]
    return domain, ''

async def check_domain_whois(domain: str) -> bool:
    if whois is None:
        return await check_domain_socket(domain)
    
    def whois_check():
        try:
            w = whois.whois(domain)
            if w is None:
                return True
            if hasattr(w, 'status'):
                if w.status is None:
                    return True
                if isinstance(w.status, list) and len(w.status) == 0:
                    return True
            if hasattr(w, 'domain_name'):
                if w.domain_name is None:
                    return True
            return False
        except Exception:
            return True
    
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(executor, whois_check),
                timeout=10.0
            )
            return result
        except asyncio.TimeoutError:
            return False

async def check_domain_dns(domain: str) -> bool:
    if dns is None:
        return await check_domain_socket(domain)
    
    def dns_check():
        try:
            dns.resolver.resolve(domain, 'A')
            return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return True
        except Exception:
            return False
    
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(executor, dns_check),
                timeout=5.0
            )
            return result
        except asyncio.TimeoutError:
            return False

async def check_domain_socket(domain: str) -> bool:
    def socket_check():
        try:
            socket.getaddrinfo(domain, 80)
            return False
        except socket.gaierror:
            return True
        except Exception:
            return False
    
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(executor, socket_check),
                timeout=5.0
            )
            return result
        except asyncio.TimeoutError:
            return False

async def check_domain_availability(domain: str) -> Dict:
    start_time = time.time()
    
    base_name, tld = extract_domain_parts(domain)
    
    if not is_valid_domain_name(base_name, tld):
        return {
            'domain': domain,
            'available': False,
            'error': f'Invalid domain: "{base_name}" does not meet requirements for .{tld} (min length: {get_min_length_for_tld(tld)})',
            'valid': False,
            'check_time': "0s"
        }
    
    dns_available = await check_domain_dns(domain)
    whois_available = await check_domain_whois(domain)
    
    is_available = dns_available and whois_available
    
    end_time = time.time()
    check_time = round(end_time - start_time, 2)
    
    return {
        'domain': domain,
        'available': is_available,
        'dns_available': dns_available,
        'whois_available': whois_available,
        'valid': True,
        'check_time': f"{check_time}s"
    }

async def check_multiple_domains(base_name: str, tlds: List[str]) -> List[Dict]:
    semaphore = asyncio.Semaphore(20)
    
    async def check_with_semaphore(tld: str):
        async with semaphore:
            if is_valid_domain_name(base_name, tld):
                domain = f"{base_name}.{tld}"
                return await check_domain_availability(domain)
            else:
                return None
    
    tasks = [check_with_semaphore(tld) for tld in tlds]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = []
    for result in results:
        if isinstance(result, dict):
            valid_results.append(result)
        elif result is not None and not isinstance(result, Exception):
            print(f"Error checking domain: {result}")
    
    return valid_results

async def run_domain_checks(domain_part: str) -> Dict:
    base_name, existing_tld = extract_domain_parts(domain_part)
    
    results = {
        "requested_domain": None,
        "available_domains": [],
        "unavailable_domains": [],
        "invalid_domains": [],
        "total_checked": 0,
        "check_summary": {}
    }
    
    invalid_for_tlds = []
    for tld in ALL_TLDS:
        if not is_valid_domain_name(base_name, tld):
            min_length = get_min_length_for_tld(tld)
            invalid_for_tlds.append({
                'tld': tld,
                'reason': f'Minimum length: {min_length} chars'
            })
    
    if invalid_for_tlds:
        results["invalid_domains"] = {
            'base_name': base_name,
            'length': len(base_name),
            'invalid_for': invalid_for_tlds[:10]
        }
    
    if existing_tld:
        exact_result = await check_domain_availability(f"{base_name}.{existing_tld}")
        results["requested_domain"] = exact_result
        
        other_tlds = [tld for tld in ALL_TLDS if tld != existing_tld]
        all_results = await check_multiple_domains(base_name, other_tlds)
        if exact_result.get('valid', True):
            all_results.append(exact_result)
    else:
        all_results = await check_multiple_domains(base_name, ALL_TLDS)
    
    for result in all_results:
        if result.get('available'):
            results["available_domains"].append(result)
        else:
            results["unavailable_domains"].append(result)
    
    results["total_checked"] = len(all_results)
    results["available_domains"].sort(key=lambda x: x['domain'])
    results["unavailable_domains"].sort(key=lambda x: x['domain'])
    
    popular_available = [r for r in results["available_domains"] 
                       if any(r['domain'].endswith(f'.{tld}') for tld in POPULAR_TLDS)]
    
    results["check_summary"] = {
        "total_available": len(results["available_domains"]),
        "total_unavailable": len(results["unavailable_domains"]),
        "total_invalid": len(invalid_for_tlds),
        "popular_available": len(popular_available),
        "country_available": len([r for r in results["available_domains"] 
                                if any(r['domain'].endswith(f'.{tld}') for tld in COUNTRY_TLDS)]),
        "new_tlds_available": len([r for r in results["available_domains"] 
                                 if any(r['domain'].endswith(f'.{tld}') for tld in NEW_TLDS)])
    }
    
    return results

@mcp.tool()
async def check_domain(domain_query: str) -> Dict:
    """
    Check domain availability. 
    
    Usage examples:
    - "mysite.com --domain" - checks exact domain
    - "mysite --domain" - checks mysite across all popular TLDs
    - "test.io --domain" - checks test.io exactly, plus test across all TLDs
    
    Args:
        domain_query (str): Domain to check with --domain flag
        
    Returns:
        Dict containing availability results for the domain and suggested alternatives
    """
    if '--domain' not in domain_query:
        return {
            "error": "Please use --domain flag. Example: 'mysite.com --domain' or 'mysite --domain'"
        }
    
    domain_part = domain_query.replace('--domain', '').strip()
    
    if not domain_part:
        return {
            "error": "Please provide a domain name. Example: 'mysite.com --domain'"
        }
    
    base_name, existing_tld = extract_domain_parts(domain_part)
    
    if not base_name:
        return {
            "error": "Invalid domain format. Example: 'mysite.com --domain'"
        }
    
    try:
        return await run_domain_checks(domain_part)
    except Exception as e:
        return {
            "error": f"Failed to check domain: {str(e)}"
        }
    
if __name__ == "__main__":
     mcp.run(transport="sse")