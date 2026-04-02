"""
Subdomain Discovery Tool for Comprehensive Domain Assessment

Discovers subdomains for a given domain to expand the scope of PQC assessment
beyond just the main domain.
"""

import json
import socket
import ssl
import urllib.request
import urllib.parse
from typing import List, Dict, Any
import logging

logger = logging.getLogger("pqc.subdomain_discovery")

# Common subdomain prefixes to check
COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "mail", "ftp", "blog", "shop", "store",
    "dev", "test", "staging", "prod", "secure", "login", "auth", "sso",
    "cdn", "static", "assets", "img", "images", "js", "css", "media",
    "support", "help", "docs", "wiki", "forum", "community", "news",
    "mobile", "m", "wap", "beta", "alpha", "demo", "sandbox", "portal"
]

def discover_subdomains_for_assessment(domain: str, max_subdomains: int = 10) -> List[Dict[str, Any]]:
    """
    Discover active subdomains for comprehensive assessment.
    
    Args:
        domain: Base domain to scan
        max_subdomains: Maximum number of subdomains to return
        
    Returns:
        List of subdomain assessment targets
    """
    discovered_targets = []
    
    # Add the main domain first
    main_target = _create_domain_target(domain)
    if main_target:
        discovered_targets.append(main_target)
    
    # Check common subdomains
    checked_count = 0
    for subdomain in COMMON_SUBDOMAINS:
        if checked_count >= max_subdomains - 1:  # -1 for main domain
            break
            
        full_domain = f"{subdomain}.{domain}"
        target = _create_domain_target(full_domain)
        if target:
            discovered_targets.append(target)
            checked_count += 1
            logger.info(f"Discovered active subdomain: {full_domain}")
    
    return discovered_targets

def _create_domain_target(domain: str) -> Dict[str, Any] | None:
    """
    Create an assessment target for a domain by probing its configuration.
    
    Args:
        domain: Domain to probe
        
    Returns:
        Assessment target dict or None if domain is not accessible
    """
    try:
        # Test if domain is reachable
        socket.gethostbyname(domain)
    except socket.gaierror:
        return None
    
    target = {
        "asset": domain,
        "description": f"Auto-discovered domain: {domain}",
        "jwt_token": "",  # Cannot fetch without authentication
        "tls_config": _probe_tls_config(domain),
        "oauth_config": _probe_oauth_config(domain),
        "key_management": _default_key_management(),
        "quantum_readiness": _default_quantum_readiness(),
        # Enhanced parameters with default values
        "certificate_security": _probe_certificate_security(domain),
        "api_encryption": _default_api_encryption(),
        "session_management": _default_session_management(),
        "data_at_rest": _default_data_at_rest(),
        "regulatory_compliance": _default_regulatory_compliance()
    }
    
    return target

def _probe_tls_config(domain: str) -> Dict[str, Any]:
    """Probe TLS configuration of a domain."""
    default_config = {
        "tls_version": "unknown",
        "key_exchange": "unknown",
        "cert_key_type": "unknown",
        "cipher_suite": "unknown",
        "hsts_enabled": False,
        "cert_pinning": False
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    default_config.update({
                        "tls_version": cipher[1],
                        "cipher_suite": cipher[0],
                        "key_exchange": cipher[0].split("-")[0] if cipher[1] == "TLSv1.2" else "ECDHE/DHE"
                    })
    except Exception as e:
        logger.debug(f"TLS probe failed for {domain}: {e}")
    
    return default_config

def _probe_oauth_config(domain: str) -> Dict[str, Any]:
    """Probe OAuth/OIDC configuration of a domain."""
    oauth_config = {}
    
    # Check for OIDC discovery endpoint
    discovery_url = f"https://{domain}/.well-known/openid-configuration"
    try:
        req = urllib.request.Request(discovery_url, headers={'User-Agent': 'PQC-Scanner/1.0'})
        with urllib.request.urlopen(req, timeout=5.0) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                oauth_config = {
                    "endpoint_url": discovery_url,
                    "signing_algorithms": data.get("id_token_signing_alg_values_supported", ["RS256"]),
                    "grant_types_supported": data.get("grant_types_supported", []),
                    "pkce_supported": "code_challenge_methods_supported" in data,
                    "jwks_key_types": ["RSA"],  # Default assumption
                    "token_endpoint_auth_methods": data.get("token_endpoint_auth_methods_supported", [])
                }
    except Exception as e:
        logger.debug(f"OAuth probe failed for {domain}: {e}")
    
    return oauth_config

def _probe_certificate_security(domain: str) -> Dict[str, Any]:
    """Probe certificate security configuration."""
    cert_config = {
        "cert_algorithm": "RSA-2048",  # Common default
        "validity_years": 1,
        "chain_depth": 3,
        "ca_trusted": True
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Extract basic certificate info
                    # This is simplified - full implementation would parse certificate details
                    cert_config["ca_trusted"] = True
                    cert_config["chain_depth"] = len(ssock.getpeercert_chain()) if hasattr(ssock, 'getpeercert_chain') else 3
    except Exception as e:
        logger.debug(f"Certificate probe failed for {domain}: {e}")
    
    return cert_config

def _default_key_management() -> Dict[str, Any]:
    """Default key management configuration (assumed insecure)."""
    return {
        "storage_type": "unknown",
        "rotation_policy": "unknown",
        "key_algorithm": "unknown",
        "key_count": 0,
        "separation_of_duties": False,
        "audit_logging": False,
        "backup_exists": False
    }

def _default_quantum_readiness() -> Dict[str, Any]:
    """Default quantum readiness configuration (assumed not ready)."""
    return {
        "pqc_algorithms_deployed": [],
        "hybrid_mode_enabled": False,
        "crypto_agile": False,
        "migration_plan_exists": False,
        "migration_plan_timeline": "",
        "pqc_testing_done": False,
        "library_supports_pqc": False
    }

def _default_api_encryption() -> Dict[str, Any]:
    """Default API encryption configuration."""
    return {
        "payload_encryption": "none",
        "field_level_encryption": False,
        "key_derivation": "PBKDF2"
    }

def _default_session_management() -> Dict[str, Any]:
    """Default session management configuration."""
    return {
        "token_algorithm": "HMAC-SHA256",
        "timeout_minutes": 30,
        "secure_cookies": False,
        "regenerate_on_auth": False
    }

def _default_data_at_rest() -> Dict[str, Any]:
    """Default data-at-rest encryption configuration."""
    return {
        "encryption_algorithm": "AES-128",
        "key_storage": "filesystem",
        "key_rotation_days": 0
    }

def _default_regulatory_compliance() -> Dict[str, Any]:
    """Default regulatory compliance configuration."""
    return {
        "frameworks": [],
        "pqc_migration_plan": False,
        "audit_logging": False,
        "crypto_documentation": False
    }