"""
Enhanced Scanner Tools for Additional PQC Assessment Parameters

Provides 5 additional scanner functions to expand assessment from 5 to 10 parameters
for comprehensive quantum vulnerability analysis.
"""

import json
from typing import Dict, Any, List

try:
    from strands import tool
except ImportError:
    def tool(f):
        return f

@tool
def scan_certificate_security(config: str) -> str:
    """
    Scan certificate security configuration for quantum vulnerabilities.
    
    Args:
        config: JSON string with certificate configuration
        
    Returns:
        JSON string with security assessment
    """
    try:
        cert_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check certificate algorithm
    cert_algorithm = cert_config.get("cert_algorithm", "RSA-2048")
    if "RSA" in cert_algorithm:
        key_size = int(cert_algorithm.split("-")[-1]) if "-" in cert_algorithm else 2048
        if key_size < 3072:
            score -= 0.4
            findings.append({
                "issue": "Quantum-vulnerable certificate algorithm",
                "details": f"RSA-{key_size} vulnerable to Shor's algorithm",
                "recommendation": "Migrate to RSA-3072+ or ML-DSA"
            })
    elif "ECDSA" in cert_algorithm or "ECC" in cert_algorithm:
        score -= 0.5
        findings.append({
            "issue": "ECDSA certificates quantum-vulnerable",
            "details": "All ECC-based certificates broken by Shor's algorithm",
            "recommendation": "Migrate to ML-DSA (FIPS 204)"
        })
    
    # Check certificate validity period
    validity_years = cert_config.get("validity_years", 1)
    if validity_years > 2:
        score -= 0.2
        findings.append({
            "issue": "Long certificate validity period",
            "details": f"{validity_years} years extends past quantum threat timeline",
            "recommendation": "Reduce validity to 1-2 years maximum"
        })
    
    # Check certificate chain depth
    chain_depth = cert_config.get("chain_depth", 3)
    if chain_depth > 4:
        score -= 0.1
        findings.append({
            "issue": "Deep certificate chain",
            "details": f"Chain depth {chain_depth} increases attack surface",
            "recommendation": "Minimize chain depth to 2-3 levels"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Certificate security evaluation complete"
    })

@tool
def scan_api_encryption(config: str) -> str:
    """
    Scan API encryption configuration for quantum vulnerabilities.
    
    Args:
        config: JSON string with API encryption configuration
        
    Returns:
        JSON string with encryption assessment
    """
    try:
        api_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check payload encryption
    payload_encryption = api_config.get("payload_encryption", "none")
    if payload_encryption == "none":
        score -= 0.3
        findings.append({
            "issue": "No API payload encryption",
            "details": "Sensitive data transmitted in plaintext",
            "recommendation": "Implement AES-256-GCM payload encryption"
        })
    elif "AES-128" in payload_encryption:
        score -= 0.2
        findings.append({
            "issue": "Weak payload encryption",
            "details": "AES-128 provides only 64-bit quantum security",
            "recommendation": "Upgrade to AES-256 for 128-bit quantum security"
        })
    
    # Check field-level encryption
    field_encryption = api_config.get("field_level_encryption", False)
    if not field_encryption:
        score -= 0.2
        findings.append({
            "issue": "No field-level encryption",
            "details": "Sensitive fields not individually encrypted",
            "recommendation": "Implement field-level encryption for PII/PHI"
        })
    
    # Check encryption key derivation
    key_derivation = api_config.get("key_derivation", "PBKDF2")
    if key_derivation in ["MD5", "SHA1"]:
        score -= 0.3
        findings.append({
            "issue": "Weak key derivation function",
            "details": f"{key_derivation} is cryptographically broken",
            "recommendation": "Use PBKDF2, scrypt, or Argon2"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "API encryption evaluation complete"
    })

@tool
def scan_session_management(config: str) -> str:
    """
    Scan session management configuration for quantum vulnerabilities.
    
    Args:
        config: JSON string with session management configuration
        
    Returns:
        JSON string with session security assessment
    """
    try:
        session_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check session token algorithm
    token_algorithm = session_config.get("token_algorithm", "HMAC-SHA256")
    if "MD5" in token_algorithm or "SHA1" in token_algorithm:
        score -= 0.4
        findings.append({
            "issue": "Weak session token algorithm",
            "details": f"{token_algorithm} is cryptographically weak",
            "recommendation": "Use HMAC-SHA256 or stronger"
        })
    
    # Check session timeout
    session_timeout = session_config.get("timeout_minutes", 30)
    if session_timeout > 60:
        score -= 0.2
        findings.append({
            "issue": "Long session timeout",
            "details": f"{session_timeout} minutes increases exposure window",
            "recommendation": "Reduce timeout to 30 minutes or less"
        })
    
    # Check secure cookie flags
    secure_cookies = session_config.get("secure_cookies", False)
    if not secure_cookies:
        score -= 0.2
        findings.append({
            "issue": "Insecure cookie configuration",
            "details": "Missing Secure, HttpOnly, SameSite flags",
            "recommendation": "Enable all security cookie flags"
        })
    
    # Check session regeneration
    session_regeneration = session_config.get("regenerate_on_auth", False)
    if not session_regeneration:
        score -= 0.2
        findings.append({
            "issue": "No session regeneration",
            "details": "Session ID not regenerated after authentication",
            "recommendation": "Regenerate session ID on privilege changes"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Session management evaluation complete"
    })

@tool
def scan_data_at_rest(config: str) -> str:
    """
    Scan data-at-rest encryption for quantum vulnerabilities.
    
    Args:
        config: JSON string with data-at-rest configuration
        
    Returns:
        JSON string with encryption assessment
    """
    try:
        data_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check encryption algorithm
    encryption_algorithm = data_config.get("encryption_algorithm", "AES-128")
    if "AES-128" in encryption_algorithm:
        score -= 0.3
        findings.append({
            "issue": "Weak data-at-rest encryption",
            "details": "AES-128 provides only 64-bit quantum security",
            "recommendation": "Upgrade to AES-256 for quantum resistance"
        })
    elif encryption_algorithm in ["DES", "3DES"]:
        score -= 0.5
        findings.append({
            "issue": "Obsolete encryption algorithm",
            "details": f"{encryption_algorithm} is cryptographically broken",
            "recommendation": "Migrate to AES-256 immediately"
        })
    
    # Check key management
    key_storage = data_config.get("key_storage", "filesystem")
    if key_storage == "filesystem":
        score -= 0.2
        findings.append({
            "issue": "Insecure key storage",
            "details": "Encryption keys stored on filesystem",
            "recommendation": "Use HSM or cloud KMS for key storage"
        })
    
    # Check key rotation
    key_rotation = data_config.get("key_rotation_days", 0)
    if key_rotation == 0 or key_rotation > 365:
        score -= 0.2
        findings.append({
            "issue": "No key rotation policy",
            "details": "Encryption keys not rotated regularly",
            "recommendation": "Implement 90-day key rotation"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Data-at-rest encryption evaluation complete"
    })

@tool
def scan_regulatory_compliance(config: str) -> str:
    """
    Scan regulatory compliance configuration for quantum readiness.
    
    Args:
        config: JSON string with compliance configuration
        
    Returns:
        JSON string with compliance assessment
    """
    try:
        compliance_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check compliance framework
    frameworks = compliance_config.get("frameworks", [])
    if not frameworks:
        score -= 0.3
        findings.append({
            "issue": "No compliance framework identified",
            "details": "No regulatory compliance framework in use",
            "recommendation": "Implement relevant compliance framework (NIST, ISO, etc.)"
        })
    
    # Check PQC migration plan
    pqc_plan = compliance_config.get("pqc_migration_plan", False)
    if not pqc_plan:
        score -= 0.4
        findings.append({
            "issue": "No PQC migration plan",
            "details": "No documented post-quantum cryptography migration plan",
            "recommendation": "Develop comprehensive PQC migration roadmap"
        })
    
    # Check audit trail
    audit_logging = compliance_config.get("audit_logging", False)
    if not audit_logging:
        score -= 0.2
        findings.append({
            "issue": "Insufficient audit logging",
            "details": "Cryptographic operations not logged for compliance",
            "recommendation": "Implement comprehensive audit logging"
        })
    
    # Check documentation
    documentation = compliance_config.get("crypto_documentation", False)
    if not documentation:
        score -= 0.1
        findings.append({
            "issue": "Missing cryptographic documentation",
            "details": "Cryptographic implementations not documented",
            "recommendation": "Document all cryptographic implementations"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Regulatory compliance evaluation complete"
    })

# IoT-specific enhanced scanners
def scan_hardware_security(config: str) -> str:
    """
    Scan IoT hardware security configuration.
    
    Args:
        config: JSON string with hardware security configuration
        
    Returns:
        JSON string with hardware security assessment
    """
    try:
        hw_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check hardware root of trust
    root_of_trust = hw_config.get("hardware_root_of_trust", False)
    if not root_of_trust:
        score -= 0.4
        findings.append({
            "issue": "No hardware root of trust",
            "details": "Device lacks secure hardware foundation",
            "recommendation": "Implement TPM, HSM, or secure enclave"
        })
    
    # Check secure boot
    secure_boot = hw_config.get("secure_boot", False)
    if not secure_boot:
        score -= 0.3
        findings.append({
            "issue": "No secure boot implementation",
            "details": "Boot process not cryptographically verified",
            "recommendation": "Enable secure boot with verified signatures"
        })
    
    # Check tamper resistance
    tamper_resistance = hw_config.get("tamper_resistance", "none")
    if tamper_resistance == "none":
        score -= 0.2
        findings.append({
            "issue": "No tamper resistance",
            "details": "Device vulnerable to physical attacks",
            "recommendation": "Implement tamper detection/response mechanisms"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Hardware security evaluation complete"
    })

def scan_communication_protocol(config: str) -> str:
    """
    Scan IoT communication protocol security.
    
    Args:
        config: JSON string with communication protocol configuration
        
    Returns:
        JSON string with protocol security assessment
    """
    try:
        comm_config = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"score": 0.0, "error": "Invalid JSON configuration"})
    
    score = 1.0
    findings = []
    
    # Check protocol security
    protocols = comm_config.get("protocols", [])
    for protocol in protocols:
        if protocol in ["HTTP", "FTP", "Telnet"]:
            score -= 0.4
            findings.append({
                "issue": f"Insecure protocol: {protocol}",
                "details": f"{protocol} transmits data in plaintext",
                "recommendation": f"Replace {protocol} with secure alternative"
            })
        elif protocol in ["TLS1.0", "TLS1.1", "SSL"]:
            score -= 0.3
            findings.append({
                "issue": f"Deprecated protocol: {protocol}",
                "details": f"{protocol} has known vulnerabilities",
                "recommendation": "Upgrade to TLS 1.3 with PQC support"
            })
    
    # Check authentication method
    auth_method = comm_config.get("authentication", "none")
    if auth_method == "none":
        score -= 0.3
        findings.append({
            "issue": "No authentication",
            "details": "Communication not authenticated",
            "recommendation": "Implement mutual authentication"
        })
    elif auth_method in ["password", "basic"]:
        score -= 0.2
        findings.append({
            "issue": "Weak authentication method",
            "details": f"{auth_method} authentication is vulnerable",
            "recommendation": "Use certificate-based or token-based authentication"
        })
    
    return json.dumps({
        "score": max(0.0, score),
        "findings": findings,
        "assessment": "Communication protocol evaluation complete"
    })