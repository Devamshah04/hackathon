"""
Public Key Scanner Tool

Strands SDK tool that analyzes public key algorithm configurations for
quantum vulnerability. Checks RSA key sizes, ECC curve parameters,
and Diffie-Hellman group settings.

Used by: PublicKeyAgent
"""

import json
from strands import tool


# ─── Vulnerability Database ──────────────────────────────────────────────────
VULNERABLE_ALGORITHMS = {
    "RSA-1024": {"risk": "CRITICAL", "reason": "RSA-1024 trivially broken even classically; immediately broken by Shor's"},
    "RSA-2048": {"risk": "CRITICAL", "reason": "RSA-2048 broken by Shor's algorithm on quantum computer"},
    "RSA-3072": {"risk": "CRITICAL", "reason": "RSA-3072 broken by Shor's algorithm on quantum computer"},
    "RSA-4096": {"risk": "HIGH",     "reason": "RSA-4096 broken by Shor's; larger key only delays, doesn't prevent"},
    "ECC-P256": {"risk": "CRITICAL", "reason": "ECDLP on P-256 solved by Shor's algorithm"},
    "ECC-P384": {"risk": "CRITICAL", "reason": "ECDLP on P-384 solved by Shor's algorithm"},
    "ECC-P521": {"risk": "HIGH",     "reason": "ECDLP on P-521 solved by Shor's algorithm"},
    "DH-1024":  {"risk": "CRITICAL", "reason": "Discrete log problem solved by Shor's; also classically weak"},
    "DH-2048":  {"risk": "CRITICAL", "reason": "Discrete log problem solved by Shor's algorithm"},
    "DH-4096":  {"risk": "HIGH",     "reason": "Discrete log problem solved by Shor's algorithm"},
    "ECDH-P256": {"risk": "CRITICAL", "reason": "ECDH key exchange broken by Shor's algorithm"},
    "ECDH-P384": {"risk": "CRITICAL", "reason": "ECDH key exchange broken by Shor's algorithm"},
}

# ─── PQC Replacement Mapping ────────────────────────────────────────────────
PQC_REPLACEMENTS = {
    # Key Exchange replacements → ML-KEM (FIPS 203)
    "RSA-KE":   {"algorithm": "ML-KEM-768",  "standard": "FIPS 203", "type": "key_exchange"},
    "DH":       {"algorithm": "ML-KEM-768",  "standard": "FIPS 203", "type": "key_exchange"},
    "ECDH":     {"algorithm": "ML-KEM-768",  "standard": "FIPS 203", "type": "key_exchange"},
    # Signature replacements → ML-DSA (FIPS 204)
    "RSA-SIG":  {"algorithm": "ML-DSA-65",   "standard": "FIPS 204", "type": "signature"},
    "ECDSA":    {"algorithm": "ML-DSA-44",   "standard": "FIPS 204", "type": "signature"},
}


@tool
def scan_public_key_config(config: str) -> str:
    """
    Analyze a public key algorithm configuration for quantum vulnerability.

    Args:
        config: JSON string with fields:
            - algorithm: str (e.g., "RSA", "ECC", "DH", "ECDH")
            - key_size: int (e.g., 2048, 256, 384)
            - usage: str ("key_exchange" | "signature" | "both")
            - context: str (description of where this is used)

    Returns:
        JSON string with vulnerability assessment and PQC recommendation.
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in config"})

    algorithm = cfg.get("algorithm", "unknown").upper()
    key_size = cfg.get("key_size", 0)
    usage = cfg.get("usage", "both")
    context = cfg.get("context", "unspecified")

    # Build lookup key
    if algorithm in ("RSA", "RSA-OAEP", "RSA-PSS"):
        lookup_key = f"RSA-{key_size}"
    elif algorithm in ("ECC", "ECDSA"):
        lookup_key = f"ECC-P{key_size}"
    elif algorithm == "ECDH":
        lookup_key = f"ECDH-P{key_size}"
    elif algorithm in ("DH", "DIFFIE-HELLMAN"):
        lookup_key = f"DH-{key_size}"
    else:
        lookup_key = f"{algorithm}-{key_size}"

    result = {
        "algorithm": algorithm,
        "key_size": key_size,
        "usage": usage,
        "context": context,
        "quantum_vulnerable": lookup_key in VULNERABLE_ALGORITHMS,
    }

    if lookup_key in VULNERABLE_ALGORITHMS:
        vuln = VULNERABLE_ALGORITHMS[lookup_key]
        result["risk_level"] = vuln["risk"]
        result["reason"] = vuln["reason"]

        # Determine replacement based on usage
        if usage in ("key_exchange", "both"):
            repl_key = "ECDH" if algorithm in ("ECDH",) else ("DH" if algorithm in ("DH", "DIFFIE-HELLMAN") else "RSA-KE")
            if repl_key in PQC_REPLACEMENTS:
                result["key_exchange_migration"] = PQC_REPLACEMENTS[repl_key]

        if usage in ("signature", "both"):
            repl_key = "ECDSA" if algorithm in ("ECC", "ECDSA") else "RSA-SIG"
            if repl_key in PQC_REPLACEMENTS:
                result["signature_migration"] = PQC_REPLACEMENTS[repl_key]
    else:
        result["risk_level"] = "INFO"
        result["reason"] = f"Algorithm '{lookup_key}' not in vulnerability database"

    return json.dumps(result, indent=2)
