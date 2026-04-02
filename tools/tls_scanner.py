"""
TLS/Transport Scanner Tool

Strands SDK tool that evaluates TLS/transport security configurations for
quantum vulnerability. Returns a 0.0–1.0 score for the tls_transport parameter.

Used by: WebApiAgent
"""

import json
from strands import tool


# ─── TLS Version Scores ─────────────────────────────────────────────────────
TLS_VERSION_SCORES = {
    "1.3_hybrid_pqc": 1.0,   # TLS 1.3 with hybrid PQ key exchange
    "1.3":            0.6,   # TLS 1.3 but classical key exchange
    "1.2":            0.35,  # Acceptable but aging
    "1.1":            0.05,  # Deprecated
    "1.0":            0.0,   # Deprecated, insecure
}

# ─── Key Exchange Scores ────────────────────────────────────────────────────
KEY_EXCHANGE_SCORES = {
    "ML-KEM-768":   1.0,
    "ML-KEM-512":   0.95,
    "ML-KEM-1024":  1.0,
    "X25519_ML-KEM": 1.0,   # hybrid
    "ECDHE_P521":   0.4,
    "ECDHE_P384":   0.35,
    "ECDHE_P256":   0.3,
    "X25519":       0.35,
    "DHE_4096":     0.25,
    "DHE_2048":     0.15,
    "RSA":          0.05,   # static RSA = no forward secrecy
}

# ─── Certificate Key Type Scores ────────────────────────────────────────────
CERT_KEY_SCORES = {
    "ML-DSA":       1.0,
    "RSA_4096":     0.25,
    "RSA_2048":     0.15,
    "RSA_1024":     0.0,
    "ECDSA_P384":   0.3,
    "ECDSA_P256":   0.25,
    "ED25519":      0.3,
}

# ─── Cipher Suite Scores ────────────────────────────────────────────────────
CIPHER_SCORES = {
    "AES_256_GCM":          0.9,
    "AES_128_GCM":          0.7,
    "CHACHA20_POLY1305":    0.9,
    "AES_256_CBC":          0.5,
    "AES_128_CBC":          0.4,
    "3DES":                 0.1,
    "RC4":                  0.0,
}


@tool
def scan_tls_config(config: str) -> str:
    """
    Analyze a TLS configuration for quantum vulnerability.

    Evaluates TLS version, key exchange mechanism, certificate key type,
    and cipher suite to produce a composite transport security score.

    Args:
        config: JSON string with fields:
            - tls_version: str (e.g., "1.3", "1.2")
            - key_exchange: str (e.g., "ECDHE_P256", "X25519")
            - cert_key_type: str (e.g., "RSA_2048", "ECDSA_P256")
            - cipher_suite: str (e.g., "AES_256_GCM", "AES_128_CBC")
            - hsts_enabled: bool (HTTP Strict Transport Security)
            - cert_pinning: bool

    Returns:
        JSON string with:
        - score (0.0–1.0 for tls_transport parameter)
        - sub-scores for each component
        - findings and recommendations
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON", "score": 0.0})

    tls_version = cfg.get("tls_version", "1.2")
    key_exchange = cfg.get("key_exchange", "unknown")
    cert_key_type = cfg.get("cert_key_type", "unknown")
    cipher_suite = cfg.get("cipher_suite", "unknown")
    hsts = cfg.get("hsts_enabled", False)
    cert_pin = cfg.get("cert_pinning", False)

    findings = []
    sub_scores = {}

    # 1. TLS version (30% of transport score)
    tls_score = TLS_VERSION_SCORES.get(tls_version, 0.0)
    sub_scores["tls_version"] = tls_score
    if tls_score < 0.5:
        findings.append({
            "component": "tls_version",
            "value": f"TLS {tls_version}",
            "risk": "CRITICAL" if tls_score <= 0.1 else "HIGH",
            "recommendation": "Upgrade to TLS 1.3 with hybrid PQC key exchange",
        })

    # 2. Key exchange (30% of transport score)
    ke_score = KEY_EXCHANGE_SCORES.get(key_exchange, 0.0)
    sub_scores["key_exchange"] = ke_score
    if ke_score < 0.5:
        findings.append({
            "component": "key_exchange",
            "value": key_exchange,
            "risk": "CRITICAL" if ke_score <= 0.1 else "HIGH",
            "recommendation": "Migrate to ML-KEM hybrid key exchange (X25519+ML-KEM-768)",
        })

    # 3. Certificate key type (20% of transport score)
    cert_score = CERT_KEY_SCORES.get(cert_key_type, 0.0)
    sub_scores["cert_key_type"] = cert_score
    if cert_score < 0.5:
        findings.append({
            "component": "certificate",
            "value": cert_key_type,
            "risk": "HIGH",
            "recommendation": "Plan certificate migration to ML-DSA signed certs",
        })

    # 4. Cipher suite (15% of transport score)
    cs_score = CIPHER_SCORES.get(cipher_suite, 0.5)
    sub_scores["cipher_suite"] = cs_score
    if cs_score < 0.5:
        findings.append({
            "component": "cipher_suite",
            "value": cipher_suite,
            "risk": "MEDIUM",
            "recommendation": "Upgrade to AES-256-GCM or ChaCha20-Poly1305",
        })

    # 5. Additional security (5%)
    extras_score = (0.5 if hsts else 0.0) + (0.5 if cert_pin else 0.0)
    sub_scores["additional_security"] = extras_score

    # Weighted composite
    composite = (
        tls_score  * 0.30 +
        ke_score   * 0.30 +
        cert_score * 0.20 +
        cs_score   * 0.15 +
        extras_score * 0.05
    )

    result = {
        "score": round(composite, 3),
        "sub_scores": sub_scores,
        "findings": findings,
        "total_findings": len(findings),
    }

    return json.dumps(result, indent=2)
