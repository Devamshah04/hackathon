"""
Network Scanner Tool

Strands SDK tool that inspects network protocol configurations for
quantum-vulnerable handshake and tunneling mechanisms.

Checks TLS versions, SSH key exchange, and IKEv2/IPsec configurations
against IETF PQC draft standards for hybrid transition modes.

Used by: NetworkProtocolAgent
"""

import json
from strands import tool


# ─── Protocol Vulnerability Database ────────────────────────────────────────
PROTOCOL_VULNERABILITIES = {
    # TLS
    "TLS_1.0": {
        "risk": "CRITICAL",
        "reason": "TLS 1.0 deprecated; uses vulnerable cipher suites; broken classically and quantum-vulnerable",
        "migration": "TLS 1.3 with hybrid PQC key exchange",
    },
    "TLS_1.1": {
        "risk": "CRITICAL",
        "reason": "TLS 1.1 deprecated; quantum-vulnerable key exchange",
        "migration": "TLS 1.3 with hybrid PQC key exchange",
    },
    "TLS_1.2": {
        "risk": "HIGH",
        "reason": "TLS 1.2 cipher suites typically use RSA/ECDHE key exchange — vulnerable to Shor's",
        "migration": "TLS 1.3 with hybrid PQC mode (e.g., X25519+ML-KEM-768)",
    },
    "TLS_1.3": {
        "risk": "MEDIUM",
        "reason": "TLS 1.3 is modern but default key exchange (X25519/P-256) is quantum-vulnerable",
        "migration": "Enable hybrid PQC key exchange (X25519+ML-KEM-768 per IETF draft)",
    },
    # SSH
    "SSH_RSA": {
        "risk": "CRITICAL",
        "reason": "SSH with RSA host keys / key exchange broken by Shor's algorithm",
        "migration": "SSH with PQ key exchange (e.g., sntrup761+x25519)",
    },
    "SSH_ECDSA": {
        "risk": "HIGH",
        "reason": "SSH with ECDSA keys vulnerable to Shor's algorithm",
        "migration": "SSH with PQ-safe key exchange and ML-DSA host keys",
    },
    "SSH_ED25519": {
        "risk": "HIGH",
        "reason": "Ed25519 is ECC-based — vulnerable to Shor's algorithm",
        "migration": "Hybrid PQ SSH (sntrup761+x25519 already supported in OpenSSH 9.0+)",
    },
    # VPN / IPsec
    "IKEv2_CLASSIC": {
        "risk": "HIGH",
        "reason": "IKEv2 with classical DH groups vulnerable to Shor's algorithm",
        "migration": "PQ-VPN with hybrid key exchange (ML-KEM + classical DH)",
    },
    "IKEV1": {
        "risk": "CRITICAL",
        "reason": "IKEv1 deprecated; uses vulnerable DH key exchange",
        "migration": "Migrate to IKEv2 with PQ-hybrid key exchange",
    },
}

# ─── Vulnerable Cipher Suites ───────────────────────────────────────────────
VULNERABLE_CIPHER_SUITES = {
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
}


@tool
def scan_network_protocol(config: str) -> str:
    """
    Analyze a network protocol configuration for quantum vulnerability.

    Args:
        config: JSON string with fields:
            - protocol: str (e.g., "TLS", "SSH", "IKEv2")
            - version: str (e.g., "1.2", "1.3")
            - key_exchange: str (e.g., "RSA", "ECDHE", "DH-2048")
            - cipher_suites: list of cipher suite strings (optional)
            - host_key_algorithm: str (for SSH, e.g., "RSA", "ED25519")
            - context: str (e.g., "web server", "VPN gateway")

    Returns:
        JSON string with protocol vulnerability assessment.
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in config"})

    protocol = cfg.get("protocol", "unknown").upper()
    version = cfg.get("version", "")
    key_exchange = cfg.get("key_exchange", "unknown")
    cipher_suites = cfg.get("cipher_suites", [])
    host_key_algo = cfg.get("host_key_algorithm", "")
    context = cfg.get("context", "unspecified")

    result = {
        "protocol": protocol,
        "version": version,
        "context": context,
        "findings": [],
    }

    # Protocol-level assessment
    if protocol == "TLS":
        lookup = f"TLS_{version}"
        if lookup in PROTOCOL_VULNERABILITIES:
            vuln = PROTOCOL_VULNERABILITIES[lookup]
            result["findings"].append({
                "component": "protocol_version",
                "risk_level": vuln["risk"],
                "reason": vuln["reason"],
                "migration": vuln["migration"],
            })

    elif protocol == "SSH":
        lookup = f"SSH_{host_key_algo.upper()}" if host_key_algo else "SSH_RSA"
        if lookup in PROTOCOL_VULNERABILITIES:
            vuln = PROTOCOL_VULNERABILITIES[lookup]
            result["findings"].append({
                "component": "ssh_key_exchange",
                "host_key_algorithm": host_key_algo,
                "risk_level": vuln["risk"],
                "reason": vuln["reason"],
                "migration": vuln["migration"],
            })

    elif protocol in ("IKEV2", "IPSEC", "VPN"):
        lookup = "IKEv2_CLASSIC"
        if lookup in PROTOCOL_VULNERABILITIES:
            vuln = PROTOCOL_VULNERABILITIES[lookup]
            result["findings"].append({
                "component": "vpn_key_exchange",
                "risk_level": vuln["risk"],
                "reason": vuln["reason"],
                "migration": vuln["migration"],
            })

    # Cipher suite analysis
    for suite in cipher_suites:
        if suite in VULNERABLE_CIPHER_SUITES:
            result["findings"].append({
                "component": "cipher_suite",
                "suite": suite,
                "risk_level": "HIGH",
                "reason": f"Cipher suite '{suite}' uses quantum-vulnerable key exchange",
                "migration": "Replace with PQ-hybrid cipher suite",
            })

    result["total_findings"] = len(result["findings"])

    return json.dumps(result, indent=2)
