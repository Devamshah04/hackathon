"""
Symmetric Scanner Tool

Strands SDK tool that evaluates symmetric encryption configurations for
quantum weakness due to Grover's Algorithm.

Grover's Algorithm halves the effective bit strength:
  - AES-128 → 64-bit effective (INSECURE)
  - AES-192 → 96-bit effective (MARGINAL)
  - AES-256 → 128-bit effective (SECURE)

Used by: SymmetricAgent
"""

import json
from strands import tool


# ─── Symmetric Algorithm Assessment ─────────────────────────────────────────
SYMMETRIC_ASSESSMENT = {
    "AES-128": {
        "post_quantum_bits": 64,
        "risk": "HIGH",
        "reason": "Grover's Algorithm halves effective strength to 64-bit — insecure",
        "recommendation": "Upgrade to AES-256",
    },
    "AES-192": {
        "post_quantum_bits": 96,
        "risk": "MEDIUM",
        "reason": "Grover's Algorithm reduces effective strength to 96-bit — marginal security",
        "recommendation": "Upgrade to AES-256",
    },
    "AES-256": {
        "post_quantum_bits": 128,
        "risk": "LOW",
        "reason": "128-bit effective post-quantum strength — considered secure",
        "recommendation": "No change needed; AES-256 is quantum-resistant",
    },
    "3DES": {
        "post_quantum_bits": 56,
        "risk": "CRITICAL",
        "reason": "3DES has 112-bit classical strength, 56-bit post-quantum — critically weak",
        "recommendation": "Migrate to AES-256 immediately",
    },
    "ChaCha20": {
        "post_quantum_bits": 128,
        "risk": "LOW",
        "reason": "256-bit key with 128-bit post-quantum effective strength — secure",
        "recommendation": "No change needed; ChaCha20 is quantum-resistant",
    },
}


@tool
def scan_symmetric_config(config: str) -> str:
    """
    Analyze a symmetric encryption configuration for quantum weakness.

    Evaluates whether Grover's Algorithm reduces the effective bit strength
    below acceptable thresholds.

    Args:
        config: JSON string with fields:
            - algorithm: str (e.g., "AES-128", "AES-256", "3DES", "ChaCha20")
            - mode: str (e.g., "GCM", "CBC", "CTR") — optional
            - context: str (e.g., "database encryption", "TLS data") — optional

    Returns:
        JSON string with quantum impact assessment and recommendation.
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in config"})

    algorithm = cfg.get("algorithm", "unknown").upper()
    mode = cfg.get("mode", "unspecified")
    context = cfg.get("context", "unspecified")

    result = {
        "algorithm": algorithm,
        "mode": mode,
        "context": context,
    }

    if algorithm in SYMMETRIC_ASSESSMENT:
        assessment = SYMMETRIC_ASSESSMENT[algorithm]
        result.update({
            "quantum_vulnerable": assessment["risk"] in ("CRITICAL", "HIGH"),
            "classical_strength_bits": int(assessment["post_quantum_bits"] * 2),
            "post_quantum_strength_bits": assessment["post_quantum_bits"],
            "risk_level": assessment["risk"],
            "reason": assessment["reason"],
            "recommendation": assessment["recommendation"],
        })
    else:
        result.update({
            "quantum_vulnerable": None,
            "risk_level": "INFO",
            "reason": f"Algorithm '{algorithm}' not in assessment database",
            "recommendation": "Manual review required",
        })

    # Mode-specific warnings
    if mode.upper() == "CBC":
        result["mode_warning"] = "CBC mode is vulnerable to padding oracle attacks regardless of quantum threat — prefer GCM or CTR"

    return json.dumps(result, indent=2)
