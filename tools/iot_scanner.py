"""
IoT Scanner Tool

Strands SDK tool that evaluates IoT device firmware metadata, signing
mechanisms, and device longevity to assess PQC migration urgency.

Devices expected to operate beyond 2030 are flagged as high priority
since quantum computers capable of breaking current crypto are projected
to be available by then.

Used by: IoTEdgeAgent
"""

import json
from datetime import datetime
from strands import tool

# ─── Quantum Threat Timeline ────────────────────────────────────────────────
QUANTUM_THREAT_YEAR = 2030  # Projected year when cryptanalytically-relevant quantum computers arrive


@tool
def scan_iot_device(firmware_metadata: str) -> str:
    """
    Analyze IoT device firmware metadata for quantum-vulnerable crypto.

    Evaluates:
      - Firmware signing algorithm and key size
      - Device expected operational lifetime (longevity risk)
      - OTA update channel security
      - Embedded crypto library versions

    Args:
        firmware_metadata: JSON string containing device firmware metadata.
            Expected fields:
              - device_name: str
              - firmware_version: str
              - signing_algorithm: str (e.g., "RSA-2048", "ECDSA-P256")
              - signing_key_size: int
              - manufacture_year: int
              - expected_lifespan_years: int
              - ota_enabled: bool
              - ota_signing: str (algorithm used for OTA updates)
              - crypto_library: str (e.g., "mbedTLS 3.4", "wolfSSL 5.6")

    Returns:
        JSON string with analysis including longevity risk assessment
        and PQC migration recommendations.
    """
    try:
        metadata = json.loads(firmware_metadata)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in firmware_metadata"})

    device_name = metadata.get("device_name", "Unknown Device")
    manufacture_year = metadata.get("manufacture_year", datetime.now().year)
    lifespan = metadata.get("expected_lifespan_years", 10)
    end_of_life_year = manufacture_year + lifespan

    signing_alg = metadata.get("signing_algorithm", "unknown")
    ota_signing = metadata.get("ota_signing", "unknown")

    result = {
        "device_name": device_name,
        "firmware_version": metadata.get("firmware_version", "unknown"),
        "findings": [],
    }

    # ── Longevity Risk Assessment ───────────────────────────────────────
    longevity_risk = "HIGH" if end_of_life_year > QUANTUM_THREAT_YEAR else "LOW"
    result["longevity_assessment"] = {
        "manufacture_year": manufacture_year,
        "expected_end_of_life": end_of_life_year,
        "quantum_threat_year": QUANTUM_THREAT_YEAR,
        "at_risk": end_of_life_year > QUANTUM_THREAT_YEAR,
        "risk_level": longevity_risk,
        "years_of_exposure": max(0, end_of_life_year - QUANTUM_THREAT_YEAR),
    }

    # ── Firmware Signing Analysis ───────────────────────────────────────
    rsa_pattern = signing_alg.upper().startswith("RSA")
    ecdsa_pattern = "EC" in signing_alg.upper() or "P256" in signing_alg.upper() or "P384" in signing_alg.upper()

    if rsa_pattern or ecdsa_pattern:
        # For firmware — recommend hash-based signatures per NIST SP 800-208
        result["findings"].append({
            "component": "firmware_signing",
            "current_algorithm": signing_alg,
            "risk_level": "CRITICAL" if longevity_risk == "HIGH" else "HIGH",
            "reason": f"{'RSA' if rsa_pattern else 'ECDSA'} vulnerable to Shor's algorithm; device operates until {end_of_life_year}",
            "migration_target": {
                "recommended_algorithm": "LMS or XMSS",
                "standard": "NIST SP 800-208",
                "rationale": "Hash-based signatures recommended for firmware due to stateful nature and long device lifetimes",
                "priority": "CRITICAL" if longevity_risk == "HIGH" else "HIGH",
            },
        })

    # ── OTA Update Channel Analysis ─────────────────────────────────────
    if metadata.get("ota_enabled", False):
        if "RSA" in ota_signing.upper() or "EC" in ota_signing.upper():
            result["findings"].append({
                "component": "ota_update_signing",
                "current_algorithm": ota_signing,
                "risk_level": "CRITICAL",
                "reason": "OTA update channel uses quantum-vulnerable signing — compromised updates could brick entire device fleet",
                "migration_target": {
                    "recommended_algorithm": "ML-DSA-65",
                    "standard": "FIPS 204",
                    "rationale": "OTA channels need agile signatures; ML-DSA supports this better than stateful LMS/XMSS",
                    "priority": "CRITICAL",
                },
            })

    # ── Crypto Library Check ────────────────────────────────────────────
    crypto_lib = metadata.get("crypto_library", "")
    if crypto_lib:
        result["crypto_library"] = {
            "name": crypto_lib,
            "note": "Verify library version supports PQC algorithms (ML-KEM, ML-DSA)",
        }

    result["total_findings"] = len(result["findings"])

    return json.dumps(result, indent=2)
