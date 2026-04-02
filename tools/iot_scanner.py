"""
IoT Scanner Tool

Strands SDK tool that evaluates IoT device firmware metadata, signing
mechanisms, and device longevity to assess PQC migration urgency.

Returns 0.0–1.0 scores for three parameters:
- firmware_signing
- device_longevity
- ota_security

Used by: IoTEdgeAgent
"""

import json
from datetime import datetime
from strands import tool

# ─── Quantum Threat Timeline ────────────────────────────────────────────────
QUANTUM_THREAT_YEAR = 2030  # Projected year when cryptanalytically-relevant quantum computers arrive

# ─── Algorithm Scoring ──────────────────────────────────────────────────────
ALG_SCORES = {
    # PQC-safe
    "LMS":        1.0,  # Stateful hash-based (SP 800-208)
    "XMSS":       1.0,  # Stateful hash-based (SP 800-208)
    "ML-DSA-65":  1.0,
    "ML-DSA-44":  1.0,
    "ML-DSA-87":  1.0,
    # Classical (Quantum-Vulnerable)
    "RSA-4096":   0.2,
    "RSA-3072":   0.15,
    "RSA-2048":   0.1,
    "RSA-1024":   0.0,
    "ECDSA-P384": 0.25,
    "ECDSA-P256": 0.2,
    "none":       0.0,
}


@tool
def scan_iot_device(firmware_metadata: str) -> str:
    """
    Analyze IoT device firmware metadata for quantum-vulnerable crypto.

    Evaluates:
      - Firmware signing algorithm and key size
      - Device expected operational lifetime (longevity risk)
      - OTA update channel security

    Args:
        firmware_metadata: JSON string containing device firmware metadata.
            Expected fields:
              - device_name: str
              - firmware_version: str
              - signing_algorithm: str (e.g., "RSA-2048", "ECDSA-P256")
              - manufacture_year: int
              - expected_lifespan_years: int
              - ota_enabled: bool
              - ota_signing: str (algorithm used for OTA updates)
              - hardware_root_of_trust: bool

    Returns:
        JSON string with analysis including sub-scores (firmware_signing,
        device_longevity, ota_security) and findings.
    """
    try:
        metadata = json.loads(firmware_metadata)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in firmware_metadata"})

    device_name = metadata.get("device_name", "Unknown Device")
    manufacture_year = metadata.get("manufacture_year", datetime.now().year)
    lifespan = metadata.get("expected_lifespan_years", 10)
    end_of_life_year = manufacture_year + lifespan

    signing_alg = metadata.get("signing_algorithm", "unknown").upper()
    ota_enabled = metadata.get("ota_enabled", False)
    ota_signing = metadata.get("ota_signing", "unknown").upper() if ota_enabled else "none"
    hrot = metadata.get("hardware_root_of_trust", False)

    findings = []
    sub_scores = {}

    # ── 1. Device Longevity (25% weight in ScoringEngine) ───────────────
    years_past_threat = end_of_life_year - QUANTUM_THREAT_YEAR
    if years_past_threat <= 0:
        # End of life before quantum threat - low longevity risk (score = 1.0)
        longevity_score = 1.0
    elif years_past_threat > 5:
        # Survives well into quantum era - high risk (score = 0.0)
        longevity_score = 0.0
    else:
        # Partially exposed (score 0.1 to 0.9)
        longevity_score = max(0.1, 1.0 - (years_past_threat * 0.2))

    sub_scores["device_longevity"] = round(longevity_score, 2)
    if longevity_score < 0.5:
        findings.append({
            "component": "device_longevity",
            "risk": "CRITICAL",
            "recommendation": f"Device expected to operate until {end_of_life_year}. Immediate PQC migration required to prevent harvest-now-decrypt-later attacks.",
        })

    # ── 2. Firmware Signing (30% weight) ────────────────────────────────
    fw_score = ALG_SCORES.get(signing_alg, 0.0)
    
    # Boost if Hardware Root of Trust is present
    if fw_score > 0 and hrot:
        fw_score = min(1.0, fw_score + 0.1)
        
    sub_scores["firmware_signing"] = round(fw_score, 2)
    if fw_score < 0.6:
        findings.append({
            "component": "firmware_signing",
            "algorithm": signing_alg,
            "risk": "CRITICAL" if fw_score <= 0.2 else "HIGH",
            "recommendation": "Migrate to LMS or XMSS per NIST SP 800-208 for long-lived firmware signatures",
        })

    # ── 3. OTA Security (20% weight) ────────────────────────────────────
    if ota_enabled:
        ota_score = ALG_SCORES.get(ota_signing, 0.0)
        sub_scores["ota_security"] = round(ota_score, 2)
        if ota_score < 0.6:
            findings.append({
                "component": "ota_security",
                "algorithm": ota_signing,
                "risk": "CRITICAL",
                "recommendation": "OTA updates are quantum-vulnerable. Migrate to ML-DSA (FIPS 204) to prevent malicious firmware flashes.",
            })
    else:
        # If OTA is not enabled, the attack surface is reduced, but updates are impossible
        # This is a mixed bag, but we'll score it moderately (e.g., 0.5) because it can't be remotely updated maliciously,
        # but it also can't be patched if a vulnerability is found. Let's make it 0.0 if lifespan extends past Q-Day.
        if longevity_score < 1.0:
            sub_scores["ota_security"] = 0.0
            findings.append({
                "component": "ota_security",
                "risk": "CRITICAL",
                "recommendation": "Device operates into quantum era but lacks OTA. Impossible to patch cryptographically.",
            })
        else:
            sub_scores["ota_security"] = 0.8

    result = {
        "device_name": device_name,
        "sub_scores": sub_scores,  # Engine will use these
        "longevity_details": {
            "manufacture_year": manufacture_year,
            "expected_lifespan": lifespan,
            "expected_end_of_life": end_of_life_year,
            "years_past_qday": max(0, years_past_threat)
        },
        "findings": findings,
        "total_findings": len(findings),
    }

    return json.dumps(result, indent=2)
