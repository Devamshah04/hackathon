"""
Enhanced Regional Standards Support for PQC Migration

Provides region-specific compliance profiles, standards, and weight modifiers
for dynamic assessment based on regulatory requirements.
"""

from typing import Dict, List, Any

# Regional Standards Profiles
ENHANCED_REGION_PROFILES: Dict[str, Dict[str, Any]] = {
    "US": {
        "name": "United States",
        "body": "NIST",
        "body_full": "National Institute of Standards and Technology",
        "standards": ["FIPS 203", "FIPS 204", "FIPS 205", "NIST IR 8547", "CNSA 2.0"],
        "deadline": "2030-2035",
        "weight_modifiers": {
            "regulatory_compliance": 1.2,
            "quantum_readiness": 1.1,
            "key_management": 1.0,
        }
    },
    "EU": {
        "name": "European Union",
        "body": "ETSI/ENISA",
        "body_full": "European Telecommunications Standards Institute / European Network and Information Security Agency",
        "standards": ["ETSI TS 103 744", "ENISA Guidelines", "European Quantum Act"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.3,
            "data_at_rest": 1.2,
            "certificate_security": 1.1,
        }
    },
    "FR": {
        "name": "France",
        "body": "ANSSI",
        "body_full": "Agence nationale de la sécurité des systèmes d'information",
        "standards": ["ANSSI Guidelines", "RGS v2.0", "FIPS 203/204 adoption"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.2,
            "key_management": 1.1,
        }
    },
    "DE": {
        "name": "Germany",
        "body": "BSI",
        "body_full": "Federal Office for Information Security (Bundesamt für Sicherheit in der Informationstechnik)",
        "standards": ["BSI TR-02102", "Common Criteria", "FIPS 203/204"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.2,
            "certificate_security": 1.1,
        }
    },
    "UK": {
        "name": "United Kingdom",
        "body": "NCSC",
        "body_full": "National Cyber Security Centre (part of GCHQ)",
        "standards": ["NCSC Guidelines", "FIPS 203/204 adoption", "UK Quantum Strategy"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "quantum_readiness": 1.1,
        }
    },
    "IN": {
        "name": "India",
        "body": "TEC/SET/DRDO",
        "body_full": "Telecommunication Engineering Centre / Society for Electronic Transactions and Security / Defense Research and Development Organization",
        "standards": ["TEC Guidelines", "SETS Standards", "DRDO Quantum Initiative"],
        "deadline": "2032",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "iot_edge": 1.2,
        }
    },
    "SG": {
        "name": "Singapore",
        "body": "HSA/NQSN+",
        "body_full": "Health Sciences Authority / National Quantum-Safe Network",
        "standards": ["NQSN+ Guidelines", "Singapore Quantum Strategy", "FIPS adoption"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "api_encryption": 1.1,
        }
    },
    "CA": {
        "name": "Canada",
        "body": "CSE",
        "body_full": "Communications Security Establishment",
        "standards": ["CSE Guidelines", "FIPS 203/204 adoption", "Canadian Quantum Strategy"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "quantum_readiness": 1.1,
        }
    },
    "AU": {
        "name": "Australia",
        "body": "ASD",
        "body_full": "Australian Signals Directorate",
        "standards": ["ASD Guidelines", "Australian Quantum Strategy", "FIPS adoption"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "key_management": 1.1,
        }
    },
    "CN": {
        "name": "China",
        "body": "CAS/ICCS",
        "body_full": "Chinese Academy of Sciences / Institute of Commercial Cryptography Standards",
        "standards": ["GM/T Standards", "CAS Quantum Standards", "National Cryptography Law"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.3,
            "quantum_readiness": 1.2,
        }
    },
    "JP": {
        "name": "Japan",
        "body": "NICT",
        "body_full": "National Institute of Information and Communications Technology / Q-LEAP Initiative",
        "standards": ["NICT Guidelines", "Q-LEAP Standards", "FIPS adoption"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "hardware_security": 1.1,
        }
    },
    "KR": {
        "name": "South Korea",
        "body": "MSIT/KpqC",
        "body_full": "Ministry of Science and ICT / Korean Post-Quantum Cryptography research group",
        "standards": ["MSIT Guidelines", "KpqC Standards", "K-Quantum Initiative"],
        "deadline": "2030",
        "weight_modifiers": {
            "regulatory_compliance": 1.1,
            "iot_edge": 1.1,
        }
    }
}

def get_enhanced_region_profile(region_code: str) -> Dict[str, Any]:
    """Get enhanced regional compliance profile."""
    region_code = region_code.upper()
    if region_code not in ENHANCED_REGION_PROFILES:
        # Default to US standards
        return ENHANCED_REGION_PROFILES["US"]
    return ENHANCED_REGION_PROFILES[region_code]

def list_supported_regions() -> List[str]:
    """List all supported region codes."""
    return list(ENHANCED_REGION_PROFILES.keys())

def get_region_compliance_requirements(region_code: str) -> Dict[str, Any]:
    """Get specific compliance requirements for a region."""
    profile = get_enhanced_region_profile(region_code)
    return {
        "standards": profile["standards"],
        "deadline": profile["deadline"],
        "regulatory_body": profile["body_full"],
        "weight_modifiers": profile.get("weight_modifiers", {})
    }