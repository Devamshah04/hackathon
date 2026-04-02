# PQC Migration Intelligence Agent Platform

A multi-agent AI system that helps organizations transition their infrastructure from classical cryptography (RSA, ECC) to **Post-Quantum Cryptography (PQC)** following NIST standards.

## 🎯 Overview

The platform uses specialized AI agents powered by **AWS Bedrock (Claude 3.5 Sonnet)** and the **Strands SDK** to:

1. **Scan** 6 infrastructure domains for quantum-vulnerable cryptography
2. **Identify** RSA, ECC, DH, AES-128, and other at-risk implementations
3. **Generate** automated migration roadmaps with NIST-approved PQC replacements

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                      Master Orchestrator                         │
│               (Aggregates + Final PQC Readiness Report)          │
└───┬──────────┬──────────┬──────────┬──────────┬──────────┬───────┘
    │          │          │          │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼────┐
│Public │ │Symme- │ │Network│ │API &  │ │IoT &  │ │Cloud & │
│Key    │ │tric   │ │Proto- │ │Web    │ │Edge   │ │Storage │
│Agent  │ │Agent  │ │col    │ │Agent  │ │Agent  │ │Agent   │
└───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬────┘
    │         │         │         │         │         │
┌───▼─────────▼─────────▼─────────▼─────────▼─────────▼────┐
│            Shared Assessment Schema v1.0                  │
│                  (S3 / Local Output)                      │
└──────────────────────────────────────────────────────────┘
```

## 📂 Project Structure

```
pqc-migration-agent/
├── agents/                       # All 6 specialized scanning agents
│   ├── __init__.py
│   ├── public_key_agent.py       # 1. Public Key Algorithms (RSA, ECC, DH)
│   ├── symmetric_agent.py        # 2. Symmetric Algorithms (AES-128 → AES-256)
│   ├── network_protocol_agent.py # 3. Network Protocols (TLS, SSH, IKEv2)
│   ├── web_api_agent.py          # 4. APIs & Web Services (JWT, OAuth)
│   ├── iot_edge_agent.py         # 5. IoT & Edge Devices (Firmware, OTA)
│   └── cloud_storage_agent.py    # 6. Cloud & Storage (Data-at-Rest)
├── core/                         # Orchestration and shared logic
│   ├── __init__.py
│   ├── orchestrator.py           # Master Aggregator Agent
│   └── base_agent.py             # Abstract base class for all agents
├── tools/                        # Strands @tool decorated scanner functions
│   ├── __init__.py
│   ├── public_key_scanner.py     # RSA/ECC/DH key analysis
│   ├── symmetric_scanner.py      # AES/3DES strength evaluation
│   ├── network_scanner.py        # TLS/SSH/VPN protocol analysis
│   ├── jwt_scanner.py            # JWT token header analysis
│   ├── oauth_scanner.py          # OAuth endpoint auditing
│   ├── iot_scanner.py            # IoT firmware/device scanning
│   └── cloud_scanner.py          # Cloud encryption & KMS analysis
├── output/                       # Local assessment storage (synced to S3)
│   └── .gitkeep
├── .kiro/                        # Kiro IDE specifications
│   └── specs/
│       └── pqc-agents.md         # System prompts and tool specs
├── requirements.txt              # Python dependencies
├── main.py                       # Entry point for the platform
├── .env.example                  # Environment variable template
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

## 🔧 Tech Stack

- **Language**: Python 3.10+
- **AI Backend**: AWS Bedrock (Claude 3.5 Sonnet — `anthropic.claude-3-5-sonnet-20241022-v2:0`)
- **Agent Framework**: [Strands Agents SDK](https://github.com/strands-agents/strands-agents) (`strands-agents`)
- **AWS Services**: Bedrock, S3
- **Key Libraries**: `boto3`, `cryptography`, `python-jose`, `PyJWT`, `pandas`

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- AWS account with Bedrock access (Claude 3.5 Sonnet enabled)
- AWS credentials configured (`aws configure` or environment variables)

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd pqc-migration-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your AWS region and S3 bucket
```

### Running

```bash
python main.py
```

## 📦 Integration Contract

All agents output assessments in a **standardized JSON format** to S3:

**S3 Path**: `assessments/{agent_name}/{timestamp}_{run_id}.json`

**Schema Version**: `1.0`

```json
{
  "schema_version": "1.0",
  "agent_name": "web_api_agent",
  "timestamp": "2026-04-02T12:00:00Z",
  "run_id": "uuid-here",
  "findings": [
    {
      "id": "finding-uuid",
      "asset": "api.example.com",
      "domain": "web_api",
      "vulnerability": {
        "algorithm": "RS256",
        "key_size": 2048,
        "location": "JWT signing",
        "risk_level": "CRITICAL",
        "reason": "RSA-2048 broken by Shor's algorithm"
      },
      "migration_target": {
        "recommended_algorithm": "ML-DSA-65",
        "standard": "FIPS 204",
        "priority": "HIGH",
        "estimated_effort": "Medium"
      }
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## 🔐 Infrastructure Domains & PQC Migration Mapping

| # | Domain | Scans For | Unsafe (Q-Vulnerable) | Safe (PQC Replacement) | Standard |
|---|--------|-----------|----------------------|----------------------|----------|
| 1 | **Public Key Algorithms** | Key Exchange & Signatures | RSA-2048, ECC P-256/384, DH | ML-KEM (Kyber), ML-DSA (Dilithium) | FIPS 203/204 |
| 2 | **Symmetric Algorithms** | Encryption Strength | AES-128 (64-bit effective) | AES-256 (128-bit effective) | Grover's mitigation |
| 3 | **Network Protocols** | Handshake & Tunneling | TLS 1.2, IKEv2 Classic, SSH-RSA | TLS 1.3 Hybrid, PQ-VPNs | IETF PQC Drafts |
| 4 | **APIs & Web Services** | Auth Tokens & Headers | JWT (RS256), OAuth2 Classic | ML-DSA Signed Tokens | FIPS 204 |
| 5 | **IoT & Edge Devices** | Firmware & Identity | RSA Signatures, Hardcoded Keys | LMS, XMSS (Stateful Hash-based) | NIST SP 800-208 |
| 6 | **Cloud & Storage** | Data-at-Rest Encryption | RSA-OAEP (2048-bit) | RSA-OAEP (4096-bit) or ML-KEM | FIPS 203 |

## 🌐 AWS Region

Workshop region is typically `us-east-1` or `me-central-1` (UAE). Check your workshop instructions for the exact region.

## 📄 License

This project was developed for the UAE/CTIB AWS Security Hackathon.
