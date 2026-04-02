# PQC Migration Intelligence Agent Platform

A multi-agent AI system that helps organizations transition their infrastructure from classical cryptography (RSA, ECC) to **Post-Quantum Cryptography (PQC)** following NIST standards.

## 🎯 Overview

The platform uses specialized AI agents powered by **AWS Bedrock (Claude 3.5 Sonnet)** and the **Strands SDK** to:

1. **Scan** various infrastructure domains (Web APIs, IoT/Edge devices, Cloud)
2. **Identify** quantum-vulnerable cryptographic implementations
3. **Generate** automated migration roadmaps with NIST-approved PQC replacements

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Master Orchestrator                 │
│            (Aggregates + Final Report)               │
└────────────┬──────────────────┬──────────────────────┘
             │                  │
    ┌────────▼────────┐  ┌──────▼──────────────┐
    │  Web/API Agent  │  │  IoT/Edge Agent      │
    │  (JWT, OAuth,   │  │  (Firmware, OTA,     │
    │   Certificates) │  │   Device Longevity)  │
    └────────┬────────┘  └──────┬──────────────┘
             │                  │
    ┌────────▼──────────────────▼──────────────┐
    │         Shared Assessment Schema          │
    │         (S3 / Local Output)               │
    └──────────────────────────────────────────┘
```

## 📂 Project Structure

```
pqc-migration-agent/
├── agents/                  # Specialized AI Agent implementations
│   ├── __init__.py
│   ├── web_api_agent.py     # API & Web Services Agent
│   └── iot_edge_agent.py    # IoT & Edge Devices Agent
├── core/                    # Orchestration and shared logic
│   ├── __init__.py
│   ├── orchestrator.py      # Master Aggregator Agent
│   └── base_agent.py        # Abstract base class for all agents
├── tools/                   # LLM tools used by agents (@tool decorated)
│   ├── __init__.py
│   ├── jwt_scanner.py       # JWT token analysis
│   ├── oauth_scanner.py     # OAuth endpoint auditing
│   └── iot_scanner.py       # IoT firmware/device scanning
├── output/                  # Local assessment storage (synced to S3)
│   └── .gitkeep
├── .kiro/                   # Kiro IDE specifications
│   └── specs/
│       └── pqc-agents.md    # System prompts and tool specs
├── requirements.txt         # Python dependencies
├── main.py                  # Entry point for the platform
├── .env.example             # Environment variable template
├── .gitignore               # Git ignore rules
└── README.md                # This file
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

## 🔐 PQC Migration Mapping

| Current Algorithm | Vulnerability | NIST PQC Replacement | Standard |
|-------------------|--------------|---------------------|----------|
| RSA / DH | Shor's Algorithm | **ML-KEM** (Kyber) | FIPS 203 |
| ECDSA / RSA-PSS | Shor's Algorithm | **ML-DSA** (Dilithium) | FIPS 204 |
| Firmware Signing | Long-lived keys | **LMS / XMSS** | NIST SP 800-208 |

## 🌐 AWS Region

Workshop region is typically `us-east-1` or `me-central-1` (UAE). Check your workshop instructions for the exact region.

## 📄 License

This project was developed for the UAE/CTIB AWS Security Hackathon.
