# PQC Migration Agent System

## Overview
Multi-agent AI system for identifying and remediating quantum-vulnerable
cryptography across an organization's infrastructure.

## Agents

### Web & API Agent (`agents/web_api_agent.py`)
- **Domain**: Web services, REST APIs, authentication systems
- **Tools**: `jwt_scanner`, `oauth_scanner`
- **Scans for**: JWT signing (RS256, ES256), OAuth configs, TLS certs
- **Recommends**: ML-DSA (FIPS 204) for signing, ML-KEM (FIPS 203) for key exchange

### IoT & Edge Agent (`agents/iot_edge_agent.py`)
- **Domain**: IoT devices, embedded systems, edge computing
- **Tools**: `iot_scanner`
- **Scans for**: Firmware signing, OTA update security, device longevity risk
- **Recommends**: LMS/XMSS (SP 800-208) for firmware, ML-DSA for OTA

### Master Orchestrator (`core/orchestrator.py`)
- **Role**: Aggregates all agent assessments into a unified PQC Readiness Report
- **Input**: Assessment JSONs from S3 (`assessments/{agent_name}/*`)
- **Output**: Consolidated report with prioritized remediation steps

## Model Configuration
- **Provider**: AWS Bedrock
- **Model**: `anthropic.claude-3-5-sonnet-20241022-v2:0`
- **Region**: `us-east-1` or `me-central-1`

## Assessment Schema
All agents output findings in schema v1.0 format — see `core/base_agent.py`
for the standardized structure.

## Tool Registration
Tools are Python functions decorated with `@tool` from `strands` SDK.
The agent runtime automatically discovers and registers them.
