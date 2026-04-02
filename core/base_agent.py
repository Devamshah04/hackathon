"""
Base Agent — Abstract base class for all PQC scanning agents.

Provides shared configuration for AWS Bedrock, standardized assessment
output schema, and S3 persistence utilities.
"""

import json
import uuid
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import boto3
from dotenv import load_dotenv

load_dotenv()

# ─── Constants ───────────────────────────────────────────────────────────────
SCHEMA_VERSION = "1.0"
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "pqc-migration-assessments")
S3_PREFIX = os.getenv("S3_PREFIX", "assessments/")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")


class BaseAgent(ABC):
    """
    Abstract base class that every scanning agent must extend.

    Responsibilities:
      - Provides a shared Bedrock client configuration
      - Enforces a standardized assessment output schema (v1.0)
      - Handles local and S3 persistence of assessment results
    """

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.run_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.findings: list[dict] = []
        self.asset_ratings: list[dict] = []   # scored & ranked output

        # AWS clients — initialised lazily on first use
        self._bedrock_client = None
        self._s3_client = None

    # ── AWS Clients ─────────────────────────────────────────────────────────
    @property
    def bedrock_client(self):
        if self._bedrock_client is None:
            self._bedrock_client = boto3.client(
                "bedrock-runtime",
                region_name=AWS_REGION,
            )
        return self._bedrock_client

    @property
    def s3_client(self):
        if self._s3_client is None:
            self._s3_client = boto3.client("s3", region_name=AWS_REGION)
        return self._s3_client

    # ── Assessment Schema ───────────────────────────────────────────────────
    def add_finding(
        self,
        asset: str,
        domain: str,
        algorithm: str,
        key_size: int | None,
        location: str,
        risk_level: str,
        reason: str,
        recommended_algorithm: str,
        standard: str,
        priority: str,
        estimated_effort: str = "Medium",
    ) -> dict:
        """Add a vulnerability finding in the standardized schema."""
        finding = {
            "id": str(uuid.uuid4()),
            "asset": asset,
            "domain": domain,
            "vulnerability": {
                "algorithm": algorithm,
                "key_size": key_size,
                "location": location,
                "risk_level": risk_level,
                "reason": reason,
            },
            "migration_target": {
                "recommended_algorithm": recommended_algorithm,
                "standard": standard,
                "priority": priority,
                "estimated_effort": estimated_effort,
            },
        }
        self.findings.append(finding)
        return finding

    def build_assessment(self) -> dict:
        """Build the full assessment JSON conforming to schema v1.0."""
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            # Support both formats: nested (from add_finding) and flat (from tools)
            if "vulnerability" in f and isinstance(f["vulnerability"], dict):
                level = f["vulnerability"].get("risk_level", "").upper()
            else:
                level = f.get("risk", f.get("risk_level", "")).upper()
            if level in risk_counts:
                risk_counts[level] += 1

        assessment = {
            "schema_version": SCHEMA_VERSION,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "critical": risk_counts["CRITICAL"],
                "high": risk_counts["HIGH"],
                "medium": risk_counts["MEDIUM"],
                "low": risk_counts["LOW"],
            },
        }

        # Include scored ratings if available
        if self.asset_ratings:
            assessment["rated_assets"] = self.asset_ratings

        return assessment

    # ── Persistence ─────────────────────────────────────────────────────────
    def save_local(self) -> str:
        """Save assessment JSON to the local output/ directory."""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filename = f"{self.timestamp.replace(':', '-')}_{self.run_id}.json"
        filepath = os.path.join(OUTPUT_DIR, self.agent_name, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(self.build_assessment(), f, indent=2)

        print(f"[{self.agent_name}] Assessment saved locally -> {filepath}")
        return filepath

    def save_to_s3(self) -> str:
        """Upload assessment JSON to S3: assessments/{agent_name}/{ts}_{run_id}.json"""
        key = f"{S3_PREFIX}{self.agent_name}/{self.timestamp.replace(':', '-')}_{self.run_id}.json"
        self.s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(self.build_assessment(), indent=2),
            ContentType="application/json",
        )
        print(f"[{self.agent_name}] Assessment uploaded → s3://{S3_BUCKET}/{key}")
        return f"s3://{S3_BUCKET}/{key}"

    # ── Abstract Interface ──────────────────────────────────────────────────
    @abstractmethod
    def scan(self, target: dict) -> dict:
        """
        Run the agent's scan against a target.

        Args:
            target: Target-specific configuration dict
                    (e.g., JWT tokens, firmware metadata, etc.)

        Returns:
            The full assessment dict.
        """
        ...
