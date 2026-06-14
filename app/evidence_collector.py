"""
Evidence Collectors: Simulated integrations with CloudTrail (AWS) and Azure AD.
In production these would call real APIs (boto3, Microsoft Graph, etc.)
This module demonstrates the architecture for automated evidence collection.
"""
import json
import hashlib
import random
from datetime import datetime, timedelta
from typing import List, Dict
from dataclasses import dataclass, field


@dataclass
class CollectedEvidence:
    evidence_id: str
    source_system: str
    evidence_type: str
    requirement_id: str
    framework: str
    timestamp: str
    description: str
    raw_data: Dict
    confidence_score: float
    signed: bool = True  # Non-repudiation flag

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "source_system": self.source_system,
            "evidence_type": self.evidence_type,
            "requirement_id": self.requirement_id,
            "framework": self.framework,
            "timestamp": self.timestamp,
            "description": self.description,
            "raw_data": self.raw_data,
            "confidence_score": self.confidence_score,
            "signed": self.signed,
            "collection_method": "automated",
        }


def _gen_id(prefix: str, seed: str) -> str:
    h = hashlib.md5(seed.encode()).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


# ─── Integration 1: AWS CloudTrail ───────────────────────────────────────────

class CloudTrailCollector:
    """
    Simulates querying AWS CloudTrail for evidence of encryption, key rotation,
    and access logging events.
    
    Production implementation:
        import boto3
        client = boto3.client('cloudtrail')
        response = client.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'RotateKey'}],
            StartTime=datetime.now() - timedelta(days=30)
        )
    """
    
    SOURCE = "AWS CloudTrail"
    
    def collect_encryption_evidence(self) -> List[CollectedEvidence]:
        now = datetime.utcnow()
        
        events = [
            {
                "eventName": "CreateKey",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789:user/infra-sec"},
                "requestParameters": {"description": "RDS AES-256 encryption key", "keySpec": "SYMMETRIC_DEFAULT"},
                "responseElements": {"keyMetadata": {"keyId": "key-abc123", "keyUsage": "ENCRYPT_DECRYPT"}},
                "eventTime": (now - timedelta(days=5)).isoformat() + "Z",
            },
            {
                "eventName": "RotateKey",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789:user/key-mgmt"},
                "requestParameters": {"keyId": "key-abc123"},
                "eventTime": (now - timedelta(days=10)).isoformat() + "Z",
            }
        ]
        
        results = []
        for ev in events:
            eid = _gen_id("CT", ev["eventName"] + ev["eventTime"])
            results.append(CollectedEvidence(
                evidence_id=eid,
                source_system=self.SOURCE,
                evidence_type="Configuration_Snapshot" if "Create" in ev["eventName"] else "Audit_Log",
                requirement_id="POL-ENC-001-REQ01",
                framework="GDPR",
                timestamp=ev["eventTime"],
                description=f"CloudTrail: {ev['eventName']} event captured. KMS key management verified.",
                raw_data=ev,
                confidence_score=0.95,
                signed=True,
            ))
        return results
    
    def collect_access_logging_evidence(self) -> List[CollectedEvidence]:
        now = datetime.utcnow()
        event = {
            "eventName": "EnableLogging",
            "requestParameters": {"bucketName": "prod-audit-logs", "loggingEnabled": True},
            "eventTime": (now - timedelta(days=2)).isoformat() + "Z",
            "retentionDays": 365,
        }
        eid = _gen_id("CT", "EnableLogging" + event["eventTime"])
        return [CollectedEvidence(
            evidence_id=eid,
            source_system=self.SOURCE,
            evidence_type="Audit_Log",
            requirement_id="POL-AUD-001-REQ01",
            framework="NIST",
            timestamp=event["eventTime"],
            description="CloudTrail S3 access logging enabled on prod-audit-logs. Retention: 365 days.",
            raw_data=event,
            confidence_score=0.97,
            signed=True,
        )]
    
    def collect_all(self) -> List[CollectedEvidence]:
        return self.collect_encryption_evidence() + self.collect_access_logging_evidence()


# ─── Integration 2: Azure AD / Okta (MFA Evidence) ───────────────────────────

class AzureADCollector:
    """
    Simulates querying Azure AD for MFA enforcement and privileged access policies.
    
    Production implementation:
        import msal, requests
        token = msal.ConfidentialClientApplication(...).acquire_token_for_client(...)
        r = requests.get(
            'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy',
            headers={'Authorization': f'Bearer {token["access_token"]}'}
        )
    """

    SOURCE = "Azure AD / Microsoft Graph"

    def collect_mfa_evidence(self) -> List[CollectedEvidence]:
        now = datetime.utcnow()
        config = {
            "conditionalAccessPolicies": [
                {
                    "displayName": "Require MFA for Admin Roles",
                    "state": "enabled",
                    "conditions": {"users": {"includeRoles": ["GlobalAdmin", "SecurityAdmin"]}},
                    "grantControls": {"builtInControls": ["mfa"]},
                    "createdDateTime": (now - timedelta(days=90)).isoformat(),
                    "modifiedDateTime": (now - timedelta(days=3)).isoformat(),
                }
            ],
            "mfaRegistrationPercentage": 0.96,
            "nonCompliantUsers": 2,
            "totalAdminUsers": 47,
        }
        eid = _gen_id("AAD", "MFA" + now.strftime("%Y%m%d"))
        return [CollectedEvidence(
            evidence_id=eid,
            source_system=self.SOURCE,
            evidence_type="Access_Report",
            requirement_id="POL-AC-001-REQ01",
            framework="NIST",
            timestamp=(now - timedelta(days=1)).isoformat() + "Z",
            description="Azure AD: MFA conditional access policy active. 96% admin compliance. 2 non-compliant users flagged.",
            raw_data=config,
            confidence_score=0.92,
            signed=True,
        )]

    def collect_privilege_review_evidence(self) -> List[CollectedEvidence]:
        now = datetime.utcnow()
        review = {
            "accessReviewId": "rev-2026-Q1",
            "scope": "All privileged roles",
            "completionDate": (now - timedelta(days=14)).isoformat(),
            "totalReviewed": 312,
            "approved": 298,
            "revoked": 14,
            "reviewers": ["soc-lead@company.com", "ciso@company.com"],
        }
        eid = _gen_id("AAD", "AccessReview" + review["accessReviewId"])
        return [CollectedEvidence(
            evidence_id=eid,
            source_system=self.SOURCE,
            evidence_type="Audit_Log",
            requirement_id="POL-AC-001-REQ02",
            framework="SOX",
            timestamp=(now - timedelta(days=14)).isoformat() + "Z",
            description="Q1 2026 privileged access review complete. 312 accounts reviewed, 14 revoked for over-provisioning.",
            raw_data=review,
            confidence_score=0.90,
            signed=True,
        )]
    
    def collect_all(self) -> List[CollectedEvidence]:
        return self.collect_mfa_evidence() + self.collect_privilege_review_evidence()


# ─── Integration Runner ───────────────────────────────────────────────────────

def run_all_collectors() -> List[Dict]:
    """Run all configured evidence collectors and return combined results."""
    collectors = [
        CloudTrailCollector(),
        AzureADCollector(),
    ]
    
    all_evidence = []
    collection_log = []
    
    for collector in collectors:
        try:
            evidence = collector.collect_all()
            all_evidence.extend(evidence)
            collection_log.append({
                "source": collector.SOURCE,
                "status": "SUCCESS",
                "records_collected": len(evidence),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
        except Exception as e:
            collection_log.append({
                "source": getattr(collector, 'SOURCE', 'Unknown'),
                "status": "FAILED",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
    
    return {
        "evidence": [e.to_dict() for e in all_evidence],
        "collection_log": collection_log,
        "total_collected": len(all_evidence),
        "run_timestamp": datetime.utcnow().isoformat() + "Z",
    }


if __name__ == "__main__":
    results = run_all_collectors()
    print(f"Collected {results['total_collected']} evidence records")
    print("\nCollection Log:")
    for log in results["collection_log"]:
        print(f"  [{log['status']}] {log['source']}: {log.get('records_collected', log.get('error', ''))}")
    print("\nSample Evidence:")
    for ev in results["evidence"][:2]:
        print(f"  {ev['evidence_id']}: {ev['description'][:80]}")