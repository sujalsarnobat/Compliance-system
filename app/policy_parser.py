"""
Policy Parser: Extracts structured requirements from raw policy documents.
Uses regex + keyword-based NLP to parse requirements without needing an LLM.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PolicyRequirement:
    req_id: str
    policy_id: str
    policy_name: str
    requirement_text: str
    responsible_team: str
    scope: str
    evidence_source: str
    audit_frequency: str
    framework_mappings: List[str]
    keywords: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "req_id": self.req_id,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "requirement_text": self.requirement_text,
            "responsible_team": self.responsible_team,
            "scope": self.scope,
            "evidence_source": self.evidence_source,
            "audit_frequency": self.audit_frequency,
            "framework_mappings": self.framework_mappings,
            "keywords": self.keywords,
        }


COMPLIANCE_KEYWORDS = {
    "encryption": ["encrypt", "aes", "tls", "kms", "key rotation", "cipher", "ssl", "https"],
    "access_control": ["mfa", "multi-factor", "least privilege", "rbac", "iam", "privileged", "admin", "permission"],
    "audit_logging": ["log", "audit", "trail", "monitoring", "siem", "retain", "retention"],
    "data_protection": ["pii", "personal data", "gdpr", "data at rest", "data in transit"],
    "incident_response": ["incident", "breach", "notification", "response"],
    "backup": ["backup", "recovery", "rto", "rpo", "disaster"],
}

def extract_keywords(text: str) -> List[str]:
    text_lower = text.lower()
    matched = []
    for category, kws in COMPLIANCE_KEYWORDS.items():
        if any(kw in text_lower for kw in kws):
            matched.append(category)
    return matched


def parse_policy_document(text: str) -> List[PolicyRequirement]:
    """Parse raw policy text into structured PolicyRequirement objects."""
    requirements = []
    
    # Split on policy blocks
    policy_blocks = re.split(r'\n---\n', text.strip())

    for block in policy_blocks:
        if not block.strip():
            continue

        # Extract policy-level metadata
        policy_name_match = re.search(r'^POLICY:\s*(.+)$', block, re.MULTILINE)
        policy_id_match = re.search(r'^POLICY_ID:\s*(\S+)', block, re.MULTILINE)

        policy_name = policy_name_match.group(1).strip() if policy_name_match else "Unknown Policy"
        policy_id = policy_id_match.group(1).strip() if policy_id_match else "UNKNOWN"

        # Split requirements within the block
        req_blocks = re.split(r'\nREQUIREMENT \d+:', block)
        req_blocks = req_blocks[1:]  # skip header block

        for i, req_block in enumerate(req_blocks, start=1):
            lines = req_block.strip().split('\n')
            if not lines:
                continue

            req_text = lines[0].strip()
            
            def extract_field(pattern: str, default: str = "N/A") -> str:
                match = re.search(pattern, req_block, re.IGNORECASE)
                return match.group(1).strip() if match else default

            responsible = extract_field(r'Responsible:\s*(.+)')
            scope = extract_field(r'Scope:\s*(.+)')
            evidence_source = extract_field(r'Evidence Source:\s*(.+)')
            audit_freq = extract_field(r'Audit Frequency:\s*(.+)')
            
            mapping_match = re.search(r'Compliance Mapping:\s*(.+)', req_block, re.IGNORECASE)
            mappings = []
            if mapping_match:
                raw = mapping_match.group(1)
                mappings = [m.strip() for m in re.split(r'[,;]', raw) if m.strip()]

            req = PolicyRequirement(
                req_id=f"{policy_id}-REQ{i:02d}",
                policy_id=policy_id,
                policy_name=policy_name,
                requirement_text=req_text,
                responsible_team=responsible,
                scope=scope,
                evidence_source=evidence_source,
                audit_frequency=audit_freq,
                framework_mappings=mappings,
                keywords=extract_keywords(req_text),
            )
            requirements.append(req)

    return requirements


def load_and_parse(filepath: str) -> List[PolicyRequirement]:
    with open(filepath, 'r') as f:
        text = f.read()
    return parse_policy_document(text)


if __name__ == "__main__":
    reqs = load_and_parse("../sample_data/policy_documents.txt")
    for r in reqs:
        print(f"[{r.req_id}] {r.policy_name}: {r.requirement_text[:60]}...")
        print(f"  Frameworks: {r.framework_mappings}")
        print(f"  Keywords: {r.keywords}")
        print()