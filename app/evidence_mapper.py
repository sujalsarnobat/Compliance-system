"""
Evidence Mapping Engine.
Links evidence_artifacts to parsed policy requirements using
framework matching, keyword scoring, and requirement ID mapping.
"""
import pandas as pd
import re
from typing import List, Dict, Tuple
from app.policy_parser import PolicyRequirement


# Framework name normalization
FRAMEWORK_ALIASES = {
    "GDPR": ["GDPR", "gdpr", "GDPR Article"],
    "NIST": ["NIST", "nist", "NIST SP", "NIST SC", "NIST AU", "NIST AC", "NIST IA"],
    "PCI-DSS": ["PCI-DSS", "PCI DSS", "pci", "PCI"],
    "SOX": ["SOX", "sox", "SOX 302", "SOX 404"],
    "ISO27001": ["ISO 27001", "ISO27001", "iso27001", "ISO 27001 A"],
    "HIPAA": ["HIPAA", "hipaa"],
}


def normalize_framework(raw: str) -> str:
    for canonical, aliases in FRAMEWORK_ALIASES.items():
        if any(raw.upper().startswith(a.upper()) for a in aliases):
            return canonical
    return raw.upper()


def keyword_overlap_score(req_text: str, evidence_summary: str, evidence_type: str) -> float:
    """Simple TF-style keyword match score between requirement and evidence."""
    from app.policy_parser import COMPLIANCE_KEYWORDS
    req_lower = req_text.lower()
    ev_lower = (evidence_summary + " " + evidence_type).lower()
    
    score = 0.0
    total_categories = len(COMPLIANCE_KEYWORDS)
    
    for category, kws in COMPLIANCE_KEYWORDS.items():
        req_hit = any(k in req_lower for k in kws)
        ev_hit = any(k in ev_lower for k in kws)
        if req_hit and ev_hit:
            score += 1.0
    
    return round(score / total_categories, 3)


def map_evidence_to_requirements(
    evidence_df: pd.DataFrame,
    requirements: List[PolicyRequirement],
) -> pd.DataFrame:
    """
    For each requirement, find evidence that supports it.
    Matching criteria:
      1. Framework alignment (primary)
      2. Keyword overlap (secondary)
    Returns a mapping dataframe.
    """
    mapping_rows = []

    for req in requirements:
        # Normalize framework names from requirement
        req_frameworks = set()
        for fm in req.framework_mappings:
            req_frameworks.add(normalize_framework(fm))

        for _, ev_row in evidence_df.iterrows():
            ev_framework = normalize_framework(str(ev_row.get('framework', '')))
            
            # Primary: framework match
            framework_match = ev_framework in req_frameworks
            if not framework_match:
                continue

            # Secondary: keyword overlap
            kw_score = keyword_overlap_score(
                req.requirement_text,
                str(ev_row.get('evidence_summary', '')),
                str(ev_row.get('evidence_type', ''))
            )

            # Compute link confidence
            link_confidence = round(
                0.6 * float(framework_match) +
                0.4 * kw_score,
                3
            )

            mapping_rows.append({
                'req_id': req.req_id,
                'policy_id': req.policy_id,
                'policy_name': req.policy_name,
                'requirement_text': req.requirement_text,
                'req_frameworks': ", ".join(req.framework_mappings),
                'req_keywords': ", ".join(req.keywords),
                'evidence_id': ev_row['evidence_id'],
                'evidence_type': ev_row['evidence_type'],
                'evidence_framework': ev_row['framework'],
                'evidence_summary': ev_row.get('evidence_summary', ''),
                'evidence_location': ev_row.get('evidence_location', ''),
                'collection_date': ev_row.get('collection_date', ''),
                'freshness_days': ev_row.get('freshness_days', 0),
                'confidence_score': ev_row.get('confidence_score', 0),
                'status': ev_row.get('status', ''),
                'link_confidence': link_confidence,
                'framework_match': framework_match,
                'keyword_score': kw_score,
            })

    if not mapping_rows:
        return pd.DataFrame()

    mapping_df = pd.DataFrame(mapping_rows)
    return mapping_df


def get_best_evidence_per_requirement(mapping_df: pd.DataFrame, top_n: int = 3) -> pd.DataFrame:
    """
    For each requirement, rank evidence by:
    1. Status (Approved > Pending > Needs_Update > Rejected)
    2. Freshness (lower days = better)
    3. Confidence score (higher = better)
    Returns top N per requirement.
    """
    if mapping_df.empty:
        return mapping_df

    STATUS_RANK = {'Approved': 0, 'Pending_Review': 1, 'Needs_Update': 2, 'Rejected': 3}
    mapping_df = mapping_df.copy()
    mapping_df['status_rank'] = mapping_df['status'].map(STATUS_RANK).fillna(4)
    
    mapping_df = mapping_df.sort_values(
        ['req_id', 'status_rank', 'freshness_days', 'confidence_score'],
        ascending=[True, True, True, False]
    )
    
    return mapping_df.groupby('req_id').head(top_n).reset_index(drop=True)


def compute_requirement_coverage(
    requirements: List[PolicyRequirement],
    best_evidence: pd.DataFrame
) -> pd.DataFrame:
    """
    For each requirement, determine compliance status based on best evidence.
    """
    covered_req_ids = set(best_evidence['req_id'].unique()) if not best_evidence.empty else set()
    
    rows = []
    for req in requirements:
        if req.req_id in covered_req_ids:
            req_evidence = best_evidence[best_evidence['req_id'] == req.req_id]
            best = req_evidence.iloc[0]
            
            approved_count = (req_evidence['status'] == 'Approved').sum()
            avg_confidence = req_evidence['confidence_score'].mean()
            avg_freshness = req_evidence['freshness_days'].mean()
            
            if approved_count > 0 and avg_freshness <= 30 and avg_confidence >= 0.75:
                compliance_status = "COMPLIANT"
            elif approved_count > 0 or avg_confidence >= 0.65:
                compliance_status = "PARTIAL"
            else:
                compliance_status = "NON_COMPLIANT"
            
            rows.append({
                'req_id': req.req_id,
                'policy_id': req.policy_id,
                'policy_name': req.policy_name,
                'requirement_text': req.requirement_text,
                'evidence_count': len(req_evidence),
                'approved_evidence': int(approved_count),
                'avg_confidence': round(float(avg_confidence), 3),
                'avg_freshness_days': round(float(avg_freshness), 1),
                'compliance_status': compliance_status,
                'frameworks': ", ".join(req.framework_mappings),
                'best_evidence_ids': ", ".join(req_evidence['evidence_id'].tolist()),
                'has_evidence': True,
            })
        else:
            rows.append({
                'req_id': req.req_id,
                'policy_id': req.policy_id,
                'policy_name': req.policy_name,
                'requirement_text': req.requirement_text,
                'evidence_count': 0,
                'approved_evidence': 0,
                'avg_confidence': 0.0,
                'avg_freshness_days': 999,
                'compliance_status': "GAP",
                'frameworks': ", ".join(req.framework_mappings),
                'best_evidence_ids': "",
                'has_evidence': False,
            })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '..')
    from app.policy_parser import load_and_parse

    requirements = load_and_parse("../sample_data/policy_documents.txt")
    evidence_df = pd.read_csv("../sample_data/evidence_artifacts.csv")

    mapping_df = map_evidence_to_requirements(evidence_df, requirements)
    best = get_best_evidence_per_requirement(mapping_df)
    coverage = compute_requirement_coverage(requirements, best)

    print("=== REQUIREMENT COVERAGE ===")
    for _, r in coverage.iterrows():
        print(f"[{r['compliance_status']}] {r['req_id']}: {r['requirement_text'][:60]}...")
        print(f"   Evidence: {r['evidence_count']} records | Approved: {r['approved_evidence']} | Avg Conf: {r['avg_confidence']:.0%}")