"""
Compliance Evidence System — Flask Backend
Provides REST API for dashboard, report generation, and evidence queries.
"""
import os
import json
import time
import sys
from pathlib import Path
from datetime import datetime

import pandas as pd
from flask import Flask, jsonify, render_template, request, send_file, abort

# Ensure app module is importable
sys.path.insert(0, str(Path(__file__).parent))

from app.policy_parser import load_and_parse
from app.evidence_validator import (
    validate_evidence, compute_framework_scorecard,
    compute_overall_metrics, self_evaluate
)
from app.evidence_mapper import (
    map_evidence_to_requirements, get_best_evidence_per_requirement,
    compute_requirement_coverage
)
from app.evidence_collector import run_all_collectors
from app.report_generator import generate_report

app = Flask(__name__, template_folder='templates', static_folder='static')

# ── Data Paths ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "sample_data"
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

POLICY_FILE   = DATA_DIR / "policy_documents.txt"
EVIDENCE_FILE = DATA_DIR / "evidence_artifacts.csv"

# ── In-Memory Cache ───────────────────────────────────────────────────────────
_cache = {}

def load_all_data():
    """Load and process everything. Cached after first load."""
    if _cache.get('loaded'):
        return _cache

    t0 = time.time()

    # 1. Parse policies
    requirements = load_and_parse(str(POLICY_FILE))
    
    # 2. Load & validate evidence
    raw_df = pd.read_csv(str(EVIDENCE_FILE))
    validated_df = validate_evidence(raw_df)
    
    # 3. Map evidence to requirements
    mapping_df = map_evidence_to_requirements(validated_df, requirements)
    best_evidence = get_best_evidence_per_requirement(mapping_df)
    coverage_df = compute_requirement_coverage(requirements, best_evidence)
    
    # 4. Compute metrics
    metrics = compute_overall_metrics(validated_df)
    scorecard = compute_framework_scorecard(validated_df)
    eval_results = self_evaluate(validated_df)
    
    _cache.update({
        'loaded': True,
        'requirements': requirements,
        'raw_df': raw_df,
        'validated_df': validated_df,
        'mapping_df': mapping_df,
        'best_evidence': best_evidence,
        'coverage_df': coverage_df,
        'metrics': metrics,
        'scorecard': scorecard,
        'eval_results': eval_results,
        'load_time_ms': round((time.time() - t0) * 1000),
    })
    return _cache


# ── Routes: Pages ─────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


# ── Routes: API ───────────────────────────────────────────────────────────────

@app.route('/api/metrics')
def api_metrics():
    data = load_all_data()
    return jsonify({
        'metrics': data['metrics'],
        'scorecard': data['scorecard'],
        'eval_results': data['eval_results'],
        'load_time_ms': data['load_time_ms'],
    })


@app.route('/api/requirements')
def api_requirements():
    data = load_all_data()
    coverage = data['coverage_df']
    return jsonify({
        'requirements': coverage.to_dict(orient='records'),
        'total': len(coverage),
        'compliant': int((coverage['compliance_status'] == 'COMPLIANT').sum()),
        'partial': int((coverage['compliance_status'] == 'PARTIAL').sum()),
        'gap': int((coverage['compliance_status'] == 'GAP').sum()),
    })


@app.route('/api/evidence')
def api_evidence():
    data = load_all_data()
    validated = data['validated_df']
    
    # Filters
    framework = request.args.get('framework', '')
    status = request.args.get('status', '')
    anomaly_only = request.args.get('anomaly_only', 'false').lower() == 'true'
    search = request.args.get('search', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    df = validated.copy()
    if framework:
        df = df[df['framework'] == framework]
    if status:
        df = df[df['status'] == status]
    if anomaly_only:
        df = df[df['is_anomaly'] == True]
    if search:
        mask = (
            df['evidence_id'].str.lower().str.contains(search) |
            df['evidence_summary'].str.lower().str.contains(search, na=False) |
            df['requirement_id'].str.lower().str.contains(search)
        )
        df = df[mask]
    
    total = len(df)
    start = (page - 1) * per_page
    end = start + per_page
    page_df = df.iloc[start:end]
    
    return jsonify({
        'evidence': page_df.to_dict(orient='records'),
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
    })


@app.route('/api/anomalies')
def api_anomalies():
    data = load_all_data()
    validated = data['validated_df']
    anomalies = validated[validated['is_anomaly'] == True]
    
    by_type = anomalies.groupby('anomaly_type').agg(
        count=('evidence_id', 'count'),
        avg_confidence=('confidence_score', 'mean'),
        frameworks=('framework', lambda x: list(x.unique())),
    ).reset_index()

    by_severity = anomalies['severity'].value_counts().to_dict()
    
    return jsonify({
        'total_anomalies': int(len(anomalies)),
        'by_type': by_type.to_dict(orient='records'),
        'by_severity': by_severity,
        'critical_count': int((anomalies['severity'] == 'CRITICAL').sum()),
        'top_anomalies': anomalies.sort_values('severity').head(10).to_dict(orient='records'),
    })


@app.route('/api/collect')
def api_collect():
    """Run evidence collectors and return results."""
    results = run_all_collectors()
    return jsonify(results)


@app.route('/api/report', methods=['POST'])
def api_generate_report():
    """Generate a PDF compliance report and return it."""
    data = load_all_data()
    
    try:
        output_path = generate_report(
            metrics=data['metrics'],
            scorecard=data['scorecard'],
            validated_df=data['validated_df'],
            coverage_df=data['coverage_df'],
            best_evidence=data['best_evidence'],
            eval_results=data['eval_results'],
            output_dir=str(OUTPUT_DIR),
        )
        return send_file(
            output_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='compliance_audit_report.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/frameworks')
def api_frameworks():
    data = load_all_data()
    return jsonify({'frameworks': list(data['validated_df']['framework'].unique())})


@app.route('/api/policy/requirements')
def api_policy_reqs():
    data = load_all_data()
    return jsonify({
        'requirements': [r.to_dict() for r in data['requirements']]
    })


if __name__ == '__main__':
    print("Loading data...")
    load_all_data()
    print("Starting server at http://localhost:5050")
    app.run(host='0.0.0.0', port=5050, debug=False)