"""
Compliance Report Generator.
Produces audit-ready PDF reports with scorecards, narratives and evidence tables.
"""
import os
from datetime import datetime
from typing import Dict, List
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from app.evidence_validator import FRESHNESS_STALE_DAYS


# ─── Color Palette ────────────────────────────────────────────────────────────
NAVY      = colors.HexColor("#0F2D5C")
BLUE      = colors.HexColor("#1A56A0")
ACCENT    = colors.HexColor("#2196F3")
GREEN     = colors.HexColor("#1B7A3E")
GREEN_LT  = colors.HexColor("#E8F5E9")
YELLOW    = colors.HexColor("#856A00")
YELLOW_LT = colors.HexColor("#FFF8E1")
RED       = colors.HexColor("#B71C1C")
RED_LT    = colors.HexColor("#FFEBEE")
GREY_HDR  = colors.HexColor("#E8EEF6")
GREY_LT   = colors.HexColor("#F5F7FA")
TEXT      = colors.HexColor("#1A1A2E")
MUTED     = colors.HexColor("#546E7A")


STATUS_COLORS = {
    "COMPLIANT":     (GREEN, GREEN_LT),
    "PARTIAL":       (YELLOW, YELLOW_LT),
    "NON_COMPLIANT": (RED, RED_LT),
    "GAP":           (RED, RED_LT),
}

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     colors.HexColor("#E65100"),
    "MEDIUM":   colors.HexColor("#856A00"),
    "LOW":      MUTED,
    "NONE":     GREEN,
}


def build_styles() -> dict:
    base = getSampleStyleSheet()
    def style(name, **kwargs):
        return ParagraphStyle(name, parent=base['Normal'], **kwargs)

    return {
        'cover_title': style('cover_title', fontSize=28, textColor=colors.white,
                             fontName='Helvetica-Bold', leading=36, alignment=TA_CENTER),
        'cover_sub':   style('cover_sub', fontSize=13, textColor=colors.HexColor("#B0C4DE"),
                             fontName='Helvetica', leading=20, alignment=TA_CENTER),
        'h1':          style('h1', fontSize=16, textColor=NAVY, fontName='Helvetica-Bold',
                             spaceBefore=14, spaceAfter=6, leading=22),
        'h2':          style('h2', fontSize=13, textColor=BLUE, fontName='Helvetica-Bold',
                             spaceBefore=10, spaceAfter=4, leading=18),
        'h3':          style('h3', fontSize=11, textColor=TEXT, fontName='Helvetica-Bold',
                             spaceBefore=8, spaceAfter=2, leading=15),
        'body':        style('body', fontSize=9.5, textColor=TEXT, fontName='Helvetica',
                             leading=14, spaceAfter=4),
        'small':       style('small', fontSize=8.5, textColor=MUTED, fontName='Helvetica',
                             leading=12),
        'badge':       style('badge', fontSize=9, fontName='Helvetica-Bold', alignment=TA_CENTER),
        'metric_val':  style('metric_val', fontSize=22, textColor=NAVY, fontName='Helvetica-Bold',
                             alignment=TA_CENTER, leading=28),
        'metric_lbl':  style('metric_lbl', fontSize=8, textColor=MUTED, fontName='Helvetica',
                             alignment=TA_CENTER, leading=12),
    }


class ComplianceReportPDF:

    def __init__(self, output_path: str):
        self.output_path = output_path
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title="Compliance Evidence Audit Report",
            author="Automated Compliance System",
        )
        self.styles = build_styles()
        self.story = []
        self.page_width = letter[0] - 1.5 * inch  # usable width

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _hr(self, color=GREY_HDR, thickness=1):
        self.story.append(HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=8))

    def _sp(self, h=8):
        self.story.append(Spacer(1, h))

    def _p(self, text, style_name='body'):
        self.story.append(Paragraph(str(text), self.styles[style_name]))

    def _status_badge(self, status: str) -> str:
        labels = {
            "COMPLIANT": "COMPLIANT",
            "PARTIAL": "PARTIAL",
            "NON_COMPLIANT": "NON-COMPLIANT",
            "GAP": "GAP",
        }
        return labels.get(status, status)

    # ── Cover Page ────────────────────────────────────────────────────────────

    def add_cover(self, metrics: Dict):
        now = datetime.now()

        # Navy banner
        banner_data = [[Paragraph("AUTOMATED COMPLIANCE EVIDENCE AUDIT", self.styles['cover_title'])]]
        banner = Table(banner_data, colWidths=[self.page_width])
        banner.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), NAVY),
            ('TOPPADDING', (0,0), (-1,-1), 36),
            ('BOTTOMPADDING', (0,0), (-1,-1), 20),
            ('LEFTPADDING', (0,0), (-1,-1), 20),
            ('RIGHTPADDING', (0,0), (-1,-1), 20),
        ]))
        self.story.append(banner)
        self._sp(6)

        sub = f"Audit Period: {metrics.get('audit_period', 'Q1-Q2 2026')}  |  Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}"
        self._p(sub, 'small')
        self._sp(18)
        self._hr(BLUE, 2)
        self._sp(12)

        # KPI row
        score = metrics.get('overall_compliance_pct', 0)
        kpi_items = [
            (f"{score:.1f}%", "Overall Compliance"),
            (str(metrics.get('total_evidence', 0)), "Evidence Records"),
            (f"{metrics.get('evidence_freshness_pct', 0):.1f}%", "Evidence Freshness"),
            (f"{metrics.get('approved_pct', 0):.1f}%", "Approved Evidence"),
            (f"{metrics.get('avg_confidence', 0):.0%}", "Avg Confidence"),
        ]

        kpi_cells = []
        for val, lbl in kpi_items:
            cell = [
                Paragraph(val, self.styles['metric_val']),
                Paragraph(lbl, self.styles['metric_lbl']),
            ]
            kpi_cells.append(cell)

        kpi_table = Table([kpi_cells], colWidths=[self.page_width / len(kpi_items)] * len(kpi_items))
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), GREY_LT),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#DADEE8")),
            ('INNERGRID', (0,0), (-1,-1), 0.3, colors.HexColor("#DADEE8")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 14),
            ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ]))
        self.story.append(kpi_table)
        self._sp(18)

        # Risk level
        risk = "LOW" if score >= 85 else "MEDIUM" if score >= 70 else "HIGH"
        risk_color = GREEN if risk == "LOW" else (YELLOW if risk == "MEDIUM" else RED)
        risk_data = [[Paragraph(f"OVERALL AUDIT RISK: {risk}", ParagraphStyle(
            'risk', fontName='Helvetica-Bold', fontSize=13,
            textColor=colors.white, alignment=TA_CENTER
        ))]]
        risk_table = Table(risk_data, colWidths=[self.page_width])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), risk_color),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        self.story.append(risk_table)
        self.story.append(PageBreak())

    # ── Framework Scorecard ───────────────────────────────────────────────────

    def add_framework_scorecard(self, scorecard: Dict):
        self._p("Framework Compliance Scorecard", 'h1')
        self._hr()

        headers = ["Framework", "Evidence", "Compliant", "Anomalies",
                   "Avg Score", "Critical", "Status"]
        col_w = [1.0*inch, 0.85*inch, 0.85*inch, 0.85*inch, 0.8*inch, 0.65*inch, 1.4*inch]

        header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
            'th', fontName='Helvetica-Bold', fontSize=8.5,
            textColor=colors.white, alignment=TA_CENTER
        )) for h in headers]

        rows = [header_row]
        row_styles = []

        for i, (fw, s) in enumerate(scorecard.items(), start=1):
            status = s['status']
            txt_col, bg_col = STATUS_COLORS.get(status, (TEXT, GREY_LT))
            score = s['compliance_score']
            badge = self._status_badge(status)

            row = [
                Paragraph(f"<b>{fw}</b>", ParagraphStyle('fw', fontName='Helvetica-Bold', fontSize=9)),
                Paragraph(str(s['total_evidence']), ParagraphStyle('c', alignment=TA_CENTER, fontSize=9)),
                Paragraph(str(s['compliant_count']), ParagraphStyle('c', alignment=TA_CENTER, fontSize=9)),
                Paragraph(str(s['anomaly_count']), ParagraphStyle('c', alignment=TA_CENTER, fontSize=9)),
                Paragraph(f"{score:.1f}%", ParagraphStyle('c', alignment=TA_CENTER, fontSize=9,
                          fontName='Helvetica-Bold', textColor=txt_col)),
                Paragraph(str(s['critical_issues']), ParagraphStyle('c', alignment=TA_CENTER, fontSize=9,
                          textColor=RED if s['critical_issues'] > 0 else GREEN,
                          fontName='Helvetica-Bold')),
                Paragraph(badge, ParagraphStyle('b', alignment=TA_CENTER, fontSize=8.5,
                          fontName='Helvetica-Bold', textColor=txt_col)),
            ]
            rows.append(row)
            if i % 2 == 0:
                row_styles.append(('BACKGROUND', (0, i), (-1, i), GREY_LT))

        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8.5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, GREY_LT]),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#DADEE8")),
            ('INNERGRID', (0,0), (-1,-1), 0.3, colors.HexColor("#DADEE8")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            *row_styles
        ]))
        self.story.append(tbl)
        self._sp(16)

    # ── Anomaly Summary ───────────────────────────────────────────────────────

    def add_anomaly_summary(self, metrics: Dict, validated_df: pd.DataFrame):
        self._p("Anomaly Distribution & Risk Analysis", 'h1')
        self._hr()

        breakdown = metrics.get('anomaly_breakdown', {})
        if not breakdown:
            self._p("No anomalies detected.", 'body')
            return

        headers = ["Anomaly Type", "Count", "% of Anomalies", "Severity"]
        col_w = [2.5*inch, 0.8*inch, 1.2*inch, 1.0*inch]

        total_anomalies = sum(breakdown.values())

        severity_map = {
            'STALE_EVIDENCE': 'HIGH',
            'MISSING_DOCUMENTATION': 'HIGH',
            'LOW_CONFIDENCE_EVIDENCE': 'MEDIUM',
            'REJECTED_EVIDENCE': 'CRITICAL',
            'COMPLIANCE_GAP': 'CRITICAL',
            'UNREVIEWED_EVIDENCE': 'MEDIUM',
            'INCOMPLETE_MAPPING': 'LOW',
        }

        header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
            'th', fontName='Helvetica-Bold', fontSize=8.5,
            textColor=colors.white, alignment=TA_CENTER
        )) for h in headers]

        rows = [header_row]
        for atype, count in sorted(breakdown.items(), key=lambda x: -x[1]):
            sev = severity_map.get(atype, 'MEDIUM')
            sev_color = SEVERITY_COLORS.get(sev, MUTED)
            pct = count / total_anomalies * 100 if total_anomalies > 0 else 0
            rows.append([
                Paragraph(atype.replace('_', ' '), ParagraphStyle('c', fontSize=9)),
                Paragraph(str(count), ParagraphStyle('c', fontSize=9, alignment=TA_CENTER)),
                Paragraph(f"{pct:.1f}%", ParagraphStyle('c', fontSize=9, alignment=TA_CENTER)),
                Paragraph(sev, ParagraphStyle('c', fontSize=9, alignment=TA_CENTER,
                          fontName='Helvetica-Bold', textColor=sev_color)),
            ])

        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BLUE),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, GREY_LT]),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#DADEE8")),
            ('INNERGRID', (0,0), (-1,-1), 0.3, colors.HexColor("#DADEE8")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
        ]))
        self.story.append(tbl)
        self._sp(12)

        # Early warning summary
        total_ew = int(metrics.get('total_early_warnings', 0))
        if total_ew > 0:
            self._p(
                f"<b>Early Warning Indicators:</b> {total_ew} additional evidence records show "
                f"aging-but-not-yet-stale freshness or below-target confidence. These are not "
                f"counted as anomalies but should be prioritized for refresh before they breach "
                f"the {FRESHNESS_STALE_DAYS}-day staleness threshold.",
                'small'
            )
        self._sp(16)

    # ── Requirement Coverage ──────────────────────────────────────────────────

    def add_requirement_coverage(self, coverage_df: pd.DataFrame, best_evidence: pd.DataFrame):
        self.story.append(PageBreak())
        self._p("Requirement Coverage — Policy Compliance Detail", 'h1')
        self._hr()

        for policy_id in coverage_df['policy_id'].unique():
            policy_rows = coverage_df[coverage_df['policy_id'] == policy_id]
            policy_name = policy_rows.iloc[0]['policy_name']

            self._p(f"Policy: {policy_name}  ({policy_id})", 'h2')

            for _, req in policy_rows.iterrows():
                status = req['compliance_status']
                txt_col, bg_col = STATUS_COLORS.get(status, (TEXT, GREY_LT))
                badge = self._status_badge(status)

                # Requirement header card
                hdr_data = [[
                    Paragraph(f"<b>[{req['req_id']}]</b> {req['requirement_text']}", ParagraphStyle(
                        'rh', fontName='Helvetica-Bold', fontSize=9.5, textColor=NAVY
                    )),
                    Paragraph(badge, ParagraphStyle(
                        'rb', fontName='Helvetica-Bold', fontSize=9,
                        textColor=txt_col, alignment=TA_RIGHT
                    )),
                ]]
                hdr_tbl = Table(hdr_data, colWidths=[self.page_width * 0.75, self.page_width * 0.25])
                hdr_tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), bg_col),
                    ('BOX', (0,0), (-1,-1), 0.5, txt_col),
                    ('TOPPADDING', (0,0), (-1,-1), 7),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                    ('LEFTPADDING', (0,0), (0,-1), 10),
                    ('RIGHTPADDING', (-1,0), (-1,-1), 10),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ]))
                self.story.append(KeepTogether([hdr_tbl]))
                self._sp(3)

                # Metrics row
                metrics_text = (
                    f"Evidence: {req['evidence_count']} records  |  "
                    f"Approved: {req['approved_evidence']}  |  "
                    f"Avg Confidence: {req['avg_confidence']:.0%}  |  "
                    f"Avg Freshness: {req['avg_freshness_days']:.0f} days  |  "
                    f"Frameworks: {req['frameworks']}"
                )
                self._p(metrics_text, 'small')

                # Top evidence table
                if not best_evidence.empty and req['has_evidence']:
                    req_ev = best_evidence[best_evidence['req_id'] == req['req_id']]
                    if not req_ev.empty:
                        ev_headers = ["Evidence ID", "Type", "Collected", "Freshness", "Confidence", "Status"]
                        ev_col_w = [1.0*inch, 1.2*inch, 0.9*inch, 0.8*inch, 0.9*inch, 1.0*inch]

                        ev_rows = [[Paragraph(f"<b>{h}</b>", ParagraphStyle(
                            'evh', fontName='Helvetica-Bold', fontSize=7.5,
                            textColor=colors.white, alignment=TA_CENTER
                        )) for h in ev_headers]]

                        for _, ev in req_ev.head(3).iterrows():
                            st = str(ev.get('status', ''))
                            st_col = GREEN if st == 'Approved' else (RED if st == 'Rejected' else YELLOW)
                            conf = float(ev.get('confidence_score', 0))
                            ev_rows.append([
                                Paragraph(str(ev['evidence_id']), ParagraphStyle('ec', fontSize=7.5)),
                                Paragraph(str(ev.get('evidence_type', '')), ParagraphStyle('ec', fontSize=7.5)),
                                Paragraph(str(ev.get('collection_date', ''))[:10], ParagraphStyle('ec', fontSize=7.5, alignment=TA_CENTER)),
                                Paragraph(f"{ev.get('freshness_days', 0)}d", ParagraphStyle('ec', fontSize=7.5, alignment=TA_CENTER,
                                          textColor=RED if ev.get('freshness_days', 0) > 90 else TEXT)),
                                Paragraph(f"{conf:.0%}", ParagraphStyle('ec', fontSize=7.5, alignment=TA_CENTER,
                                          textColor=GREEN if conf >= 0.75 else RED)),
                                Paragraph(st, ParagraphStyle('ec', fontSize=7.5, alignment=TA_CENTER,
                                          fontName='Helvetica-Bold', textColor=st_col)),
                            ])

                        ev_tbl = Table(ev_rows, colWidths=ev_col_w)
                        ev_tbl.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), MUTED),
                            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, GREY_LT]),
                            ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor("#DADEE8")),
                            ('INNERGRID', (0,0), (-1,-1), 0.2, colors.HexColor("#DADEE8")),
                            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                            ('TOPPADDING', (0,0), (-1,-1), 4),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                            ('LEFTPADDING', (0,0), (-1,-1), 5),
                        ]))
                        self.story.append(ev_tbl)

                self._sp(12)

    # ── Self-Evaluation Page ──────────────────────────────────────────────────

    def add_self_evaluation(self, eval_results: Dict):
        self.story.append(PageBreak())
        self._p("Anomaly Detection — Self-Evaluation Metrics", 'h1')
        self._hr()

        self._p(
            "The system classifies evidence anomalies using rule-based logic against "
            "the anomaly_marker ground-truth proxy (evidence_labels.csv was not supplied "
            "in this dataset, so anomaly_marker — already present in evidence_artifacts.csv — "
            "serves as ground truth). A second, independent early-warning layer flags "
            "aging or below-target-confidence evidence using only raw freshness and "
            "confidence fields, surfaced separately in the dashboard.",
            'body'
        )
        self._sp(10)

        target_precision = 0.70
        target_recall = 0.60

        p = eval_results['precision']
        r = eval_results['recall']
        f1 = eval_results['f1_score']

        p_ok = p >= target_precision
        r_ok = r >= target_recall

        metrics = [
            ("Precision", eval_results['precision_pct'], "≥70%", p_ok),
            ("Recall", eval_results['recall_pct'], "≥60%", r_ok),
            ("F1 Score", eval_results['f1_pct'], "—", None),
            ("True Positives", str(eval_results['true_positives']), "—", None),
            ("False Positives", str(eval_results['false_positives']), "—", None),
            ("False Negatives", str(eval_results['false_negatives']), "—", None),
            ("True Negatives", str(eval_results['true_negatives']), "—", None),
        ]

        rows = [[Paragraph(f"<b>{h}</b>", ParagraphStyle('h', fontName='Helvetica-Bold', fontSize=9,
                           textColor=colors.white)) for h in ["Metric", "Result", "Target", "Pass/Fail"]]]
        col_w = [2.0*inch, 1.2*inch, 1.0*inch, 1.0*inch]

        for m, val, target, ok in metrics:
            pass_text = ""
            pass_col = TEXT
            if ok is True:
                pass_text = "✓ PASS"
                pass_col = GREEN
            elif ok is False:
                pass_text = "✗ FAIL"
                pass_col = RED

            rows.append([
                Paragraph(m, ParagraphStyle('c', fontSize=9)),
                Paragraph(f"<b>{val}</b>", ParagraphStyle('c', fontSize=9, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph(target, ParagraphStyle('c', fontSize=9, alignment=TA_CENTER, textColor=MUTED)),
                Paragraph(pass_text, ParagraphStyle('c', fontSize=9, fontName='Helvetica-Bold',
                          textColor=pass_col, alignment=TA_CENTER)),
            ])

        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, GREY_LT]),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#DADEE8")),
            ('INNERGRID', (0,0), (-1,-1), 0.3, colors.HexColor("#DADEE8")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
        ]))
        self.story.append(tbl)
        self._sp(14)

        verdict = "MEETS TARGET" if (p_ok and r_ok) else "NEEDS IMPROVEMENT"
        verdict_col = GREEN if (p_ok and r_ok) else RED
        verdict_data = [[Paragraph(
            f"Classifier Verdict: {verdict}",
            ParagraphStyle('v', fontName='Helvetica-Bold', fontSize=11,
                           textColor=colors.white, alignment=TA_CENTER)
        )]]
        vtbl = Table(verdict_data, colWidths=[self.page_width * 0.5])
        vtbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), verdict_col),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        self.story.append(vtbl)

    # ── Build ─────────────────────────────────────────────────────────────────

    def build(self, metrics, scorecard, anomaly_df, coverage_df, best_evidence, eval_results):
        self.add_cover(metrics)
        self.add_framework_scorecard(scorecard)
        self.add_anomaly_summary(metrics, anomaly_df)
        self.add_requirement_coverage(coverage_df, best_evidence)
        self.add_self_evaluation(eval_results)
        self.doc.build(self.story)
        return self.output_path


def generate_report(
    metrics: Dict,
    scorecard: Dict,
    validated_df: pd.DataFrame,
    coverage_df: pd.DataFrame,
    best_evidence: pd.DataFrame,
    eval_results: Dict,
    output_dir: str = "outputs",
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"compliance_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(output_dir, filename)
    
    rpt = ComplianceReportPDF(output_path)
    rpt.build(metrics, scorecard, validated_df, coverage_df, best_evidence, eval_results)
    return output_path