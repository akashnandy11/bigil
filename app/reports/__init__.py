from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, make_response
from flask_login import login_required, current_user
from app.models import Report, Case, Evidence, AttackTimeline, IOC, ThreatActor, Alert
from app import db
from datetime import datetime
import random, string

reports = Blueprint('reports', __name__)


def generate_report_number():
    return 'RPT-' + ''.join(random.choices(string.digits, k=6)) + '-' + str(datetime.utcnow().year)


def _build_report_content(report_type, case, evidence_items, timeline_events, alerts, iocs):
    """Generate forensic report body from real case database records."""
    lines = [
        f'BIGIL Forensic Investigation Report',
        f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
        f'Report Type: {report_type.upper()}',
        '',
    ]
    if case:
        lines.extend([
            '=== CASE SUMMARY ===',
            f'Case Number: {case.case_number}',
            f'Title: {case.title}',
            f'Status: {case.status} | Priority: {case.priority}',
            f'Type: {case.case_type}',
            f'Victim: {case.victim_org or "N/A"} ({case.victim_sector or "N/A"})',
            f'Description: {case.description or "N/A"}',
            f'Tags: {case.tags or "N/A"}',
            '',
        ])
    else:
        lines.append('No case linked to this report.\n')

    if evidence_items:
        lines.append('=== DIGITAL EVIDENCE (VERIFIED RECORDS) ===')
        for ev in evidence_items:
            verified = 'VERIFIED' if ev.verified else 'PENDING'
            lines.append(
                f'  [{ev.evidence_id}] {ev.title} ({ev.category}) — {verified}'
            )
            lines.append(f'    Source: {ev.source or "N/A"}')
            lines.append(f'    File: {ev.file_name or "N/A"} ({ev.file_size or 0:,} bytes)')
            if ev.file_hash_sha256:
                lines.append(f'    SHA256: {ev.file_hash_sha256}')
            lines.append('')
    else:
        lines.append('=== DIGITAL EVIDENCE ===\n  No evidence items linked.\n')

    if timeline_events:
        lines.append('=== ATTACK TIMELINE ===')
        for ev in timeline_events:
            lines.append(
                f'  {ev.event_time.strftime("%Y-%m-%d %H:%M")} [{ev.attack_phase}] {ev.event_title}'
            )
            if ev.source_ip or ev.dest_ip:
                lines.append(f'    Network: {ev.source_ip or "?"} → {ev.dest_ip or "?"}')
            if ev.mitre_technique:
                lines.append(f'    MITRE: {ev.mitre_technique}')
        lines.append('')
    else:
        lines.append('=== ATTACK TIMELINE ===\n  No timeline events recorded.\n')

    if alerts:
        lines.append('=== SECURITY ALERTS ===')
        for a in alerts:
            lines.append(f'  [{a.severity.upper()}] {a.title} — {a.status}')
            if a.source:
                lines.append(f'    Source: {a.source}')
            if a.description:
                lines.append(f'    {a.description[:200]}')
        lines.append('')
    else:
        lines.append('=== SECURITY ALERTS ===\n  No alerts for this case.\n')

    if iocs:
        lines.append('=== INDICATORS OF COMPROMISE ===')
        try:
            from threat_intel_engine import ThreatIntelAggregator
            agg = ThreatIntelAggregator()
            lines.append('--- External TI Enrichment (top IOCs) ---')
            for ioc in iocs[:5]:
                report = agg.enrich(ioc.value, ioc.ioc_type if ioc.ioc_type in ('ip', 'domain', 'url', 'hash_sha256', 'hash_md5') else None)
                if report.get('providers_successful'):
                    lines.append(
                        f'  {ioc.value}: risk={report["unified_risk_score"]} '
                        f'level={report["unified_risk_level"]} — {report["summary"][:120]}'
                    )
            lines.append('')
        except Exception:
            pass
        for ioc in iocs[:20]:
            lines.append(
                f'  [{ioc.ioc_type}] {ioc.value} — {ioc.threat_actor or "Unknown"} '
                f'(confidence: {ioc.confidence}%)'
            )
        lines.append('')

    lines.append('=== END OF REPORT ===')
    lines.append('This report was auto-generated from BIGIL investigation database records.')
    return '\n'.join(lines)


@reports.route('/')
@login_required
def index():
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    cases = Case.query.all()
    return render_template('reports/index.html', reports=all_reports, cases=cases)


@reports.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    cases = Case.query.all()
    if request.method == 'POST':
        case_id = request.form.get('case_id', type=int)
        report_type = request.form.get('report_type', 'forensic')
        title = request.form.get('title', 'Investigation Report')

        case = Case.query.get(case_id) if case_id else None
        evidence_items = Evidence.query.filter_by(case_id=case_id).all() if case_id else []
        timeline_events = AttackTimeline.query.filter_by(case_id=case_id).order_by(AttackTimeline.event_time.asc()).all() if case_id else []
        alerts = Alert.query.filter_by(case_id=case_id).all() if case_id else []
        iocs = IOC.query.filter_by(case_id=case_id).all() if case_id else []

        content = _build_report_content(
            report_type, case, evidence_items, timeline_events, alerts, iocs
        )

        report = Report(
            report_number=generate_report_number(),
            title=title,
            report_type=report_type,
            case_id=case_id,
            created_by=current_user.id,
            content=content,
            status='draft'
        )
        db.session.add(report)
        db.session.commit()

        return render_template('reports/view.html',
                               report=report,
                               case=case,
                               evidence_items=evidence_items,
                               timeline_events=timeline_events,
                               alerts=alerts,
                               generated_at=datetime.utcnow())

    return render_template('reports/generate.html', cases=cases)


@reports.route('/<int:id>')
@login_required
def view(id):
    report = Report.query.get_or_404(id)
    case = Case.query.get(report.case_id) if report.case_id else None
    evidence_items = Evidence.query.filter_by(case_id=report.case_id).all() if report.case_id else []
    timeline_events = AttackTimeline.query.filter_by(case_id=report.case_id).order_by(AttackTimeline.event_time.asc()).all() if report.case_id else []
    alerts = Alert.query.filter_by(case_id=report.case_id).all() if report.case_id else []
    return render_template('reports/view.html',
                           report=report, case=case,
                           evidence_items=evidence_items,
                           timeline_events=timeline_events,
                           alerts=alerts,
                           generated_at=report.created_at)
