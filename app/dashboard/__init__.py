from flask import Blueprint, render_template, jsonify, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import Case, Evidence, Alert, AuditLog, IOC, APTCampaign, ThreatActor, AttackTimeline
from app import db
from datetime import datetime, timedelta
from sqlalchemy import func

dashboard = Blueprint('dashboard', __name__)


@dashboard.route('/')
@dashboard.route('/dashboard')
@login_required
def index():
    # KPI stats
    total_cases = Case.query.count()
    active_cases = Case.query.filter_by(status='active').count()
    open_cases = Case.query.filter_by(status='open').count()
    closed_cases = Case.query.filter_by(status='closed').count()
    total_evidence = Evidence.query.count()
    critical_alerts = Alert.query.filter_by(severity='critical', status='open').count()
    high_alerts = Alert.query.filter_by(severity='high', status='open').count()
    total_iocs = IOC.query.count()
    active_campaigns = APTCampaign.query.filter_by(status='active').count()

    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(8).all()

    # Recent cases
    recent_cases = Case.query.order_by(Case.created_at.desc()).limit(5).all()

    # Case priority breakdown for chart
    critical_cases = Case.query.filter_by(priority='critical').count()
    high_cases = Case.query.filter_by(priority='high').count()
    medium_cases = Case.query.filter_by(priority='medium').count()
    low_cases = Case.query.filter_by(priority='low').count()

    # Cases by type
    case_types = db.session.query(Case.case_type, func.count(Case.id)).group_by(Case.case_type).all()

    # Recent activity
    recent_activity = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    # Active threat actors
    threat_actors = ThreatActor.query.order_by(ThreatActor.risk_score.desc()).limit(5).all()

    # Timeline events in last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_timeline_events = AttackTimeline.query.filter(
        AttackTimeline.event_time >= thirty_days_ago
    ).count()

    stats = {
        'total_cases': total_cases,
        'active_cases': active_cases,
        'open_cases': open_cases,
        'closed_cases': closed_cases,
        'total_evidence': total_evidence,
        'critical_alerts': critical_alerts,
        'high_alerts': high_alerts,
        'total_iocs': total_iocs,
        'active_campaigns': active_campaigns,
        'recent_timeline_events': recent_timeline_events,
        'priority_data': {
            'critical': critical_cases,
            'high': high_cases,
            'medium': medium_cases,
            'low': low_cases
        },
        'case_types': {ct[0]: ct[1] for ct in case_types if ct[0]}
    }

    # Security posture & breach prevention metrics
    try:
        from ml_models.investigation_engine import compute_security_posture
        security_posture = compute_security_posture(stats)
    except Exception:
        security_posture = {'score': 72, 'grade': 'B', 'status': 'at_risk', 'factors': {}}

    # Slow poison / early warning indicators from open critical alerts
    slow_poison_alerts = [
        a for a in recent_alerts
        if a.severity in ('critical', 'high') and a.status == 'open'
    ][:4]

    early_warnings = []
    if critical_alerts > 0:
        early_warnings.append({
            'level': 'critical',
            'title': 'Critical Incidents Require Triage',
            'prediction': f'{critical_alerts} critical alert(s) may indicate active compromise',
            'recommendation': 'Prioritize log forensics and attack timeline reconstruction.'
        })
    if active_campaigns > 0:
        early_warnings.append({
            'level': 'high',
            'title': 'Active APT Campaigns',
            'prediction': f'{active_campaigns} nation-state campaign(s) tracked in intelligence feeds',
            'recommendation': 'Cross-reference IOCs and correlate with open investigations.'
        })
    if open_cases > 3:
        early_warnings.append({
            'level': 'medium',
            'title': 'Investigation Backlog',
            'prediction': 'Multiple open cases may delay breach containment',
            'recommendation': 'Assign investigators and escalate critical-priority cases.'
        })

    evidence_sources = [
        'Windows Event Logs', 'Linux Logs', 'Firewall Logs', 'Auth Logs',
        'Network Traffic', 'DNS Logs', 'Proxy Logs', 'PCAP', 'Email Headers', 'Threat Intel'
    ]

    threat_actor_nodes = [
        {'value': a.name, 'count': a.risk_score, 'type': 'actor'}
        for a in threat_actors
    ]

    try:
        from ml_models.predictor import models_loaded
        ml_status = models_loaded()
    except Exception:
        ml_status = {'ids_loaded': False, 'unsw_loaded': False, 'log_loaded': False}

    return render_template('dashboard/index.html',
                           stats=stats,
                           recent_alerts=recent_alerts,
                           recent_cases=recent_cases,
                           recent_activity=recent_activity,
                           threat_actors=threat_actors,
                           threat_actor_nodes=threat_actor_nodes,
                           security_posture=security_posture,
                           slow_poison_alerts=slow_poison_alerts,
                           early_warnings=early_warnings,
                           evidence_sources=evidence_sources,
                           ml_status=ml_status)


@dashboard.route('/alerts/<int:id>/resolve', methods=['POST'])
@login_required
def resolve_alert(id):
    alert = Alert.query.get_or_404(id)
    alert.status = request.form.get('status', 'resolved')
    if alert.status == 'resolved':
        alert.resolved_at = datetime.utcnow()
    db.session.commit()
    flash(f'Alert marked as {alert.status}.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard.route('/api/health')
def api_health():
    """Backend health check — ML models, database, threat intel providers."""
    from threat_intel_engine.config import get_provider_status
    try:
        from ml_models.predictor import models_loaded
        ml = models_loaded()
    except Exception as exc:
        ml = {'error': str(exc)}
    try:
        from app.models import User, Case
        db_ok = User.query.count() >= 0 and Case.query.count() >= 0
    except Exception:
        db_ok = False
    providers = get_provider_status()
    return jsonify({
        'status': 'ok' if db_ok else 'degraded',
        'database': db_ok,
        'ml_models': ml,
        'threat_intel_providers': providers,
    })


@dashboard.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard live data"""
    alerts_by_severity = {
        'critical': Alert.query.filter_by(severity='critical', status='open').count(),
        'high': Alert.query.filter_by(severity='high', status='open').count(),
        'medium': Alert.query.filter_by(severity='medium', status='open').count(),
        'low': Alert.query.filter_by(severity='low', status='open').count(),
    }
    return jsonify({'alerts': alerts_by_severity, 'timestamp': datetime.utcnow().isoformat()})
