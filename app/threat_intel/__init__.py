import json
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.models import IOC, ThreatActor, APTCampaign, ThreatIntelLookup, AuditLog
from app import db
from datetime import datetime

threat_intel = Blueprint('threat_intel', __name__)


def _get_aggregator():
    from threat_intel_engine import ThreatIntelAggregator
    return ThreatIntelAggregator()


def _save_lookup(report: dict):
    try:
        entry = ThreatIntelLookup(
            user_id=current_user.id,
            indicator=report['indicator'],
            indicator_type=report.get('indicator_type', ''),
            unified_risk_score=report.get('unified_risk_score', 0),
            unified_risk_level=report.get('unified_risk_level', 'unknown'),
            providers_queried=report.get('providers_queried', 0),
            malicious_consensus=report.get('malicious_consensus', 0),
            result_json=json.dumps(report, default=str)[:50000],
        )
        db.session.add(entry)
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='TI_ENRICHMENT',
            resource_type='indicator',
            resource_id=report['indicator'][:64],
            details=f"TI lookup: score={report.get('unified_risk_score')} level={report.get('unified_risk_level')}",
            status='success',
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


@threat_intel.route('/')
@login_required
def index():
    total_iocs = IOC.query.count()
    active_iocs = IOC.query.filter_by(is_active=True).count()
    critical_iocs = IOC.query.filter_by(severity='critical').count()
    threat_actors = ThreatActor.query.count()
    ioc_by_type = {}
    for ioc_type in ['ip', 'network_flow', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email', 'filename']:
        ioc_by_type[ioc_type] = IOC.query.filter_by(ioc_type=ioc_type).count()

    recent_iocs = IOC.query.order_by(IOC.created_at.desc()).limit(10).all()
    top_actors = ThreatActor.query.order_by(ThreatActor.risk_score.desc()).limit(5).all()

    from threat_intel_engine.config import get_provider_status
    provider_status = get_provider_status()
    configured_count = sum(1 for p in provider_status if p['configured'])

    recent_lookups = ThreatIntelLookup.query.order_by(
        ThreatIntelLookup.created_at.desc()
    ).limit(8).all()

    return render_template('threat_intel/index.html',
                           total_iocs=total_iocs,
                           active_iocs=active_iocs,
                           critical_iocs=critical_iocs,
                           threat_actors_count=threat_actors,
                           ioc_by_type=ioc_by_type,
                           recent_iocs=recent_iocs,
                           top_actors=top_actors,
                           provider_status=provider_status,
                           configured_count=configured_count,
                           recent_lookups=recent_lookups)


@threat_intel.route('/iocs')
@login_required
def iocs():
    page = request.args.get('page', 1, type=int)
    ioc_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    search = request.args.get('search', '')

    query = IOC.query
    if ioc_type:
        query = query.filter_by(ioc_type=ioc_type)
    if severity:
        query = query.filter_by(severity=severity)
    if search:
        query = query.filter(
            IOC.value.ilike(f'%{search}%') |
            IOC.threat_actor.ilike(f'%{search}%') |
            IOC.campaign.ilike(f'%{search}%')
        )

    iocs_list = query.order_by(IOC.created_at.desc()).paginate(page=page, per_page=25)
    return render_template('threat_intel/iocs.html', iocs=iocs_list,
                           ioc_type=ioc_type, severity=severity, search=search)


@threat_intel.route('/iocs/add', methods=['GET', 'POST'])
@login_required
def add_ioc():
    if request.method == 'POST':
        ioc = IOC(
            ioc_type=request.form.get('ioc_type'),
            value=request.form.get('value', '').strip(),
            description=request.form.get('description', ''),
            threat_actor=request.form.get('threat_actor', ''),
            campaign=request.form.get('campaign', ''),
            severity=request.form.get('severity', 'medium'),
            confidence=int(request.form.get('confidence', 70)),
            tags=request.form.get('tags', ''),
            is_active=True
        )
        db.session.add(ioc)
        db.session.commit()
        flash('IOC added to threat intelligence database.', 'success')
        return redirect(url_for('threat_intel.iocs'))
    return render_template('threat_intel/add_ioc.html')


@threat_intel.route('/lookup', methods=['GET', 'POST'])
@login_required
def lookup():
    report = None
    query_value = ''
    enrich_external = True

    if request.method == 'POST':
        query_value = request.form.get('query', '').strip()
        enrich_external = request.form.get('enrich_external', 'on') == 'on'

        local_matches = IOC.query.filter(IOC.value.ilike(f'%{query_value}%')).all()

        if enrich_external and query_value:
            agg = _get_aggregator()
            report = agg.enrich_with_local(query_value, local_matches)
            _save_lookup(report)
            ok = report.get('providers_successful', 0)
            flash(
                f'Threat intel enrichment complete: {ok} provider(s) responded, '
                f'risk score {report.get("unified_risk_score", 0)}/100.',
                'success' if ok else 'warning'
            )
        else:
            report = {
                'indicator': query_value,
                'local_matches': [
                    {
                        'type': i.ioc_type, 'value': i.value, 'severity': i.severity,
                        'threat_actor': i.threat_actor or '', 'confidence': i.confidence,
                        'description': i.description or '', 'source': 'BIGIL Database',
                    }
                    for i in local_matches
                ],
                'provider_results': [],
                'unified_risk_score': max((i.confidence for i in local_matches), default=0),
                'unified_risk_level': local_matches[0].severity if local_matches else 'info',
                'summary': f'{len(local_matches)} local match(es) only (external TI disabled).',
            }

    from threat_intel_engine.config import get_provider_status
    return render_template('threat_intel/lookup.html',
                           report=report,
                           query_value=query_value,
                           enrich_external=enrich_external,
                           provider_status=get_provider_status())


@threat_intel.route('/bulk', methods=['GET', 'POST'])
@login_required
def bulk():
    results = []
    ip_list = ''
    if request.method == 'POST':
        ip_list = request.form.get('ip_list', '')
        ips = [line.strip() for line in ip_list.replace(',', '\n').split('\n') if line.strip()]
        if ips:
            agg = _get_aggregator()
            results = agg.bulk_enrich_ips(ips)
            for r in results:
                _save_lookup(r)
            flash(f'Analyzed {len(results)} IP address(es) across threat intelligence feeds.', 'success')

    from threat_intel_engine.config import get_provider_status
    return render_template('threat_intel/bulk.html',
                           results=results,
                           ip_list=ip_list,
                           provider_status=get_provider_status())


@threat_intel.route('/providers')
@login_required
def providers():
    from threat_intel_engine.config import get_provider_status, PROVIDERS
    status = get_provider_status()
    recent = ThreatIntelLookup.query.order_by(ThreatIntelLookup.created_at.desc()).limit(15).all()
    return render_template('threat_intel/providers.html',
                           provider_status=status,
                           providers_config=PROVIDERS,
                           recent_lookups=recent)


@threat_intel.route('/api/enrich', methods=['POST'])
@login_required
def api_enrich():
    data = request.get_json(silent=True) or {}
    indicator = (data.get('indicator') or request.form.get('indicator', '')).strip()
    if not indicator:
        return jsonify({'error': 'indicator required'}), 400

    local = IOC.query.filter(IOC.value.ilike(f'%{indicator}%')).all()
    report = _get_aggregator().enrich_with_local(indicator, local)
    _save_lookup(report)
    return jsonify(report)


@threat_intel.route('/api/iocs')
@login_required
def api_iocs():
    iocs_list = IOC.query.filter_by(is_active=True).order_by(IOC.created_at.desc()).limit(100).all()
    data = [{
        'id': i.id,
        'type': i.ioc_type,
        'value': i.value,
        'severity': i.severity,
        'threat_actor': i.threat_actor,
        'confidence': i.confidence
    } for i in iocs_list]
    return jsonify(data)


@threat_intel.route('/api/providers')
@login_required
def api_providers():
    from threat_intel_engine.config import get_provider_status
    return jsonify(get_provider_status())
