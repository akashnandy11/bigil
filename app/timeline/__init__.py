from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.models import AttackTimeline, Case
from app import db
from datetime import datetime

timeline = Blueprint('timeline', __name__)

ATTACK_PHASES = ['recon', 'initial_access', 'execution', 'persistence', 'privilege_escalation',
                 'lateral_movement', 'collection', 'exfiltration', 'command_control']

PHASE_LABELS = {
    'recon': 'Reconnaissance',
    'initial_access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege_escalation': 'Privilege Escalation',
    'lateral_movement': 'Lateral Movement',
    'collection': 'Collection',
    'exfiltration': 'Exfiltration',
    'command_control': 'C2 Communication'
}


@timeline.route('/')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'closed').all()
    case_id = request.args.get('case_id', type=int)
    selected_case = None
    events = []

    if case_id:
        selected_case = Case.query.get(case_id)
        events = AttackTimeline.query.filter_by(case_id=case_id).order_by(AttackTimeline.event_time.asc()).all()
    else:
        events = AttackTimeline.query.order_by(AttackTimeline.event_time.asc()).limit(50).all()

    return render_template('timeline/index.html',
                           cases=cases,
                           selected_case=selected_case,
                           events=events,
                           phase_labels=PHASE_LABELS)


@timeline.route('/api/events')
@login_required
def api_events():
    case_id = request.args.get('case_id', type=int)
    query = AttackTimeline.query
    if case_id:
        query = query.filter_by(case_id=case_id)
    events = query.order_by(AttackTimeline.event_time.asc()).all()
    data = [{
        'id': e.id,
        'title': e.event_title,
        'description': e.event_description,
        'phase': e.attack_phase,
        'phase_label': PHASE_LABELS.get(e.attack_phase, e.attack_phase),
        'severity': e.severity,
        'event_time': e.event_time.strftime('%Y-%m-%d %H:%M:%S') if e.event_time else '',
        'source_ip': e.source_ip,
        'dest_ip': e.dest_ip,
        'mitre_technique': e.mitre_technique,
        'notes': e.notes
    } for e in events]
    return jsonify(data)


@timeline.route('/add', methods=['GET', 'POST'])
@login_required
def add_event():
    cases = Case.query.filter(Case.status != 'closed').all()
    if request.method == 'POST':
        event_time_str = request.form.get('event_time', '')
        try:
            event_time = datetime.strptime(event_time_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            event_time = datetime.utcnow()

        event = AttackTimeline(
            case_id=request.form.get('case_id') or None,
            event_time=event_time,
            event_title=request.form.get('title', ''),
            event_description=request.form.get('description', ''),
            attack_phase=request.form.get('attack_phase', 'initial_access'),
            mitre_technique=request.form.get('mitre_technique', ''),
            severity=request.form.get('severity', 'medium'),
            source_ip=request.form.get('source_ip', ''),
            dest_ip=request.form.get('dest_ip', ''),
            notes=request.form.get('notes', '')
        )
        db.session.add(event)
        db.session.commit()
        flash('Timeline event added successfully.', 'success')
        return redirect(url_for('timeline.index'))

    return render_template('timeline/add_event.html', cases=cases, phases=ATTACK_PHASES, phase_labels=PHASE_LABELS)
