from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.models import Case, InvestigationNote, Alert, Evidence, User
from app import db
from datetime import datetime

workspace = Blueprint('workspace', __name__)


@workspace.route('/')
@login_required
def index():
    cases = Case.query.filter(Case.status.in_(['open', 'active'])).order_by(Case.updated_at.desc()).all()
    my_cases = Case.query.filter_by(assigned_to=current_user.id).filter(Case.status != 'closed').all()
    open_alerts = Alert.query.filter_by(status='open').order_by(Alert.created_at.desc()).limit(10).all()
    return render_template('workspace/index.html', cases=cases, my_cases=my_cases, open_alerts=open_alerts)


@workspace.route('/cases')
@login_required
def cases():
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)

    query = Case.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)
    if search:
        query = query.filter(
            Case.title.ilike(f'%{search}%') |
            Case.case_number.ilike(f'%{search}%') |
            Case.victim_org.ilike(f'%{search}%')
        )

    cases_list = query.order_by(Case.created_at.desc()).paginate(page=page, per_page=15)
    investigators = User.query.filter(User.role.in_(['investigator', 'analyst', 'admin'])).all()
    my_cases = Case.query.filter_by(assigned_to=current_user.id).filter(Case.status != 'closed').all()
    open_alerts = Alert.query.filter_by(status='open').order_by(Alert.created_at.desc()).limit(10).all()
    return render_template('workspace/cases.html', cases=cases_list,
                           status_filter=status_filter, priority_filter=priority_filter,
                           search=search, investigators=investigators,
                           my_cases=my_cases, open_alerts=open_alerts)


@workspace.route('/cases/new', methods=['GET', 'POST'])
@login_required
def new_case():
    investigators = User.query.filter(User.role.in_(['investigator', 'analyst', 'admin'])).all()
    if request.method == 'POST':
        import random, string
        case_num = 'CYB-' + ''.join(random.choices(string.digits, k=6)) + '-' + str(datetime.utcnow().year)
        case = Case(
            case_number=case_num,
            title=request.form.get('title', ''),
            description=request.form.get('description', ''),
            status='open',
            priority=request.form.get('priority', 'medium'),
            case_type=request.form.get('case_type', ''),
            assigned_to=request.form.get('assigned_to') or current_user.id,
            created_by=current_user.id,
            tags=request.form.get('tags', ''),
            victim_org=request.form.get('victim_org', ''),
            victim_sector=request.form.get('victim_sector', '')
        )
        db.session.add(case)
        db.session.commit()
        flash(f'Case {case_num} created successfully.', 'success')
        return redirect(url_for('workspace.case_detail', id=case.id))
    return render_template('workspace/new_case.html', investigators=investigators)


@workspace.route('/cases/<int:id>')
@login_required
def case_detail(id):
    case = Case.query.get_or_404(id)
    notes = InvestigationNote.query.filter_by(case_id=id).order_by(InvestigationNote.created_at.desc()).all()
    evidence_items = Evidence.query.filter_by(case_id=id).all()
    alerts = Alert.query.filter_by(case_id=id).order_by(Alert.created_at.desc()).all()
    investigators = User.query.filter(User.role.in_(['investigator', 'analyst', 'admin'])).all()
    return render_template('workspace/case_detail.html',
                           case=case, notes=notes, evidence_items=evidence_items,
                           alerts=alerts, investigators=investigators)


@workspace.route('/cases/<int:id>/note', methods=['POST'])
@login_required
def add_note(id):
    case = Case.query.get_or_404(id)
    note = InvestigationNote(
        case_id=id,
        author_id=current_user.id,
        title=request.form.get('title', 'Note'),
        content=request.form.get('content', ''),
        note_type=request.form.get('note_type', 'general')
    )
    db.session.add(note)
    db.session.commit()
    flash('Investigation note added.', 'success')
    return redirect(url_for('workspace.case_detail', id=id))


@workspace.route('/cases/<int:id>/status', methods=['POST'])
@login_required
def update_status(id):
    case = Case.query.get_or_404(id)
    new_status = request.form.get('status', case.status)
    case.status = new_status
    if new_status == 'closed':
        case.closed_at = datetime.utcnow()
    db.session.commit()
    flash(f'Case status updated to {new_status}.', 'success')
    return redirect(url_for('workspace.case_detail', id=id))
