from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from app.models import AuditLog, User, Evidence
from app import db
from datetime import datetime, timedelta
from sqlalchemy import func

audit = Blueprint('audit', __name__)


@audit.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    user_filter = request.args.get('user_id', type=int)
    action_filter = request.args.get('action', '')
    search = request.args.get('search', '')

    query = AuditLog.query
    if user_filter:
        query = query.filter_by(user_id=user_filter)
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
    if search:
        query = query.filter(
            AuditLog.action.ilike(f'%{search}%') |
            AuditLog.details.ilike(f'%{search}%') |
            AuditLog.resource_type.ilike(f'%{search}%')
        )

    logs = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=30)
    users = User.query.all()

    # Stats
    today = datetime.utcnow().date()
    today_logs = AuditLog.query.filter(
        func.date(AuditLog.timestamp) == today
    ).count()

    actions_summary = db.session.query(
        AuditLog.action, func.count(AuditLog.id)
    ).group_by(AuditLog.action).order_by(func.count(AuditLog.id).desc()).limit(10).all()

    total_evidence = Evidence.query.count()
    verified_evidence = Evidence.query.filter_by(verified=True).count()
    integrity_pct = round((verified_evidence / total_evidence * 100) if total_evidence else 100, 1)

    return render_template('audit/index.html',
                           logs=logs,
                           users=users,
                           today_logs=today_logs,
                           integrity_pct=integrity_pct,
                           verified_evidence=verified_evidence,
                           total_evidence=total_evidence,
                           actions_summary=actions_summary,
                           user_filter=user_filter,
                           action_filter=action_filter,
                           search=search)


@audit.route('/api/activity')
@login_required
def api_activity():
    """Last 7 days activity per day"""
    seven_days = []
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).date()
        count = AuditLog.query.filter(func.date(AuditLog.timestamp) == day).count()
        seven_days.append({'date': str(day), 'count': count})
    return jsonify(seven_days)
