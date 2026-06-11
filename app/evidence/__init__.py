import os
import hashlib
import json
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.models import Evidence, EvidenceChain, Case, AuditLog
from app import db
from datetime import datetime

evidence = Blueprint('evidence', __name__)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def generate_evidence_id():
    import random, string
    prefix = 'EV'
    suffix = ''.join(random.choices(string.digits, k=8))
    return f'{prefix}-{suffix}'


@evidence.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', '')
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')

    query = Evidence.query
    if category_filter:
        query = query.filter_by(category=category_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search:
        query = query.filter(
            Evidence.title.ilike(f'%{search}%') |
            Evidence.evidence_id.ilike(f'%{search}%') |
            Evidence.file_hash_sha256.ilike(f'%{search}%')
        )

    evidences = query.order_by(Evidence.collected_at.desc()).paginate(page=page, per_page=20)
    cases = Case.query.filter(Case.status != 'closed').all()
    return render_template('evidence/index.html', evidences=evidences, cases=cases,
                           category_filter=category_filter, status_filter=status_filter, search=search)


@evidence.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    cases = Case.query.filter(Case.status != 'closed').all()
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'warning')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(upload_path)

            md5_hash, sha256_hash = compute_hashes(upload_path)
            file_size = os.path.getsize(upload_path)

            ev = Evidence(
                evidence_id=generate_evidence_id(),
                case_id=request.form.get('case_id') or None,
                title=request.form.get('title', filename),
                description=request.form.get('description', ''),
                category=request.form.get('category', 'artifact'),
                file_name=filename,
                file_path=upload_path,
                file_size=file_size,
                file_hash_md5=md5_hash,
                file_hash_sha256=sha256_hash,
                source=request.form.get('source', ''),
                collected_by=current_user.id,
                tags=request.form.get('tags', ''),
                status='collected'
            )
            db.session.add(ev)
            db.session.flush()

            chain = EvidenceChain(
                evidence_id=ev.id,
                action='collected',
                performed_by=current_user.id,
                notes=f'Evidence uploaded by {current_user.username}',
                location='BIGIL Platform'
            )
            db.session.add(chain)

            audit = AuditLog(
                user_id=current_user.id,
                action='EVIDENCE_UPLOAD',
                resource_type='evidence',
                resource_id=ev.evidence_id,
                ip_address=request.remote_addr,
                details=f'Uploaded evidence: {filename} SHA256:{sha256_hash}',
                status='success'
            )
            db.session.add(audit)
            db.session.commit()

            flash(f'Evidence {ev.evidence_id} uploaded and hashed successfully.', 'success')
            return redirect(url_for('evidence.detail', id=ev.id))
        else:
            flash('File type not allowed.', 'danger')

    return render_template('evidence/upload.html', cases=cases)


@evidence.route('/<int:id>/download')
@login_required
def download(id):
    ev = Evidence.query.get_or_404(id)
    if not ev.file_path or not os.path.isfile(ev.file_path):
        flash('Evidence file not found on disk.', 'danger')
        return redirect(url_for('evidence.detail', id=id))
    return send_file(ev.file_path, as_attachment=True, download_name=ev.file_name or os.path.basename(ev.file_path))


@evidence.route('/<int:id>')
@login_required
def detail(id):
    ev = Evidence.query.get_or_404(id)
    chain = EvidenceChain.query.filter_by(evidence_id=id).order_by(EvidenceChain.performed_at.asc()).all()
    return render_template('evidence/detail.html', evidence=ev, chain=chain)


@evidence.route('/<int:id>/verify', methods=['POST'])
@login_required
def verify(id):
    ev = Evidence.query.get_or_404(id)
    if not ev.file_path or not os.path.isfile(ev.file_path):
        flash('Cannot verify: evidence file missing on disk.', 'danger')
        return redirect(url_for('evidence.detail', id=id))

    md5_hash, sha256_hash = compute_hashes(ev.file_path)
    if ev.file_hash_sha256 and sha256_hash != ev.file_hash_sha256:
        flash(
            f'Integrity check FAILED. Stored SHA256 {ev.file_hash_sha256[:16]}... '
            f'does not match file {sha256_hash[:16]}...',
            'danger'
        )
        audit = AuditLog(
            user_id=current_user.id,
            action='EVIDENCE_VERIFY_FAILED',
            resource_type='evidence',
            resource_id=ev.evidence_id,
            ip_address=request.remote_addr,
            details=f'Hash mismatch on verify. Expected {ev.file_hash_sha256}, got {sha256_hash}',
            status='failure'
        )
        db.session.add(audit)
        db.session.commit()
        return redirect(url_for('evidence.detail', id=id))

    ev.file_hash_md5 = md5_hash
    ev.file_hash_sha256 = sha256_hash
    ev.file_size = os.path.getsize(ev.file_path)
    ev.verified = True
    ev.verified_by = current_user.id
    ev.status = 'verified'

    chain = EvidenceChain(
        evidence_id=ev.id,
        action='verified',
        performed_by=current_user.id,
        notes=f'Integrity verified by {current_user.username}. SHA256: {sha256_hash}',
        location='BIGIL Platform'
    )
    db.session.add(chain)
    audit = AuditLog(
        user_id=current_user.id,
        action='EVIDENCE_VERIFY',
        resource_type='evidence',
        resource_id=ev.evidence_id,
        ip_address=request.remote_addr,
        details=f'Hash verified OK. SHA256:{sha256_hash}',
        status='success'
    )
    db.session.add(audit)
    db.session.commit()
    flash('Evidence integrity verified — SHA256 hash matches stored record.', 'success')
    return redirect(url_for('evidence.detail', id=id))
