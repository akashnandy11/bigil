from datetime import datetime
from app import db, login_manager, bcrypt
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='analyst')  # admin, investigator, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    badge_number = db.Column(db.String(32), unique=True)
    full_name = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Investigator(db.Model):
    __tablename__ = 'investigators'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    rank = db.Column(db.String(64))
    unit = db.Column(db.String(128))
    specialization = db.Column(db.String(128))
    cases_handled = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref='investigator_profile')


class Case(db.Model):
    __tablename__ = 'cases'
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(32), unique=True, nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(32), default='open')  # open, active, closed, pending
    priority = db.Column(db.String(16), default='medium')  # critical, high, medium, low
    case_type = db.Column(db.String(64))  # APT, ransomware, phishing, etc.
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime)
    tags = db.Column(db.String(256))
    victim_org = db.Column(db.String(256))
    victim_sector = db.Column(db.String(128))

    evidence_items = db.relationship('Evidence', backref='case', lazy='dynamic')
    notes = db.relationship('InvestigationNote', backref='case', lazy='dynamic')
    alerts = db.relationship('Alert', backref='case', lazy='dynamic')
    assigned_to_user = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_cases')
    created_by_user = db.relationship('User', foreign_keys=[created_by], backref='created_cases')


class Evidence(db.Model):
    __tablename__ = 'evidence'
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(32), unique=True, nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(64))  # network, filesystem, memory, email, log, artifact
    file_name = db.Column(db.String(256))
    file_path = db.Column(db.String(512))
    file_size = db.Column(db.Integer)
    file_hash_md5 = db.Column(db.String(32))
    file_hash_sha256 = db.Column(db.String(64))
    source = db.Column(db.String(256))
    collected_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    collected_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    verified_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    tags = db.Column(db.String(256))
    status = db.Column(db.String(32), default='collected')  # collected, verified, analyzed, archived

    chain_of_custody = db.relationship('EvidenceChain', backref='evidence_item', lazy='dynamic')
    user = db.relationship('User', foreign_keys=[collected_by], backref='collected_evidences')
    verifier = db.relationship('User', foreign_keys=[verified_by], backref='verified_evidences')


class EvidenceChain(db.Model):
    __tablename__ = 'evidence_chain'
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'))
    action = db.Column(db.String(64))  # collected, transferred, analyzed, returned, archived
    performed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    location = db.Column(db.String(256))
    user = db.relationship('User', foreign_keys=[performed_by], backref='custody_actions')


class AttackTimeline(db.Model):
    __tablename__ = 'attack_timelines'
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    event_time = db.Column(db.DateTime, nullable=False)
    event_title = db.Column(db.String(256), nullable=False)
    event_description = db.Column(db.Text)
    attack_phase = db.Column(db.String(64))  # recon, initial_access, execution, persistence, lateral_movement, exfiltration
    mitre_technique = db.Column(db.String(64))
    severity = db.Column(db.String(16), default='medium')
    source_ip = db.Column(db.String(64))
    dest_ip = db.Column(db.String(64))
    evidence_ref = db.Column(db.String(32))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class IOC(db.Model):
    __tablename__ = 'iocs'
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(32))  # ip, domain, url, hash_md5, hash_sha256, email, filename
    value = db.Column(db.String(512), nullable=False, index=True)
    description = db.Column(db.Text)
    threat_actor = db.Column(db.String(128))
    campaign = db.Column(db.String(128))
    severity = db.Column(db.String(16), default='medium')  # critical, high, medium, low
    confidence = db.Column(db.Integer, default=70)  # 0-100
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    tags = db.Column(db.String(256))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))


class ThreatActor(db.Model):
    __tablename__ = 'threat_actors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    aliases = db.Column(db.String(512))
    origin_country = db.Column(db.String(64))
    motivation = db.Column(db.String(256))
    sophistication = db.Column(db.String(32))  # nation-state, advanced, intermediate, basic
    active_since = db.Column(db.String(16))
    description = db.Column(db.Text)
    targets = db.Column(db.String(512))  # sectors targeted
    ttps = db.Column(db.Text)  # JSON of MITRE techniques
    tools = db.Column(db.Text)
    infrastructure = db.Column(db.Text)
    risk_score = db.Column(db.Integer, default=50)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class APTCampaign(db.Model):
    __tablename__ = 'apt_campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    threat_actor_id = db.Column(db.Integer, db.ForeignKey('threat_actors.id'))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(32), default='active')  # active, concluded, suspected
    targets = db.Column(db.Text)  # JSON list
    objective = db.Column(db.String(256))
    description = db.Column(db.Text)
    ttps_used = db.Column(db.Text)  # JSON
    iocs_count = db.Column(db.Integer, default=0)
    confidence = db.Column(db.Integer, default=70)
    risk_level = db.Column(db.String(16), default='high')
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    threat_actor = db.relationship('ThreatActor', backref='campaigns')


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    report_number = db.Column(db.String(32), unique=True)
    title = db.Column(db.String(256), nullable=False)
    report_type = db.Column(db.String(64))  # forensic, executive, evidence, timeline, closure
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text)
    status = db.Column(db.String(32), default='draft')  # draft, final, approved
    user = db.relationship('User', foreign_keys=[created_by], backref='reports')
    case = db.relationship('Case', foreign_keys=[case_id], backref='reports')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(128), nullable=False)
    resource_type = db.Column(db.String(64))
    resource_id = db.Column(db.String(64))
    ip_address = db.Column(db.String(64))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default='success')
    user = db.relationship('User', foreign_keys=[user_id], backref='audit_logs')


class InvestigationNote(db.Model):
    __tablename__ = 'investigation_notes'
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(256))
    content = db.Column(db.Text, nullable=False)
    note_type = db.Column(db.String(32), default='general')  # general, technical, legal, intelligence
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author = db.relationship('User', foreign_keys=[author_id], backref='investigation_notes')


class ThreatIntelLookup(db.Model):
    __tablename__ = 'threat_intel_lookups'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    indicator = db.Column(db.String(512), nullable=False, index=True)
    indicator_type = db.Column(db.String(32))
    unified_risk_score = db.Column(db.Float, default=0)
    unified_risk_level = db.Column(db.String(16), default='unknown')
    providers_queried = db.Column(db.Integer, default=0)
    malicious_consensus = db.Column(db.Integer, default=0)
    result_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id], backref='ti_lookups')


class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default='medium')  # critical, high, medium, low
    alert_type = db.Column(db.String(64))  # anomaly, ioc_match, threshold, manual
    source = db.Column(db.String(128))
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.String(32), default='open')  # open, investigating, resolved, false_positive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    risk_score = db.Column(db.Integer, default=50)
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='alerts')
