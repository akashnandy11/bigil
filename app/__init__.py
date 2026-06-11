from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import config
import os

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
bcrypt = Bcrypt()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please login to access the BIGIL platform.'
login_manager.login_message_category = 'warning'

def create_app(config_name='default'):
    app = Flask(__name__, instance_relative_config=True, template_folder='../templates', static_folder='../static')
    app.config.from_object(config[config_name])
    app.url_map.strict_slashes = False

    # Ensure instance and uploads folder exist
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    # Register blueprints
    from app.auth import auth as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.dashboard import dashboard as dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/')

    from app.apt import apt as apt_bp
    app.register_blueprint(apt_bp, url_prefix='/apt')

    from app.logs import logs as logs_bp
    app.register_blueprint(logs_bp, url_prefix='/logs')

    from app.evidence import evidence as evidence_bp
    app.register_blueprint(evidence_bp, url_prefix='/evidence')

    from app.timeline import timeline as timeline_bp
    app.register_blueprint(timeline_bp, url_prefix='/timeline')

    from app.threat_intel import threat_intel as threat_intel_bp
    app.register_blueprint(threat_intel_bp, url_prefix='/threat-intel')

    from app.workspace import workspace as workspace_bp
    app.register_blueprint(workspace_bp, url_prefix='/workspace')

    from app.geo import geo as geo_bp
    app.register_blueprint(geo_bp, url_prefix='/geo')

    from app.reports import reports as reports_bp
    app.register_blueprint(reports_bp, url_prefix='/reports')

    from app.audit import audit as audit_bp
    app.register_blueprint(audit_bp, url_prefix='/audit')

    @app.context_processor
    def inject_ml_status():
        try:
            from ml_models.predictor import models_loaded
            return {'ml_status': models_loaded()}
        except Exception:
            return {'ml_status': {'ids_loaded': False, 'unsw_loaded': False, 'log_loaded': False}}

    return app
