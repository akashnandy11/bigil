import os
from pathlib import Path
from dotenv import load_dotenv

basedir = Path(__file__).resolve().parent
load_dotenv(basedir / '.env')

_DEFAULT_DB = basedir / 'instance' / 'bigil.db'
_DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)


def _database_uri() -> str:
    env_url = (os.environ.get('DATABASE_URL') or '').strip()
    if env_url:
        if env_url.startswith('sqlite:///') and not env_url.startswith('sqlite:////'):
            rel = env_url.replace('sqlite:///', '', 1)
            if rel and not Path(rel).is_absolute():
                return 'sqlite:///' + str((basedir / rel).resolve()).replace('\\', '/')
        return env_url
    return 'sqlite:///' + str(_DEFAULT_DB.resolve()).replace('\\', '/')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'bigil-gurugram-cyber-cell-2024-secret-key'
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = str(basedir / 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max upload
    ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json', 'xml', 'evtx', 'zip', 'pcap', 'pdf', 'png', 'jpg'}

    # Threat Intelligence Provider API Keys (set in .env)
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    MALWAREBAZAAR_API_KEY = os.environ.get('MALWAREBAZAAR_API_KEY', '')
    URLHAUS_API_KEY = os.environ.get('URLHAUS_API_KEY', '')

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
