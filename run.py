import os
import sys
from pathlib import Path

# Always run from project root so datasets, .env, and DB paths resolve correctly.
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db

app = create_app()
app.url_map.strict_slashes = False


def _ensure_database():
    """Initialize DB tables; import sample data only if database is empty."""
    db.create_all()
    uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if uri.startswith('sqlite:///'):
        db_file = Path(uri.replace('sqlite:///', '', 1))
        if db_file.exists() and db_file.stat().st_size > 0:
            from app.models import User
            if User.query.count() > 0:
                return
    print('[BIGIL] Database empty — importing real dataset evidence...')
    from import_real_data import main as import_data
    import_data()


if __name__ == '__main__':
    with app.app_context():
        _ensure_database()

    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ('1', 'true', 'yes')

    print('=' * 60)
    print('  BIGIL Forensic Platform')
    print(f'  Open: http://127.0.0.1:{port}')
    print('  Login: dcp_suresh / Gurugram@1234')
    print('=' * 60)

    # Disable reloader on Windows to avoid double-process port conflicts.
    use_reloader = debug and os.name != 'nt'
    app.run(debug=debug, host=host, port=port, use_reloader=use_reloader)
