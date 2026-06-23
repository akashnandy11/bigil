import sys
import os

# Ensure the project root is in sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.chdir(ROOT)

from app import create_app, db

app = create_app()
app.url_map.strict_slashes = False

# Initialize DB on cold start
with app.app_context():
    db.create_all()

# Vercel expects a module-level `app` object (WSGI)
