"""
Entry point for SecureShield.
Just creates the app and starts Flask.
"""

from app import create_app
from config import FLASK_HOST, FLASK_PORT, DEBUG

if __name__ == "__main__":
    app = create_app()
    print(f"[SecureShield] Running on http://{FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=DEBUG)
