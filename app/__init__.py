"""
App factory for SecureShield.
Creates the Flask app and registers the proxy blueprint.
"""

from flask import Flask


def create_app():
    """Set up the Flask app and register routes."""
    app = Flask(__name__)

    import config
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["TARGET_HOST"] = config.TARGET_HOST
    app.config["BRUTE_FORCE_THRESHOLD"] = config.BRUTE_FORCE_THRESHOLD
    app.config["BRUTE_FORCE_COOLDOWN"] = config.BRUTE_FORCE_COOLDOWN

    # set up the database
    from app.models import init_db
    init_db()

    # proxy handles all the forwarding
    from app.proxy import proxy_bp
    app.register_blueprint(proxy_bp)

    # dashboard for viewing security events
    from app.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    print(f"[SecureShield] Forwarding to: {config.TARGET_HOST}")
    print(f"[SecureShield] Ready.")

    return app
